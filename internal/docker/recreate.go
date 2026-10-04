package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// The calls below support recreating a container with a new image. They
// keep container and image configuration as generic JSON objects so that
// settings this package does not know about survive the round trip from
// inspect to create unchanged.

// Inspect is a container as GET /containers/{id}/json returns it.
type Inspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"` // image ID
	State struct {
		Status     string `json:"Status"`
		Running    bool   `json:"Running"`
		Restarting bool   `json:"Restarting"`
		StartedAt  string `json:"StartedAt"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount    int            `json:"RestartCount"`
	Config          map[string]any `json:"Config"`
	HostConfig      map[string]any `json:"HostConfig"`
	Mounts          []Mount        `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]map[string]any `json:"Networks"`
	} `json:"NetworkSettings"`
}

// Mount is one entry of a container's Mounts.
type Mount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

// Health returns the health check status, or "" without a health check.
func (i Inspect) Health() string {
	if i.State.Health == nil {
		return ""
	}
	return i.State.Health.Status
}

// getNumbers is get with numbers kept exact (json.Number), so large values
// such as memory limits survive being sent back to the daemon.
func (c *Client) getNumbers(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("docker %s: decode: %w", path, err)
	}
	return nil
}

// InspectContainer returns a container's full configuration.
func (c *Client) InspectContainer(ctx context.Context, id string) (Inspect, error) {
	var v Inspect
	err := c.getNumbers(ctx, "/containers/"+url.PathEscape(id)+"/json", &v)
	return v, err
}

// ImageConfig returns an image's default container configuration.
func (c *Client) ImageConfig(ctx context.Context, ref string) (map[string]any, error) {
	var v struct {
		Config map[string]any `json:"Config"`
	}
	err := c.getNumbers(ctx, "/images/"+ref+"/json", &v)
	return v.Config, err
}

// ImageDigests returns an image's repository digests (repo@sha256:...).
func (c *Client) ImageDigests(ctx context.Context, ref string) ([]string, error) {
	var v struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	err := c.get(ctx, "/images/"+ref+"/json", nil, &v)
	return v.RepoDigests, err
}

// NetworkModes maps every container name with its HostConfig.NetworkMode, to
// find containers sharing another container's network namespace.
func (c *Client) NetworkModes(ctx context.Context) (map[string]string, error) {
	var list []struct {
		ID         string   `json:"Id"`
		Names      []string `json:"Names"`
		HostConfig struct {
			NetworkMode string `json:"NetworkMode"`
		} `json:"HostConfig"`
	}
	if err := c.get(ctx, "/containers/json", url.Values{"all": {"true"}}, &list); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(list))
	for _, ctr := range list {
		name := ctr.ID
		if len(ctr.Names) > 0 {
			name = ctr.Names[0][1:]
		}
		out[name] = ctr.HostConfig.NetworkMode
	}
	return out, nil
}

// PullAuth pulls repository@digest with an optional X-Registry-Auth value.
func (c *Client) PullAuth(ctx context.Context, repository, digest, registryAuth string) error {
	u := c.base + "/images/create?" + url.Values{"fromImage": {repository}, "tag": {digest}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	if registryAuth != "" {
		req.Header.Set("X-Registry-Auth", registryAuth)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("pull %s@%s: %w", repository, digest, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&msg)
		return &StatusError{Path: "/images/create", Code: resp.StatusCode, Message: msg.Message}
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var line struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &line) == nil && line.Error != "" {
			return fmt.Errorf("pull %s@%s: %s", repository, digest, line.Error)
		}
	}
	return sc.Err()
}

// TagImage points repository:tag at the image ref.
func (c *Client) TagImage(ctx context.Context, ref, repository, tag string) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return c.post(ctx, "/images/"+ref+"/tag", url.Values{"repo": {repository}, "tag": {tag}}, nil, nil)
}

// RenameContainer renames a container.
func (c *Client) RenameContainer(ctx context.Context, id, name string) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/rename", url.Values{"name": {name}}, nil, nil)
}

// StopContainer stops a container, giving it the container's configured
// stop timeout; an already stopped container is not an error.
func (c *Client) StopContainer(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	resp, err := c.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop", nil, nil)
	if err != nil {
		return err
	}
	return resp.Body.Close() // 204, or 304 when already stopped
}

// StartContainer starts a container.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return c.post(ctx, "/containers/"+url.PathEscape(id)+"/start", nil, nil, nil)
}

// CreateContainer creates a named container from a create request body
// (the container config with HostConfig and NetworkingConfig).
func (c *Client) CreateContainer(ctx context.Context, name string, body map[string]any) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var created struct {
		ID string `json:"Id"`
	}
	err := c.post(ctx, "/containers/create", url.Values{"name": {name}}, body, &created)
	return created.ID, err
}

// ConnectNetwork attaches a container to a network with an endpoint config.
func (c *Client) ConnectNetwork(ctx context.Context, network, id string, endpoint map[string]any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return c.post(ctx, "/networks/"+url.PathEscape(network)+"/connect", nil,
		map[string]any{"Container": id, "EndpointConfig": endpoint}, nil)
}

// RemoveKeepVolumes force-removes a container but leaves its volumes, which
// a replacement container may be using.
func (c *Client) RemoveKeepVolumes(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	resp, err := c.do(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id), url.Values{"force": {"true"}}, nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// LogTail returns the last lines of a container's combined output.
func (c *Client) LogTail(ctx context.Context, id string, lines int) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs",
		url.Values{"stdout": {"true"}, "stderr": {"true"}, "tail": {strconv.Itoa(lines)}}, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return "", err
	}
	// Containers without a TTY return a multiplexed stream; with a TTY the
	// output is raw.
	if len(body) >= 8 && (body[0] == 1 || body[0] == 2) && body[1] == 0 && body[2] == 0 && body[3] == 0 {
		stdout, stderr, err := demux(bytes.NewReader(body), 256<<10)
		if err == nil {
			return string(append(stdout, stderr...)), nil
		}
	}
	return string(body), nil
}

// Raw sends a request whose response body is not needed, for Engine API
// calls without a dedicated method (tests create networks and volumes).
func (c *Client) Raw(ctx context.Context, method, path string, body any) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	resp, err := c.do(ctx, method, path, nil, body)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}
