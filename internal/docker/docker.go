// Package docker is a minimal client for the Docker Engine API over its Unix
// socket. It covers what the agent reports plus running the short-lived SBOM
// scanner container, which keeps the agent free of the full Docker SDK and its
// dependency tree.
package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one Docker daemon.
type Client struct {
	http *http.Client
	base string
}

// New returns a client for the daemon listening on socketPath.
func New(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:    2,
		IdleConnTimeout: 30 * time.Second,
	}
	// No client-wide timeout: waiting for a scanner container can take
	// minutes. Each call bounds itself with its context.
	return &Client{http: &http.Client{Transport: transport}, base: "http://docker"}
}

// NewWithHTTP returns a client that sends requests to baseURL with hc; tests
// use it with an httptest server.
func NewWithHTTP(hc *http.Client, baseURL string) *Client {
	return &Client{http: hc, base: strings.TrimRight(baseURL, "/")}
}

// requestTimeout bounds ordinary API calls.
const requestTimeout = 30 * time.Second

// StatusError is a non-success response from the daemon.
type StatusError struct {
	Path    string
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("docker %s: %d %s: %s", e.Path, e.Code, http.StatusText(e.Code), e.Message)
}

// IsNotFound reports whether err is a 404 from the daemon.
func IsNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

// do sends a request and returns the response for status 2xx; the caller
// closes the body.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any) (*http.Response, error) {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker %s: %w", path, err)
	}
	if resp.StatusCode/100 != 2 {
		defer func() { _ = resp.Body.Close() }()
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&msg)
		return nil, &StatusError{Path: path, Code: resp.StatusCode, Message: msg.Message}
	}
	return resp, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := c.do(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("docker %s: decode: %w", path, err)
	}
	return nil
}

// Version is the subset of GET /version the agent reports.
type Version struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	OS            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
}

// Version returns the daemon's version.
func (c *Client) Version(ctx context.Context) (Version, error) {
	var v Version
	err := c.get(ctx, "/version", nil, &v)
	return v, err
}

// Info is the subset of GET /info the agent reports.
type Info struct {
	NCPU     int   `json:"NCPU"`
	MemTotal int64 `json:"MemTotal"`
}

// Info returns host information from the daemon.
func (c *Client) Info(ctx context.Context) (Info, error) {
	var v Info
	err := c.get(ctx, "/info", nil, &v)
	return v, err
}

// ContainerSummary is one entry of GET /containers/json.
type ContainerSummary struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	ImageID string            `json:"ImageID"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Labels  map[string]string `json:"Labels"`
	Created int64             `json:"Created"`
}

// Name returns the container's primary name without the leading slash.
func (s ContainerSummary) Name() string {
	if len(s.Names) == 0 {
		return s.ID[:min(12, len(s.ID))]
	}
	return strings.TrimPrefix(s.Names[0], "/")
}

// Containers lists all containers, running or not.
func (c *Client) Containers(ctx context.Context) ([]ContainerSummary, error) {
	var out []ContainerSummary
	err := c.get(ctx, "/containers/json", url.Values{"all": {"true"}}, &out)
	return out, err
}

// ContainerDetail is the subset of GET /containers/{id}/json the agent uses.
type ContainerDetail struct {
	RestartCount int `json:"RestartCount"`
	State        struct {
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
}

// StartedAt parses the container's start time; it is zero for containers
// that never started.
func (d ContainerDetail) StartedAt() time.Time {
	t, err := time.Parse(time.RFC3339Nano, d.State.StartedAt)
	if err != nil || t.Year() < 2000 {
		return time.Time{}
	}
	return t
}

// Health returns the health check status, or "" without a health check.
func (d ContainerDetail) Health() string {
	if d.State.Health == nil {
		return ""
	}
	return d.State.Health.Status
}

// Container inspects one container.
func (c *Client) Container(ctx context.Context, id string) (ContainerDetail, error) {
	var d ContainerDetail
	err := c.get(ctx, "/containers/"+url.PathEscape(id)+"/json", nil, &d)
	return d, err
}

// ImageSummary is one entry of GET /images/json.
type ImageSummary struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Size        int64    `json:"Size"`
	Created     int64    `json:"Created"`
}

// Images lists the images on the host.
func (c *Client) Images(ctx context.Context) ([]ImageSummary, error) {
	var out []ImageSummary
	err := c.get(ctx, "/images/json", nil, &out)
	return out, err
}

// ImageExists reports whether ref (a name, ID or name@digest) is present.
func (c *Client) ImageExists(ctx context.Context, ref string) (bool, error) {
	var v struct {
		ID string `json:"Id"`
	}
	err := c.get(ctx, "/images/"+ref+"/json", nil, &v)
	if IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// PullImage pulls repository@digest. The daemon streams JSON progress lines;
// an error line fails the pull.
func (c *Client) PullImage(ctx context.Context, repository, digest string) error {
	resp, err := c.do(ctx, http.MethodPost, "/images/create", url.Values{"fromImage": {repository}, "tag": {digest}}, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
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

// RunSpec describes a one-shot container.
type RunSpec struct {
	Image  string
	Cmd    []string
	Binds  []string
	Labels map[string]string
	// MaxStdout caps captured standard output; the run fails beyond it.
	MaxStdout int64
}

// RunResult is a finished one-shot container.
type RunResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// Run creates, starts and waits for a locked-down container with no network,
// a read-only root filesystem, a tmpfs /tmp and no capabilities, then returns
// its output. The container is always removed.
func (c *Client) Run(ctx context.Context, spec RunSpec) (RunResult, error) {
	create := map[string]any{
		"Image":  spec.Image,
		"Cmd":    spec.Cmd,
		"Labels": spec.Labels,
		"HostConfig": map[string]any{
			"Binds":          spec.Binds,
			"NetworkMode":    "none",
			"ReadonlyRootfs": true,
			"Tmpfs":          map[string]string{"/tmp": "rw,size=512m"},
			"CapDrop":        []string{"ALL"},
			"SecurityOpt":    []string{"no-new-privileges"},
		},
	}
	var created struct {
		ID string `json:"Id"`
	}
	if err := c.post(ctx, "/containers/create", nil, create, &created); err != nil {
		return RunResult{}, err
	}
	defer func() {
		rmCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
		defer cancel()
		if resp, err := c.do(rmCtx, http.MethodDelete, "/containers/"+created.ID, url.Values{"force": {"true"}}, nil); err == nil {
			_ = resp.Body.Close()
		}
	}()
	if err := c.post(ctx, "/containers/"+created.ID+"/start", nil, nil, nil); err != nil {
		return RunResult{}, err
	}
	var waited struct {
		StatusCode int `json:"StatusCode"`
		Error      *struct {
			Message string `json:"Message"`
		} `json:"Error"`
	}
	if err := c.post(ctx, "/containers/"+created.ID+"/wait", nil, nil, &waited); err != nil {
		return RunResult{}, err
	}
	if waited.Error != nil && waited.Error.Message != "" {
		return RunResult{}, fmt.Errorf("wait: %s", waited.Error.Message)
	}
	logCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	resp, err := c.do(logCtx, http.MethodGet, "/containers/"+created.ID+"/logs", url.Values{"stdout": {"true"}, "stderr": {"true"}}, nil)
	if err != nil {
		return RunResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	stdout, stderr, err := demux(resp.Body, spec.MaxStdout)
	if err != nil {
		return RunResult{}, err
	}
	return RunResult{ExitCode: waited.StatusCode, Stdout: stdout, Stderr: stderr}, nil
}

func (c *Client) post(ctx context.Context, path string, query url.Values, body, out any) error {
	resp, err := c.do(ctx, http.MethodPost, path, query, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("docker %s: decode: %w", path, err)
	}
	return nil
}

// maxStderr bounds captured standard error, which is only used in messages.
const maxStderr = 64 << 10

// demux splits Docker's multiplexed log stream (8-byte frame headers naming
// the stream and payload length) into stdout and stderr.
func demux(r io.Reader, maxStdout int64) ([]byte, []byte, error) {
	var stdout, stderr bytes.Buffer
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return stdout.Bytes(), stderr.Bytes(), nil
			}
			return nil, nil, fmt.Errorf("read log frame: %w", err)
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		switch hdr[0] {
		case 1:
			if maxStdout > 0 && int64(stdout.Len())+n > maxStdout {
				return nil, nil, fmt.Errorf("container output exceeds %d bytes", maxStdout)
			}
			if _, err := io.CopyN(&stdout, r, n); err != nil {
				return nil, nil, err
			}
		default:
			keep := min(n, max(0, maxStderr-int64(stderr.Len())))
			if _, err := io.CopyN(&stderr, r, keep); err != nil {
				return nil, nil, err
			}
			if _, err := io.CopyN(io.Discard, r, n-keep); err != nil {
				return nil, nil, err
			}
		}
	}
}
