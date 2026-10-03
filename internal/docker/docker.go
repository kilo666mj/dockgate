// Package docker is a minimal read-only client for the Docker Engine API
// over its Unix socket. It covers only what the agent reports, which keeps
// the agent free of the full Docker SDK and its dependency tree.
package docker

import (
	"context"
	"encoding/json"
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
	return &Client{http: &http.Client{Transport: transport, Timeout: 30 * time.Second}, base: "http://docker"}
}

// NewWithHTTP returns a client that sends requests to baseURL with hc; tests
// use it with an httptest server.
func NewWithHTTP(hc *http.Client, baseURL string) *Client {
	return &Client{http: hc, base: strings.TrimRight(baseURL, "/")}
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("docker %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var body struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body)
		return fmt.Errorf("docker %s: %s: %s", path, resp.Status, body.Message)
	}
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
