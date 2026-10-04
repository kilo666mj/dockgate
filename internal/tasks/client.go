package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Client talks to Taskboard's MCP endpoint with a dedicated agent
// credential. Taskboard accepts agent credentials only on /mcp.
type Client struct {
	Endpoint string // e.g. https://taskboard.example.net/mcp
	Token    string
	Version  string
	HTTP     *http.Client
}

type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

func (c *Client) call(ctx context.Context, tool string, args any) (Task, error) {
	base := c.HTTP
	if base == nil {
		base = &http.Client{Timeout: 30 * time.Second}
	}
	next := base.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	hc := *base
	hc.Transport = bearer{token: c.Token, next: next}
	client := mcp.NewClient(&mcp.Implementation{Name: "dockgate", Version: c.Version}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: c.Endpoint, HTTPClient: &hc}, nil)
	if err != nil {
		return Task{}, fmt.Errorf("connect to taskboard: %w", err)
	}
	defer func() { _ = session.Close() }()
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return Task{}, fmt.Errorf("taskboard %s: %w", tool, err)
	}
	if res.IsError {
		return Task{}, fmt.Errorf("taskboard %s: %s", tool, toolText(res))
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return Task{}, err
	}
	var out struct {
		Task struct {
			ID      string `json:"id"`
			Version int64  `json:"version"`
			Status  string `json:"status"`
			Owner   string `json:"owner"`
		} `json:"task"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Task{}, fmt.Errorf("taskboard %s response: %w", tool, err)
	}
	if out.Task.ID == "" {
		return Task{}, errors.New("taskboard " + tool + ": response has no task")
	}
	return Task{ID: out.Task.ID, Version: out.Task.Version, Status: out.Task.Status, Owner: out.Task.Owner}, nil
}

func toolText(res *mcp.CallToolResult) string {
	var parts []string
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, " ")
}

// Create files an agent-lane task. force_new is set because dockgate keeps
// its own one-task-per-container record, and Taskboard's title similarity
// would otherwise treat containers with similar names as duplicates.
func (c *Client) Create(ctx context.Context, r CreateRequest) (Task, error) {
	return c.call(ctx, "task_create", map[string]any{
		"title": r.Title, "summary": r.Summary, "visibility": "agent", "type": "work", "project": r.Project,
		"priority": r.Priority, "checklist": r.Checklist, "requirements": r.Requirements,
		"force_new": true, "idempotency_key": r.IdempotencyKey,
	})
}

// Get reads a task.
func (c *Client) Get(ctx context.Context, id string) (Task, error) {
	return c.call(ctx, "task_get", map[string]any{"task_id": id})
}

// Refresh updates an unclaimed task's summary and priority.
func (c *Client) Refresh(ctx context.Context, id string, version int64, summary, priority string) (Task, error) {
	return c.call(ctx, "task_update", map[string]any{
		"task_id": id, "expected_version": version, "summary": summary, "priority": priority,
	})
}

// Cancel cancels an unclaimed task with a note.
func (c *Client) Cancel(ctx context.Context, id string, version int64, note string) (Task, error) {
	return c.call(ctx, "task_update", map[string]any{
		"task_id": id, "expected_version": version, "status": "cancelled", "current_note": note,
	})
}
