package mcpapi

import (
	"context"
	"errors"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"go.michaelspost.com/dockgate/internal/jobs"
	"go.michaelspost.com/dockgate/internal/store"
)

type updateRequestInput struct {
	Host      string `json:"host" jsonschema:"host name as dockgate_fleet_status shows it"`
	Container string `json:"container" jsonschema:"container name"`
	Reason    string `json:"reason" jsonschema:"why the update is needed, shown to the approver"`
	TaskID    string `json:"taskboard_task_id,omitempty" jsonschema:"the Taskboard task this request belongs to, if any"`
	Requester string `json:"requester,omitempty" jsonschema:"who is asking, e.g. your agent name; recorded with the request"`
}

type jobView struct {
	store.Job
	ApprovalURL string `json:"approval_url,omitempty"`
}

type jobOutput struct {
	Job jobView `json:"job"`
}

func (t *tools) view(j store.Job) jobView {
	v := jobView{Job: j}
	if j.State == store.JobPendingApproval {
		v.ApprovalURL = t.jobs.URL(j.ID)
	}
	return v
}

func (t *tools) updateRequest(ctx context.Context, _ *mcp.CallToolRequest, in updateRequestInput) (*mcp.CallToolResult, jobOutput, error) {
	if strings.TrimSpace(in.Reason) == "" {
		return nil, jobOutput{}, errors.New("reason is required: say what the update fixes")
	}
	actor := "mcp"
	if r := strings.TrimSpace(in.Requester); r != "" {
		actor += ":" + truncateRunes(r, 80)
	}
	job, err := t.jobs.RequestUpdate(ctx, jobs.Request{
		Host: in.Host, Container: in.Container, Reason: in.Reason, TaskID: in.TaskID, Actor: actor,
	})
	if errors.Is(err, jobs.ErrDenied) {
		// A denial is an answer, not a failure: return the recorded job.
		return nil, jobOutput{Job: t.view(job)}, nil
	}
	if err != nil {
		return nil, jobOutput{}, err
	}
	return nil, jobOutput{Job: t.view(job)}, nil
}

type jobStatusInput struct {
	JobID string `json:"job_id"`
}

func (t *tools) jobStatus(ctx context.Context, _ *mcp.CallToolRequest, in jobStatusInput) (*mcp.CallToolResult, jobOutput, error) {
	job, err := t.store.Job(ctx, strings.TrimSpace(in.JobID))
	if errors.Is(err, store.ErrNotFound) {
		return nil, jobOutput{}, errors.New("no such job")
	}
	if err != nil {
		return nil, jobOutput{}, err
	}
	return nil, jobOutput{Job: t.view(job)}, nil
}

type jobListInput struct {
	Host     string `json:"host,omitempty"`
	OpenOnly bool   `json:"open_only,omitempty" jsonschema:"only jobs pending approval, approved or running"`
	Limit    int    `json:"limit,omitempty" jsonschema:"at most this many, default 50"`
}

type jobListOutput struct {
	Jobs []jobView `json:"jobs"`
}

func (t *tools) jobList(ctx context.Context, _ *mcp.CallToolRequest, in jobListInput) (*mcp.CallToolResult, jobListOutput, error) {
	f := store.JobFilter{Host: in.Host, Limit: in.Limit}
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if in.OpenOnly {
		f.States = store.OpenJobStates
	}
	list, err := t.store.Jobs(ctx, f)
	if err != nil {
		return nil, jobListOutput{}, err
	}
	out := jobListOutput{Jobs: []jobView{}}
	for _, j := range list {
		out.Jobs = append(out.Jobs, t.view(j))
	}
	return nil, out, nil
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
