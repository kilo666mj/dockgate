package tasks

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// ApprovalMarker starts the line of an approval question that names the
// update it approves, as JSON: {"host":…,"container":…,"digest":…}. The
// worker asking the question writes it; the answer approves exactly that.
const ApprovalMarker = "dockgate-approval: "

// ApproveOption is the choice that approves the update for dockgate to run.
const ApproveOption = "Let the agent update it"

// Approvals finds an operator's approval for an update in the Taskboard task
// that asked for it.
type Approvals struct {
	API interface {
		callRaw(ctx context.Context, tool string, args any) (json.RawMessage, error)
	}
	// Approvers are the Taskboard person principals whose answer approves.
	Approvers []string
}

// NewApprovals reads approvals with c for the given approvers.
func NewApprovals(c *Client, approvers []string) *Approvals {
	return &Approvals{API: c, Approvers: approvers}
}

type approvalTarget struct {
	Host      string `json:"host"`
	Container string `json:"container"`
	Digest    string `json:"digest"`
}

// ApprovedBy returns the approver who chose ApproveOption on a question in
// task taskID that names this host, container and digest, or "" when nobody
// did. Taskboard records who answered, so an agent cannot answer for them.
func (a *Approvals) ApprovedBy(ctx context.Context, taskID, host, container, digest string) (string, error) {
	if taskID == "" || len(a.Approvers) == 0 {
		return "", nil
	}
	raw, err := a.API.callRaw(ctx, "task_escalation_list", map[string]any{"task_id": taskID})
	if err != nil {
		return "", err
	}
	var escalations struct {
		Escalations []struct {
			QuestionMessageID string `json:"question_message_id"`
			Status            string `json:"status"`
			SelectedOption    string `json:"selected_option"`
			ResolvedBy        string `json:"resolved_by"`
		} `json:"escalations"`
	}
	if err := json.Unmarshal(raw, &escalations); err != nil {
		return "", fmt.Errorf("taskboard task_escalation_list response: %w", err)
	}
	approved := map[string]string{} // question message ID -> approver
	for _, e := range escalations.Escalations {
		if e.Status == "answered" && e.SelectedOption == ApproveOption && slices.Contains(a.Approvers, e.ResolvedBy) {
			approved[e.QuestionMessageID] = e.ResolvedBy
		}
	}
	if len(approved) == 0 {
		return "", nil
	}
	raw, err = a.API.callRaw(ctx, "task_message_list", map[string]any{"task_id": taskID, "limit": 200})
	if err != nil {
		return "", err
	}
	var messages struct {
		Messages []struct {
			ID   string `json:"id"`
			Body string `json:"body"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &messages); err != nil {
		return "", fmt.Errorf("taskboard task_message_list response: %w", err)
	}
	want := approvalTarget{Host: host, Container: container, Digest: digest}
	for _, m := range messages.Messages {
		person, ok := approved[m.ID]
		if !ok {
			continue
		}
		if target, ok := parseApprovalTarget(m.Body); ok && target == want {
			return person, nil
		}
	}
	return "", nil
}

// parseApprovalTarget reads the ApprovalMarker line of a question. A
// question with several marker lines is ambiguous and approves nothing.
func parseApprovalTarget(body string) (approvalTarget, bool) {
	var found []approvalTarget
	for _, line := range strings.Split(body, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), ApprovalMarker)
		if !ok {
			continue
		}
		var t approvalTarget
		if err := json.Unmarshal([]byte(rest), &t); err != nil || t.Host == "" || t.Container == "" || t.Digest == "" {
			return approvalTarget{}, false
		}
		found = append(found, t)
	}
	if len(found) != 1 {
		return approvalTarget{}, false
	}
	return found[0], true
}
