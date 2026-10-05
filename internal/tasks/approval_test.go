package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type fakeRaw struct {
	escalations, messages string
	err                   error
}

func (f fakeRaw) callRaw(_ context.Context, tool string, _ any) (json.RawMessage, error) {
	if f.err != nil {
		return nil, f.err
	}
	if tool == "task_escalation_list" {
		return json.RawMessage(f.escalations), nil
	}
	return json.RawMessage(f.messages), nil
}

const target = `dockgate-approval: {"host":"dock01","container":"web","digest":"sha256:new"}`

func messages(body string) string {
	b, _ := json.Marshal(map[string]any{"messages": []map[string]string{{"id": "Q1", "body": body}}})
	return string(b)
}

func escalation(status, option, by string) string {
	b, _ := json.Marshal(map[string]any{"escalations": []map[string]string{{"question_message_id": "Q1", "status": status, "selected_option": option, "resolved_by": by}}})
	return string(b)
}

func TestApprovedBy(t *testing.T) {
	question := "Before I request the update of web on dock01: how should it be applied?\n\n" + target
	for _, test := range []struct {
		name, escalations, messages, want string
	}{
		{"approved", escalation("answered", ApproveOption, "person-1"), messages(question), "person-1"},
		{"another person", escalation("answered", ApproveOption, "person-2"), messages(question), ""},
		{"other choice", escalation("answered", "I'll approve in dockgate", "person-1"), messages(question), ""},
		{"unanswered", escalation("open", "", ""), messages(question), ""},
		{"other digest", escalation("answered", ApproveOption, "person-1"), messages(question[:len(question)-len(target)] + `dockgate-approval: {"host":"dock01","container":"web","digest":"sha256:old"}`), ""},
		{"no marker", escalation("answered", ApproveOption, "person-1"), messages("Apply it?"), ""},
		{"two markers", escalation("answered", ApproveOption, "person-1"), messages(question + "\n" + target), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := &Approvals{API: fakeRaw{escalations: test.escalations, messages: test.messages}, Approvers: []string{"person-1"}}
			got, err := a.ApprovedBy(context.Background(), "T1", "dock01", "web", "sha256:new")
			if err != nil || got != test.want {
				t.Fatalf("ApprovedBy = %q, %v; want %q", got, err, test.want)
			}
		})
	}
	a := &Approvals{API: fakeRaw{err: errors.New("down")}, Approvers: []string{"person-1"}}
	if _, err := a.ApprovedBy(context.Background(), "T1", "dock01", "web", "sha256:new"); err == nil {
		t.Fatal("ApprovedBy hid a Taskboard error")
	}
	none := &Approvals{API: fakeRaw{err: errors.New("must not be called")}}
	if got, err := none.ApprovedBy(context.Background(), "T1", "dock01", "web", "sha256:new"); got != "" || err != nil {
		t.Fatalf("no approvers = %q, %v", got, err)
	}
}
