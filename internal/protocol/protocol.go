// Package protocol defines the messages exchanged between the dockgate agent
// and server, and the join token an operator hands to a new agent.
package protocol

import (
	"encoding/json"
	"time"
)

// API paths on the server's agent listener.
const (
	PathEnroll = "/v1/enroll"
	PathRenew  = "/v1/agent/renew"
	PathReport = "/v1/agent/report"
	PathSBOM   = "/v1/agent/sbom"
)

// EnrollRequest is sent once, without a client certificate, to exchange a
// join token for a client certificate.
type EnrollRequest struct {
	TokenID     string `json:"token_id"`
	TokenSecret string `json:"token_secret"`
	// Name is the agent's display name; the server uses the token's name
	// when the token carries one.
	Name string `json:"name"`
	// CSR is a PEM-encoded certificate signing request for the agent's key.
	CSR string `json:"csr"`
}

// EnrollResponse carries the agent's identity and certificates.
type EnrollResponse struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name"`
	// Certificate is the PEM-encoded client certificate.
	Certificate string `json:"certificate"`
	// CA is the PEM-encoded CA certificate the agent must trust.
	CA string `json:"ca"`
}

// RenewRequest asks for a fresh certificate for the agent's existing key.
// It is sent over mTLS with the current certificate.
type RenewRequest struct {
	CSR string `json:"csr"`
}

// RenewResponse carries the renewed certificate.
type RenewResponse struct {
	Certificate string `json:"certificate"`
}

// Report is the agent's periodic snapshot of its Docker host.
type Report struct {
	AgentVersion string      `json:"agent_version"`
	Hostname     string      `json:"hostname"`
	CollectedAt  time.Time   `json:"collected_at"`
	Docker       DockerInfo  `json:"docker"`
	Containers   []Container `json:"containers"`
	Images       []Image     `json:"images"`
	// Errors lists collection problems that did not stop the report.
	Errors []string `json:"errors,omitempty"`
	// Scanning is true when the agent generates SBOMs; SBOMPending then lists
	// the image IDs it has queued or is inventorying, so the server can tell
	// a lost request from a slow one.
	Scanning    bool     `json:"scanning,omitempty"`
	SBOMPending []string `json:"sbom_pending,omitempty"`
	// Jobs is true when the agent executes jobs; JobsRunning then lists the
	// jobs it holds (queued, running, or with an unsent result).
	Jobs        bool     `json:"jobs,omitempty"`
	JobsRunning []string `json:"jobs_running,omitempty"`
}

// DockerInfo describes the Docker engine on the host.
type DockerInfo struct {
	Version       string `json:"version"`
	APIVersion    string `json:"api_version"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	KernelVersion string `json:"kernel_version"`
	CPUs          int    `json:"cpus"`
	MemoryBytes   int64  `json:"memory_bytes"`
}

// Container is one container on the host.
type Container struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Image          string            `json:"image"`
	ImageID        string            `json:"image_id"`
	State          string            `json:"state"`
	Status         string            `json:"status"`
	Health         string            `json:"health,omitempty"`
	RestartCount   int               `json:"restart_count"`
	Created        time.Time         `json:"created"`
	StartedAt      time.Time         `json:"started_at,omitzero"`
	ComposeProject string            `json:"compose_project,omitempty"`
	ComposeService string            `json:"compose_service,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Update         *UpdateCheck      `json:"update,omitempty"`
}

// Image is one image on the host.
type Image struct {
	ID          string    `json:"id"`
	RepoTags    []string  `json:"repo_tags,omitempty"`
	RepoDigests []string  `json:"repo_digests,omitempty"`
	SizeBytes   int64     `json:"size_bytes"`
	Created     time.Time `json:"created"`
}

// Update check outcomes.
const (
	UpdateCurrent     = "current"
	UpdateAvailable   = "available"
	UpdateUnknown     = "unknown"     // the check could not decide, see Error
	UpdateUnsupported = "unsupported" // the image reference cannot be checked
)

// UpdateCheck is the result of comparing a container's image with its
// registry tag.
type UpdateCheck struct {
	Status       string    `json:"status"`
	Reference    string    `json:"reference"`
	LocalDigests []string  `json:"local_digests,omitempty"`
	RemoteDigest string    `json:"remote_digest,omitempty"`
	CheckedAt    time.Time `json:"checked_at"`
	Error        string    `json:"error,omitempty"`
}

// ReportResponse tells the agent when to report next and which images the
// server needs an SBOM for.
type ReportResponse struct {
	NextReportSeconds int `json:"next_report_seconds"`
	// SBOMRequests are local image IDs (sha256:...) to inventory. The agent
	// decides how; the server never sends a command.
	SBOMRequests []string `json:"sbom_requests,omitempty"`
	// Jobs are approved jobs for this agent, each sent once.
	Jobs []Job `json:"jobs,omitempty"`
}

// FormatCycloneDXJSON is the only SBOM format agents send.
const FormatCycloneDXJSON = "cyclonedx-json"

// SBOMUpload carries one image's SBOM, or the reason it could not be made.
type SBOMUpload struct {
	ImageID   string `json:"image_id"`
	Format    string `json:"format,omitempty"`
	Generator string `json:"generator,omitempty"`
	// Document is the SBOM itself; empty when Error is set.
	Document   json.RawMessage `json:"document,omitempty"`
	Error      string          `json:"error,omitempty"`
	DurationMS int64           `json:"duration_ms"`
}

// Error is the JSON body of a failed API request.
type Error struct {
	Error string `json:"error"`
}
