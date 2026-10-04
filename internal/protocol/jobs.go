package protocol

// PathJobResult is where an agent reports a finished job.
const PathJobResult = "/v1/agent/job"

// JobUpdate recreates a container with an approved image. It is the only
// job kind; agents refuse any other.
const JobUpdate = "update"

// Job is work the server hands an agent in a report response. It carries
// data, never a command: the agent decides how to carry it out.
type Job struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	// ContainerID and ContainerName identify the container as the server
	// last saw it; the agent refuses the job if either changed.
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	// Reference is the image reference the container was created with
	// (repository:tag); the new container keeps it.
	Reference string `json:"reference"`
	// Digest is the approved, scanned manifest digest (sha256:...) that
	// Reference must resolve to.
	Digest string `json:"digest"`
}

// Job result states.
const (
	JobSucceeded  = "succeeded"
	JobFailed     = "failed"      // nothing changed, or the old container could not be restored
	JobRolledBack = "rolled_back" // the new container failed and the old one runs again
)

// JobResult is an agent's report on a job.
type JobResult struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// Steps is the agent's log of what it did, in order.
	Steps          []string `json:"steps"`
	NewContainerID string   `json:"new_container_id,omitempty"`
	DurationMS     int64    `json:"duration_ms"`
}
