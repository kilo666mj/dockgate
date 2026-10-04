package store

import "strings"

// UpdateExempt reports why a container is left out of update tasks and
// update jobs, or "" when it is not. Such containers are still inventoried
// and scanned.
func UpdateExempt(container string) string {
	// docker buildx create runs BuildKit daemons as containers; they are
	// build infrastructure that buildx recreates itself, not services.
	if strings.HasPrefix(container, "buildx_buildkit_") {
		return "it is a buildx builder container, which buildx manages itself"
	}
	return ""
}
