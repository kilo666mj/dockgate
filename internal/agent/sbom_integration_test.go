//go:build integration

// Integration test for SBOMs of images with JAR files against a real Docker
// daemon. It needs network once to fetch the Java DB (about 1.5 GB) into the
// dockgate-trivy-java-db volume. Point it at a local image that contains a
// JAR file:
//
//	DGTEST_JAR_IMAGE=sha256:... go test -tags integration -run TestIntegrationSBOM ./internal/agent
package agent

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"go.michaelspost.com/dockgate/internal/docker"
)

func TestIntegrationSBOMWithJAR(t *testing.T) {
	image := os.Getenv("DGTEST_JAR_IMAGE")
	if image == "" {
		t.Skip("DGTEST_JAR_IMAGE not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	g := &SBOMGenerator{Docker: docker.New(socket()), SocketPath: socket()}
	doc, err := g.Generate(ctx, image)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var bom struct {
		BOMFormat  string `json:"bomFormat"`
		Components []any  `json:"components"`
	}
	if err := json.Unmarshal(doc, &bom); err != nil || bom.BOMFormat != "CycloneDX" || len(bom.Components) == 0 {
		t.Fatalf("SBOM = %.200s, %v", doc, err)
	}
	if g.javaDBAt.IsZero() {
		t.Log("Java DB was not needed; is there a JAR in the image?")
	}
}
