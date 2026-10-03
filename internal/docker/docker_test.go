package docker

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func frame(stream byte, payload string) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = stream
	binary.BigEndian.PutUint32(b[4:], uint32(len(payload)))
	copy(b[8:], payload)
	return b
}

func TestDemux(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(1, `{"a":`))
	in.Write(frame(2, "warning\n"))
	in.Write(frame(1, `1}`))
	stdout, stderr, err := demux(&in, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(stdout) != `{"a":1}` || string(stderr) != "warning\n" {
		t.Fatalf("stdout %q stderr %q", stdout, stderr)
	}
}

func TestDemuxLimits(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(1, strings.Repeat("x", 100)))
	if _, _, err := demux(&in, 50); err == nil {
		t.Fatal("stdout over the limit accepted")
	}

	in.Reset()
	in.Write(frame(2, strings.Repeat("e", maxStderr+10)))
	in.Write(frame(1, "ok"))
	stdout, stderr, err := demux(&in, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(stdout) != "ok" || len(stderr) != maxStderr {
		t.Fatalf("stdout %q, stderr %d bytes", stdout, len(stderr))
	}
}

func TestDemuxTruncatedFrame(t *testing.T) {
	b := frame(1, "hello")
	if _, _, err := demux(bytes.NewReader(b[:10]), 0); err == nil {
		t.Fatal("truncated frame accepted")
	}
}
