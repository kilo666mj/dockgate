package protocol

import (
	"strings"
	"testing"
)

func TestJoinTokenRoundTrip(t *testing.T) {
	want := JoinToken{ID: "0123456789abcdef", Secret: "s3cr3t-_x", CAPin: strings.Repeat("ab", 32)}
	got, err := ParseJoinToken(" " + want.String() + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseJoinTokenRejects(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	for _, s := range []string{
		"",
		"dgt2.id.secret." + pin,
		"dgt1.id.secret",
		"dgt1..secret." + pin,
		"dgt1.id.secret.zz",
		"dgt1.id.secret." + pin[:62],
	} {
		if _, err := ParseJoinToken(s); err == nil {
			t.Errorf("ParseJoinToken(%q) succeeded", s)
		}
	}
}
