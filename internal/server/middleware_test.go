package server

import (
	"strings"
	"testing"
)

func TestLogSafe(t *testing.T) {
	got := logSafe("a\r\nFAKE: forged\x1b[31m\x00z")
	if strings.ContainsAny(got, "\r\n\x1b\x00") {
		t.Errorf("control characters survived: %q", got)
	}
	if logSafe("plain-ünïcode") != "plain-ünïcode" {
		t.Error("ordinary text must be unchanged")
	}
}
