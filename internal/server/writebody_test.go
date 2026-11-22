package server

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type brokenWriter struct{ http.ResponseWriter }

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("client went away") }

func TestWriteBody_LogsAFailedWrite(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	jsonOK(brokenWriter{httptest.NewRecorder()}, map[string]string{"a": "b"})
	if !strings.Contains(buf.String(), "response write failed") {
		t.Errorf("a failed response write must be logged, got %q", buf.String())
	}

	buf.Reset()
	rec := httptest.NewRecorder()
	jsonOK(rec, map[string]string{"a": "b"})
	if buf.Len() != 0 || !strings.Contains(rec.Body.String(), `"a":"b"`) {
		t.Errorf("a normal write must be silent and complete: log=%q body=%q", buf.String(), rec.Body.String())
	}
}
