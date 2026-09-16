package storage

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestCopyObjectFallsBackWhenCopySourceIsFalselyMissing(t *testing.T) {
	const (
		bucket = "test-bucket"
		src    = "agents/agent/exports/user-1/report.md"
		dst    = "agents/agent/media/run-1/report.md"
		body   = "fallback copy content"
	)
	var copyCalls, headCalls, getCalls, putCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/"+bucket+"/"+dst && r.Header.Get("X-Amz-Copy-Source") != "":
			copyCalls.Add(1)
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>copy source lookup is broken</Message></Error>`)
		case r.Method == http.MethodHead && r.URL.Path == "/"+bucket+"/"+src:
			headCalls.Add(1)
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Header().Set("Content-Type", "text/markdown")
			w.Header().Set("ETag", `"source-etag"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/"+bucket+"/"+src:
			getCalls.Add(1)
			w.Header().Set("Content-Type", "text/markdown")
			_, _ = io.WriteString(w, body)
		case r.Method == http.MethodPut && r.URL.Path == "/"+bucket+"/"+dst:
			putCalls.Add(1)
			got, err := io.ReadAll(r.Body)
			if err != nil || string(got) != body {
				t.Errorf("fallback body = %q, %v", got, err)
			}
			if r.Header.Get("Content-Type") != "text/markdown" {
				t.Errorf("fallback content type = %q", r.Header.Get("Content-Type"))
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected S3 request %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()

	client := NewS3ClientFromParams(server.URL, "access", "secret", bucket, "us-east-1")
	if err := client.CopyObject(context.Background(), src, dst); err != nil {
		t.Fatalf("copy with fallback: %v", err)
	}
	if copyCalls.Load() != 1 || headCalls.Load() != 1 || getCalls.Load() != 1 || putCalls.Load() != 1 {
		t.Fatalf("calls copy=%d head=%d get=%d put=%d", copyCalls.Load(), headCalls.Load(), getCalls.Load(), putCalls.Load())
	}
}
