package runtime

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/storage"
	"go.uber.org/zap"
)

func TestDeliveredFilesDownloadButMediaRemainsInline(t *testing.T) {
	s3 := storage.NewS3ClientFromParams("https://files.example", "test", "test", "bucket", "us-east-1")
	parts := []wire.DisplayPart{
		{Type: "file", Source: "agents/a/media/run/memo.md", Filename: "memo.md"},
		{Type: "file", Source: "agents/a/media/run/video.mp4", MimeType: "video/mp4", Filename: "video.mp4"},
	}
	check := func(t *testing.T, got []wire.DisplayPart) {
		t.Helper()
		for i, part := range got {
			u, err := url.Parse(part.URL)
			if err != nil {
				t.Fatal(err)
			}
			disposition := u.Query().Get("response-content-disposition")
			if i == 0 && (!strings.HasPrefix(disposition, "attachment;") || !strings.Contains(disposition, "memo.md")) {
				t.Fatalf("file download disposition = %q", disposition)
			}
			if i == 1 && disposition != "" {
				t.Fatalf("video forced to download: %q", disposition)
			}
		}
	}
	t.Run("typed", func(t *testing.T) { check(t, resolveDisplayParts(context.Background(), s3, zap.NewNop(), parts)) })
	t.Run("persisted", func(t *testing.T) {
		raw, _ := json.Marshal(parts)
		var got []wire.DisplayPart
		if err := json.Unmarshal(ResolveMediaPartsJSON(context.Background(), s3, zap.NewNop(), raw), &got); err != nil {
			t.Fatal(err)
		}
		check(t, got)
	})
}
