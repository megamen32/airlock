package api

import "testing"

func TestDeliveredFileCannotSelectUndeliveredOrForeignStorage(t *testing.T) {
	raw := []byte(`[{"type":"file","source":"agents/app/media/run/memo.md","filename":"памятка.md"}]`)
	part, ok := deliveredFile(raw, "agents/app/media/run/memo.md", "app")
	if !ok || part.Filename != "памятка.md" {
		t.Fatal("delivered file not found")
	}
	for _, source := range []string{"agents/app/exports/private.md", "agents/other/media/run/memo.md", "agents/app/media/../secret", "agents/app/media/run/missing.md"} {
		if _, ok := deliveredFile(raw, source, "app"); ok {
			t.Fatalf("accepted undelivered source %q", source)
		}
	}
	unsafe := []byte(`[{"type":"file","source":"agents/app/media/run/memo.md","filename":"../secret"}]`)
	if _, ok := deliveredFile(unsafe, "agents/app/media/run/memo.md", "app"); ok {
		t.Fatal("unsafe download filename")
	}
}
