package builder

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCopyAgentRepoWithRelativeBasePath(t *testing.T) {
	basePath, err := os.MkdirTemp(".", ".copy-agent-repo-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(basePath) })

	// A relative path is valid configuration and all other repository helpers
	// resolve it from the server process working directory.
	basePath = filepath.Base(basePath)
	if err := InitAgentRepo(basePath, "source"); err != nil {
		t.Fatalf("InitAgentRepo: %v", err)
	}
	if err := CopyAgentRepo(basePath, "source", "destination"); err != nil {
		t.Fatalf("CopyAgentRepo: %v", err)
	}

	destination := filepath.Join(basePath, "destination")
	if _, err := os.Stat(filepath.Join(destination, ".git")); err != nil {
		t.Fatalf("destination repository: %v", err)
	}
	if err := git(destination, "remote", "get-url", "origin"); err == nil {
		t.Fatal("clone unexpectedly retained its source remote")
	}
}
