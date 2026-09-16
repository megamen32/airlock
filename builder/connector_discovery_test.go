package builder

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConnectorDiscoveryIgnoresEmptyRemovedPackage(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"removed", "active"} {
		if err := os.MkdirAll(filepath.Join(root, "connectors", name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "connectors", "active", "main.go"), []byte("package main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	packages, err := discoverConnectorPackages(root)
	if err != nil || len(packages) != 1 || packages[0].slug != "active" {
		t.Fatalf("packages=%#v err=%v", packages, err)
	}
}
