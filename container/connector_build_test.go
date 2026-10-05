package container

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestManifestErrorWithoutDiagnosticBuffer(t *testing.T) {
	want := errors.New("connector container failed before stderr capture")
	if got := manifestError(want, nil); !errors.Is(got, want) {
		t.Fatalf("manifestError(nil) = %v, want %v", got, want)
	}
}

func TestConnectorCompilerStaysWithinSandboxProcessBudget(t *testing.T) {
	for _, target := range []string{"", "linux-amd64", "linux-arm64"} {
		env, err := connectorBuildEnvironment(target)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(env, "GOMAXPROCS=2") {
			t.Fatal("compiler runtime follows host CPU count")
		}
		if !slices.ContainsFunc(env, func(v string) bool { return strings.HasPrefix(v, "GOFLAGS=") && strings.Contains(v, "-p=2") }) {
			t.Fatal("compiler package parallelism is unbounded")
		}
	}
}
