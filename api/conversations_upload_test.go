package api

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestIncomingUploadPathIsPrivateToTheAuthenticatedUser(t *testing.T) {
	userID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	path, err := incomingUploadPath(userID, "meeting.mp4")
	if err != nil {
		t.Fatalf("build private upload path: %v", err)
	}
	wantPrefix := "__incoming/user-" + userID.String() + "/"
	if !strings.HasPrefix(path, wantPrefix) || !strings.HasSuffix(path, "-meeting.mp4") {
		t.Fatalf("upload path = %q, want private incoming path below %q", path, wantPrefix)
	}
}

func TestIncomingUploadPathRejectsMissingUserAndUnsafeFilename(t *testing.T) {
	if _, err := incomingUploadPath(uuid.Nil, "meeting.mp4"); err == nil {
		t.Fatal("accepted an upload without an authenticated user")
	}
	userID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	if _, err := incomingUploadPath(userID, "../other-user.mp4"); err == nil {
		t.Fatal("accepted traversal in an upload filename")
	}
}
