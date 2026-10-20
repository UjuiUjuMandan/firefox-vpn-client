package vpnclient

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWritePrivateFileReplacesContentAndTightensPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")

	// G306: deliberately loose so the test proves writePrivateFile tightens it.
	err := os.WriteFile(path, []byte("old"), 0644) //nolint:gosec // G306
	if err != nil {
		t.Fatalf("creating old token file: %v", err)
	}

	err = writePrivateFile(path, []byte("new"))
	if err != nil {
		t.Fatalf("writePrivateFile returned error: %v", err)
	}

	data, err := os.ReadFile(path) //nolint:gosec // G304: path is a t.TempDir fixture
	if err != nil {
		t.Fatalf("reading token file: %v", err)
	}

	if string(data) != "new" {
		t.Fatalf("expected replaced content, got %q", data)
	}

	if runtime.GOOS == "windows" {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}

	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("expected token file mode 0600, got %o", got)
	}
}
