package firewall

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileIfChangedSkipsUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lite-plus-firewall.service")
	changed, err := writeFileIfChanged(path, "unit-v1\n", 0o644)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	changed, err = writeFileIfChanged(path, "unit-v1\n", 0o644)
	if err != nil || changed {
		t.Fatalf("same content must not rewrite: changed=%v err=%v", changed, err)
	}
	changed, err = writeFileIfChanged(path, "unit-v2\n", 0o644)
	if err != nil || !changed {
		t.Fatalf("new content must rewrite: changed=%v err=%v", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "unit-v2\n" {
		t.Fatalf("got %q err=%v", got, err)
	}
}
