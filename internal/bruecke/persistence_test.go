package bruecke

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteJSONFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeJSONFile(path, "test store", map[string]int{"version": 1}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONFile(path, "test store", map[string]int{"version": 2}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\n  \"version\": 2\n}\n" {
		t.Fatalf("unexpected JSON: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("permissions = %o, want 600", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file remains: %v", err)
	}
}

func TestWriteJSONFileFailures(t *testing.T) {
	t.Run("encoding preserves existing store", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := writeJSONFile(path, "test store", make(chan int))
		if err == nil || !strings.HasPrefix(err.Error(), "encode test store:") {
			t.Fatalf("unexpected error: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "original" {
			t.Fatalf("existing store changed: %q, %v", data, err)
		}
	})
	t.Run("missing parent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "state.json")
		if err := writeJSONFile(path, "test store", 1); err == nil || !strings.HasPrefix(err.Error(), "write test store:") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("failed replacement removes temporary file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writeJSONFile(path, "test store", 1); err == nil || !strings.HasPrefix(err.Error(), "replace test store:") {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("temporary file remains: %v", err)
		}
	})
}
