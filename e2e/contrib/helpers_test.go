package contrib

import (
	"os"
	"path/filepath"
	"testing"
)

// loadWasm reads a wasm file relative to the repo root. From contrib/e2e/
// the repo root is two directories up.
func loadWasm(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("reading %s (build the plugin first): %v", rel, err)
	}
	return b
}
