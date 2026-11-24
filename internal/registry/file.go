package registry

import (
	"context"
	"os"
)

// FileSource loads the registry document from a file. The file is re-read
// whenever the Registry's cache expires, so edits take effect without a
// restart; replace it atomically (write and rename) so a half-written file
// is never read.
type FileSource struct {
	Path string
}

func (f FileSource) Load(context.Context) ([]byte, error) {
	return os.ReadFile(f.Path)
}

func (f FileSource) String() string { return "file " + f.Path }
