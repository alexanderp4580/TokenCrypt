package vault

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// File limits include JSON and base64 overhead for the 1 MiB value limit.
const (
	maxVaultFileBytes = 2 << 20
	maxMetaFileBytes  = 8 << 20
)

// readBounded checks size before allocating and limits reads even if the file grows.
func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > max {
		return nil, fmt.Errorf("%w: file exceeds size limit", ErrCorrupt)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: file exceeds size limit", ErrCorrupt)
	}
	return b, nil
}

// beforeRename is a test hook called after the temporary file is written and
// synced and before it is renamed over the target. A non-nil error aborts the
// write.
var beforeRename func() error

// syncDir flushes directory entries to disk. It is a variable so tests can
// observe and fail it.
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// writeFileAtomic writes data to path through a temporary file in the same
// directory: write, fsync, rename, then fsync of the directory. The file mode
// is 0600. An error before the rename removes the temporary file and leaves
// the target unchanged. An error from the final directory fsync is returned
// after the rename: the target then already holds the new content and only its
// durability across a crash is unconfirmed.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if beforeRename != nil {
		if err := beforeRename(); err != nil {
			os.Remove(tmpName)
			return err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}
