package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// The output contract, including what holds after a crash and on Windows or
// network filesystems, is documented in docs/output-safety.md. In short:
//
//   - The input is never written: an output path that resolves to the input
//     file (same path, another path, a symlink or a hard link to it) is refused.
//   - Without -force the output is created with O_EXCL, so an existing file or
//     symlink is never replaced, even if it appears after any check.
//   - With -force the data is written to a temporary file in the destination
//     directory, synced, closed and then renamed over the destination. The
//     destination is never deleted or truncated, so a reported failure leaves
//     it unchanged.
//   - Every write, sync, close, rename and cleanup error is reported, and a
//     file left incomplete by a reported failure is removed. Nothing is
//     cleaned up if the process is killed.

// outputPerm is the mode of a new output file. NFC files contain sector keys,
// so only the owner may read them. On Windows only the owner-write bit is used
// (it controls the read-only attribute); access is governed by inherited ACLs.
const outputPerm fs.FileMode = 0o600

var errSameFile = errors.New("output is the same file as the input")

// outputFile is the subset of *os.File used to write the output.
type outputFile interface {
	io.Writer
	Sync() error
	Close() error
	Name() string
}

// fileOps are the filesystem operations used to publish the output. Production
// code uses osFileOps; tests replace single operations to inject failures.
type fileOps struct {
	createNew  func(name string) (outputFile, error)
	createTemp func(dir, pattern string) (outputFile, error)
	rename     func(oldpath, newpath string) error
	remove     func(name string) error
}

var osFileOps = fileOps{
	createNew: func(name string) (outputFile, error) {
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, outputPerm)
		if err != nil {
			// Return an untyped nil: a nil *os.File in an interface is not nil.
			return nil, err
		}
		return f, nil
	},
	createTemp: func(dir, pattern string) (outputFile, error) {
		f, err := os.CreateTemp(dir, pattern) // mode 0600
		if err != nil {
			return nil, err
		}
		return f, nil
	},
	rename: os.Rename,
	remove: os.Remove,
}

// checkOutputIsNotInput fails if output names the file described by input,
// through any path, symlink or hard link. It compares file identity, not path
// strings. The check is made once, before writing; it does not protect against
// another process swapping files concurrently.
func checkOutputIsNotInput(input fs.FileInfo, output string) error {
	info, err := os.Stat(output)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("cannot check output file '%s': %w", output, err)
	case os.SameFile(input, info):
		return fmt.Errorf("refusing to write '%s': %w", output, errSameFile)
	default:
		return nil
	}
}

// writeOutputFile publishes data as the file name. Without force it never
// replaces an existing file; with force it replaces name by renaming a fully
// written temporary file over it.
func writeOutputFile(ops fileOps, name string, data []byte, force bool) error {
	if force {
		return replaceFile(ops, name, data)
	}
	return createNewFile(ops, name, data)
}

func createNewFile(ops fileOps, name string, data []byte) error {
	f, err := ops.createNew(name)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("refusing to overwrite existing file (use -force to replace it): %w", err)
	}
	if err != nil {
		return fmt.Errorf("failed to create NFC file '%s': %w", name, err)
	}
	if err := writeAndClose(f, data); err != nil {
		// The file was created exclusively above, so it is ours to remove.
		return removeAfterFailure(ops, f.Name(), err)
	}
	return nil
}

func replaceFile(ops fileOps, name string, data []byte) error {
	// The temporary file must be in the destination directory: rename is only
	// atomic within one filesystem. filepath.Dir returns "." for a bare name.
	tmp, err := ops.createTemp(filepath.Dir(name), "."+filepath.Base(name)+".*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create NFC file '%s': %w", name, err)
	}
	if err := writeAndClose(tmp, data); err != nil {
		return removeAfterFailure(ops, tmp.Name(), err)
	}
	if err := ops.rename(tmp.Name(), name); err != nil {
		return removeAfterFailure(ops, tmp.Name(), fmt.Errorf("failed to replace '%s': %w", name, err))
	}
	return nil
}

// writeAndClose writes data, asks the OS to flush it to storage (File.Sync)
// and closes f. The file is closed even when writing or syncing fails.
func writeAndClose(f outputFile, data []byte) error {
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		err = fmt.Errorf("failed to write '%s': %w", f.Name(), err)
	} else if err = f.Sync(); err != nil {
		err = fmt.Errorf("failed to sync '%s': %w", f.Name(), err)
	}
	if closeErr := f.Close(); closeErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to close '%s': %w", f.Name(), closeErr))
	}
	return err
}

// removeAfterFailure removes a file left incomplete by cause. A failed removal
// is reported together with cause, naming the file that was left behind.
func removeAfterFailure(ops fileOps, name string, cause error) error {
	if err := ops.remove(name); err != nil {
		return errors.Join(cause, fmt.Errorf("failed to remove incomplete file '%s': %w", name, err))
	}
	return cause
}
