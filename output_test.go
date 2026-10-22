package main

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var (
	newData = []byte("new NFC content\n")
	oldData = []byte("existing file that must survive\n")
)

func writeTestFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func statFile(t *testing.T, name string) fs.FileInfo {
	t.Helper()
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// symlinkOrSkip creates a symlink, skipping the test where the platform or
// account cannot create one (Windows without the required privilege).
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func linkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Link(target, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
}

// assertDirEntries checks that dir contains exactly the given names, which
// catches leftover temporary files.
func assertDirEntries(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(entries))
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("directory contains %q, want %q", got, want)
	}
}

func assertContent(t *testing.T, name string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s contains %q, want %q", name, got, want)
	}
}

// assertOwnerOnly checks the mode of a file created by writeOutputFile. On
// Windows Go maps permissions to the read-only attribute only, so the file is
// expected to be writable and access is left to the inherited ACLs.
func assertOwnerOnly(t *testing.T, name string) {
	t.Helper()
	perm := statFile(t, name).Mode().Perm()
	if runtime.GOOS == "windows" {
		if perm&0o200 == 0 {
			t.Errorf("%s is read-only (mode %v), want a writable file", name, perm)
		}
		t.Logf("Windows reports mode %v; access is controlled by inherited ACLs", perm)
		return
	}
	if perm != outputPerm {
		t.Errorf("%s has mode %v, want %v", name, perm, outputPerm)
	}
}

// openedFileInfo returns the identity of the file name opens, the way
// parseProxMark3JSONFile obtains it for the input.
func openedFileInfo(t *testing.T, name string) fs.FileInfo {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestCheckOutputIsNotInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup creates files in dir and returns the input and output paths.
		setup    func(t *testing.T, dir string) (input, output string)
		wantSame bool
	}{
		{
			name: "output does not exist",
			setup: func(t *testing.T, dir string) (string, string) {
				in := filepath.Join(dir, "d.json")
				writeTestFile(t, in, oldData)
				return in, filepath.Join(dir, "card.nfc")
			},
		},
		{
			name: "different file with the same content",
			setup: func(t *testing.T, dir string) (string, string) {
				in, out := filepath.Join(dir, "d.json"), filepath.Join(dir, "copy.json")
				writeTestFile(t, in, oldData)
				writeTestFile(t, out, oldData)
				return in, out
			},
		},
		{
			name: "identical path",
			setup: func(t *testing.T, dir string) (string, string) {
				in := filepath.Join(dir, "d.json")
				writeTestFile(t, in, oldData)
				return in, in
			},
			wantSame: true,
		},
		{
			name: "dot alias",
			setup: func(t *testing.T, dir string) (string, string) {
				in := filepath.Join(dir, "d.json")
				writeTestFile(t, in, oldData)
				return in, dir + string(filepath.Separator) + "." + string(filepath.Separator) + "d.json"
			},
			wantSame: true,
		},
		{
			name: "parent directory alias",
			setup: func(t *testing.T, dir string) (string, string) {
				in := filepath.Join(dir, "d.json")
				writeTestFile(t, in, oldData)
				if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
					t.Fatal(err)
				}
				sep := string(filepath.Separator)
				return in, dir + sep + "sub" + sep + ".." + sep + "d.json"
			},
			wantSame: true,
		},
		{
			name: "output is a symlink to the input",
			setup: func(t *testing.T, dir string) (string, string) {
				in, out := filepath.Join(dir, "d.json"), filepath.Join(dir, "link.nfc")
				writeTestFile(t, in, oldData)
				symlinkOrSkip(t, in, out)
				return in, out
			},
			wantSame: true,
		},
		{
			name: "input is a symlink to the output",
			setup: func(t *testing.T, dir string) (string, string) {
				target, in := filepath.Join(dir, "d.json"), filepath.Join(dir, "link.json")
				writeTestFile(t, target, oldData)
				symlinkOrSkip(t, target, in)
				return in, target
			},
			wantSame: true,
		},
		{
			name: "output is a hard link to the input",
			setup: func(t *testing.T, dir string) (string, string) {
				in, out := filepath.Join(dir, "d.json"), filepath.Join(dir, "hard.nfc")
				writeTestFile(t, in, oldData)
				linkOrSkip(t, in, out)
				return in, out
			},
			wantSame: true,
		},
		{
			name: "output is a dangling symlink",
			setup: func(t *testing.T, dir string) (string, string) {
				in, out := filepath.Join(dir, "d.json"), filepath.Join(dir, "dangling.nfc")
				writeTestFile(t, in, oldData)
				symlinkOrSkip(t, filepath.Join(dir, "missing"), out)
				return in, out
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			in, out := tt.setup(t, t.TempDir())
			err := checkOutputIsNotInput(openedFileInfo(t, in), out)
			if tt.wantSame {
				if !errors.Is(err, errSameFile) {
					t.Fatalf("checkOutputIsNotInput() error = %v, want %v", err, errSameFile)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkOutputIsNotInput() error = %v, want nil", err)
			}
		})
	}
}

func TestCheckOutputIsNotInput_CaseInsensitiveAlias(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := filepath.Join(dir, "dump.json")
	writeTestFile(t, in, oldData)
	upper := filepath.Join(dir, "DUMP.JSON")
	info, err := os.Stat(upper)
	if err != nil || !os.SameFile(info, statFile(t, in)) {
		t.Skip("filesystem is case-sensitive")
	}
	if err := checkOutputIsNotInput(openedFileInfo(t, in), upper); !errors.Is(err, errSameFile) {
		t.Fatalf("checkOutputIsNotInput() error = %v, want %v", err, errSameFile)
	}
}

func TestCheckOutputIsNotInput_StatError(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports a path through a file as not found")
	}

	dir := t.TempDir()
	in := filepath.Join(dir, "d.json")
	writeTestFile(t, in, oldData)
	// A path that continues through a regular file cannot be checked; the
	// check must fail closed rather than assume the output is safe.
	if err := checkOutputIsNotInput(statFile(t, in), filepath.Join(in, "card.nfc")); err == nil {
		t.Fatal("checkOutputIsNotInput() error = nil, want an error")
	}
}

func TestWriteOutputFile_New(t *testing.T) {
	t.Parallel()

	for _, force := range []bool{false, true} {
		force := force
		t.Run(forceName(force), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			out := filepath.Join(dir, "card.nfc")
			if err := writeOutputFile(osFileOps, out, newData, force); err != nil {
				t.Fatalf("writeOutputFile() error = %v", err)
			}
			assertContent(t, out, newData)
			assertOwnerOnly(t, out)
			assertDirEntries(t, dir, "card.nfc")
		})
	}
}

// Regression test for D-11: an existing output is kept unless -force is given.
func TestWriteOutputFile_ExistingWithoutForce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	out := filepath.Join(dir, "card.nfc")
	writeTestFile(t, out, oldData)

	err := writeOutputFile(osFileOps, out, newData, false)
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("writeOutputFile() error = %v, want fs.ErrExist", err)
	}
	if !strings.Contains(err.Error(), "-force") {
		t.Errorf("error %q does not mention -force", err)
	}
	assertContent(t, out, oldData)
	assertDirEntries(t, dir, "card.nfc")
}

func TestWriteOutputFile_ExistingWithForce(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	out := filepath.Join(dir, "card.nfc")
	writeTestFile(t, out, oldData) // mode 0644 is not carried over

	if err := writeOutputFile(osFileOps, out, newData, true); err != nil {
		t.Fatalf("writeOutputFile() error = %v", err)
	}
	assertContent(t, out, newData)
	assertOwnerOnly(t, out)
	assertDirEntries(t, dir, "card.nfc")
}

func TestWriteOutputFile_Symlinks(t *testing.T) {
	t.Parallel()

	t.Run("dangling symlink is not followed without force", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		out := filepath.Join(dir, "card.nfc")
		symlinkOrSkip(t, filepath.Join(dir, "target.nfc"), out)

		if err := writeOutputFile(osFileOps, out, newData, false); !errors.Is(err, fs.ErrExist) {
			t.Fatalf("writeOutputFile() error = %v, want fs.ErrExist", err)
		}
		assertDirEntries(t, dir, "card.nfc") // the target was not created
	})

	t.Run("force replaces the link, not its target", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		target, out := filepath.Join(dir, "target.nfc"), filepath.Join(dir, "card.nfc")
		writeTestFile(t, target, oldData)
		symlinkOrSkip(t, target, out)

		if err := writeOutputFile(osFileOps, out, newData, true); err != nil {
			t.Fatalf("writeOutputFile() error = %v", err)
		}
		assertContent(t, target, oldData)
		assertContent(t, out, newData)
		if info, err := os.Lstat(out); err != nil || info.Mode()&fs.ModeSymlink != 0 {
			t.Errorf("output is still a symlink (err %v)", err)
		}
		assertDirEntries(t, dir, "card.nfc", "target.nfc")
	})
}

func TestWriteOutputFile_MissingDirectory(t *testing.T) {
	t.Parallel()

	for _, force := range []bool{false, true} {
		force := force
		t.Run(forceName(force), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			out := filepath.Join(dir, "missing", "card.nfc")
			err := writeOutputFile(osFileOps, out, newData, force)
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("writeOutputFile() error = %v, want fs.ErrNotExist", err)
			}
			if !strings.Contains(err.Error(), "failed to create NFC file") {
				t.Errorf("error %q does not mention the output file", err)
			}
			assertDirEntries(t, dir)
		})
	}
}

func TestWriteOutputFile_ReadOnlyDirectory(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("directory permission bits do not restrict file creation on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	for _, force := range []bool{false, true} {
		force := force
		t.Run(forceName(force), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			out := filepath.Join(dir, "card.nfc")
			if force {
				writeTestFile(t, out, oldData)
			}
			if err := os.Chmod(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

			if err := writeOutputFile(osFileOps, out, newData, force); !errors.Is(err, fs.ErrPermission) {
				t.Fatalf("writeOutputFile() error = %v, want fs.ErrPermission", err)
			}
			if force {
				assertContent(t, out, oldData)
				assertDirEntries(t, dir, "card.nfc")
			} else {
				assertDirEntries(t, dir)
			}
		})
	}
}

// A destination that is a directory makes the final rename fail on every
// platform, with real filesystem semantics.
func TestWriteOutputFile_ReplaceFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	out := filepath.Join(dir, "card.nfc")
	if err := os.Mkdir(out, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(out, "keep"), oldData)

	err := writeOutputFile(osFileOps, out, newData, true)
	if err == nil || !strings.Contains(err.Error(), "failed to replace") {
		t.Fatalf("writeOutputFile() error = %v, want a replace error", err)
	}
	assertContent(t, filepath.Join(out, "keep"), oldData)
	assertDirEntries(t, dir, "card.nfc")
}

// Replacing a read-only or open destination differs between platforms. Either
// outcome is acceptable as long as no data is lost; the test logs which one
// this platform shows (see docs/output-safety.md).
func TestWriteOutputFile_ForcePlatformBehavior(t *testing.T) {
	t.Parallel()

	check := func(t *testing.T, dir, out string, err error) {
		t.Helper()
		if err != nil {
			t.Logf("%s/%s: replacement refused: %v", runtime.GOOS, t.Name(), err)
			assertContent(t, out, oldData)
		} else {
			t.Logf("%s/%s: replacement succeeded", runtime.GOOS, t.Name())
			assertContent(t, out, newData)
		}
		assertDirEntries(t, dir, "card.nfc")
	}

	t.Run("read-only destination", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		out := filepath.Join(dir, "card.nfc")
		writeTestFile(t, out, oldData)
		if err := os.Chmod(out, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(out, 0o644) })
		check(t, dir, out, writeOutputFile(osFileOps, out, newData, true))
	})

	t.Run("destination open for reading", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		out := filepath.Join(dir, "card.nfc")
		writeTestFile(t, out, oldData)
		f, err := os.Open(out)
		if err != nil {
			t.Fatal(err)
		}
		err = writeOutputFile(osFileOps, out, newData, true)
		if closeErr := f.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		check(t, dir, out, err)
	})
}

// faultyFile wraps a real file so that injected failures leave the same
// on-disk state a real failure would.
type faultyFile struct {
	*os.File
	f *faults
}

func (ff faultyFile) Write(p []byte) (int, error) {
	switch {
	case ff.f.writeErr != nil:
		n := min(ff.f.writeLimit, len(p))
		if _, err := ff.File.Write(p[:n]); err != nil {
			return 0, err
		}
		return n, ff.f.writeErr
	case ff.f.shortWrite:
		return ff.File.Write(p[:len(p)/2])
	default:
		return ff.File.Write(p)
	}
}

func (ff faultyFile) Sync() error {
	if ff.f.syncErr != nil {
		return ff.f.syncErr
	}
	return ff.File.Sync()
}

func (ff faultyFile) Close() error {
	err := ff.File.Close() // the handle is released even when Close reports an error
	if ff.f.closeErr != nil {
		return ff.f.closeErr
	}
	return err
}

// faults describes the failures to inject into the real file operations.
type faults struct {
	createErr  error
	writeErr   error
	writeLimit int // bytes written before writeErr is returned
	shortWrite bool
	syncErr    error
	closeErr   error
	renameErr  error
	removeErr  error
	// beforeCreate and beforeRename run just before the real operation,
	// to simulate another process changing the destination.
	beforeCreate func()
	beforeRename func()
}

func (f *faults) ops() fileOps {
	wrap := func(create func() (outputFile, error)) (outputFile, error) {
		if f.beforeCreate != nil {
			f.beforeCreate()
		}
		if f.createErr != nil {
			return nil, f.createErr
		}
		file, err := create()
		if err != nil {
			return nil, err
		}
		osFile, ok := file.(*os.File)
		if !ok {
			return nil, errors.New("unexpected file type")
		}
		return faultyFile{File: osFile, f: f}, nil
	}
	return fileOps{
		createNew: func(name string) (outputFile, error) {
			return wrap(func() (outputFile, error) { return osFileOps.createNew(name) })
		},
		createTemp: func(dir, pattern string) (outputFile, error) {
			return wrap(func() (outputFile, error) { return osFileOps.createTemp(dir, pattern) })
		},
		rename: func(oldpath, newpath string) error {
			if f.beforeRename != nil {
				f.beforeRename()
			}
			if f.renameErr != nil {
				return f.renameErr
			}
			return os.Rename(oldpath, newpath)
		},
		remove: func(name string) error {
			if f.removeErr != nil {
				return f.removeErr
			}
			return os.Remove(name)
		},
	}
}

// Regression tests for D-07 and D-08: every failure while writing, syncing,
// closing or publishing is reported, the incomplete file is removed, and an
// existing destination is left untouched.
func TestWriteOutputFile_InjectedFailures(t *testing.T) {
	t.Parallel()

	errInjected := errors.New("injected failure")
	tests := []struct {
		name      string
		faults    faults
		forceOnly bool
		wantErr   error
	}{
		{name: "create fails", faults: faults{createErr: errInjected}, wantErr: errInjected},
		{name: "first write fails", faults: faults{writeErr: errInjected}, wantErr: errInjected},
		{name: "write fails after partial data", faults: faults{writeErr: errInjected, writeLimit: 5}, wantErr: errInjected},
		{name: "short write without error", faults: faults{shortWrite: true}, wantErr: io.ErrShortWrite},
		{name: "sync fails", faults: faults{syncErr: errInjected}, wantErr: errInjected},
		{name: "close fails", faults: faults{closeErr: errInjected}, wantErr: errInjected},
		{name: "write and close fail", faults: faults{writeErr: errInjected, closeErr: io.ErrClosedPipe}, wantErr: io.ErrClosedPipe},
		{name: "rename fails", faults: faults{renameErr: errInjected}, forceOnly: true, wantErr: errInjected},
	}
	for _, tt := range tests {
		for _, existing := range []bool{false, true} {
			for _, force := range []bool{false, true} {
				tt, existing, force := tt, existing, force
				if tt.forceOnly && !force || existing && !force {
					continue // without force an existing file is refused before any write
				}
				name := tt.name + "/" + forceName(force)
				if existing {
					name += "/existing destination"
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					dir := t.TempDir()
					out := filepath.Join(dir, "card.nfc")
					if existing {
						writeTestFile(t, out, oldData)
					}
					f := tt.faults
					err := writeOutputFile(f.ops(), out, newData, force)
					if !errors.Is(err, tt.wantErr) {
						t.Fatalf("writeOutputFile() error = %v, want %v", err, tt.wantErr)
					}
					if existing {
						assertContent(t, out, oldData)
						assertDirEntries(t, dir, "card.nfc")
					} else {
						assertDirEntries(t, dir) // the incomplete file was removed
					}
				})
			}
		}
	}
}

// A file that cannot be removed after a failure is reported, not hidden.
func TestWriteOutputFile_CleanupFailure(t *testing.T) {
	t.Parallel()

	errWrite := errors.New("injected write failure")
	errRemove := errors.New("injected remove failure")
	for _, force := range []bool{false, true} {
		force := force
		t.Run(forceName(force), func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			out := filepath.Join(dir, "card.nfc")
			if force {
				writeTestFile(t, out, oldData)
			}
			f := faults{writeErr: errWrite, writeLimit: 3, removeErr: errRemove}
			err := writeOutputFile(f.ops(), out, newData, force)
			if !errors.Is(err, errWrite) || !errors.Is(err, errRemove) {
				t.Fatalf("writeOutputFile() error = %v, want both %v and %v", err, errWrite, errRemove)
			}
			if !strings.Contains(err.Error(), "failed to remove incomplete file") {
				t.Errorf("error %q does not name the file left behind", err)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if force {
				// The destination is intact and the temporary file is left.
				assertContent(t, out, oldData)
				if len(entries) != 2 {
					t.Errorf("directory has %d entries, want the destination and one temporary file", len(entries))
				}
			} else if len(entries) != 1 {
				t.Errorf("directory has %d entries, want the incomplete output", len(entries))
			}
		})
	}
}

// The exclusive create decides, not an earlier existence check: a file or
// symlink that appears just before creation is never overwritten or followed.
func TestWriteOutputFile_DestinationAppearsBeforeCreate(t *testing.T) {
	t.Parallel()

	t.Run("regular file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		out := filepath.Join(dir, "card.nfc")
		f := faults{beforeCreate: func() { writeTestFile(t, out, oldData) }}
		if err := writeOutputFile(f.ops(), out, newData, false); !errors.Is(err, fs.ErrExist) {
			t.Fatalf("writeOutputFile() error = %v, want fs.ErrExist", err)
		}
		assertContent(t, out, oldData)
	})

	t.Run("symlink to the input", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		in, out := filepath.Join(dir, "d.json"), filepath.Join(dir, "card.nfc")
		writeTestFile(t, in, oldData)
		f := faults{beforeCreate: func() { symlinkOrSkip(t, in, out) }}
		if err := writeOutputFile(f.ops(), out, newData, false); !errors.Is(err, fs.ErrExist) {
			t.Fatalf("writeOutputFile() error = %v, want fs.ErrExist", err)
		}
		assertContent(t, in, oldData)
	})
}

// With -force the rename replaces the destination name itself. If it becomes a
// link to the input after the identity check, the input still survives.
func TestWriteOutputFile_DestinationLinkedBeforeRename(t *testing.T) {
	t.Parallel()

	for _, kind := range []string{"symlink", "hard link"} {
		kind := kind
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			in, out := filepath.Join(dir, "d.json"), filepath.Join(dir, "card.nfc")
			writeTestFile(t, in, oldData)
			f := faults{beforeRename: func() {
				if kind == "symlink" {
					symlinkOrSkip(t, in, out)
				} else {
					linkOrSkip(t, in, out)
				}
			}}
			if err := writeOutputFile(f.ops(), out, newData, true); err != nil {
				t.Fatalf("writeOutputFile() error = %v", err)
			}
			assertContent(t, in, oldData)
			assertContent(t, out, newData)
			assertDirEntries(t, dir, "card.nfc", "d.json")
		})
	}
}

func forceName(force bool) string {
	if force {
		return "force"
	}
	return "no force"
}
