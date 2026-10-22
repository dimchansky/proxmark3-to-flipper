package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// The CLI is tested as a subprocess: parseArgs registers flags on the global
// flag.CommandLine and main calls os.Exit, so run cannot be called twice in one
// process.
//
// Set CLI_GOCOVERDIR to an existing directory to build the CLI with coverage
// instrumentation. Every run writes to its own subdirectory, because parallel
// processes sharing one GOCOVERDIR can collide on the metadata file:
//
//	CLI_GOCOVERDIR=$PWD/cover go test ./...
//	go tool covdata percent -i "$(ls -d cover/*/ | paste -sd, -)"

var (
	cliOnce     sync.Once
	cliDir      string
	cliPath     string
	errCLIBuild error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if cliDir != "" {
		_ = os.RemoveAll(cliDir)
	}
	os.Exit(code)
}

// buildCLI compiles the command once per test binary. go test puts its own
// toolchain first on PATH, so the binary is built with the same Go version.
func buildCLI(t *testing.T) string {
	t.Helper()
	cliOnce.Do(func() {
		cliDir, errCLIBuild = os.MkdirTemp("", "proxmark3-to-flipper-cli-")
		if errCLIBuild != nil {
			return
		}
		cliPath = filepath.Join(cliDir, "proxmark3-to-flipper")
		if runtime.GOOS == "windows" {
			cliPath += ".exe"
		}
		args := []string{"build", "-o", cliPath}
		if os.Getenv("CLI_GOCOVERDIR") != "" {
			args = append(args, "-cover")
		}
		out, err := exec.Command("go", append(args, ".")...).CombinedOutput()
		if err != nil {
			errCLIBuild = fmt.Errorf("go build: %w\n%s", err, out)
		}
	})
	if errCLIBuild != nil {
		t.Fatalf("building the CLI: %v", errCLIBuild)
	}
	return cliPath
}

type cliResult struct {
	code   int
	stdout string
	stderr string
}

func runCLI(t *testing.T, dir string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(buildCLI(t), args...)
	cmd.Dir = dir
	if coverDir := os.Getenv("CLI_GOCOVERDIR"); coverDir != "" {
		runDir, err := os.MkdirTemp(coverDir, "run-")
		if err != nil {
			t.Fatal(err)
		}
		cmd.Env = append(os.Environ(), "GOCOVERDIR="+runDir)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("running the CLI: %v", err)
	}
	return cliResult{code: cmd.ProcessState.ExitCode(), stdout: stdout.String(), stderr: stderr.String()}
}

// copyFixture copies a fixture into dir so that tests never write next to
// the committed testdata.
func copyFixture(t *testing.T, dir, fixture string) string {
	t.Helper()
	dst := filepath.Join(dir, filepath.Base(fixture))
	if err := os.WriteFile(dst, readFile(t, fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

func assertNoFile(t *testing.T, name string) {
	t.Helper()
	if _, err := os.Lstat(name); err == nil {
		t.Errorf("%s exists, want no output file", name)
	} else if !os.IsNotExist(err) {
		t.Errorf("stat %s: %v", name, err)
	}
}

// assertUsage checks that the flag summary was printed after a usage error.
func assertUsage(t *testing.T, stderr string) {
	t.Helper()
	for _, want := range []string{"Usage of ", "-i string", "-o string", "-force", "Version: "} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr)
		}
	}
}

func TestCLI_Convert(t *testing.T) {
	t.Parallel()

	for _, tt := range conversionCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			in := copyFixture(t, dir, tt.fixture)
			out := filepath.Join(dir, "card.nfc")

			res := runCLI(t, dir, "-i", in, "-o", out)
			if res.code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr:\n%s", res.code, res.stderr)
			}
			if res.stdout != "" || res.stderr != "" {
				t.Errorf("successful conversion printed stdout %q, stderr %q; want no output", res.stdout, res.stderr)
			}
			assertSameText(t, tt.golden, readFile(t, out), readFile(t, tt.golden))
			// The input must be left untouched.
			if !bytes.Equal(readFile(t, in), readFile(t, tt.fixture)) {
				t.Error("input file was modified")
			}
		})
	}
}

func TestCLI_RelativePaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	copyFixture(t, dir, fixture1K)
	res := runCLI(t, dir, "-i", filepath.Base(fixture1K), "-o", "out.nfc")
	if res.code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", res.code, res.stderr)
	}
	assertSameText(t, golden1K, readFile(t, filepath.Join(dir, "out.nfc")), readFile(t, golden1K))
}

func TestCLI_Help(t *testing.T) {
	t.Parallel()

	for _, flagName := range []string{"-h", "-help", "--help"} {
		flagName := flagName
		t.Run(flagName, func(t *testing.T) {
			t.Parallel()
			res := runCLI(t, t.TempDir(), flagName)
			if res.code != 0 {
				t.Errorf("exit code = %d, want 0", res.code)
			}
			if res.stdout != "" {
				t.Errorf("stdout = %q, want help on stderr only", res.stdout)
			}
			assertUsage(t, res.stderr)
		})
	}
}

func TestCLI_UsageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    func(dir string) []string
		wantErr string
	}{
		{
			name:    "no arguments",
			args:    func(string) []string { return nil },
			wantErr: "error: please provide input Proxmark3 dump file in JSON format\n",
		},
		{
			name:    "missing input argument",
			args:    func(dir string) []string { return []string{"-o", filepath.Join(dir, "card.nfc")} },
			wantErr: "error: please provide input Proxmark3 dump file in JSON format\n",
		},
		{
			name:    "empty input argument",
			args:    func(dir string) []string { return []string{"-i", "", "-o", filepath.Join(dir, "card.nfc")} },
			wantErr: "error: please provide input Proxmark3 dump file in JSON format\n",
		},
		{
			// The message is wrong (it asks for the input file); see D-10.
			name:    "missing output argument",
			args:    func(dir string) []string { return []string{"-i", copyFixture(t, dir, fixture1K)} },
			wantErr: "error: ",
		},
		{
			name:    "flag without value",
			args:    func(string) []string { return []string{"-i"} },
			wantErr: "flag needs an argument: -i\n",
		},
		{
			name:    "unknown flag",
			args:    func(string) []string { return []string{"-x"} },
			wantErr: "flag provided but not defined: -x\n",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			res := runCLI(t, dir, tt.args(dir)...)
			if res.code == 0 {
				t.Fatalf("exit code = 0, want a failure")
			}
			if res.stdout != "" {
				t.Errorf("stdout = %q, want diagnostics on stderr only", res.stdout)
			}
			if !strings.HasPrefix(res.stderr, tt.wantErr) {
				t.Errorf("stderr does not start with %q:\n%s", tt.wantErr, res.stderr)
			}
			assertUsage(t, res.stderr)
			assertNoFile(t, filepath.Join(dir, "card.nfc"))
		})
	}
}

func TestCLI_InputErrors(t *testing.T) {
	t.Parallel()

	valid := string(readFile(t, fixture1K))
	tests := []struct {
		name    string
		input   *string // nil: the input file does not exist
		wantErr string
	}{
		{name: "nonexistent input", input: nil, wantErr: "error: failed to parse Proxmark3 dump file '"},
		{name: "empty file", input: strPtr(""), wantErr: "error: failed to decode Proxmark3 JSON file: EOF\n"},
		{name: "malformed JSON", input: strPtr(valid[:len(valid)/2]), wantErr: "error: failed to decode Proxmark3 JSON file: "},
		{name: "not produced by Proxmark3", input: strPtr(strings.Replace(valid, `"proxmark3"`, `"other"`, 1)), wantErr: "error: JSON file must be produced by Proxmark3\n"},
		{name: "not a MIFARE Classic dump", input: strPtr(strings.Replace(valid, `"mfcard"`, `"mfu"`, 1)), wantErr: "error: expecting Mifare card dump\n"},
		{name: "invalid UID hex", input: strPtr(strings.Replace(valid, `"11223344"`, `"XX223344"`, 1)), wantErr: "error: cannot parse card UID: "},
		{name: "invalid block hex", input: strPtr(strings.Replace(valid, `"0102030405060708090A0B0C0D0E0F10"`, `"0102030405060708090A0B0C0D0E0F1"`, 1)), wantErr: "error: cannot parse block 1 data: "},
		{name: "missing block index", input: strPtr(strings.Replace(valid, `"7": "`, `"700": "`, 1)), wantErr: "error: cannot find Mifare card data for block 7\n"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			in := filepath.Join(dir, "dump.json")
			if tt.input != nil {
				if err := os.WriteFile(in, []byte(*tt.input), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := filepath.Join(dir, "card.nfc")

			res := runCLI(t, dir, "-i", in, "-o", out)
			if res.code != 1 {
				t.Errorf("exit code = %d, want 1", res.code)
			}
			if res.stdout != "" {
				t.Errorf("stdout = %q, want diagnostics on stderr only", res.stdout)
			}
			if !strings.HasPrefix(res.stderr, tt.wantErr) {
				t.Errorf("stderr does not start with %q:\n%s", tt.wantErr, res.stderr)
			}
			if strings.Contains(res.stderr, "Usage of ") {
				t.Errorf("usage printed for a non-usage error:\n%s", res.stderr)
			}
			assertNoFile(t, out)
		})
	}
}

func TestCLI_OutputDirectoryMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)
	out := filepath.Join(dir, "missing", "card.nfc")
	res := runCLI(t, dir, "-i", in, "-o", out)
	if res.code != 1 {
		t.Errorf("exit code = %d, want 1", res.code)
	}
	if !strings.HasPrefix(res.stderr, "error: failed to create NFC file '") {
		t.Errorf("stderr = %q, want a create error", res.stderr)
	}
	assertNoFile(t, out)
}

// Regression test for D-01: the input survives every way of naming it as
// the output, with or without -force.
func TestCLI_OutputIsInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// setup returns the -i and -o arguments, relative to dir.
		setup func(t *testing.T, dir string) (in, out string)
	}{
		{name: "identical path", setup: func(t *testing.T, dir string) (string, string) {
			return "d.json", "d.json"
		}},
		{name: "relative alias", setup: func(t *testing.T, dir string) (string, string) {
			return "d.json", "." + string(filepath.Separator) + "d.json"
		}},
		{name: "absolute and relative path", setup: func(t *testing.T, dir string) (string, string) {
			return filepath.Join(dir, "d.json"), "d.json"
		}},
		{name: "output is a symlink to the input", setup: func(t *testing.T, dir string) (string, string) {
			symlinkOrSkip(t, "d.json", filepath.Join(dir, "link.nfc"))
			return "d.json", "link.nfc"
		}},
		{name: "input is a symlink to the output", setup: func(t *testing.T, dir string) (string, string) {
			symlinkOrSkip(t, "d.json", filepath.Join(dir, "link.json"))
			return "link.json", "d.json"
		}},
		{name: "output is a hard link to the input", setup: func(t *testing.T, dir string) (string, string) {
			linkOrSkip(t, filepath.Join(dir, "d.json"), filepath.Join(dir, "hard.nfc"))
			return "d.json", "hard.nfc"
		}},
	}
	for _, tt := range tests {
		for _, force := range []bool{false, true} {
			tt, force := tt, force
			t.Run(tt.name+"/"+forceName(force), func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "d.json"), readFile(t, fixture1K), 0o600); err != nil {
					t.Fatal(err)
				}
				in, out := tt.setup(t, dir)
				before, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				args := []string{"-i", in, "-o", out}
				if force {
					args = append(args, "-force")
				}

				res := runCLI(t, dir, args...)
				if res.code != 1 {
					t.Errorf("exit code = %d, want 1", res.code)
				}
				if !strings.Contains(res.stderr, "is the same file as the input") {
					t.Errorf("stderr = %q, want a same-file error", res.stderr)
				}
				assertContent(t, filepath.Join(dir, "d.json"), readFile(t, fixture1K))
				names := make([]string, len(before))
				for i, e := range before {
					names[i] = e.Name()
				}
				assertDirEntries(t, dir, names...)
			})
		}
	}
}

// Regression test for D-11: an existing output is replaced only with -force.
func TestCLI_ExistingOutput(t *testing.T) {
	t.Parallel()

	t.Run("refused without -force", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		in := copyFixture(t, dir, fixture1K)
		out := filepath.Join(dir, "card.nfc")
		writeTestFile(t, out, oldData)

		res := runCLI(t, dir, "-i", in, "-o", out)
		if res.code != 1 {
			t.Errorf("exit code = %d, want 1", res.code)
		}
		if !strings.HasPrefix(res.stderr, "error: refusing to overwrite existing file (use -force to replace it): ") {
			t.Errorf("stderr = %q, want a refusal that mentions -force", res.stderr)
		}
		if strings.Contains(res.stderr, "Usage of ") {
			t.Errorf("usage printed for a non-usage error:\n%s", res.stderr)
		}
		assertContent(t, out, oldData)
		assertDirEntries(t, dir, filepath.Base(in), "card.nfc")
	})

	t.Run("replaced with -force", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		in := copyFixture(t, dir, fixture4K)
		out := filepath.Join(dir, "card.nfc")
		writeTestFile(t, out, oldData)

		res := runCLI(t, dir, "-force", "-i", in, "-o", out)
		if res.code != 0 || res.stdout != "" || res.stderr != "" {
			t.Fatalf("exit code %d, stdout %q, stderr %q; want silent success", res.code, res.stdout, res.stderr)
		}
		assertSameText(t, golden4K, readFile(t, out), readFile(t, golden4K))
		assertOwnerOnly(t, out)
		assertDirEntries(t, dir, filepath.Base(in), "card.nfc")
	})
}

// Regression test for D-13: a new output file is readable by its owner only.
func TestCLI_OutputPermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)
	out := filepath.Join(dir, "card.nfc")
	if res := runCLI(t, dir, "-i", in, "-o", out); res.code != 0 {
		t.Fatalf("exit code = %d; stderr:\n%s", res.code, res.stderr)
	}
	assertOwnerOnly(t, out)
	assertDirEntries(t, dir, filepath.Base(in), "card.nfc")
}

func strPtr(s string) *string { return &s }
