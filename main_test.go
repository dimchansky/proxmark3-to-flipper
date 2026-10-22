package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
)

// Most CLI tests call run in-process (runCLI). A few run the built binary
// (runBinary) to check what only a real process shows: exit codes through
// os.Exit, and paths relative to the working directory.
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

// runCLI calls the command's entry point in this process.
func runCLI(t *testing.T, args ...string) cliResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return cliResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// runBinary runs the built executable in dir.
func runBinary(t *testing.T, dir string, args ...string) cliResult {
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

// usageHint follows every usage error.
const usageHint = "Run 'proxmark3-to-flipper -help' for usage.\n"

func TestCLI_Convert(t *testing.T) {
	t.Parallel()

	for _, tt := range conversionCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			in := copyFixture(t, dir, tt.fixture)
			out := filepath.Join(dir, "card.nfc")

			res := runCLI(t, "-i", in, "-o", out)
			if res.code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr:\n%s", res.code, res.stderr)
			}
			if res.stdout != "" || res.stderr != tt.stderr {
				t.Errorf("successful conversion printed stdout %q, stderr %q; want stderr %q", res.stdout, res.stderr, tt.stderr)
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
	res := runBinary(t, dir, "-i", filepath.Base(fixture1K), "-o", "out.nfc")
	if res.code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr:\n%s", res.code, res.stderr)
	}
	assertSameText(t, golden1K, readFile(t, filepath.Join(dir, "out.nfc")), readFile(t, golden1K))
}

func TestCLI_Help(t *testing.T) {
	t.Parallel()

	for _, arg := range []string{"-h", "-help", "--h", "--help"} {
		arg := arg
		t.Run(arg, func(t *testing.T) {
			t.Parallel()
			res := runCLI(t, arg)
			if res.code != exitOK || res.stdout != usage || res.stderr != "" {
				t.Errorf("exit code %d, stdout %q, stderr %q; want 0 and the help text on stdout only", res.code, res.stdout, res.stderr)
			}
		})
	}
	// Help wins over other arguments, as with the flag package.
	if res := runCLI(t, "-i", "x.json", "-help", "extra"); res.code != exitOK || res.stdout != usage {
		t.Errorf("-help after other flags: exit code %d, stdout %q", res.code, res.stdout)
	}
	for _, flagName := range []string{"-i FILE", "-o FILE", "-force", "-version", "-h, -help"} {
		if !strings.Contains(usage, "\n  "+flagName+" ") {
			t.Errorf("help does not describe %s", flagName)
		}
	}
}

func TestCLI_Version(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"-version"}, {"--version"}, {"-version", "-i", "x.json"}} {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			res := runCLI(t, args...)
			if res.code != exitOK || res.stderr != "" {
				t.Fatalf("exit code %d, stderr %q; want 0 and no diagnostics", res.code, res.stderr)
			}
			if res.stdout != versionString()+"\n" || !strings.HasPrefix(res.stdout, "proxmark3-to-flipper ") {
				t.Errorf("stdout = %q, want one version line", res.stdout)
			}
		})
	}
}

func TestFormatVersion(t *testing.T) {
	t.Parallel()

	vcs := func(revision, modified string) *debug.BuildInfo {
		info := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}
		info.Settings = []debug.BuildSetting{{Key: "vcs.revision", Value: revision}, {Key: "vcs.modified", Value: modified}}
		return info
	}
	const rev = "0123456789abcdef0123456789abcdef01234567"
	tests := []struct {
		name            string
		version, commit string
		info            *debug.BuildInfo
		want            string
	}{
		{name: "no build information", want: "proxmark3-to-flipper devel"},
		{name: "local build without VCS data", info: &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, want: "proxmark3-to-flipper devel"},
		{name: "local build in a clean checkout", info: vcs(rev, "false"), want: "proxmark3-to-flipper devel (commit 0123456789ab)"},
		{name: "local build with changes", info: vcs(rev, "true"), want: "proxmark3-to-flipper devel (commit 0123456789ab, modified)"},
		{name: "go install of a tag", info: &debug.BuildInfo{Main: debug.Module{Version: "v1.2.0"}}, want: "proxmark3-to-flipper v1.2.0"},
		{
			name: "go install of an untagged commit",
			info: &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261022120000-0123456789ab"}},
			want: "proxmark3-to-flipper v0.0.0-20261022120000-0123456789ab",
		},
		{name: "release build from ldflags", version: "1.2.0", commit: rev, info: vcs("ffff", "false"), want: "proxmark3-to-flipper v1.2.0 (commit 0123456789ab)"},
		{name: "ldflags version with v prefix", version: "v1.2.0", want: "proxmark3-to-flipper v1.2.0"},
		{name: "short ldflags commit", version: "1.2.0", commit: "abc1234", want: "proxmark3-to-flipper v1.2.0 (commit abc1234)"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatVersion(tt.version, tt.commit, tt.info); got != tt.want {
				t.Errorf("formatVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Regression tests for D-10 and D-19: usage errors exit with 2, name the
// problem in one line followed by a hint, and create nothing.
func TestCLI_UsageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		args    func(dir string) []string
		wantErr string
	}{
		{name: "no arguments", args: func(string) []string { return nil }, wantErr: "missing -i: name the Proxmark3 JSON dump to read"},
		{name: "missing -i", args: func(dir string) []string { return []string{"-o", filepath.Join(dir, "card.nfc")} }, wantErr: "missing -i: name the Proxmark3 JSON dump to read"},
		{name: "empty -i", args: func(dir string) []string { return []string{"-i", "", "-o", filepath.Join(dir, "card.nfc")} }, wantErr: "missing -i: name the Proxmark3 JSON dump to read"},
		{name: "missing -o", args: func(dir string) []string { return []string{"-i", copyFixture(t, dir, fixture1K)} }, wantErr: "missing -o: name the Flipper NFC file to write"},
		{name: "empty -o", args: func(dir string) []string { return []string{"-i", copyFixture(t, dir, fixture1K), "-o", ""} }, wantErr: "missing -o: name the Flipper NFC file to write"},
		{name: "flag without value", args: func(string) []string { return []string{"-i"} }, wantErr: "flag needs an argument: -i"},
		{name: "unknown flag", args: func(string) []string { return []string{"-x"} }, wantErr: "flag provided but not defined: -x"},
		{name: "invalid boolean", args: func(string) []string { return []string{"-force=maybe"} }, wantErr: `invalid boolean value "maybe" for -force: parse error`},
		{
			name: "positional argument",
			args: func(dir string) []string {
				return []string{"-i", copyFixture(t, dir, fixture1K), "-o", filepath.Join(dir, "card.nfc"), "extra.json"}
			},
			wantErr: `unexpected argument "extra.json"`,
		},
		{
			name: "argument after --",
			args: func(dir string) []string {
				return []string{"-i", copyFixture(t, dir, fixture1K), "-o", filepath.Join(dir, "card.nfc"), "--", "-force"}
			},
			wantErr: `unexpected argument "-force"`,
		},
		{
			name: "positional argument before the flags",
			args: func(dir string) []string {
				return []string{"dump.json", "-i", copyFixture(t, dir, fixture1K), "-o", filepath.Join(dir, "card.nfc")}
			},
			wantErr: `unexpected argument "dump.json"`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			args := tt.args(dir) // may copy the input fixture into dir
			before, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			res := runCLI(t, args...)
			if res.code != exitUsage {
				t.Errorf("exit code = %d, want %d", res.code, exitUsage)
			}
			if want := "error: " + tt.wantErr + "\n" + usageHint; res.stderr != want {
				t.Errorf("stderr = %q, want %q", res.stderr, want)
			}
			if res.stdout != "" {
				t.Errorf("stdout = %q, want nothing", res.stdout)
			}
			names := make([]string, len(before))
			for i, e := range before {
				names[i] = e.Name()
			}
			assertDirEntries(t, dir, names...)
		})
	}
}

// Both dash forms of the flags work.
func TestCLI_DoubleDashFlags(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)
	out := filepath.Join(dir, "card.nfc")
	writeTestFile(t, out, oldData)
	res := runCLI(t, "--i", in, "--o="+out, "--force")
	if res.code != exitOK || res.stderr != "" {
		t.Fatalf("exit code %d, stderr %q; want success", res.code, res.stderr)
	}
	assertSameText(t, golden1K, readFile(t, out), readFile(t, golden1K))
}

// run keeps no state between calls: flags from one call must not leak into
// the next, which a global flag.CommandLine would make impossible.
func TestCLI_RepeatedInvocation(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)
	out := filepath.Join(dir, "card.nfc")
	steps := []struct {
		args []string
		code int
	}{
		{args: []string{"-help"}, code: exitOK},
		{args: []string{"-i", in, "-o", out}, code: exitOK},
		{args: []string{"-i", in, "-o", out}, code: exitFailure}, // exists, and -force is not remembered
		{args: []string{"-i", in}, code: exitUsage},              // -o is not remembered either
		{args: []string{"-force", "-i", in, "-o", out}, code: exitOK},
		{args: []string{"-version"}, code: exitOK},
		{args: []string{"-i", in, "-o", out}, code: exitFailure},
	}
	for i, step := range steps {
		if res := runCLI(t, step.args...); res.code != step.code {
			t.Errorf("call %d %q: exit code %d, want %d; stderr %q", i+1, step.args, res.code, step.code, res.stderr)
		}
	}
	assertSameText(t, golden1K, readFile(t, out), readFile(t, golden1K))
}

// The executable reports the same exit codes and streams as run.
func TestBinary_ExitCodes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout bool // whether stdout is expected
		stderr bool
	}{
		{name: "conversion", args: []string{"-i", in, "-o", filepath.Join(dir, "card.nfc")}, code: exitOK},
		{name: "help", args: []string{"-help"}, code: exitOK, stdout: true},
		{name: "version", args: []string{"--version"}, code: exitOK, stdout: true},
		{name: "usage error", args: []string{"-i", in}, code: exitUsage, stderr: true},
		{name: "unknown flag", args: []string{"-x"}, code: exitUsage, stderr: true},
		{name: "invalid input", args: []string{"-i", filepath.Join(dir, "missing.json"), "-o", filepath.Join(dir, "other.nfc")}, code: exitFailure, stderr: true},
	}
	for _, tt := range tests {
		res := runBinary(t, dir, tt.args...)
		if res.code != tt.code || (res.stdout != "") != tt.stdout || (res.stderr != "") != tt.stderr {
			t.Errorf("%s: exit code %d, stdout %q, stderr %q; want code %d", tt.name, res.code, res.stdout, res.stderr, tt.code)
		}
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
		{name: "nonexistent input", input: nil, wantErr: "error: cannot open Proxmark3 dump: open "},
		{name: "empty file", input: strPtr(""), wantErr: "error: failed to decode Proxmark3 JSON file at byte offset 0: unexpected end of JSON input\n"},
		{name: "malformed JSON", input: strPtr(valid[:len(valid)/2]), wantErr: "error: failed to decode Proxmark3 JSON file at byte offset "},
		{name: "trailing data", input: strPtr(valid + "{}"), wantErr: "error: failed to decode Proxmark3 JSON file at byte offset "},
		{name: "duplicate block", input: strPtr(strings.Replace(valid, `"7": "`, `"6": "00", "7": "`, 1)), wantErr: `error: failed to decode Proxmark3 JSON file: duplicate key "6" in blocks` + "\n"},
		{name: "not produced by Proxmark3", input: strPtr(strings.Replace(valid, `"proxmark3"`, `"other"`, 1)), wantErr: "error: JSON file must be produced by Proxmark3\n"},
		{name: "not a MIFARE Classic dump", input: strPtr(strings.Replace(valid, `"mfcard"`, `"mfu"`, 1)), wantErr: `error: unsupported FileType "mfu", expecting a MIFARE Classic dump ("mfcard", "mfc v2" or "mfc v3")` + "\n"},
		{name: "invalid UID hex", input: strPtr(strings.Replace(valid, `"11223344"`, `"XX223344"`, 1)), wantErr: "error: invalid Card.UID: invalid hexadecimal character at offset 0: "},
		{name: "invalid block hex", input: strPtr(strings.Replace(valid, `"0102030405060708090A0B0C0D0E0F10"`, `"0102030405060708090A0B0C0D0E0F1"`, 1)), wantErr: "error: invalid block 1: odd number of hexadecimal digits (31): "},
		{name: "missing block index", input: strPtr(strings.Replace(valid, `"7": "`, `"700": "`, 1)), wantErr: "error: missing block 7\n"},
		{name: "invalid block index", input: strPtr(strings.Replace(valid, `"7": "`, `"x7": "`, 1)), wantErr: `error: invalid block index "x7": want a decimal number without sign or leading zeros` + "\n"},
		{name: "2K dump", input: strPtr(string(readFile(t, fixture2K))), wantErr: "error: MIFARE Classic 2K dumps (128 blocks) are not supported: the Flipper NFC format has no 2K card type\n"},
		{name: "oversized input", input: strPtr(valid + strings.Repeat(" ", maxInputSize)), wantErr: "error: input is larger than 1048576 bytes, too large for a MIFARE Classic dump\n"},
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

			res := runCLI(t, "-i", in, "-o", out)
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

// An invalid dump must leave an existing output alone, even with -force,
// and must not print the card data it rejected.
func TestCLI_InvalidInputWithForce(t *testing.T) {
	t.Parallel()

	const secret = "A1B2C3D4E5F6"
	valid := string(readFile(t, fixture1K))
	tests := []struct {
		name  string
		input string
	}{
		{name: "invalid trailer", input: strings.Replace(valid, `"AAAAAAAAAA00FF078069BBBBBBBBBB00"`, `"`+secret+`FF078069`+secret[:11]+`Z"`, 1)},
		{name: "short trailer", input: strings.Replace(valid, `"AAAAAAAAAA00FF078069BBBBBBBBBB00"`, `"`+secret+`FF078069`+secret[:10]+`"`, 1)},
		{name: "2K dump", input: string(readFile(t, fixture2K))},
		{name: "trailing data", input: valid + "x"},
		{name: "mfc v2 without blocks", input: `{"Created":"proxmark3","FileType":"mfc v2","Card":{"UID":"11223344","ATQA":"0400","SAK":"08"}}`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			in := filepath.Join(dir, "dump.json")
			if err := os.WriteFile(in, []byte(tt.input), 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "card.nfc")
			writeTestFile(t, out, oldData)

			res := runCLI(t, "-force", "-i", in, "-o", out)
			if res.code != 1 {
				t.Errorf("exit code = %d, want 1", res.code)
			}
			if strings.Contains(strings.ToUpper(res.stderr), secret[:8]) {
				t.Errorf("stderr repeats card data: %q", res.stderr)
			}
			assertContent(t, out, oldData)
			assertDirEntries(t, dir, "card.nfc", "dump.json")
		})
	}
}

// The mfc v3 warning describes a finished conversion, so it must not appear
// when the output could not be published; the output rules still hold then.
func TestCLI_DroppedFieldsWarning(t *testing.T) {
	t.Parallel()

	t.Run("printed after a successful conversion", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		in := copyFixture(t, dir, fixtureV3)
		out := filepath.Join(dir, "card.nfc")
		res := runCLI(t, "-i", in, "-o", out)
		if res.code != 0 || res.stderr != warningV3 {
			t.Fatalf("exit code %d, stderr %q; want 0 and %q", res.code, res.stderr, warningV3)
		}
		assertSameText(t, golden1K, readFile(t, out), readFile(t, golden1K))
	})

	failures := []struct {
		name  string
		setup func(t *testing.T, dir string) (args []string, keep string)
	}{
		{name: "existing output without -force", setup: func(t *testing.T, dir string) ([]string, string) {
			out := filepath.Join(dir, "card.nfc")
			writeTestFile(t, out, oldData)
			return []string{"-o", out}, out
		}},
		{name: "output is the input", setup: func(t *testing.T, dir string) ([]string, string) {
			in := filepath.Join(dir, filepath.Base(fixtureV3))
			return []string{"-o", in, "-force"}, ""
		}},
		{name: "missing output directory", setup: func(t *testing.T, dir string) ([]string, string) {
			return []string{"-o", filepath.Join(dir, "missing", "card.nfc"), "-force"}, ""
		}},
	}
	for _, tt := range failures {
		tt := tt
		t.Run("not printed when "+tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			in := copyFixture(t, dir, fixtureV3)
			args, keep := tt.setup(t, dir)
			res := runCLI(t, append([]string{"-i", in}, args...)...)
			if res.code != 1 {
				t.Errorf("exit code = %d, want 1", res.code)
			}
			if strings.Contains(res.stderr, "warning:") || !strings.HasPrefix(res.stderr, "error: ") {
				t.Errorf("stderr = %q, want only the error", res.stderr)
			}
			assertContent(t, in, readFile(t, fixtureV3))
			if keep != "" {
				assertContent(t, keep, oldData)
			}
			names := []string{filepath.Base(fixtureV3)}
			if keep != "" {
				names = append(names, filepath.Base(keep))
			}
			assertDirEntries(t, dir, names...)
		})
	}
}

func TestCLI_OutputDirectoryMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)
	out := filepath.Join(dir, "missing", "card.nfc")
	res := runCLI(t, "-i", in, "-o", out)
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

				res := runBinary(t, dir, args...) // the paths are relative to dir
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

		res := runCLI(t, "-i", in, "-o", out)
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

		res := runCLI(t, "-force", "-i", in, "-o", out)
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
	if res := runCLI(t, "-i", in, "-o", out); res.code != 0 {
		t.Fatalf("exit code = %d; stderr:\n%s", res.code, res.stderr)
	}
	assertOwnerOnly(t, out)
	assertDirEntries(t, dir, filepath.Base(in), "card.nfc")
}

// The mode of a new output must not depend on the caller's umask being
// restrictive. Each umask is set in a shell that then runs the CLI, so the
// umask of the test process is never changed.
func TestCLI_OutputPermissionsUnderUmask(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("umask does not apply on Windows")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no POSIX shell: %v", err)
	}
	cli := buildCLI(t)

	tests := []struct {
		umask string
		want  os.FileMode
	}{
		{umask: "000", want: 0o600}, // the program itself must not grant more
		{umask: "022", want: 0o600},
		{umask: "077", want: 0o600},
		{umask: "277", want: 0o400}, // a stricter umask is honored
	}
	for _, tt := range tests {
		tt := tt
		for _, force := range []bool{false, true} {
			force := force
			t.Run("umask "+tt.umask+"/"+forceName(force), func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				in := copyFixture(t, dir, fixture1K)
				out := filepath.Join(dir, "card.nfc")
				if force {
					writeTestFile(t, out, oldData)
				}
				args := []string{"-c", `umask "$1" && shift && exec "$@"`, "sh", tt.umask, cli, "-i", in, "-o", out}
				if force {
					args = append(args, "-force")
				}
				cmd := exec.Command(sh, args...)
				cmd.Dir = dir
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("conversion failed: %v\n%s", err, output)
				}
				if perm := statFile(t, out).Mode().Perm(); perm != tt.want {
					t.Errorf("mode = %v, want %v", perm, tt.want)
				}
			})
		}
	}
}

func strPtr(s string) *string { return &s }
