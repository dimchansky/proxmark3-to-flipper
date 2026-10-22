// Command verifydist checks the release artifacts that GoReleaser wrote to a
// dist directory: the exact set of archives, the SHA-256 checksum file, the
// contents of every archive, and the format, build settings and embedded
// version of every executable. With -smoke it also extracts one archive and
// runs its executable against the test fixtures.
//
// Usage, from the repository root after "goreleaser release":
//
//	go run ./tools/verifydist -commit "$(git rev-parse HEAD)" -version 1.0.0
//	go run ./tools/verifydist -commit "$(git rev-parse HEAD)" -snapshot -smoke host
//
// It exits with status 1 and lists every problem if any check fails.
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const project = "proxmark3-to-flipper"

// target is one release platform. Keep in sync with .goreleaser.yaml.
type target struct {
	name   string // platform part of the archive name
	goos   string
	goarch string
	goarm  string
	zip    bool
}

var targets = []target{
	{name: "windows_amd64", goos: "windows", goarch: "amd64", zip: true},
	{name: "windows_arm64", goos: "windows", goarch: "arm64", zip: true},
	{name: "macos_amd64", goos: "darwin", goarch: "amd64"},
	{name: "macos_arm64", goos: "darwin", goarch: "arm64"},
	{name: "linux_amd64", goos: "linux", goarch: "amd64"},
	{name: "linux_arm64", goos: "linux", goarch: "arm64"},
	{name: "linux_armv7", goos: "linux", goarch: "arm", goarm: "7"},
}

func (t target) archive(version string) string {
	ext := ".tar.gz"
	if t.zip {
		ext = ".zip"
	}
	return fmt.Sprintf("%s_%s_%s%s", project, version, t.name, ext)
}

func (t target) platform() string {
	if t.goarm != "" {
		return t.goos + "/" + t.goarch + "/v" + t.goarm
	}
	return t.goos + "/" + t.goarch
}

func (t target) binary() string {
	if t.goos == "windows" {
		return project + ".exe"
	}
	return project
}

type options struct {
	dist, commit, version, smoke, emulator string
	snapshot                               bool
}

func main() {
	var opt options
	flag.StringVar(&opt.dist, "dist", "dist", "GoReleaser output directory")
	flag.StringVar(&opt.commit, "commit", "", "full commit SHA the artifacts must be built from (required)")
	flag.StringVar(&opt.version, "version", "", "expected version without the v prefix (required unless -snapshot)")
	flag.BoolVar(&opt.snapshot, "snapshot", false, "expect a snapshot version X.Y.Z-SNAPSHOT-<commit>")
	flag.StringVar(&opt.smoke, "smoke", "", `target to run smoke tests on, e.g. linux_amd64, or "host"`)
	flag.StringVar(&opt.emulator, "emulator", "", `command that runs the smoke-test executable, e.g. "qemu-arm-static" or "arch -x86_64"`)
	flag.Parse()

	problems, err := verify(opt)
	if err != nil {
		problems = append(problems, err.Error())
	}
	if len(problems) > 0 {
		fmt.Fprintf(os.Stderr, "verifydist: %d problem(s):\n", len(problems))
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  -", p)
		}
		os.Exit(1)
	}
	fmt.Println("verifydist: all checks passed")
}

func verify(opt options) ([]string, error) {
	if len(opt.commit) != 40 {
		return nil, errors.New("-commit must be a full 40-character SHA")
	}
	version, err := checkMetadata(opt)
	if err != nil {
		return nil, err
	}
	license, err := os.ReadFile("LICENSE")
	if err != nil {
		return nil, err
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		return nil, err
	}

	var problems []string
	report := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	// The dist root must hold exactly the expected archives.
	want := map[string]target{}
	for _, t := range targets {
		want[t.archive(version)] = t
	}
	entries, err := os.ReadDir(opt.dist)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".zip") || strings.HasSuffix(name, ".tar.gz") {
			if _, ok := want[name]; !ok {
				report("unexpected archive %s", name)
			}
		}
	}

	sums, err := readChecksums(filepath.Join(opt.dist, fmt.Sprintf("%s_%s_checksums.txt", project, version)))
	if err != nil {
		return nil, err
	}
	for name := range sums {
		if _, ok := want[name]; !ok {
			report("checksum file lists unexpected file %s", name)
		}
	}

	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t := want[name]
		data, err := os.ReadFile(filepath.Join(opt.dist, name))
		if err != nil {
			report("missing archive %s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(data)
		switch listed, ok := sums[name]; {
		case !ok:
			report("%s is not in the checksum file", name)
		case listed != hex.EncodeToString(sum[:]):
			report("%s: SHA-256 %x does not match the checksum file", name, sum)
		}
		files, err := readArchive(name, data)
		if err != nil {
			report("%s: %v", name, err)
			continue
		}
		for _, p := range checkArchive(t, files, license, readme, version, opt.commit) {
			report("%s: %s", name, p)
		}
		fmt.Printf("checked %-60s %8d bytes  %-14s sha256 %x\n", name, len(data), t.platform(), sum)
	}
	if len(problems) > 0 || opt.smoke == "" {
		return problems, nil
	}

	smoke := opt.smoke
	if smoke == "host" {
		smoke = hostTarget()
	}
	for _, t := range targets {
		if t.name == smoke {
			files, err := readArchiveFile(filepath.Join(opt.dist, t.archive(version)))
			if err != nil {
				return problems, err
			}
			for _, p := range smokeTest(t, files[t.binary()].data, opt.emulator, version, opt.commit) {
				report("smoke %s: %s", t.name, p)
			}
			return problems, nil
		}
	}
	return problems, fmt.Errorf("no release target %q", smoke)
}

// checkMetadata checks dist/metadata.json against the expected commit and
// version and returns the version the artifacts are named with.
func checkMetadata(opt options) (string, error) {
	raw, err := os.ReadFile(filepath.Join(opt.dist, "metadata.json"))
	if err != nil {
		return "", err
	}
	var meta struct {
		ProjectName string `json:"project_name"`
		Tag         string `json:"tag"`
		Version     string `json:"version"`
		Commit      string `json:"commit"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "", fmt.Errorf("metadata.json: %w", err)
	}
	switch {
	case meta.ProjectName != project:
		return "", fmt.Errorf("metadata.json: project %q, want %q", meta.ProjectName, project)
	case meta.Commit != opt.commit:
		return "", fmt.Errorf("metadata.json: commit %q, want %q", meta.Commit, opt.commit)
	case opt.snapshot && !strings.HasSuffix(meta.Version, "-SNAPSHOT-"+opt.commit[:7]):
		return "", fmt.Errorf("metadata.json: version %q is not a snapshot of %s", meta.Version, opt.commit[:7])
	case !opt.snapshot && (opt.version == "" || meta.Version != opt.version || meta.Tag != "v"+opt.version):
		return "", fmt.Errorf("metadata.json: version %q, tag %q; want version %q from tag v%s", meta.Version, meta.Tag, opt.version, opt.version)
	}
	return meta.Version, nil
}

// readChecksums parses a "<sha256>  <file name>" checksum file.
func readChecksums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sums := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok || len(sum) != 64 || strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("%s: malformed line %q", path, sc.Text())
		}
		if _, dup := sums[name]; dup {
			return nil, fmt.Errorf("%s: %s is listed twice", path, name)
		}
		sums[name] = sum
	}
	return sums, sc.Err()
}

type archivedFile struct {
	data []byte
	mode os.FileMode
}

func readArchiveFile(path string) (map[string]archivedFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return readArchive(path, data)
}

// readArchive returns the regular files of a .zip or .tar.gz archive and
// rejects any other kind of entry.
func readArchive(name string, data []byte) (map[string]archivedFile, error) {
	files := map[string]archivedFile{}
	add := func(path string, mode os.FileMode, r io.Reader) error {
		if !mode.IsRegular() {
			return fmt.Errorf("entry %q is not a regular file", path)
		}
		if _, dup := files[path]; dup {
			return fmt.Errorf("entry %q appears twice", path)
		}
		b, err := io.ReadAll(r)
		files[path] = archivedFile{data: b, mode: mode}
		return err
	}
	if strings.HasSuffix(name, ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			err = add(f.Name, f.Mode(), rc)
			_ = rc.Close()
			if err != nil {
				return nil, err
			}
		}
		return files, nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		if err := add(h.Name, h.FileInfo().Mode(), tr); err != nil {
			return nil, err
		}
	}
}

func checkArchive(t target, files map[string]archivedFile, license, readme []byte, version, commit string) []string {
	var problems []string
	for name := range files {
		if name != t.binary() && name != "LICENSE" && name != "README.md" {
			problems = append(problems, fmt.Sprintf("unexpected entry %q", name))
		}
	}
	if !bytes.Equal(files["LICENSE"].data, license) {
		problems = append(problems, "LICENSE is missing or differs from the repository's")
	}
	if !bytes.Equal(files["README.md"].data, readme) {
		problems = append(problems, "README.md is missing or differs from the repository's")
	}
	bin, ok := files[t.binary()]
	if !ok || len(bin.data) == 0 {
		return append(problems, fmt.Sprintf("executable %q is missing or empty", t.binary()))
	}
	if bin.mode.Perm()&0o111 != 0o111 {
		problems = append(problems, fmt.Sprintf("executable mode is %v, want 0755", bin.mode.Perm()))
	}
	if err := checkMachine(t, bin.data); err != nil {
		problems = append(problems, err.Error())
	}
	return append(problems, checkBuildInfo(t, bin.data, version, commit)...)
}

// checkMachine checks the executable format and CPU architecture.
func checkMachine(t target, data []byte) error {
	r := bytes.NewReader(data)
	switch t.goos {
	case "linux":
		f, err := elf.NewFile(r)
		if err != nil {
			return fmt.Errorf("not an ELF executable: %w", err)
		}
		want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64, "arm": elf.EM_ARM}[t.goarch]
		if f.Machine != want || f.Type != elf.ET_EXEC {
			return fmt.Errorf("ELF %v %v, want %v executable", f.Type, f.Machine, want)
		}
	case "darwin":
		f, err := macho.NewFile(r)
		if err != nil {
			return fmt.Errorf("not a Mach-O executable: %w", err)
		}
		want := map[string]macho.Cpu{"amd64": macho.CpuAmd64, "arm64": macho.CpuArm64}[t.goarch]
		if f.Cpu != want || f.Type != macho.TypeExec {
			return fmt.Errorf("Mach-O %v %v, want %v executable", f.Type, f.Cpu, want)
		}
	case "windows":
		f, err := pe.NewFile(r)
		if err != nil {
			return fmt.Errorf("not a PE executable: %w", err)
		}
		want := map[string]uint16{"amd64": pe.IMAGE_FILE_MACHINE_AMD64, "arm64": pe.IMAGE_FILE_MACHINE_ARM64}[t.goarch]
		if f.Machine != want || f.Characteristics&pe.IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
			return fmt.Errorf("PE machine %#x, want %#x executable", f.Machine, want)
		}
	}
	return nil
}

// checkBuildInfo checks the build settings Go records in the executable and
// the version and commit set with -ldflags -X. Go omits -ldflags from the
// build information when -trimpath is used, so those two values are looked
// up as strings in the executable instead.
func checkBuildInfo(t target, data []byte, version, commit string) []string {
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return []string{fmt.Sprintf("no Go build information: %v", err)}
	}
	want := map[string]string{
		"GOOS":         t.goos,
		"GOARCH":       t.goarch,
		"CGO_ENABLED":  "0",
		"-trimpath":    "true",
		"vcs.revision": commit,
		"vcs.modified": "false",
	}
	if t.goarm != "" {
		want["GOARM"] = t.goarm
	}
	got := map[string]string{}
	for _, s := range info.Settings {
		got[s.Key] = s.Value
	}
	var problems []string
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if got[k] != want[k] {
			problems = append(problems, fmt.Sprintf("build setting %s=%q, want %q", k, got[k], want[k]))
		}
	}
	if info.Path != "github.com/dimchansky/proxmark3-to-flipper" {
		problems = append(problems, fmt.Sprintf("built from %q", info.Path))
	}
	if info.GoVersion != runtime.Version() {
		problems = append(problems, fmt.Sprintf("built with %s, want %s", info.GoVersion, runtime.Version()))
	}
	for _, s := range []string{version, commit} {
		if !bytes.Contains(data, []byte(s)) {
			problems = append(problems, fmt.Sprintf("does not embed %q (missing -X main.version/main.commit?)", s))
		}
	}
	return problems
}

func hostTarget() string {
	for _, t := range targets {
		if t.goos == runtime.GOOS && t.goarch == runtime.GOARCH {
			return t.name
		}
	}
	return runtime.GOOS + "_" + runtime.GOARCH
}

// smokeTest runs the extracted executable the way a user would.
func smokeTest(t target, bin []byte, emulator, version, commit string) []string {
	dir, err := os.MkdirTemp("", "verifydist-")
	if err != nil {
		return []string{err.Error()}
	}
	defer func() { _ = os.RemoveAll(dir) }()
	exe := filepath.Join(dir, t.binary())
	if err := os.WriteFile(exe, bin, 0o700); err != nil { //nolint:gosec // the extracted file must be executable
		return []string{err.Error()}
	}

	var problems []string
	fail := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	run := func(args ...string) (int, string, string) {
		name, cmdArgs := exe, args
		if prefix := strings.Fields(emulator); len(prefix) > 0 {
			name, cmdArgs = prefix[0], append(append(prefix[1:], exe), args...)
		}
		cmd := exec.Command(name, cmdArgs...) //nolint:gosec // runs the executable under test
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var exitErr *exec.ExitError
		if err != nil && !errors.As(err, &exitErr) {
			fail("cannot run %s: %v", t.binary(), err)
			return -1, "", ""
		}
		return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
	}

	wantVersion := fmt.Sprintf("%s v%s (commit %s)\n", project, version, commit[:12])
	if code, out, errOut := run("-version"); code != 0 || out != wantVersion || errOut != "" {
		fail("-version: exit %d, stdout %q, stderr %q; want %q", code, out, errOut, wantVersion)
	}
	if code, out, _ := run("-help"); code != 0 || !strings.HasPrefix(out, "Usage: "+project+" ") {
		fail("-help: exit %d, stdout %q", code, firstLine(out))
	}
	if code, _, _ := run("-i"); code != 2 {
		fail("usage error: exit %d, want 2", code)
	}

	conversions := []struct{ fixture, golden string }{
		{"mfcard-1k-uid4.json", "mfc-1k-uid4.nfc"},
		{"mfcard-1k-uid7.json", "mfc-1k-uid7.nfc"},
		{"mfcard-4k-uid4.json", "mfc-4k-uid4.nfc"},
		{"mfcard-mini-uid4.json", "mfc-mini-uid4.nfc"},
		{"mfc-v2-1k-uid4.json", "mfc-1k-uid4.nfc"},
	}
	for _, c := range conversions {
		out := filepath.Join(dir, c.fixture+".nfc")
		code, _, errOut := run("-i", filepath.Join("testdata", "proxmark3", c.fixture), "-o", out)
		got, readErr := os.ReadFile(out)
		want, wantErr := os.ReadFile(filepath.Join("testdata", "flipper", c.golden))
		if code != 0 || readErr != nil || wantErr != nil || !bytes.Equal(got, want) {
			fail("%s: exit %d, stderr %q, output does not match %s", c.fixture, code, errOut, c.golden)
		}
	}

	invalidOut := filepath.Join(dir, "invalid.nfc")
	if code, _, _ := run("-i", filepath.Join("testdata", "proxmark3", "mfcard-2k-uid4.json"), "-o", invalidOut); code != 1 {
		fail("invalid dump: exit %d, want 1", code)
	}
	if _, err := os.Lstat(invalidOut); err == nil {
		fail("invalid dump created %s", filepath.Base(invalidOut))
	}

	existing := filepath.Join(dir, "existing.nfc")
	keep := []byte("existing file\n")
	if err := os.WriteFile(existing, keep, 0o600); err != nil {
		return append(problems, err.Error())
	}
	if code, _, _ := run("-i", filepath.Join("testdata", "proxmark3", "mfcard-1k-uid4.json"), "-o", existing); code != 1 {
		fail("existing output without -force: exit %d, want 1", code)
	}
	if got, _ := os.ReadFile(existing); !bytes.Equal(got, keep) {
		fail("existing output was changed without -force")
	}
	if len(problems) == 0 {
		how := "natively"
		if emulator != "" {
			how = "under " + emulator
		}
		fmt.Printf("smoke tests passed for %s (%s) on a %s/%s host, run %s\n", t.name, t.platform(), runtime.GOOS, runtime.GOARCH, how)
	}
	return problems
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}
