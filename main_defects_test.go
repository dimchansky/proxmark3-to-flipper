//go:build knowndefects

package main

// Intended-behavior tests for the defects recorded in
// docs/audit-and-compatibility.md. Each test states the behavior the converter
// should have and FAILS against the audit baseline; the failure message shows
// the actual behavior. They are excluded from the default build so that the
// baseline suite stays green, and are run with:
//
//	go test -tags knowndefects -run 'TestDefect' ./...
//
// When a defect is fixed, move its test into the default suite and delete it
// from this file. D-01, D-07 and D-13 were fixed in Task 02; their regression
// tests are TestCLI_OutputIsInput, TestWriteOutputFile_InjectedFailures and
// TestCLI_OutputPermissions.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fixtureV3 = "testdata/proxmark3/mfc-v3-1k-uid4.json"
	fixture2K = "testdata/proxmark3/mfcard-2k-uid4.json"
)

// zeroBlocks returns n all-zero 16-byte blocks in Proxmark3 hex form.
func zeroBlocks(n int) []string {
	blocks := make([]string, n)
	for i := range blocks {
		blocks[i] = strings.Repeat("00", 16)
	}
	return blocks
}

// convert parses a dump and renders it.
func convert(input string) (string, error) {
	card, err := parseProxmark3JSON(strings.NewReader(input))
	if err != nil {
		return "", err
	}
	return string(renderNFC(card)), nil
}

func expectRejected(t *testing.T, input string) {
	t.Helper()
	out, err := convert(input)
	if err == nil {
		t.Errorf("conversion succeeded, want an error; output starts with:\n%s", firstLines(out, 12))
	}
}

// D-02: dumps written by Proxmark3 v4.17511 and later use FileType "mfc v2"
// (or "mfc v3"), which the converter rejects.
func TestDefectD02_CurrentProxmark3FileTypes(t *testing.T) {
	for _, fixture := range []string{fixtureV2, fixtureV3} {
		fixture := fixture
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			out, err := convert(string(readFile(t, fixture)))
			if err != nil {
				t.Fatalf("conversion error = %v, want the same output as for FileType mfcard", err)
			}
			assertSameText(t, golden1K, []byte(out), readFile(t, golden1K))
		})
	}
}

// D-03: a dump without card data or blocks is "converted" with exit code 0
// into a file that Flipper cannot load.
func TestDefectD03_EmptyDumpAccepted(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "no Card and no blocks", input: `{"Created":"proxmark3","FileType":"mfcard"}`},
		{name: "no Card", input: `{"Created":"proxmark3","FileType":"mfcard","blocks":{` + numberedBlocks(zeroBlocks(64)) + `}}`},
		{name: "empty blocks", input: pm3JSON("mfcard", "11223344", "0400", "08", nil, false)},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) { expectRejected(t, tt.input) })
	}
}

// D-04: block counts other than 64 and 256 produce "Mifare Classic type: 0K"
// or "2K"; Flipper only accepts MINI, 1K and 4K.
func TestDefectD04_UnsupportedBlockCounts(t *testing.T) {
	t.Run("Mini is written as MINI", func(t *testing.T) {
		out, err := convert(string(readFile(t, fixtureMini)))
		if err != nil {
			t.Fatalf("conversion error = %v", err)
		}
		assertSameText(t, expectedMini, []byte(out), readFile(t, expectedMini))
	})
	t.Run("2K is rejected", func(t *testing.T) {
		expectRejected(t, string(readFile(t, fixture2K)))
	})
	for _, n := range []int{1, 19, 21, 63, 65, 128, 255, 257} {
		n := n
		t.Run(fmt.Sprintf("%d blocks are rejected", n), func(t *testing.T) {
			expectRejected(t, pm3JSON("mfcard", "11223344", "0400", "08", zeroBlocks(n), false))
		})
	}
}

// D-05: blocks are not checked to be 16 bytes long.
func TestDefectD05_BlockSizeNotValidated(t *testing.T) {
	for _, value := range []string{"", "00", strings.Repeat("00", 15), strings.Repeat("00", 17), strings.Repeat("00", 32)} {
		value := value
		t.Run(fmt.Sprintf("%d bytes", len(value)/2), func(t *testing.T) {
			expectRejected(t, pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(zeroBlocks(64), 9, value), false))
		})
	}
}

// D-06: UID, ATQA and SAK lengths are not validated. Flipper requires a 4, 7
// or 10 byte UID (4 or 7 in firmware before the unified format), a 2 byte ATQA
// and a 1 byte SAK.
func TestDefectD06_CardIdentityNotValidated(t *testing.T) {
	tests := []struct {
		name, uid, atqa, sak string
	}{
		{name: "empty UID", uid: "", atqa: "0400", sak: "08"},
		{name: "3-byte UID", uid: "112233", atqa: "0400", sak: "08"},
		{name: "5-byte UID", uid: "1122334455", atqa: "0400", sak: "08"},
		{name: "11-byte UID", uid: "1122334455667788990011", atqa: "0400", sak: "08"},
		{name: "empty ATQA", uid: "11223344", atqa: "", sak: "08"},
		{name: "1-byte ATQA", uid: "11223344", atqa: "04", sak: "08"},
		{name: "3-byte ATQA", uid: "11223344", atqa: "040000", sak: "08"},
		{name: "empty SAK", uid: "11223344", atqa: "0400", sak: ""},
		{name: "2-byte SAK", uid: "11223344", atqa: "0400", sak: "0800"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expectRejected(t, pm3JSON("mfcard", tt.uid, tt.atqa, tt.sak, zeroBlocks(64), false))
		})
	}
}

// D-09: anything after the first JSON value is ignored.
func TestDefectD09_TrailingDataAccepted(t *testing.T) {
	valid := string(readFile(t, fixture1K))
	for name, suffix := range map[string]string{
		"garbage":         "garbage",
		"second document": valid,
		"closing brace":   "}",
	} {
		suffix := suffix
		t.Run(name, func(t *testing.T) { expectRejected(t, valid+suffix) })
	}
}

// D-10: the diagnostic for a missing -o asks for the input file, and usage
// errors exit with 1 while flag syntax errors exit with 2.
func TestDefectD10_UsageDiagnostics(t *testing.T) {
	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)

	res := runCLI(t, dir, "-i", in)
	if !strings.Contains(strings.SplitN(res.stderr, "\n", 2)[0], "output") {
		t.Errorf("first stderr line = %q, want it to ask for the output file", strings.SplitN(res.stderr, "\n", 2)[0])
	}
	if res.code != 2 {
		t.Errorf("exit code for missing -o = %d, want 2 (usage error)", res.code)
	}
	if res := runCLI(t, dir); res.code != 2 {
		t.Errorf("exit code without arguments = %d, want 2 (usage error)", res.code)
	}
}

// D-12: duplicate block keys are accepted and the last value silently wins.
func TestDefectD12_DuplicateBlockKeys(t *testing.T) {
	valid := pm3JSON("mfcard", "11223344", "0400", "08", zeroBlocks(64), false)
	dup := strings.Replace(valid, `"63": "`, `"5": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "63": "`, 1)
	expectRejected(t, dup)
}

// D-18: a block key that is not a decimal index is reported as a missing
// block with a different number.
func TestDefectD18_NonNumericBlockKeyDiagnostic(t *testing.T) {
	valid := pm3JSON("mfcard", "11223344", "0400", "08", zeroBlocks(64), false)
	input := strings.Replace(valid, `"63": "`, `"foo": "00", "63": "`, 1)
	_, err := convert(input)
	if err == nil || !strings.Contains(err.Error(), "foo") {
		t.Errorf("error = %v, want it to name the unexpected key \"foo\"", err)
	}
}

// D-19: positional arguments are silently ignored.
func TestDefectD19_PositionalArgumentsIgnored(t *testing.T) {
	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)
	res := runCLI(t, dir, "-i", in, "-o", filepath.Join(dir, "card.nfc"), "extra.json")
	if res.code == 0 {
		t.Errorf("exit code = 0, want a usage error for the unexpected argument")
	}
}

func numberedBlocks(blocks []string) string {
	parts := make([]string, len(blocks))
	for i, b := range blocks {
		parts[i] = fmt.Sprintf("%q: %q", fmt.Sprint(i), b)
	}
	return strings.Join(parts, ",")
}
