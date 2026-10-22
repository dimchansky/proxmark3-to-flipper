//go:build knowndefects

package main

// Intended-behavior tests for the defects recorded in
// docs/audit-and-compatibility.md that are still open. Each test states the
// behavior the converter should have and FAILS against the current
// implementation; the failure message shows the actual behavior. They are
// excluded from the default build so that the main suite stays green, and are
// run with:
//
//	go test -tags knowndefects -run 'TestDefect' ./...
//
// When a defect is fixed, move its test into the default suite and delete it
// from this file. Fixed so far, with their regression tests:
//
//   - Task 02: D-01 (TestCLI_OutputIsInput), D-07 and D-08
//     (TestWriteOutputFile_InjectedFailures), D-11 (TestCLI_ExistingOutput),
//     D-13 (TestCLI_OutputPermissions).
//   - Task 03: D-02 (conversionCases), D-03, D-04, D-05, D-06, D-09, D-12 and
//     D-18 (TestParseProxmark3JSON_Rejected), D-14
//     (TestParseProxmark3JSON_SizeLimit), D-15
//     (TestParseProxmark3JSON_ErrorsDoNotLeakData, TestCLI_InvalidInputWithForce).

import (
	"path/filepath"
	"strings"
	"testing"
)

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

// D-19: positional arguments are silently ignored.
func TestDefectD19_PositionalArgumentsIgnored(t *testing.T) {
	dir := t.TempDir()
	in := copyFixture(t, dir, fixture1K)
	res := runCLI(t, dir, "-i", in, "-o", filepath.Join(dir, "card.nfc"), "extra.json")
	if res.code == 0 {
		t.Errorf("exit code = 0, want a usage error for the unexpected argument")
	}
}
