// Command proxmark3-to-flipper converts a Proxmark3 MIFARE Classic JSON dump
// into a Flipper Zero NFC file.
//
// Usage:
//
//	proxmark3-to-flipper -i dump.json -o card.nfc [-force]
//
// See README.md for usage and docs/conversion.md for the conversion rules.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

const programName = "proxmark3-to-flipper"

// Exit codes.
const (
	exitOK      = 0 // conversion done, or help or version printed
	exitFailure = 1 // invalid input or a failure writing the output
	exitUsage   = 2 // invalid flags or arguments
)

// version and commit identify a release build. Release automation sets them
// with -ldflags "-X main.version=… -X main.commit=…" (the GoReleaser default);
// other builds fall back to the module build information.
var (
	version string
	commit  string
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type config struct {
	input   string
	output  string
	force   bool
	version bool
}

// run executes the command with the given arguments (without the program
// name) and returns the exit code. It has no global state, so it can be called
// repeatedly, including from parallel tests.
func run(args []string, stdout, stderr io.Writer) int {
	var cfg config
	fs := flag.NewFlagSet(programName, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // run prints help and errors itself
	fs.StringVar(&cfg.input, "i", "", "")
	fs.StringVar(&cfg.output, "o", "", "")
	fs.BoolVar(&cfg.force, "force", false, "")
	fs.BoolVar(&cfg.version, "version", false, "")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, usage)
			return exitOK
		}
		return usageError(stderr, err.Error())
	}
	if cfg.version {
		_, _ = fmt.Fprintln(stdout, versionString())
		return exitOK
	}
	switch {
	case fs.NArg() > 0:
		return usageError(stderr, fmt.Sprintf("unexpected argument %.64q", fs.Arg(0)))
	case cfg.input == "":
		return usageError(stderr, "missing -i: name the Proxmark3 JSON dump to read")
	case cfg.output == "":
		return usageError(stderr, "missing -o: name the Flipper NFC file to write")
	}

	if err := convert(cfg, stderr); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return exitFailure
	}
	return exitOK
}

const usage = `Usage: proxmark3-to-flipper -i DUMP.json -o CARD.nfc [-force]

Convert a Proxmark3 MIFARE Classic JSON dump (FileType "mfcard", "mfc v2"
or "mfc v3") of a Mini, 1K or 4K card into a Flipper Zero NFC file.

Options:
  -i FILE     Proxmark3 JSON dump to read
  -o FILE     Flipper NFC file to write; an existing file is kept
  -force      replace the output file if it already exists
  -version    print version information and exit
  -h, -help   print this help and exit

Exit status: 0 on success, 1 if the conversion fails, 2 on invalid usage.
`

func usageError(stderr io.Writer, msg string) int {
	_, _ = fmt.Fprintf(stderr, "error: %s\nRun '%s -help' for usage.\n", msg, programName)
	return exitUsage
}

// convert reads, validates and writes the card. Everything is validated and
// rendered before the output is touched.
func convert(cfg config, stderr io.Writer) error {
	card, input, err := parseProxMark3JSONFile(cfg.input)
	if err != nil {
		return err
	}

	data := renderNFC(card)
	if err := checkOutputIsNotInput(input, cfg.output); err != nil {
		return err
	}
	if err := writeOutputFile(osFileOps, cfg.output, data, cfg.force); err != nil {
		return err
	}

	// Report dropped fields only for a conversion that actually happened.
	if len(card.Dropped) > 0 {
		verb := "was"
		if len(card.Dropped) > 1 {
			verb = "were"
		}
		_, _ = fmt.Fprintf(stderr, "warning: %s cannot be stored in a Flipper MIFARE Classic file and %s not converted\n",
			strings.Join(card.Dropped, " and "), verb)
	}
	return nil
}

func versionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		info = nil
	}
	return formatVersion(version, commit, info)
}

// formatVersion builds the -version line. An ldflags version wins; otherwise
// the module version from the build information is used: a tag for
// "go install …@vX.Y.Z", a pseudo-version (v0.0.0-…) for an untagged commit,
// and "devel" when the build has no version at all. The commit comes from
// ldflags or from the VCS information that "go build" records.
func formatVersion(version, commit string, info *debug.BuildInfo) string {
	modified := false
	if info != nil {
		if version == "" && info.Main.Version != "(devel)" {
			version = info.Main.Version
		}
		for _, s := range info.Settings {
			switch {
			case s.Key == "vcs.revision" && commit == "":
				commit = s.Value
			case s.Key == "vcs.modified":
				modified = s.Value == "true"
			}
		}
	}
	switch {
	case version == "":
		version = "devel"
	case !strings.HasPrefix(version, "v") && version != "devel":
		version = "v" + version // GoReleaser passes the tag without its "v"
	}

	line := programName + " " + version
	if commit != "" {
		if len(commit) > 12 {
			commit = commit[:12]
		}
		line += " (commit " + commit
		if modified {
			line += ", modified"
		}
		line += ")"
	}
	return line
}
