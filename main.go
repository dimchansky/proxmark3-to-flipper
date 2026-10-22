package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	// Version (set by compiler) is the version of program
	Version = "undefined"
	// BuildTime (set by compiler) is the program build time in '+%Y-%m-%dT%H:%M:%SZ' format
	BuildTime = "undefined"
	// GitHash (set by compiler) is the git commit hash of source tree
	GitHash = "undefined"
)

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		var usageErr usageError
		if errors.As(err, &usageErr) {
			flag.Usage()
		}
		os.Exit(1)
	}
}

type usageError string

func (u usageError) Error() string {
	return string(u)
}

func run() error {
	cfg, err := parseArgs()
	if err != nil {
		return err
	}

	card, input, err := parseProxMark3JSONFile(cfg.InputJSONFile)
	if err != nil {
		return err
	}

	// Render before touching the output, so that only I/O can fail there.
	data := renderNFC(card)
	if err := checkOutputIsNotInput(input, cfg.OutputNFCFile); err != nil {
		return err
	}
	if err := writeOutputFile(osFileOps, cfg.OutputNFCFile, data, cfg.Force); err != nil {
		return err
	}

	// Report dropped fields only for a conversion that actually happened.
	if len(card.Dropped) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "warning: %s cannot be stored in a Flipper MIFARE Classic file and %s not converted\n",
			strings.Join(card.Dropped, " and "), pluralWas(len(card.Dropped)))
	}
	return nil
}

func pluralWas(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}

type config struct {
	InputJSONFile string
	OutputNFCFile string
	Force         bool
}

func parseArgs() (*config, error) {
	var cfg config
	flag.StringVar(&cfg.InputJSONFile, "i", "", "input Proxmark3 dump file in JSON format")
	flag.StringVar(&cfg.OutputNFCFile, "o", "", "output Flipper file in NFC format")
	flag.BoolVar(&cfg.Force, "force", false, "replace the output file if it already exists")
	defaultUsage := flag.Usage
	flag.Usage = func() {
		defaultUsage()
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Version: %s\tBuildTime: %v\tGitHash: %s\n", Version, BuildTime, GitHash)
	}
	flag.Parse()

	if cfg.InputJSONFile == "" {
		return nil, usageError("please provide input Proxmark3 dump file in JSON format")
	}

	if cfg.OutputNFCFile == "" {
		return nil, usageError("please provide input Proxmark3 dump file in JSON format")
	}

	return &cfg, nil
}
