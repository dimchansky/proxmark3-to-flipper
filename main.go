package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
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
	return writeOutputFile(osFileOps, cfg.OutputNFCFile, data, cfg.Force)
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

type hexData []byte

func (h hexData) String() string {
	var sb strings.Builder

	n := len(h)
	for i := 0; i < n-1; i++ {
		fmt.Fprintf(&sb, "%02X ", h[i])
	}
	if n >= 1 {
		fmt.Fprintf(&sb, "%02X", h[n-1])
	}

	return sb.String()
}

type mifareCard struct {
	UID    hexData
	ATQA   hexData
	SAK    hexData
	Blocks []hexData
}

// parseProxMark3JSONFile parses the dump in fileName. It also returns the
// identity of the file that was read, for checkOutputIsNotInput.
func parseProxMark3JSONFile(fileName string) (*mifareCard, fs.FileInfo, error) {
	jsonFile, err := os.Open(fileName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Proxmark3 dump file '%s': %w", fileName, err)
	}
	defer func() {
		// The file is only read; a close error cannot affect the parsed data.
		_ = jsonFile.Close()
	}()

	info, err := jsonFile.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Proxmark3 dump file '%s': %w", fileName, err)
	}
	card, err := parseProxmark3JSON(jsonFile)
	if err != nil {
		return nil, nil, err
	}
	return card, info, nil
}

func parseProxmark3JSON(r io.Reader) (*mifareCard, error) {
	var proxmark3JSON struct {
		Created  string `json:"Created"`
		FileType string `json:"FileType"`
		Card     struct {
			UID  string `json:"UID"`
			ATQA string `json:"ATQA"`
			SAK  string `json:"SAK"`
		} `json:"Card"`
		Blocks map[string]string `json:"blocks"`
	}

	if err := json.NewDecoder(r).Decode(&proxmark3JSON); err != nil {
		return nil, fmt.Errorf("failed to decode Proxmark3 JSON file: %w", err)
	}

	if proxmark3JSON.Created != "proxmark3" {
		return nil, errors.New("JSON file must be produced by Proxmark3")
	}

	if proxmark3JSON.FileType != "mfcard" {
		return nil, errors.New("expecting Mifare card dump")
	}

	card := &proxmark3JSON.Card
	uid, err := decodeHexData(card.UID)
	if err != nil {
		return nil, fmt.Errorf("cannot parse card UID: %w", err)
	}
	atqa, err := decodeHexData(card.ATQA)
	if err != nil {
		return nil, fmt.Errorf("cannot parse card ATQA: %w", err)
	}
	sak, err := decodeHexData(card.SAK)
	if err != nil {
		return nil, fmt.Errorf("cannot parse card SAK: %w", err)
	}

	blocksMap := proxmark3JSON.Blocks
	blocksNum := len(blocksMap)
	blocks := make([]hexData, blocksNum)
	for i := 0; i < blocksNum; i++ {
		blockNumStr := strconv.Itoa(i)
		blockData, ok := blocksMap[blockNumStr]
		if !ok {
			return nil, fmt.Errorf("cannot find Mifare card data for block %d", i)
		}
		bs, err := decodeHexData(blockData)
		if err != nil {
			return nil, fmt.Errorf("cannot parse block %d data: %w", i, err)
		}
		// TODO: check block length
		blocks[i] = bs
	}

	return &mifareCard{
		UID:    uid,
		ATQA:   atqa,
		SAK:    sak,
		Blocks: blocks,
	}, nil
}

func decodeHexData(hexStr string) (bs hexData, err error) {
	bs, err = hex.DecodeString(hexStr)
	if err != nil {
		err = fmt.Errorf("failed to parse hex data '%s': %w", hexStr, err)
	}
	return
}

// renderNFC returns c in the Flipper NFC file format. Rendering to memory
// cannot fail, so the output file is only touched once the content is complete.
func renderNFC(c *mifareCard) []byte {
	var b bytes.Buffer
	b.WriteString(`Filetype: Flipper NFC device
Version: 2
# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card
Device type: Mifare Classic
# UID, ATQA and SAK are common for all formats
`)
	fmt.Fprintf(&b, "UID: %s\n", c.UID)
	fmt.Fprintf(&b, "ATQA: %s\n", c.ATQA)
	fmt.Fprintf(&b, "SAK: %s\n", c.SAK)
	b.WriteString("# Mifare Classic specific data\n")
	mfSize := 0
	switch len(c.Blocks) {
	case 64:
		mfSize = 1
	case 128:
		mfSize = 2
	case 256:
		mfSize = 4
	}
	fmt.Fprintf(&b, "Mifare Classic type: %dK\n", mfSize)
	b.WriteString(`Data format version: 2
# Mifare Classic blocks, '??' means unknown data
`)
	for i, block := range c.Blocks {
		fmt.Fprintf(&b, "Block %d: %s\n", i, block)
	}
	return b.Bytes()
}
