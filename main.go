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
	"sort"
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

// maxInputSize bounds how much of the input is read. A complete 4K dump as
// written by Proxmark3, including SectorKeys and AccessConditionsText, is about
// 28 KB, so 1 MiB leaves ample headroom while bounding memory use.
const maxInputSize = 1 << 20

// supportedFileTypes are the Proxmark3 FileType values of MIFARE Classic dumps.
// All three store the card data used here in the same fields; "mfc v3" adds
// Card.ATS and Card.SIGNATURE (see docs/audit-and-compatibility.md).
var supportedFileTypes = map[string]bool{"mfcard": true, "mfc v2": true, "mfc v3": true}

// cardTypes maps a complete dump's block count to the Flipper "Mifare Classic
// type". MIFARE Classic 2K (128 blocks) has no Flipper type.
var cardTypes = map[int]string{20: "MINI", 64: "1K", 256: "4K"}

// mifareCard is a validated MIFARE Classic dump: UID has 4, 7 or 10 bytes,
// ATQA 2 and SAK 1, Type matches len(Blocks) and every block has 16 bytes.
type mifareCard struct {
	UID    hexData
	ATQA   hexData
	SAK    hexData
	Type   string
	Blocks []hexData
	// Dropped names input fields that a Flipper MIFARE Classic file cannot
	// store and that were therefore not converted.
	Dropped []string
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

// proxmark3Dump holds the fields of a Proxmark3 MIFARE Classic JSON dump that
// the conversion reads; other fields are ignored. Pointers tell a missing
// field from an empty one.
type proxmark3Dump struct {
	Created  string `json:"Created"`
	FileType string `json:"FileType"`
	Card     *struct {
		UID       *string `json:"UID"`
		ATQA      *string `json:"ATQA"`
		SAK       *string `json:"SAK"`
		ATS       *string `json:"ATS"`
		Signature *string `json:"SIGNATURE"`
	} `json:"Card"`
	Blocks map[string]string `json:"blocks"`
}

// parseProxmark3JSON reads one Proxmark3 MIFARE Classic JSON document from r
// and validates it completely. Errors never contain card data: hex values are
// described by field, position and length only.
func parseProxmark3JSON(r io.Reader) (*mifareCard, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInputSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read Proxmark3 JSON file: %w", err)
	}
	if len(data) > maxInputSize {
		return nil, fmt.Errorf("input is larger than %d bytes, too large for a MIFARE Classic dump", maxInputSize)
	}

	// json.Unmarshal accepts exactly one JSON value; trailing data is an error.
	var dump proxmark3Dump
	if err := json.Unmarshal(data, &dump); err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return nil, fmt.Errorf("failed to decode Proxmark3 JSON file at byte offset %d: %w", syntaxErr.Offset, err)
		}
		return nil, fmt.Errorf("failed to decode Proxmark3 JSON file: %w", err)
	}
	if err := checkDuplicateKeys(data); err != nil {
		return nil, fmt.Errorf("failed to decode Proxmark3 JSON file: %w", err)
	}

	if dump.Created != "proxmark3" {
		return nil, errors.New("JSON file must be produced by Proxmark3")
	}
	if !supportedFileTypes[dump.FileType] {
		return nil, fmt.Errorf(`unsupported FileType %.32q, expecting a MIFARE Classic dump ("mfcard", "mfc v2" or "mfc v3")`, dump.FileType)
	}
	if dump.Card == nil {
		return nil, errors.New("missing Card")
	}

	card := &mifareCard{}
	if card.UID, err = requiredHex("Card.UID", dump.Card.UID); err != nil {
		return nil, err
	}
	if n := len(card.UID); n != 4 && n != 7 && n != 10 {
		return nil, fmt.Errorf("invalid Card.UID: %d bytes, want 4, 7 or 10", n)
	}
	if card.ATQA, err = requiredHex("Card.ATQA", dump.Card.ATQA); err != nil {
		return nil, err
	}
	if n := len(card.ATQA); n != 2 {
		return nil, fmt.Errorf("invalid Card.ATQA: %d bytes, want 2", n)
	}
	if card.SAK, err = requiredHex("Card.SAK", dump.Card.SAK); err != nil {
		return nil, err
	}
	if n := len(card.SAK); n != 1 {
		return nil, fmt.Errorf("invalid Card.SAK: %d bytes, want 1", n)
	}
	if dump.Card.ATS != nil && *dump.Card.ATS != "" {
		card.Dropped = append(card.Dropped, "Card.ATS")
	}
	if dump.Card.Signature != nil && *dump.Card.Signature != "" {
		card.Dropped = append(card.Dropped, "Card.SIGNATURE")
	}

	if card.Type, card.Blocks, err = parseBlocks(dump.Blocks); err != nil {
		return nil, err
	}
	return card, nil
}

// parseBlocks checks that the block keys are exactly "0" … "n-1", that n is
// the size of a card Flipper supports, and decodes every 16-byte block.
func parseBlocks(m map[string]string) (string, []hexData, error) {
	if m == nil {
		return "", nil, errors.New("missing blocks")
	}
	n := len(m)
	if n == 0 {
		return "", nil, errors.New("dump has no blocks")
	}
	for i := 0; i < n; i++ {
		if _, ok := m[strconv.Itoa(i)]; !ok {
			return "", nil, blockIndexError(m, i)
		}
	}
	// The keys are now exactly the canonical indices 0 … n-1.

	cardType, ok := cardTypes[n]
	switch {
	case n == 128:
		return "", nil, errors.New("MIFARE Classic 2K dumps (128 blocks) are not supported: the Flipper NFC format has no 2K card type")
	case !ok:
		return "", nil, fmt.Errorf("unsupported number of blocks: %d (a complete MIFARE Classic Mini, 1K or 4K dump has 20, 64 or 256)", n)
	}

	blocks := make([]hexData, n)
	for i := range blocks {
		name := "block " + strconv.Itoa(i)
		value := m[strconv.Itoa(i)]
		b, err := requiredHex(name, &value)
		if err != nil {
			return "", nil, err
		}
		if len(b) != 16 {
			return "", nil, fmt.Errorf("invalid %s: %d bytes, want 16", name, len(b))
		}
		blocks[i] = b
	}
	return cardType, blocks, nil
}

// blockIndexError explains why block i is missing: either a key is not a
// canonical decimal index, or index i is genuinely absent.
func blockIndexError(m map[string]string, i int) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if n, err := strconv.Atoi(k); err != nil || n < 0 || strconv.Itoa(n) != k {
			return fmt.Errorf("invalid block index %.16q: want a decimal number without sign or leading zeros", k)
		}
	}
	return fmt.Errorf("missing block %d", i)
}

// requiredHex decodes a required hexadecimal field. The value is not included
// in errors, because it may be a sector key.
func requiredHex(name string, value *string) (hexData, error) {
	if value == nil {
		return nil, fmt.Errorf("missing %s", name)
	}
	b, err := hex.DecodeString(*value)
	if err == nil {
		return b, nil
	}
	var invalid hex.InvalidByteError
	if errors.As(err, &invalid) {
		offset := strings.IndexByte(*value, byte(invalid))
		return nil, fmt.Errorf("invalid %s: invalid hexadecimal character at offset %d: %w", name, offset, err)
	}
	return nil, fmt.Errorf("invalid %s: odd number of hexadecimal digits (%d): %w", name, len(*value), err)
}

// checkDuplicateKeys fails if any JSON object in data has the same key twice.
// encoding/json silently keeps the last value, which would make an edited or
// corrupted dump ambiguous. Keys are compared case-insensitively because that
// is how encoding/json matches them to struct fields. data must be valid JSON.
func checkDuplicateKeys(data []byte) error {
	type frame struct {
		keys    map[string]bool // nil for an array
		path    string
		wantKey bool
		lastKey string
	}
	var stack []*frame
	// valueDone records that the enclosing object now expects its next key.
	valueDone := func() {
		if len(stack) > 0 && stack[len(stack)-1].keys != nil {
			stack[len(stack)-1].wantKey = true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch tok {
		case json.Delim('{'), json.Delim('['):
			path := "the top-level value"
			if top != nil {
				path = top.lastKey
				if top.keys == nil {
					path = top.path + " array"
				}
			}
			f := &frame{path: path}
			if tok == json.Delim('{') {
				f.keys, f.wantKey = map[string]bool{}, true
			}
			stack = append(stack, f)
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
			valueDone()
		default:
			if top == nil || !top.wantKey {
				valueDone() // a scalar value
				continue
			}
			key, _ := tok.(string) // object keys are always strings
			folded := strings.ToLower(key)
			if top.keys[folded] {
				return fmt.Errorf("duplicate key %.32q in %s", key, top.path)
			}
			top.keys[folded] = true
			top.wantKey, top.lastKey = false, key
		}
	}
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
	fmt.Fprintf(&b, "Mifare Classic type: %s\n", c.Type)
	b.WriteString(`Data format version: 2
# Mifare Classic blocks, '??' means unknown data
`)
	for i, block := range c.Blocks {
		fmt.Fprintf(&b, "Block %d: %s\n", i, block)
	}
	return b.Bytes()
}
