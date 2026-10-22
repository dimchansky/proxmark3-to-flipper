package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The tests in this file characterize the converter as of the audit baseline
// (see docs/audit-and-compatibility.md). They assert behavior that is correct
// with respect to the upstream formats. Behavior that is known to be wrong is
// captured by the intended-behavior tests in main_defects_test.go, which are
// built only with -tags knowndefects and currently fail.

const (
	fixture1K    = "testdata/proxmark3/mfcard-1k-uid4.json"
	fixture1K7   = "testdata/proxmark3/mfcard-1k-uid7.json"
	fixture4K    = "testdata/proxmark3/mfcard-4k-uid4.json"
	fixtureV2    = "testdata/proxmark3/mfc-v2-1k-uid4.json"
	fixtureMini  = "testdata/proxmark3/mfcard-mini-uid4.json"
	golden1K     = "testdata/flipper/mfc-1k-uid4.nfc"
	golden1K7    = "testdata/flipper/mfc-1k-uid7.nfc"
	golden4K     = "testdata/flipper/mfc-4k-uid4.nfc"
	expectedMini = "testdata/flipper/mfc-mini-uid4.expected.nfc"
)

// conversionCases are the conversions the baseline supports correctly.
var conversionCases = []struct {
	name    string
	fixture string
	golden  string
}{
	{name: "1K with 4-byte UID", fixture: fixture1K, golden: golden1K},
	{name: "1K with 7-byte UID", fixture: fixture1K7, golden: golden1K7},
	{name: "4K with 4-byte UID", fixture: fixture4K, golden: golden4K},
}

func TestHexData_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   hexData
		want string
	}{
		{name: "nil", in: nil, want: ""},
		{name: "empty", in: hexData{}, want: ""},
		{name: "single byte is zero padded", in: hexData{0x0A}, want: "0A"},
		{name: "bytes are uppercase and space separated", in: hexData{0x00, 0xab, 0xFF, 0x10}, want: "00 AB FF 10"},
		{name: "full block", in: bytes.Repeat([]byte{0xFE}, 16), want: strings.TrimSpace(strings.Repeat("FE ", 16))},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.String(); got != tt.want {
				t.Errorf("hexData(%x).String() = %q, want %q", []byte(tt.in), got, tt.want)
			}
		})
	}
}

func TestParseProxMark3JSONFile(t *testing.T) {
	t.Parallel()

	t.Run("valid file", func(t *testing.T) {
		t.Parallel()
		card, info, err := parseProxMark3JSONFile(fixture1K)
		if err != nil {
			t.Fatalf("parseProxMark3JSONFile(%q) error = %v", fixture1K, err)
		}
		if len(card.Blocks) != 64 {
			t.Errorf("len(Blocks) = %d, want 64", len(card.Blocks))
		}
		// The returned identity is what the output is compared against.
		want, err := os.Stat(fixture1K)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(info, want) {
			t.Errorf("returned FileInfo does not identify %s", fixture1K)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		name := filepath.Join(t.TempDir(), "does-not-exist.json")
		_, _, err := parseProxMark3JSONFile(name)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("parseProxMark3JSONFile(%q) error = %v, want fs.ErrNotExist", name, err)
		}
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not name the input file", err)
		}
	})

	t.Run("directory instead of file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if _, _, err := parseProxMark3JSONFile(dir); err == nil {
			t.Fatalf("parseProxMark3JSONFile(%q) error = nil, want an error", dir)
		}
	})
}

func TestParseProxmark3JSON_Fixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		fixture string
		uid     string
		atqa    string
		sak     string
		blocks  int
	}{
		{name: "1K with 4-byte UID", fixture: fixture1K, uid: "11223344", atqa: "0400", sak: "08", blocks: 64},
		{name: "1K with 7-byte UID", fixture: fixture1K7, uid: "04112233445566", atqa: "4400", sak: "08", blocks: 64},
		{name: "4K with 4-byte UID", fixture: fixture4K, uid: "A0A1A2A3", atqa: "0200", sak: "18", blocks: 256},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			raw := readFile(t, tt.fixture)
			card, err := parseProxmark3JSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("parseProxmark3JSON(%s) error = %v", tt.fixture, err)
			}

			assertBytes(t, "UID", card.UID, mustHex(t, tt.uid))
			assertBytes(t, "ATQA", card.ATQA, mustHex(t, tt.atqa))
			assertBytes(t, "SAK", card.SAK, mustHex(t, tt.sak))

			// Every block must be decoded from the JSON entry with the same
			// index, so block order and content are checked against the
			// fixture itself rather than against the parser's view of it.
			want := fixtureBlocks(t, raw)
			if len(card.Blocks) != tt.blocks || len(want) != tt.blocks {
				t.Fatalf("len(Blocks) = %d, fixture has %d, want %d", len(card.Blocks), len(want), tt.blocks)
			}
			for i, b := range card.Blocks {
				if len(b) != 16 {
					t.Errorf("block %d has %d bytes, want 16", i, len(b))
				}
				if !bytes.Equal(b, want[i]) {
					t.Errorf("block %d = %X, want %X", i, []byte(b), want[i])
				}
			}
		})
	}
}

func TestParseProxmark3JSON_BlockOrderIndependentOfKeyOrder(t *testing.T) {
	t.Parallel()

	var blocks []string
	for i := 0; i < 64; i++ {
		blocks = append(blocks, fmt.Sprintf("%02X%s", i, strings.Repeat("00", 15)))
	}
	ascending := pm3JSON("mfcard", "11223344", "0400", "08", blocks, false)
	descending := pm3JSON("mfcard", "11223344", "0400", "08", blocks, true)

	a, err := parseProxmark3JSON(strings.NewReader(ascending))
	if err != nil {
		t.Fatalf("ascending keys: %v", err)
	}
	d, err := parseProxmark3JSON(strings.NewReader(descending))
	if err != nil {
		t.Fatalf("descending keys: %v", err)
	}
	for i := range a.Blocks {
		if a.Blocks[i][0] != byte(i) || d.Blocks[i][0] != byte(i) {
			t.Fatalf("block %d starts with %02X (ascending) and %02X (descending), want %02X",
				i, a.Blocks[i][0], d.Blocks[i][0], byte(i))
		}
	}
}

func TestParseProxmark3JSON_Accepted(t *testing.T) {
	t.Parallel()

	blocks := make([]string, 64)
	for i := range blocks {
		blocks[i] = strings.Repeat("00", 16)
	}

	tests := []struct {
		name  string
		input string
		check func(t *testing.T, c *mifareCard)
	}{
		{
			name:  "lowercase hex is decoded",
			input: pm3JSON("mfcard", "aabbccdd", "0400", "08", replaceBlock(blocks, 1, "abcdef0123456789abcdef0123456789"), false),
			check: func(t *testing.T, c *mifareCard) {
				t.Helper()
				assertBytes(t, "UID", c.UID, []byte{0xAA, 0xBB, 0xCC, 0xDD})
				assertBytes(t, "block 1", c.Blocks[1], mustHex(t, "ABCDEF0123456789ABCDEF0123456789"))
			},
		},
		{
			name: "unknown fields are ignored",
			input: strings.Replace(pm3JSON("mfcard", "11223344", "0400", "08", blocks, false),
				`"Card": {`, `"Extra": {"nested": [1, 2, 3]}, "Card": {"ATS": "00",`, 1),
			check: func(t *testing.T, c *mifareCard) {
				t.Helper()
				assertBytes(t, "UID", c.UID, []byte{0x11, 0x22, 0x33, 0x44})
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			card, err := parseProxmark3JSON(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("parseProxmark3JSON() error = %v", err)
			}
			tt.check(t, card)
		})
	}
}

func TestParseProxmark3JSON_Rejected(t *testing.T) {
	t.Parallel()

	blocks := make([]string, 64)
	for i := range blocks {
		blocks[i] = strings.Repeat("00", 16)
	}
	valid := pm3JSON("mfcard", "11223344", "0400", "08", blocks, false)

	// errors.As targets are declared per call: the subtests run in parallel.
	isSyntaxErr := func(err error) bool { var e *json.SyntaxError; return errors.As(err, &e) }
	isTypeErr := func(err error) bool { var e *json.UnmarshalTypeError; return errors.As(err, &e) }
	isInvalidByte := func(err error) bool { var e hex.InvalidByteError; return errors.As(err, &e) }

	tests := []struct {
		name    string
		input   string
		wantMsg string
		wantErr func(error) bool
	}{
		{name: "empty input", input: "", wantMsg: "failed to decode Proxmark3 JSON file"},
		{name: "truncated JSON", input: valid[:len(valid)/2], wantMsg: "failed to decode Proxmark3 JSON file"},
		{
			name: "invalid JSON syntax", input: `{"Created": "proxmark3",}`, wantMsg: "failed to decode Proxmark3 JSON file",
			wantErr: isSyntaxErr,
		},
		{
			name: "root is an array", input: `[]`, wantMsg: "failed to decode Proxmark3 JSON file",
			wantErr: isTypeErr,
		},
		{
			name: "blocks is an array", input: `{"Created":"proxmark3","FileType":"mfcard","blocks":["00"]}`,
			wantMsg: "failed to decode Proxmark3 JSON file",
			wantErr: isTypeErr,
		},
		{name: "Created missing", input: strings.Replace(valid, `"Created": "proxmark3",`, "", 1), wantMsg: "must be produced by Proxmark3"},
		{name: "Created from another tool", input: strings.Replace(valid, `"proxmark3"`, `"flipper"`, 1), wantMsg: "must be produced by Proxmark3"},
		{name: "Created is case sensitive", input: strings.Replace(valid, `"proxmark3"`, `"Proxmark3"`, 1), wantMsg: "must be produced by Proxmark3"},
		{name: "FileType missing", input: strings.Replace(valid, `"FileType": "mfcard",`, "", 1), wantMsg: "expecting Mifare card dump"},
		{name: "FileType of another card family", input: strings.Replace(valid, `"mfcard"`, `"mfu"`, 1), wantMsg: "expecting Mifare card dump"},
		{name: "FileType raw", input: strings.Replace(valid, `"mfcard"`, `"raw"`, 1), wantMsg: "expecting Mifare card dump"},
		{
			name: "UID is not hex", input: strings.Replace(valid, `"11223344"`, `"1122334G"`, 1), wantMsg: "cannot parse card UID",
			wantErr: isInvalidByte,
		},
		{
			name: "UID has odd length", input: strings.Replace(valid, `"11223344"`, `"1122334"`, 1), wantMsg: "cannot parse card UID",
			wantErr: func(err error) bool { return errors.Is(err, hex.ErrLength) },
		},
		{name: "UID contains spaces", input: strings.Replace(valid, `"11223344"`, `"11 22 33 44"`, 1), wantMsg: "cannot parse card UID"},
		{name: "ATQA is not hex", input: strings.Replace(valid, `"0400"`, `"04XX"`, 1), wantMsg: "cannot parse card ATQA"},
		{name: "SAK is not hex", input: strings.Replace(valid, `"SAK": "08"`, `"SAK": "0x"`, 1), wantMsg: "cannot parse card SAK"},
		{
			name:    "block is not hex",
			input:   pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(blocks, 5, strings.Repeat("ZZ", 16)), false),
			wantMsg: "cannot parse block 5 data",
			wantErr: isInvalidByte,
		},
		{
			name:    "block has odd length",
			input:   pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(blocks, 63, strings.Repeat("0", 31)), false),
			wantMsg: "cannot parse block 63 data",
			wantErr: func(err error) bool { return errors.Is(err, hex.ErrLength) },
		},
		{
			name:    "block index missing",
			input:   strings.Replace(valid, `"10": "`, `"64": "`, 1),
			wantMsg: "cannot find Mifare card data for block 10",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			card, err := parseProxmark3JSON(strings.NewReader(tt.input))
			if err == nil {
				t.Fatalf("parseProxmark3JSON() = %+v, want an error containing %q", card, tt.wantMsg)
			}
			if card != nil {
				t.Errorf("parseProxmark3JSON() returned a card together with error %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantMsg)
			}
			if tt.wantErr != nil && !tt.wantErr(err) {
				t.Errorf("error %q (%T) does not wrap the expected cause", err, errors.Unwrap(err))
			}
		})
	}
}

func TestRenderNFC_Golden(t *testing.T) {
	t.Parallel()

	for _, tt := range conversionCases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			card, _, err := parseProxMark3JSONFile(tt.fixture)
			if err != nil {
				t.Fatalf("parse %s: %v", tt.fixture, err)
			}
			assertSameText(t, tt.golden, renderNFC(card), readFile(t, tt.golden))
		})
	}
}

func TestRenderNFC_Header(t *testing.T) {
	t.Parallel()

	card := &mifareCard{
		UID:    hexData{0xDE, 0xAD, 0xBE, 0xEF},
		ATQA:   hexData{0x04, 0x00},
		SAK:    hexData{0x08},
		Blocks: make([]hexData, 64),
	}
	for i := range card.Blocks {
		card.Blocks[i] = make(hexData, 16)
	}

	got := string(renderNFC(card))

	// Flipper NFC file format version 2, MIFARE Classic data format version 2.
	// ATQA is written in the order Proxmark3 stores it, which is the order
	// version 2 expects (LSB first).
	wantHeader := "Filetype: Flipper NFC device\n" +
		"Version: 2\n" +
		"# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card\n" +
		"Device type: Mifare Classic\n" +
		"# UID, ATQA and SAK are common for all formats\n" +
		"UID: DE AD BE EF\n" +
		"ATQA: 04 00\n" +
		"SAK: 08\n" +
		"# Mifare Classic specific data\n" +
		"Mifare Classic type: 1K\n" +
		"Data format version: 2\n" +
		"# Mifare Classic blocks, '??' means unknown data\n" +
		"Block 0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00\n"
	if !strings.HasPrefix(got, wantHeader) {
		t.Errorf("renderNFC() header mismatch\n got: %q\nwant: %q", firstLines(got, 13), wantHeader)
	}
	if strings.Contains(got, "\r") {
		t.Error("output contains carriage returns, want LF line endings")
	}
}

func TestRenderNFC_CardType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		blocks int
		want   string
	}{
		{blocks: 64, want: "Mifare Classic type: 1K\n"},
		{blocks: 256, want: "Mifare Classic type: 4K\n"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(strconv.Itoa(tt.blocks)+" blocks", func(t *testing.T) {
			t.Parallel()
			card := &mifareCard{UID: hexData{1, 2, 3, 4}, ATQA: hexData{4, 0}, SAK: hexData{8}, Blocks: make([]hexData, tt.blocks)}
			for i := range card.Blocks {
				card.Blocks[i] = make(hexData, 16)
			}
			got := string(renderNFC(card))
			if !strings.Contains(got, tt.want) {
				t.Errorf("output does not contain %q", tt.want)
			}
			if n := strings.Count(got, "\nBlock "); n != tt.blocks {
				t.Errorf("output has %d block lines, want %d", n, tt.blocks)
			}
		})
	}
}

func TestRenderNFC_Deterministic(t *testing.T) {
	t.Parallel()

	card, _, err := parseProxMark3JSONFile(fixture4K)
	if err != nil {
		t.Fatal(err)
	}
	first := renderNFC(card)
	for i := 0; i < 5; i++ {
		again, _, err := parseProxMark3JSONFile(fixture4K)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, renderNFC(again)) {
			t.Fatalf("conversion %d differs from the first conversion", i+2)
		}
	}
}

// TestGoldenFiles checks the golden files themselves, independently of the
// converter: each one must satisfy the Flipper NFC version 2 MIFARE Classic
// layout and carry exactly the card described by its JSON fixture.
func TestGoldenFiles(t *testing.T) {
	t.Parallel()

	cases := append([]struct {
		name    string
		fixture string
		golden  string
	}{}, conversionCases...)
	cases = append(cases, struct {
		name    string
		fixture string
		golden  string
	}{name: "Mini (expected output)", fixture: fixtureMini, golden: expectedMini})

	for _, tt := range cases {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			nfc := parseFlipperV2(t, readFile(t, tt.golden))

			var doc struct {
				Card struct{ UID, ATQA, SAK string }
			}
			raw := readFile(t, tt.fixture)
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			assertBytes(t, "UID", nfc.uid, mustHex(t, doc.Card.UID))
			assertBytes(t, "ATQA", nfc.atqa, mustHex(t, doc.Card.ATQA))
			assertBytes(t, "SAK", nfc.sak, mustHex(t, doc.Card.SAK))

			want := fixtureBlocks(t, raw)
			if len(nfc.blocks) != len(want) {
				t.Fatalf("golden has %d blocks, fixture has %d", len(nfc.blocks), len(want))
			}
			for i := range want {
				if !bytes.Equal(nfc.blocks[i], want[i]) {
					t.Errorf("golden block %d = %X, fixture block %d = %X", i, nfc.blocks[i], i, want[i])
				}
			}
		})
	}
}

// FuzzParseProxmark3JSON checks that arbitrary input never panics the parser
// or the renderer, and that an accepted dump is rendered with every block.
func FuzzParseProxmark3JSON(f *testing.F) {
	for _, name := range []string{fixture1K, fixture1K7, fixtureV2, fixtureMini} {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"Created":"proxmark3","FileType":"mfcard","Card":{"UID":"","ATQA":"","SAK":""},"blocks":{"0":""}}`))
	f.Add([]byte(`{"Created":"proxmark3","FileType":"mfcard","blocks":{"0":"00","1":"0011"}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		card, err := parseProxmark3JSON(bytes.NewReader(data))
		if err != nil {
			return
		}
		if got := strings.Count(string(renderNFC(card)), "\nBlock "); got != len(card.Blocks) {
			t.Fatalf("output has %d block lines, card has %d blocks", got, len(card.Blocks))
		}
	})
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q in test: %v", s, err)
	}
	return b
}

func assertBytes(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s = %X, want %X", what, got, want)
	}
}

// assertSameText compares two text files line by line and reports the first
// differing line, which is far more readable than a byte dump of 256 blocks.
func assertSameText(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if bytes.Equal(got, want) {
		return
	}
	g := strings.Split(string(got), "\n")
	w := strings.Split(string(want), "\n")
	for i := 0; i < len(g) || i < len(w); i++ {
		var gl, wl string
		if i < len(g) {
			gl = g[i]
		}
		if i < len(w) {
			wl = w[i]
		}
		if gl != wl {
			t.Fatalf("output differs from %s at line %d\n got: %q\nwant: %q", name, i+1, gl, wl)
		}
	}
	t.Fatalf("output differs from %s", name)
}

func firstLines(s string, n int) string {
	lines := strings.SplitAfterN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "")
}

// fixtureBlocks decodes the "blocks" object of a Proxmark3 JSON document
// without going through the parser under test.
func fixtureBlocks(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var doc struct {
		Blocks map[string]string `json:"blocks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	blocks := make([][]byte, len(doc.Blocks))
	for k, v := range doc.Blocks {
		i, err := strconv.Atoi(k)
		if err != nil || i < 0 || i >= len(blocks) {
			t.Fatalf("fixture block key %q is not a dense index", k)
		}
		blocks[i] = mustHex(t, v)
	}
	return blocks
}

// pm3JSON builds a Proxmark3-style MIFARE Classic dump. With descending set the
// block keys are emitted from the highest index down.
func pm3JSON(fileType, uid, atqa, sak string, blocks []string, descending bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "{\n  \"Created\": \"proxmark3\",\n  \"FileType\": %q,\n", fileType)
	fmt.Fprintf(&sb, "  \"Card\": {\n    \"UID\": %q,\n    \"ATQA\": %q,\n    \"SAK\": %q\n  },\n", uid, atqa, sak)
	sb.WriteString("  \"blocks\": {\n")
	for n := range blocks {
		i := n
		if descending {
			i = len(blocks) - 1 - n
		}
		sep := ","
		if n == len(blocks)-1 {
			sep = ""
		}
		fmt.Fprintf(&sb, "    \"%d\": %q%s\n", i, blocks[i], sep)
	}
	sb.WriteString("  }\n}\n")
	return sb.String()
}

func replaceBlock(blocks []string, i int, value string) []string {
	out := append([]string(nil), blocks...)
	out[i] = value
	return out
}

type flipperV2File struct {
	uid, atqa, sak []byte
	cardType       string
	blocks         [][]byte
}

var (
	hexByteList  = `[0-9A-F]{2}(?: [0-9A-F]{2})*`
	reUID        = regexp.MustCompile(`^UID: (` + hexByteList + `)$`)
	reATQA       = regexp.MustCompile(`^ATQA: ([0-9A-F]{2} [0-9A-F]{2})$`)
	reSAK        = regexp.MustCompile(`^SAK: ([0-9A-F]{2})$`)
	reBlock      = regexp.MustCompile(`^Block (\d+): ((?:[0-9A-F]{2}|\?\?)(?: (?:[0-9A-F]{2}|\?\?)){15})$`)
	blocksByType = map[string]int{"MINI": 20, "1K": 64, "4K": 256}
)

// parseFlipperV2 is a strict reader for the subset of the Flipper NFC format
// this tool emits: file format version 2, device type "Mifare Classic", MIFARE
// Classic data format version 2. It fails the test on any deviation, including
// a block count that does not match the declared card type, so it can be used
// both to review golden files and to judge converter output.
func parseFlipperV2(t *testing.T, data []byte) flipperV2File {
	t.Helper()
	text := string(data)
	if !strings.HasSuffix(text, "\n") {
		t.Fatal("file does not end with a newline")
	}
	if strings.Contains(text, "\r") {
		t.Fatal("file contains carriage returns")
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	fixed := []string{"Filetype: Flipper NFC device", "Version: 2", "Device type: Mifare Classic"}
	if len(lines) < 8 {
		t.Fatalf("file has %d non-comment lines, want at least 8", len(lines))
	}
	for i, want := range fixed {
		if lines[i] != want {
			t.Fatalf("line %q, want %q", lines[i], want)
		}
	}

	var f flipperV2File
	m := reUID.FindStringSubmatch(lines[3])
	if m == nil {
		t.Fatalf("malformed UID line %q", lines[3])
	}
	f.uid = spacedHex(t, m[1])
	if n := len(f.uid); n != 4 && n != 7 && n != 10 {
		t.Fatalf("UID has %d bytes, want 4, 7 or 10", n)
	}
	if m = reATQA.FindStringSubmatch(lines[4]); m == nil {
		t.Fatalf("malformed ATQA line %q", lines[4])
	}
	f.atqa = spacedHex(t, m[1])
	if m = reSAK.FindStringSubmatch(lines[5]); m == nil {
		t.Fatalf("malformed SAK line %q", lines[5])
	}
	f.sak = spacedHex(t, m[1])

	const typePrefix = "Mifare Classic type: "
	typ := strings.TrimPrefix(lines[6], typePrefix)
	want, known := blocksByType[typ]
	if !strings.HasPrefix(lines[6], typePrefix) || !known {
		t.Fatalf("line %q, want a Mifare Classic type of MINI, 1K or 4K", lines[6])
	}
	f.cardType = typ
	if lines[7] != "Data format version: 2" {
		t.Fatalf("line %q, want %q", lines[7], "Data format version: 2")
	}

	blockLines := lines[8:]
	if len(blockLines) != want {
		t.Fatalf("file has %d block lines, %s needs %d", len(blockLines), typ, want)
	}
	for i, l := range blockLines {
		m := reBlock.FindStringSubmatch(l)
		if m == nil {
			t.Fatalf("malformed block line %q", l)
		}
		if m[1] != strconv.Itoa(i) {
			t.Fatalf("block line %q is out of order, want block %d", l, i)
		}
		if strings.Contains(m[2], "??") {
			t.Fatalf("block %d has unknown bytes, which this tool never writes", i)
		}
		f.blocks = append(f.blocks, spacedHex(t, m[2]))
	}
	return f
}

func spacedHex(t *testing.T, s string) []byte {
	t.Helper()
	return mustHex(t, strings.ReplaceAll(s, " ", ""))
}
