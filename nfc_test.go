package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	fixture1K   = "testdata/proxmark3/mfcard-1k-uid4.json"
	fixture1K7  = "testdata/proxmark3/mfcard-1k-uid7.json"
	fixture4K   = "testdata/proxmark3/mfcard-4k-uid4.json"
	fixtureV2   = "testdata/proxmark3/mfc-v2-1k-uid4.json"
	fixtureV3   = "testdata/proxmark3/mfc-v3-1k-uid4.json"
	fixtureMini = "testdata/proxmark3/mfcard-mini-uid4.json"
	fixture2K   = "testdata/proxmark3/mfcard-2k-uid4.json"
	golden1K    = "testdata/flipper/mfc-1k-uid4.nfc"
	golden1K7   = "testdata/flipper/mfc-1k-uid7.nfc"
	golden4K    = "testdata/flipper/mfc-4k-uid4.nfc"
	goldenMini  = "testdata/flipper/mfc-mini-uid4.nfc"

	// warningV3 is printed when an "mfc v3" dump's extra fields are dropped.
	warningV3 = "warning: Card.ATS and Card.SIGNATURE cannot be stored in a Flipper MIFARE Classic file and were not converted\n"
)

// conversionCases are the supported conversions. The 1K and 4K golden files
// predate the parser rewrite and must stay byte-for-byte identical; the "mfc
// v2" and "mfc v3" fixtures hold the same card as fixture1K.
var conversionCases = []struct {
	name    string
	fixture string
	golden  string
	stderr  string // expected diagnostics of a successful conversion
}{
	{name: "1K with 4-byte UID", fixture: fixture1K, golden: golden1K},
	{name: "1K with 7-byte UID", fixture: fixture1K7, golden: golden1K7},
	{name: "4K with 4-byte UID", fixture: fixture4K, golden: golden4K},
	{name: "Mini", fixture: fixtureMini, golden: goldenMini},
	{name: "mfc v2", fixture: fixtureV2, golden: golden1K},
	{name: "mfc v3", fixture: fixtureV3, golden: golden1K, stderr: warningV3},
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

// An independent check against the MIFARE Classic 4K example in the Flipper
// NFC format documentation (pinned in docs/audit-and-compatibility.md):
// https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/documentation/file_formats/NfcFileFormats.md
// The example is a version 4 file, so its ATQA is MSB first ("00 02"); block 0
// carries the same ATQA LSB first ("02 00"), which is where Proxmark3 takes
// the JSON ATQA from. Blocks the example elides ("...") are filled with the
// pattern the example shows; only the listed lines are compared.
func TestRenderNFC_FlipperDocumentationExample(t *testing.T) {
	t.Parallel()

	const zero = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
	const trailer = "FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF"
	listed := map[int]string{
		0: "BA E2 7C 9D B9 18 02 00 46 44 53 37 30 56 30 31",
		1: zero, 2: zero, 3: trailer, 4: zero, 5: zero, 6: zero, 7: trailer,
		238: zero, 239: trailer, 255: trailer,
	}
	for i := 240; i < 255; i++ {
		listed[i] = zero
	}
	var blocks []string
	for i := 0; i < 256; i++ {
		line, ok := listed[i]
		if !ok {
			line = zero // elided in the example
			if i < 128 && i%4 == 3 || i >= 128 && (i-128)%16 == 15 {
				line = trailer
			}
		}
		blocks = append(blocks, strings.ReplaceAll(line, " ", ""))
	}
	block0 := mustHex(t, blocks[0])
	atqa := hex.EncodeToString(block0[6:8]) // as pm3_save_mf_dump derives it
	card, err := parseProxmark3JSON(strings.NewReader(pm3JSON("mfc v2", "BAE27C9D", atqa, "18", blocks, false)))
	if err != nil {
		t.Fatal(err)
	}
	out := string(renderNFC(card))

	// Version 2 stores ATQA LSB first: the reverse of the example's "00 02".
	for _, want := range []string{"UID: BA E2 7C 9D\n", "ATQA: 02 00\n", "SAK: 18\n", "Mifare Classic type: 4K\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not contain %q", want)
		}
	}
	for i, line := range listed {
		if want := fmt.Sprintf("\nBlock %d: %s\n", i, line); !strings.Contains(out, want) {
			t.Errorf("output does not contain %q", strings.TrimSpace(want))
		}
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
		Type:   "1K",
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
		blocks   int
		cardType string
		want     string
	}{
		{blocks: 20, cardType: "MINI", want: "Mifare Classic type: MINI\n"},
		{blocks: 64, cardType: "1K", want: "Mifare Classic type: 1K\n"},
		{blocks: 256, cardType: "4K", want: "Mifare Classic type: 4K\n"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(strconv.Itoa(tt.blocks)+" blocks", func(t *testing.T) {
			t.Parallel()
			card := &mifareCard{UID: hexData{1, 2, 3, 4}, ATQA: hexData{4, 0}, SAK: hexData{8}, Type: tt.cardType, Blocks: make([]hexData, tt.blocks)}
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

	for _, tt := range conversionCases {
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
