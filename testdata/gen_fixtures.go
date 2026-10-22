//go:build ignore

// gen_fixtures regenerates the synthetic Proxmark3 JSON fixtures and the
// expected Flipper NFC files in this directory.
//
// Every card is synthetic: UIDs, manufacturer bytes, keys and data blocks are
// generated from fixed patterns and do not come from a real card. Sector keys
// follow the pattern AA AA AA AA AA <sector> (key A) and BB BB BB BB BB <sector>
// (key B) so that a misplaced sector trailer is easy to spot.
//
// The expected NFC files are rendered from the same card model as the JSON
// inputs, by a writer that follows the Flipper NFC file format version 2 and
// MIFARE Classic data format version 2 (see docs/audit-and-compatibility.md).
// The writer below shares no code with the converter under test, so a golden
// file is an independent statement of the expected output, not a snapshot of
// the converter.
//
// Usage, from the repository root:
//
//	go run testdata/gen_fixtures.go
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type card struct {
	uid       []byte
	atqa      []byte // ISO/IEC 14443-3 wire order (LSB first), as Proxmark3 stores it
	sak       byte
	manuf     []byte // manufacturer bytes that fill the rest of block 0
	blocks    int
	flipper   string // value of "Mifare Classic type", empty if not representable
	signature []byte // only written for "mfc v3"
}

type fixture struct {
	json     string // file name under testdata/proxmark3
	fileType string
	card     card
	nfc      string // file name under testdata/flipper, empty if no expected output
}

var (
	uid4    = []byte{0x11, 0x22, 0x33, 0x44}
	uid4k   = []byte{0xA0, 0xA1, 0xA2, 0xA3}
	uid7    = []byte{0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	manuf4  = []byte("SYNTHFIX")
	manuf7  = []byte("SYNFIX")
	card1K  = card{uid: uid4, atqa: []byte{0x04, 0x00}, sak: 0x08, manuf: manuf4, blocks: 64, flipper: "1K"}
	card1K7 = card{uid: uid7, atqa: []byte{0x44, 0x00}, sak: 0x08, manuf: manuf7, blocks: 64, flipper: "1K"}
	card4K  = card{uid: uid4k, atqa: []byte{0x02, 0x00}, sak: 0x18, manuf: manuf4, blocks: 256, flipper: "4K"}
	cardMin = card{uid: uid4, atqa: []byte{0x04, 0x00}, sak: 0x09, manuf: manuf4, blocks: 20, flipper: "MINI"}
	card2K  = card{uid: uid4, atqa: []byte{0x04, 0x00}, sak: 0x19, manuf: manuf4, blocks: 128}
)

var fixtures = []fixture{
	{json: "mfcard-1k-uid4.json", fileType: "mfcard", card: card1K, nfc: "mfc-1k-uid4.nfc"},
	{json: "mfcard-1k-uid7.json", fileType: "mfcard", card: card1K7, nfc: "mfc-1k-uid7.nfc"},
	{json: "mfcard-4k-uid4.json", fileType: "mfcard", card: card4K, nfc: "mfc-4k-uid4.nfc"},
	// Same card as mfcard-1k-uid4.json in the newer Proxmark3 file types.
	{json: "mfc-v2-1k-uid4.json", fileType: "mfc v2", card: card1K},
	{json: "mfc-v3-1k-uid4.json", fileType: "mfc v3", card: withSignature(card1K)},
	// Expected output for a converter that supports MIFARE Classic Mini.
	{json: "mfcard-mini-uid4.json", fileType: "mfcard", card: cardMin, nfc: "mfc-mini-uid4.expected.nfc"},
	// MIFARE Classic 2K has no Flipper representation.
	{json: "mfcard-2k-uid4.json", fileType: "mfcard", card: card2K},
}

func withSignature(c card) card {
	c.signature = make([]byte, 32)
	for i := range c.signature {
		c.signature[i] = byte(0xE0 + i%16)
	}
	return c
}

// isSectorTrailer reports whether block i is the last block of its sector.
// Sectors 0-31 have 4 blocks; sectors 32-39 (MIFARE Classic 4K only) have 16.
func isSectorTrailer(i int) bool {
	if i < 128 {
		return i%4 == 3
	}
	return (i-128)%16 == 15
}

func sectorOf(i int) int {
	if i < 128 {
		return i / 4
	}
	return 32 + (i-128)/16
}

func (c card) block(i int) []byte {
	b := make([]byte, 16)
	switch {
	case i == 0:
		n := copy(b, c.uid)
		if len(c.uid) == 4 {
			b[n] = c.uid[0] ^ c.uid[1] ^ c.uid[2] ^ c.uid[3] // BCC
			n++
		}
		b[n] = c.sak
		n++
		n += copy(b[n:], c.atqa)
		copy(b[n:], c.manuf)
	case isSectorTrailer(i):
		s := byte(sectorOf(i))
		copy(b[0:6], []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, s})
		copy(b[6:10], []byte{0xFF, 0x07, 0x80, 0x69})
		copy(b[10:16], []byte{0xBB, 0xBB, 0xBB, 0xBB, 0xBB, s})
	default:
		for j := range b {
			b[j] = byte(i + j)
		}
	}
	return b
}

func hexCompact(b []byte) string { return fmt.Sprintf("%X", b) }

func hexSpaced(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, " ")
}

// renderJSON mirrors the layout written by the Proxmark3 client: compact
// uppercase hex strings, blocks keyed by decimal index in ascending order and
// per-sector key material. AccessConditionsText is omitted because it is
// human-readable output that neither the converter nor the Proxmark3 loader
// reads.
func renderJSON(f fixture) string {
	c := f.card
	var sb strings.Builder
	sb.WriteString("{\n")
	sb.WriteString("  \"Created\": \"proxmark3\",\n")
	fmt.Fprintf(&sb, "  \"FileType\": %q,\n", f.fileType)
	sb.WriteString("  \"Card\": {\n")
	fmt.Fprintf(&sb, "    \"UID\": %q,\n", hexCompact(c.uid))
	fmt.Fprintf(&sb, "    \"ATQA\": %q,\n", hexCompact(c.atqa))
	if c.signature != nil {
		fmt.Fprintf(&sb, "    \"SAK\": %q,\n", hexCompact([]byte{c.sak}))
		fmt.Fprintf(&sb, "    \"ATS\": %q,\n", "00")
		fmt.Fprintf(&sb, "    \"SIGNATURE\": %q\n", hexCompact(c.signature))
	} else {
		fmt.Fprintf(&sb, "    \"SAK\": %q\n", hexCompact([]byte{c.sak}))
	}
	sb.WriteString("  },\n")
	sb.WriteString("  \"blocks\": {\n")
	for i := 0; i < c.blocks; i++ {
		sep := ","
		if i == c.blocks-1 {
			sep = ""
		}
		fmt.Fprintf(&sb, "    \"%d\": %q%s\n", i, hexCompact(c.block(i)), sep)
	}
	sb.WriteString("  },\n")
	sb.WriteString("  \"SectorKeys\": {\n")
	var trailers []int
	for i := 0; i < c.blocks; i++ {
		if isSectorTrailer(i) {
			trailers = append(trailers, i)
		}
	}
	for n, i := range trailers {
		b := c.block(i)
		sb.WriteString(fmt.Sprintf("    \"%d\": {\n", sectorOf(i)))
		fmt.Fprintf(&sb, "      \"KeyA\": %q,\n", hexCompact(b[0:6]))
		fmt.Fprintf(&sb, "      \"KeyB\": %q,\n", hexCompact(b[10:16]))
		fmt.Fprintf(&sb, "      \"AccessConditions\": %q\n", hexCompact(b[6:10]))
		if n == len(trailers)-1 {
			sb.WriteString("    }\n")
		} else {
			sb.WriteString("    },\n")
		}
	}
	sb.WriteString("  }\n")
	sb.WriteString("}\n")
	return sb.String()
}

// renderNFC writes a Flipper NFC file format version 2 MIFARE Classic file.
// Version 2 stores ATQA in the same byte order as Proxmark3 (LSB first); the
// comment lines are the ones written by Flipper firmware that used version 2.
func renderNFC(c card) string {
	var sb strings.Builder
	sb.WriteString("Filetype: Flipper NFC device\n")
	sb.WriteString("Version: 2\n")
	sb.WriteString("# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card\n")
	sb.WriteString("Device type: Mifare Classic\n")
	sb.WriteString("# UID, ATQA and SAK are common for all formats\n")
	fmt.Fprintf(&sb, "UID: %s\n", hexSpaced(c.uid))
	fmt.Fprintf(&sb, "ATQA: %s\n", hexSpaced(c.atqa))
	fmt.Fprintf(&sb, "SAK: %s\n", hexSpaced([]byte{c.sak}))
	sb.WriteString("# Mifare Classic specific data\n")
	fmt.Fprintf(&sb, "Mifare Classic type: %s\n", c.flipper)
	sb.WriteString("Data format version: 2\n")
	sb.WriteString("# Mifare Classic blocks, '??' means unknown data\n")
	for i := 0; i < c.blocks; i++ {
		fmt.Fprintf(&sb, "Block %d: %s\n", i, hexSpaced(c.block(i)))
	}
	return sb.String()
}

func main() {
	dir := "testdata"
	for _, f := range fixtures {
		write(filepath.Join(dir, "proxmark3", f.json), renderJSON(f))
		if f.nfc != "" {
			write(filepath.Join(dir, "flipper", f.nfc), renderNFC(f.card))
		}
	}
}

func write(path, content string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		log.Fatal(err)
	}
}
