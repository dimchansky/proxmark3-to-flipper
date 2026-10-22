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
	"strconv"
	"strings"
	"testing"
)

// The tests in this file assert the conversion contract described in
// docs/audit-and-compatibility.md. Behavior that is known to be wrong and not
// fixed yet is captured by the intended-behavior tests in main_defects_test.go,
// which are built only with -tags knowndefects and currently fail.

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

	blocks := zeroBlocks(64)
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
				`"Card": {`, `"Extra": {"nested": [1, {"a": 2}, [3]]}, "Card": {"Other": "x",`, 1),
			check: func(t *testing.T, c *mifareCard) {
				t.Helper()
				assertBytes(t, "UID", c.UID, []byte{0x11, 0x22, 0x33, 0x44})
				if len(c.Dropped) != 0 {
					t.Errorf("Dropped = %q, want none", c.Dropped)
				}
			},
		},
		{
			name:  "mfc v2",
			input: pm3JSON("mfc v2", "11223344", "0400", "08", blocks, false),
			check: func(t *testing.T, c *mifareCard) { t.Helper(); assertType(t, c, "1K", 64) },
		},
		{
			name:  "mfc v3 drops ATS and SIGNATURE",
			input: strings.Replace(pm3JSON("mfc v3", "11223344", "0400", "08", blocks, false), `"SAK": "08"`, `"SAK": "08", "ATS": "00", "SIGNATURE": "`+strings.Repeat("00", 32)+`"`, 1),
			check: func(t *testing.T, c *mifareCard) {
				t.Helper()
				if strings.Join(c.Dropped, ",") != "Card.ATS,Card.SIGNATURE" {
					t.Errorf("Dropped = %q, want Card.ATS and Card.SIGNATURE", c.Dropped)
				}
			},
		},
		{
			name:  "empty ATS is not reported",
			input: strings.Replace(pm3JSON("mfc v3", "11223344", "0400", "08", blocks, false), `"SAK": "08"`, `"SAK": "08", "ATS": ""`, 1),
			check: func(t *testing.T, c *mifareCard) {
				t.Helper()
				if len(c.Dropped) != 0 {
					t.Errorf("Dropped = %q, want none", c.Dropped)
				}
			},
		},
		{
			name:  "7-byte UID",
			input: pm3JSON("mfcard", "04112233445566", "4400", "08", blocks, false),
			check: func(t *testing.T, c *mifareCard) { t.Helper(); assertType(t, c, "1K", 64) },
		},
		{
			name:  "10-byte UID",
			input: pm3JSON("mfcard", "04112233445566778899", "4400", "08", blocks, false),
			check: func(t *testing.T, c *mifareCard) { t.Helper(); assertType(t, c, "1K", 64) },
		},
		{
			name:  "Mini",
			input: pm3JSON("mfcard", "11223344", "0400", "09", zeroBlocks(20), false),
			check: func(t *testing.T, c *mifareCard) { t.Helper(); assertType(t, c, "MINI", 20) },
		},
		{
			name:  "4K",
			input: pm3JSON("mfcard", "11223344", "0200", "18", zeroBlocks(256), false),
			check: func(t *testing.T, c *mifareCard) { t.Helper(); assertType(t, c, "4K", 256) },
		},
		{
			name:  "all-zero data is kept as is",
			input: pm3JSON("mfcard", "11223344", "0400", "08", zeroBlocks(64), false),
			check: func(t *testing.T, c *mifareCard) {
				t.Helper()
				assertBytes(t, "block 3", c.Blocks[3], make([]byte, 16))
			},
		},
		{
			name:  "whitespace after the document",
			input: pm3JSON("mfcard", "11223344", "0400", "08", blocks, false) + " \n\t\r\n",
			check: func(t *testing.T, c *mifareCard) { t.Helper(); assertType(t, c, "1K", 64) },
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

	blocks := zeroBlocks(64)
	valid := pm3JSON("mfcard", "11223344", "0400", "08", blocks, false)
	withBlock := func(i int, value string) string {
		return pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(blocks, i, value), false)
	}
	withCard := func(uid, atqa, sak string) string {
		return pm3JSON("mfcard", uid, atqa, sak, blocks, false)
	}

	// errors.As targets are declared per call: the subtests run in parallel.
	isSyntaxErr := func(err error) bool { var e *json.SyntaxError; return errors.As(err, &e) }
	isTypeErr := func(err error) bool { var e *json.UnmarshalTypeError; return errors.As(err, &e) }
	isInvalidByte := func(err error) bool { var e hex.InvalidByteError; return errors.As(err, &e) }
	isErrLength := func(err error) bool { return errors.Is(err, hex.ErrLength) }

	tests := []struct {
		name    string
		input   string
		wantMsg string
		wantErr func(error) bool
	}{
		// JSON syntax and structure.
		{name: "empty input", input: "", wantMsg: "failed to decode Proxmark3 JSON file"},
		{name: "truncated JSON", input: valid[:len(valid)/2], wantMsg: "failed to decode Proxmark3 JSON file"},
		{name: "invalid JSON syntax", input: `{"Created": "proxmark3",}`, wantMsg: "failed to decode Proxmark3 JSON file at byte offset 25", wantErr: isSyntaxErr},
		{name: "root is an array", input: `[]`, wantMsg: "failed to decode Proxmark3 JSON file", wantErr: isTypeErr},
		{name: "root is null", input: `null`, wantMsg: "must be produced by Proxmark3"},
		{name: "blocks is an array", input: `{"Created":"proxmark3","FileType":"mfcard","blocks":["00"]}`, wantMsg: "failed to decode Proxmark3 JSON file", wantErr: isTypeErr},
		{name: "block is a number", input: strings.Replace(valid, `"5": "`+strings.Repeat("00", 16)+`"`, `"5": 0`, 1), wantMsg: "failed to decode Proxmark3 JSON file", wantErr: isTypeErr},
		// D-09: exactly one document.
		{name: "trailing garbage", input: valid + "garbage", wantMsg: "failed to decode Proxmark3 JSON file", wantErr: isSyntaxErr},
		{name: "trailing closing brace", input: valid + "}", wantMsg: "failed to decode Proxmark3 JSON file", wantErr: isSyntaxErr},
		{name: "second document", input: valid + valid, wantMsg: "failed to decode Proxmark3 JSON file", wantErr: isSyntaxErr},
		// D-12: duplicate keys.
		{name: "duplicate block key", input: strings.Replace(valid, `"63": "`, `"5": "`+strings.Repeat("FF", 16)+`", "63": "`, 1), wantMsg: `duplicate key "5" in blocks`},
		{name: "duplicate blocks object", input: strings.Replace(valid, `"Card": {`, `"blocks": {}, "Card": {`, 1), wantMsg: `duplicate key "blocks" in the top-level value`},
		{name: "duplicate UID", input: strings.Replace(valid, `"UID": "11223344",`, `"UID": "11223344", "UID": "55667788",`, 1), wantMsg: `duplicate key "UID" in Card`},
		{name: "duplicate key differing in case", input: strings.Replace(valid, `"UID": "11223344",`, `"UID": "11223344", "uid": "55667788",`, 1), wantMsg: `duplicate key "uid" in Card`},
		{name: "duplicate key in ignored metadata", input: strings.Replace(valid, `"Card": {`, `"Extra": {"a": 1, "a": 2}, "Card": {`, 1), wantMsg: `duplicate key "a" in Extra`},
		// Metadata.
		{name: "Created missing", input: strings.Replace(valid, `"Created": "proxmark3",`, "", 1), wantMsg: "must be produced by Proxmark3"},
		{name: "Created from another tool", input: strings.Replace(valid, `"proxmark3"`, `"flipper"`, 1), wantMsg: "must be produced by Proxmark3"},
		{name: "Created is case sensitive", input: strings.Replace(valid, `"proxmark3"`, `"Proxmark3"`, 1), wantMsg: "must be produced by Proxmark3"},
		{name: "FileType missing", input: strings.Replace(valid, `"FileType": "mfcard",`, "", 1), wantMsg: `unsupported FileType ""`},
		{name: "FileType of another card family", input: strings.Replace(valid, `"mfcard"`, `"mfu"`, 1), wantMsg: `unsupported FileType "mfu"`},
		{name: "FileType raw", input: strings.Replace(valid, `"mfcard"`, `"raw"`, 1), wantMsg: `unsupported FileType "raw"`},
		{name: "FileType mfc v4", input: strings.Replace(valid, `"mfcard"`, `"mfc v4"`, 1), wantMsg: `unsupported FileType "mfc v4"`},
		// D-03: required card data.
		{name: "no Card and no blocks", input: `{"Created":"proxmark3","FileType":"mfcard"}`, wantMsg: "missing Card"},
		{name: "Card is null", input: `{"Created":"proxmark3","FileType":"mfcard","Card":null,"blocks":{}}`, wantMsg: "missing Card"},
		{name: "UID missing", input: strings.Replace(valid, `"UID": "11223344",`, "", 1), wantMsg: "missing Card.UID"},
		{name: "UID is null", input: strings.Replace(valid, `"UID": "11223344"`, `"UID": null`, 1), wantMsg: "missing Card.UID"},
		{name: "ATQA missing", input: strings.Replace(valid, `"ATQA": "0400",`, "", 1), wantMsg: "missing Card.ATQA"},
		{name: "SAK missing", input: strings.Replace(valid, `,
    "SAK": "08"`, "", 1), wantMsg: "missing Card.SAK"},
		{name: "blocks missing", input: `{"Created":"proxmark3","FileType":"mfcard","Card":{"UID":"11223344","ATQA":"0400","SAK":"08"}}`, wantMsg: "missing blocks"},
		{name: "blocks is null", input: `{"Created":"proxmark3","FileType":"mfcard","Card":{"UID":"11223344","ATQA":"0400","SAK":"08"},"blocks":null}`, wantMsg: "missing blocks"},
		{name: "blocks is empty", input: pm3JSON("mfcard", "11223344", "0400", "08", nil, false), wantMsg: "dump has no blocks"},
		// D-06: card identity lengths.
		{name: "empty UID", input: withCard("", "0400", "08"), wantMsg: "invalid Card.UID: 0 bytes, want 4, 7 or 10"},
		{name: "3-byte UID", input: withCard("112233", "0400", "08"), wantMsg: "invalid Card.UID: 3 bytes"},
		{name: "5-byte UID", input: withCard("1122334455", "0400", "08"), wantMsg: "invalid Card.UID: 5 bytes"},
		{name: "11-byte UID", input: withCard("1122334455667788990011", "0400", "08"), wantMsg: "invalid Card.UID: 11 bytes"},
		{name: "empty ATQA", input: withCard("11223344", "", "08"), wantMsg: "invalid Card.ATQA: 0 bytes, want 2"},
		{name: "1-byte ATQA", input: withCard("11223344", "04", "08"), wantMsg: "invalid Card.ATQA: 1 bytes, want 2"},
		{name: "3-byte ATQA", input: withCard("11223344", "040000", "08"), wantMsg: "invalid Card.ATQA: 3 bytes, want 2"},
		{name: "empty SAK", input: withCard("11223344", "0400", ""), wantMsg: "invalid Card.SAK: 0 bytes, want 1"},
		{name: "2-byte SAK", input: withCard("11223344", "0400", "0800"), wantMsg: "invalid Card.SAK: 2 bytes, want 1"},
		// Hex syntax.
		{name: "UID is not hex", input: withCard("1122334G", "0400", "08"), wantMsg: "invalid Card.UID: invalid hexadecimal character at offset 7", wantErr: isInvalidByte},
		{name: "UID has odd length", input: withCard("1122334", "0400", "08"), wantMsg: "invalid Card.UID: odd number of hexadecimal digits (7)", wantErr: isErrLength},
		{name: "UID contains spaces", input: withCard("11 22 33 44", "0400", "08"), wantMsg: "invalid Card.UID: invalid hexadecimal character at offset 2", wantErr: isInvalidByte},
		{name: "UID has a 0x prefix", input: withCard("0x11223344", "0400", "08"), wantMsg: "invalid Card.UID: invalid hexadecimal character at offset 1", wantErr: isInvalidByte},
		{name: "ATQA is not hex", input: withCard("11223344", "04XX", "08"), wantMsg: "invalid Card.ATQA: invalid hexadecimal character at offset 2", wantErr: isInvalidByte},
		{name: "SAK is not hex", input: withCard("11223344", "0400", "0x"), wantMsg: "invalid Card.SAK: invalid hexadecimal character at offset 1", wantErr: isInvalidByte},
		{name: "block is not hex", input: withBlock(5, strings.Repeat("ZZ", 16)), wantMsg: "invalid block 5: invalid hexadecimal character at offset 0", wantErr: isInvalidByte},
		{name: "block has odd length", input: withBlock(63, strings.Repeat("0", 31)), wantMsg: "invalid block 63: odd number of hexadecimal digits (31)", wantErr: isErrLength},
		// D-05: block lengths.
		{name: "empty block", input: withBlock(9, ""), wantMsg: "invalid block 9: 0 bytes, want 16"},
		{name: "1-byte block", input: withBlock(9, "00"), wantMsg: "invalid block 9: 1 bytes, want 16"},
		{name: "15-byte block", input: withBlock(9, strings.Repeat("00", 15)), wantMsg: "invalid block 9: 15 bytes, want 16"},
		{name: "17-byte block", input: withBlock(9, strings.Repeat("00", 17)), wantMsg: "invalid block 9: 17 bytes, want 16"},
		{name: "32-byte block", input: withBlock(0, strings.Repeat("00", 32)), wantMsg: "invalid block 0: 32 bytes, want 16"},
		// D-18: block indices.
		{name: "block index missing", input: strings.Replace(valid, `"10": "`, `"64": "`, 1), wantMsg: "missing block 10"},
		{name: "last block index missing", input: strings.Replace(valid, `"63": "`, `"64": "`, 1), wantMsg: "missing block 63"},
		{name: "non-numeric block index", input: strings.Replace(valid, `"63": "`, `"foo": "00", "63": "`, 1), wantMsg: `invalid block index "foo"`},
		{name: "block index with leading zero", input: strings.Replace(valid, `"7": "`, `"07": "`, 1), wantMsg: `invalid block index "07"`},
		{name: "negative block index", input: strings.Replace(valid, `"7": "`, `"-7": "`, 1), wantMsg: `invalid block index "-7"`},
		{name: "block index with plus sign", input: strings.Replace(valid, `"7": "`, `"+7": "`, 1), wantMsg: `invalid block index "+7"`},
		{name: "block index with space", input: strings.Replace(valid, `"7": "`, `" 7": "`, 1), wantMsg: `invalid block index " 7"`},
		{name: "fractional block index", input: strings.Replace(valid, `"7": "`, `"7.0": "`, 1), wantMsg: `invalid block index "7.0"`},
	}
	// D-04: only complete Mini, 1K and 4K dumps.
	for _, n := range []int{1, 19, 21, 63, 65, 127, 129, 255, 257} {
		tests = append(tests, struct {
			name    string
			input   string
			wantMsg string
			wantErr func(error) bool
		}{
			name:    fmt.Sprintf("%d blocks", n),
			input:   pm3JSON("mfcard", "11223344", "0400", "08", zeroBlocks(n), false),
			wantMsg: fmt.Sprintf("unsupported number of blocks: %d", n),
		})
	}
	tests = append(tests, struct {
		name    string
		input   string
		wantMsg string
		wantErr func(error) bool
	}{name: "2K", input: string(readFile(t, fixture2K)), wantMsg: "MIFARE Classic 2K dumps (128 blocks) are not supported"})

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

// Regression test for D-15: diagnostics describe a bad value by field,
// position and length but never repeat it, because it may be a sector key.
func TestParseProxmark3JSON_ErrorsDoNotLeakData(t *testing.T) {
	t.Parallel()

	const secret = "A1B2C3D4E5F6" // stands for a 6-byte sector key
	trailer := secret + "FF078069" + secret
	blocks := zeroBlocks(64)
	tests := []struct {
		name  string
		input string
	}{
		{name: "invalid character at the end", input: pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(blocks, 3, trailer[:31]+"Z"), false)},
		{name: "invalid character at the start", input: pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(blocks, 3, "Z"+trailer[1:]), false)},
		{name: "odd length", input: pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(blocks, 3, trailer+"0"), false)},
		{name: "too short", input: pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(blocks, 3, trailer[:30]), false)},
		{name: "too long", input: pm3JSON("mfcard", "11223344", "0400", "08", replaceBlock(blocks, 3, trailer+"00"), false)},
		{name: "invalid UID", input: pm3JSON("mfcard", secret+"Z", "0400", "08", blocks, false)},
		{name: "UID too long", input: pm3JSON("mfcard", secret+secret, "0400", "08", blocks, false)},
		{name: "duplicate trailer", input: strings.Replace(pm3JSON("mfcard", "11223344", "0400", "08", blocks, false), `"63": "`, `"3": "`+trailer+`", "63": "`, 1)},
		{name: "wrong card size", input: pm3JSON("mfcard", "11223344", "0400", "08", append(replaceBlock(blocks, 3, trailer), trailer), false)},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseProxmark3JSON(strings.NewReader(tt.input))
			if err == nil {
				t.Fatal("parseProxmark3JSON() error = nil, want an error")
			}
			msg := strings.ToUpper(err.Error())
			if strings.Contains(msg, secret[:8]) || strings.Contains(msg, "FF078069") {
				t.Errorf("error %q repeats card data", err)
			}
		})
	}
}

// Regression test for D-14: input is read through a bounded reader.
func TestParseProxmark3JSON_SizeLimit(t *testing.T) {
	t.Parallel()

	doc := pm3JSON("mfcard", "11223344", "0400", "08", zeroBlocks(64), false)
	pad := func(n int) string { return doc + strings.Repeat(" ", n-len(doc)) }

	t.Run("exactly the limit is accepted", func(t *testing.T) {
		t.Parallel()
		if _, err := parseProxmark3JSON(strings.NewReader(pad(maxInputSize))); err != nil {
			t.Fatalf("parseProxmark3JSON() error = %v", err)
		}
	})
	t.Run("one byte over the limit is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := parseProxmark3JSON(strings.NewReader(pad(maxInputSize + 1)))
		if err == nil || !strings.Contains(err.Error(), "input is larger than 1048576 bytes") {
			t.Fatalf("parseProxmark3JSON() error = %v, want a size error", err)
		}
	})
	t.Run("an endless input is not read to the end", func(t *testing.T) {
		t.Parallel()
		r := &countingReader{}
		if _, err := parseProxmark3JSON(r); err == nil {
			t.Fatal("parseProxmark3JSON() error = nil, want a size error")
		}
		if r.n > maxInputSize+1 {
			t.Errorf("read %d bytes, want at most %d", r.n, maxInputSize+1)
		}
	})
	t.Run("the largest realistic dump fits", func(t *testing.T) {
		t.Parallel()
		// A 4K fixture with long access-condition texts, as Proxmark3 writes,
		// stays far below the limit.
		if n := len(readFile(t, fixture4K)); n*16 > maxInputSize {
			t.Errorf("4K fixture is %d bytes; the limit leaves less than 16x headroom", n)
		}
	})
}

// countingReader yields spaces forever and counts the bytes it returned.
type countingReader struct{ n int }

func (r *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.n += len(p)
	return len(p), nil
}

// The 4K layout changes at block 128: sectors 0-31 have 4 blocks, sectors
// 32-39 have 16. The converter keeps blocks as a flat list, so the trailers of
// the large sectors must stay at blocks 143, 159, …, 255.
func TestParseProxmark3JSON_4KLayout(t *testing.T) {
	t.Parallel()

	card, _, err := parseProxMark3JSONFile(fixture4K)
	if err != nil {
		t.Fatal(err)
	}
	trailer := func(sector byte) []byte {
		return []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, sector, 0xFF, 0x07, 0x80, 0x69, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, sector}
	}
	for i := 1; i < 256; i++ {
		var want []byte
		switch {
		case i < 128 && i%4 == 3:
			want = trailer(byte(i / 4))
		case i >= 128 && (i-128)%16 == 15:
			want = trailer(byte(32 + (i-128)/16))
		default:
			want = make([]byte, 16)
			for j := range want {
				want[j] = byte(i + j) //nolint:gosec // wraps at 256, like the fixture pattern
			}
		}
		assertBytes(t, fmt.Sprintf("block %d", i), card.Blocks[i], want)
	}
}

// FuzzParseProxmark3JSON checks that arbitrary input never panics, and that
// every accepted dump satisfies the card model and renders to a Flipper file
// that a strict reader parses back to the same card.
func FuzzParseProxmark3JSON(f *testing.F) {
	for _, name := range []string{fixture1K, fixture1K7, fixtureV2, fixtureV3, fixtureMini} {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(`{"Created":"proxmark3","FileType":"mfcard","Card":{"UID":"","ATQA":"","SAK":""},"blocks":{"0":""}}`))
	f.Add([]byte(`{"Created":"proxmark3","FileType":"mfcard","blocks":{"0":"00","1":"0011"}}`))
	f.Add([]byte(pm3JSON("mfc v2", "04112233445566778899", "4400", "08", zeroBlocks(20), true)))

	f.Fuzz(func(t *testing.T, data []byte) {
		card, err := parseProxmark3JSON(bytes.NewReader(data))
		if err != nil {
			if card != nil {
				t.Fatalf("card returned together with error %v", err)
			}
			return
		}
		if n := len(card.UID); n != 4 && n != 7 && n != 10 {
			t.Fatalf("accepted a %d-byte UID", n)
		}
		if len(card.ATQA) != 2 || len(card.SAK) != 1 {
			t.Fatalf("accepted ATQA %d bytes, SAK %d bytes", len(card.ATQA), len(card.SAK))
		}
		if want, ok := cardTypes[len(card.Blocks)]; !ok || want != card.Type {
			t.Fatalf("accepted %d blocks as type %q", len(card.Blocks), card.Type)
		}
		for i, b := range card.Blocks {
			if len(b) != 16 {
				t.Fatalf("accepted block %d with %d bytes", i, len(b))
			}
		}
		nfc := parseFlipperV2(t, renderNFC(card))
		assertBytes(t, "UID", nfc.uid, card.UID)
		assertBytes(t, "ATQA", nfc.atqa, card.ATQA)
		assertBytes(t, "SAK", nfc.sak, card.SAK)
		if nfc.cardType != card.Type {
			t.Fatalf("rendered type %q, card type %q", nfc.cardType, card.Type)
		}
		for i := range card.Blocks {
			assertBytes(t, fmt.Sprintf("block %d", i), nfc.blocks[i], card.Blocks[i])
		}
	})
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

// zeroBlocks returns n all-zero 16-byte blocks in Proxmark3 hex form.
func zeroBlocks(n int) []string {
	blocks := make([]string, n)
	for i := range blocks {
		blocks[i] = strings.Repeat("00", 16)
	}
	return blocks
}

func assertType(t *testing.T, c *mifareCard, cardType string, blocks int) {
	t.Helper()
	if c.Type != cardType || len(c.Blocks) != blocks {
		t.Errorf("card is %q with %d blocks, want %q with %d", c.Type, len(c.Blocks), cardType, blocks)
	}
}

func replaceBlock(blocks []string, i int, value string) []string {
	out := append([]string(nil), blocks...)
	out[i] = value
	return out
}
