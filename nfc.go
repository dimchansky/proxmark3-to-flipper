package main

import (
	"bytes"
	"fmt"
	"strings"
)

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
