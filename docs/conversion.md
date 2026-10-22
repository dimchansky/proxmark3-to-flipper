# Conversion contract

What `proxmark3-to-flipper` accepts, what it writes, and what it rejects. The
upstream research behind these rules, with pinned source links, is in
[audit-and-compatibility.md](audit-and-compatibility.md). How the output file is
written is described in [output-safety.md](output-safety.md).

No conversion has been validated on Flipper Zero or Proxmark3 hardware. The
rules below follow the upstream source code.

## Input

A single Proxmark3 MIFARE Classic JSON dump of at most 1 MiB.

| `FileType` | Written by | Accepted | Notes |
| --- | --- | --- | --- |
| `mfcard` | Proxmark3 client up to v4.17140 (2023-09) | yes | |
| `mfc v2` | Proxmark3 client v4.17511 (2023-11) and later | yes | same fields as `mfcard`; identical output |
| `mfc v3` | defined by the client, no producer found in its source | yes | `Card.ATS` and `Card.SIGNATURE` are dropped with a warning |
| anything else (`mfu`, `raw`, …) | | no | |

Required fields: `Created` equal to `proxmark3`, `FileType`, `Card.UID`,
`Card.ATQA`, `Card.SAK` and `blocks`. Other fields, including `SectorKeys` and
`AccessConditionsText`, are ignored: Proxmark3 derives them from the sector
trailers in `blocks`, and the trailers are what is converted.

| Field | Rule |
| --- | --- |
| `Card.UID` | 4, 7 or 10 bytes |
| `Card.ATQA` | 2 bytes, in the order Proxmark3 stores them (LSB first) |
| `Card.SAK` | 1 byte |
| `blocks` | object with keys `"0"` … `"n-1"`, decimal without sign or leading zeros; every value 16 bytes |
| hex values | an even number of hex digits, upper- or lowercase, no spaces or prefixes |

| Blocks | Card | Result |
| --- | --- | --- |
| 20 | MIFARE Classic Mini | `Mifare Classic type: MINI` |
| 64 | MIFARE Classic 1K | `Mifare Classic type: 1K` |
| 128 | MIFARE Classic 2K | rejected: Flipper has no 2K type |
| 256 | MIFARE Classic 4K | `Mifare Classic type: 4K` |
| any other | incomplete or unknown | rejected |

## Output

A Flipper NFC file, file format version 2, device type `Mifare Classic`,
MIFARE Classic data format version 2. UID, ATQA and SAK bytes are written as
they appear in the JSON. Version 2 expects ATQA LSB first, which is
Proxmark3's order, so no byte is swapped. All blocks are written in index
order, as uppercase hex bytes separated by single spaces.

Firmware notes (from the firmware source, not tested on devices):

- Version 2 files are read by every Flipper firmware since 2022. Firmware
  0.68.1 reads only version 2.
- `MINI` is not known to firmware 0.68.1.
- A 10-byte UID loads in current firmware, but not in 0.68.1 or 0.80.1, which
  accept 4 or 7 bytes only.

## Rejected input

Every rejection exits with status 1, prints one `error: …` line to stderr and
leaves the output path untouched, even with `-force`. Validation finishes
before any output file is opened.

- **Malformed JSON:** syntax errors (reported with the byte offset), a
  non-object root, wrong value types, or anything but whitespace after the
  document.
- **Duplicate keys:** any object containing a key twice. Keys are compared
  case-insensitively because `encoding/json` matches struct fields that way,
  so `"UID"` and `"uid"` count as the same key. The check covers the whole
  document, including ignored metadata: Proxmark3 never writes duplicates, and
  a document that contains them is ambiguous.
- **Missing or invalid fields:** missing `Card` fields or `blocks`, wrong
  lengths, invalid hex, non-canonical, missing or extra block indices.
- **Unsupported card sizes:** see the table above.
- **Input over 1 MiB (1,048,576 bytes):** at most one byte beyond the limit is
  read. A complete 4K dump as Proxmark3 writes it, with `SectorKeys` and
  `AccessConditionsText`, is about 28 KB, so the limit leaves more than 30×
  headroom while bounding memory use.

Diagnostics name the field, block index, byte count or character offset. They
never repeat a hex value, because block values contain sector keys. A
wrapped `encoding/hex` error can name the single offending character.

## Data that cannot be converted

- **`mfc v3` `Card.ATS` and `Card.SIGNATURE`.** A Flipper MIFARE Classic file
  has no field for them. When either is present and non-empty, the conversion
  succeeds with this warning on stderr:
  `warning: Card.ATS and Card.SIGNATURE cannot be stored in a Flipper MIFARE Classic file and were not converted`.
  (Proxmark3 writes only the first ATS byte anyway, because of a `sizeof`
  quirk in its writer.)
- **Unread data.** Proxmark3 stores blocks it could not read, and keys it did
  not find, as zeros. The JSON cannot tell them from real zeros, so they are
  converted as known data, and Flipper treats them as such. The converter does
  not guess: all-zero blocks or keys are kept as they are, never replaced by
  `??`, and missing keys are not reconstructed.
- **UID versus block 0.** Current Proxmark3 derives `Card` from block 0, but
  older clients and edited dumps need not agree with it. The converter does not
  cross-check them.
- **Partial dumps** (fewer blocks than the card has) are rejected, not padded.
