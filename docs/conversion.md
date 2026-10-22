# Conversion contract

What `proxmark3-to-flipper` accepts, what it writes, what it rejects, and the
upstream facts these rules rest on. How the output file is written is described
in [output-safety.md](output-safety.md).

No conversion has been validated on Flipper Zero or Proxmark3 hardware. The
rules below follow the upstream source code, pinned in [References](#references).

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

These are the sizes Proxmark3 dumps (`MIFARE_MINI_MAXBLOCK` … `MIFARE_4K_MAXBLOCK`).
On a 4K card, sectors 0–31 have 4 blocks and sectors 32–39 have 16; the
converter keeps the flat block list, so no sector arithmetic is involved.

## Output

A Flipper NFC file, file format version 2, device type `Mifare Classic`,
MIFARE Classic data format version 2. All blocks are written in index order, as
uppercase hex bytes separated by single spaces.

**ATQA byte order.** Proxmark3 keeps the two ATQA bytes in the order the card
sends them, least significant byte first, and writes them to the JSON in that
order: a MIFARE Classic 1K (ATQA `0x0004`) is `"ATQA": "0400"`. The Proxmark3
client *displays* them swapped (`00 04`). Flipper file format version 2 also
stores ATQA LSB first; versions 3 and later store it MSB first, and the
firmware swaps the bytes when it loads them. So the converter copies the JSON
bytes unchanged into a version 2 file (`ATQA: 04 00`). Writing a newer version
number would require swapping ATQA as well.

**Why version 2.** Every Flipper firmware since 2022 reads version 2: firmware
0.68.1 reads only version 2, 0.80.1 reads 2 and 3, and current firmware reads 2
to 4. The MIFARE Classic *data* format version (`Data format version: 2`) is
separate from the file version; version 2 marks unknown bytes with `??` and
derives the known keys from the sector trailers.

Firmware limits, from the firmware source (not tested on devices):

| Feature | Current firmware | 0.80.1 | 0.68.1 |
| --- | --- | --- | --- |
| file format version 2 | yes | yes | yes (only version) |
| `MINI` card type | yes | yes | no |
| 10-byte UID | yes | no (4 or 7 only) | no (4 or 7 only) |

Community firmware forks were not checked.

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
  has no field for them. When either is present and non-empty and the output
  was written, the command prints:
  `warning: Card.ATS and Card.SIGNATURE cannot be stored in a Flipper MIFARE Classic file and were not converted`.
  (Proxmark3 writes only the first ATS byte anyway, because its writer passes
  `sizeof(ats_len)` as the length.)
- **Unread data.** Proxmark3 stores blocks it could not read, and keys it did
  not find, as zeros. The JSON cannot tell them from real zeros, so they are
  converted as known data, and Flipper treats them as such. The converter does
  not guess: all-zero blocks or keys are kept as they are, never replaced by
  `??`, and missing keys are not reconstructed.
- **UID versus block 0.** Current Proxmark3 derives `Card` from block 0: a
  4-byte UID if the BCC matches, a 7-byte UID if block 0's ATQA bytes say so,
  otherwise an empty UID (which this converter rejects). Older clients and
  edited dumps need not agree with block 0, and the converter does not
  cross-check them.
- **`SectorKeys`** duplicates the trailers. If the two disagree, the trailer
  in `blocks` is what is converted.
- **Partial dumps** (fewer blocks than the card has) are rejected, not padded.
  The Proxmark3 client itself loads them by stopping at the first missing
  block and zero-padding short blocks; padding here would turn unknown data
  into apparently known zeros.

## References

Pinned commits used for the facts above:

- Proxmark3 client, master at
  [`0b9597e`](https://github.com/RfidResearchGroup/proxmark3/tree/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16):
  - JSON writer for `mfc v2`/`mfc v3`, [`prepareJSON` in fileutils.c](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/fileutils.c#L1161-L1245);
    `mfcard` writer at [v4.17140](https://github.com/RfidResearchGroup/proxmark3/blob/6ca0ce704afc400a9682f0ce7daff24c6857252c/client/src/fileutils.c)
    (the last release writing `mfcard`; v4.17511 is the first writing `mfc v2`)
  - JSON loader, [fileutils.c](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/fileutils.c#L2704-L2763)
  - UID/ATQA/SAK derived from block 0, [`pm3_save_mf_dump`](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/fileutils.c#L4907-L4938)
  - zero-filled dump buffer, [cmdhfmf.c](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/cmdhfmf.c#L1775)
  - ATQA storage order, [`iso14a_card_select_t`](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/include/mifare.h#L52-L85),
    and swapped display, [cmdhf14a.c](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/cmdhf14a.c#L722)
  - card sizes, [mifaredefault.h](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/mifare/mifaredefault.h#L33-L43)
- Flipper Zero firmware, `dev` at
  [`66613d2`](https://github.com/flipperdevices/flipperzero-firmware/tree/66613d2b46e4aa533aeaf8181d2a1e6566616a4e):
  - [NFC file format documentation](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/documentation/file_formats/NfcFileFormats.md)
    (rendered at [developer.flipper.net](https://developer.flipper.net/flipperzero/doxygen/nfc_file_format.html))
  - format versions, [nfc_common.h](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/nfc_common.h#L12-L18),
    and minimum version, [nfc_device.c](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/nfc_device.c#L342-L347)
  - ATQA swap for versions after 2 and UID lengths, [iso14443_3a.c](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/protocols/iso14443_3a/iso14443_3a.c#L62-L141)
  - MIFARE Classic types, data format version and block parsing, [mf_classic.c](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/protocols/mf_classic/mf_classic.c)
- Older firmware:
  [0.68.1 nfc_device.c](https://github.com/flipperdevices/flipperzero-firmware/blob/5c52bb76217679db33b8cb6bff4273df11785388/lib/nfc/nfc_device.c#L1116-L1129)
  (version 2 only; 4- or 7-byte UID; `1K`/`4K` only) and
  [0.80.1 nfc_device.c](https://github.com/flipperdevices/flipperzero-firmware/blob/c41fe8e4e452b66cbd8486c39729990a5a319f9b/lib/nfc/nfc_device.c#L1131-L1170)
  (versions 2 and 3; ATQA swapped for 3).
