# Audit and compatibility report (Task 01)

This report records the state of `proxmark3-to-flipper` at the audit baseline,
the upstream file formats it converts between, and the defects found. It is the
input for the next implementation phase. No production code was changed.

Contents:

1. [Baseline](#1-baseline)
2. [Current behavior](#2-current-behavior)
3. [Upstream formats](#3-upstream-formats)
4. [Compatibility matrix](#4-compatibility-matrix)
5. [Findings](#5-findings)
6. [Reproducing the findings](#6-reproducing-the-findings)
7. [Test suite](#7-test-suite)
8. [Open questions](#8-open-questions)
9. [Recommended order for Task 02](#9-recommended-order-for-task-02)
10. [Recommended README structure](#10-recommended-readme-structure)

Statements are marked as **verified** (read in pinned upstream source, or
reproduced locally) or **hypothesis** (plausible, not proven). No conversion was
validated on Flipper Zero or Proxmark3 hardware.

## 1. Baseline

### Repository

| Item | Value |
| --- | --- |
| Baseline commit | `d5abbc8e238397eb28239f547b29b44dc1bc03ea` ("Initial implementation", 2022-10-07). HEAD matched the commit given in the task. |
| History | 2 commits on `main`; no other branches, tags or releases |
| Files | `main.go` (223 lines, the whole program), `go.mod`, `README.md` (2 lines), `LICENSE` (Apache-2.0), `.gitignore` |
| Module | `github.com/dimchansky/proxmark3-to-flipper`, `go 1.19`, no dependencies, no `go.sum` |
| Tests, CI, docs | none |
| Untracked in the working copy | `tmp/` with real card dumps (`.json` and `.nfc`) and an IDE folder `.idea/` (ignored). `tmp/` was **not** ignored; it is now added to `.gitignore` so the dumps cannot be committed by accident. None of its content was copied into this repository (checked: no block of those dumps appears in any committed file). |

### GitHub configuration (read-only inspection)

| Setting | Value | Relevance for CI/CD |
| --- | --- | --- |
| Visibility, license | public, Apache-2.0 | |
| Default branch | `main`, **not protected**, no rulesets | Add required checks before relying on CI |
| Workflows | none | |
| Actions | enabled, all actions allowed, SHA pinning not required | Consider restricting and requiring SHA pinning |
| Releases / tags | none | |
| Immutable releases | **disabled** | Must be enabled before the first immutable release |
| Secret scanning, push protection | disabled | |
| Dependabot security updates | disabled | |
| Merge methods | merge, squash, rebase allowed; branch not deleted on merge | |
| Issues / PRs | none | |
| `SECURITY.md` | absent | |

No setting was changed.

### Environment and baseline checks

macOS 26.6.1 (arm64), Go 1.27.3 (`GOTOOLCHAIN=auto`), golangci-lint 2.15.0,
staticcheck 2026.2.2, govulncheck 1.9.0.

| Check at baseline | Result |
| --- | --- |
| `gofmt -l .` | clean |
| `go build ./...` | ok |
| `go vet ./...` | ok |
| `go test ./...` | ok, but `[no test files]`: nothing was tested |
| `go test -race ./...` | same |
| `golangci-lint run` (default linters) | 7 issues: unchecked `Close` (2), ineffectual assignment to `err` (3), QF1012 (2) |
| `staticcheck ./...` | 6 × SA4006 (`err` value never used) in `writeNFC` |
| `govulncheck ./...` | no vulnerabilities |
| gosec (via golangci-lint) | G304 on `os.Open`/`os.Create` of user-supplied paths: expected for a CLI, not a finding |

## 2. Current behavior

```
proxmark3-to-flipper -i <dump.json> -o <card.nfc>
```

1. Flags are parsed with the global `flag.CommandLine`. `-i` and `-o` are
   required; positional arguments are ignored.
2. The input is decoded with `json.NewDecoder(...).Decode` into a struct with
   `Created`, `FileType`, `Card.{UID,ATQA,SAK}` and `blocks` (map from string to
   hex string). Other fields (`SectorKeys`, `ATS`, `SIGNATURE`, …) are ignored.
3. `Created` must equal `proxmark3` and `FileType` must equal `mfcard`.
4. UID, ATQA and SAK are hex-decoded with no length check.
5. Blocks: `n = len(blocks)`; keys `"0"` … `"n-1"` must all exist; each value is
   hex-decoded with no length check.
6. The output is created with `os.Create` (truncating any existing file) only
   after the input was parsed, and written as Flipper NFC **file format
   version 2**, device type `Mifare Classic`, MIFARE Classic data format
   version 2. UID, ATQA and SAK bytes are written in the order they appear in
   the JSON. `Mifare Classic type` is `1K` for 64 blocks, `2K` for 128, `4K`
   for 256 and `0K` for anything else.
7. On success nothing is printed and the exit code is 0. Errors are printed as
   `error: <message>` on stderr with exit code 1; for a missing `-i`/`-o` the
   usage text follows. `-h` prints usage and exits 0; an unknown flag exits 2.

Exact output for a 1K dump (from `testdata/flipper/mfc-1k-uid4.nfc`):

```
Filetype: Flipper NFC device
Version: 2
# Nfc device type can be UID, Mifare Ultralight, Mifare Classic, Bank card
Device type: Mifare Classic
# UID, ATQA and SAK are common for all formats
UID: 11 22 33 44
ATQA: 04 00
SAK: 08
# Mifare Classic specific data
Mifare Classic type: 1K
Data format version: 2
# Mifare Classic blocks, '??' means unknown data
Block 0: 11 22 33 44 44 08 04 00 53 59 4E 54 48 46 49 58
...
Block 63: AA AA AA AA AA 0F FF 07 80 69 BB BB BB BB BB 0F
```

## 3. Upstream formats

Pinned references:

- Proxmark3 (Iceman): master at [`0b9597e`](https://github.com/RfidResearchGroup/proxmark3/tree/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16)
  (2026-10), plus release tags v4.9237 … v4.23346.
- Flipper Zero firmware: `dev` at [`66613d2`](https://github.com/flipperdevices/flipperzero-firmware/tree/66613d2b46e4aa533aeaf8181d2a1e6566616a4e),
  [0.68.1](https://github.com/flipperdevices/flipperzero-firmware/tree/5c52bb76217679db33b8cb6bff4273df11785388) (2022-10, contemporary with this tool) and
  [0.80.1](https://github.com/flipperdevices/flipperzero-firmware/tree/c41fe8e4e452b66cbd8486c39729990a5a319f9b) (2023-03).
- [Flipper NFC file format documentation](https://developer.flipper.net/flipperzero/doxygen/nfc_file_format.html),
  source [`documentation/file_formats/NfcFileFormats.md`](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/documentation/file_formats/NfcFileFormats.md).

### 3.1 Proxmark3 MIFARE Classic JSON

**Writer** ([`prepareJSON`, fileutils.c L1161-L1245](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/fileutils.c#L1161-L1245)), verified:

| Field | `mfcard` | `mfc v2` | `mfc v3` |
| --- | --- | --- | --- |
| `Created` | `proxmark3` | `proxmark3` | `proxmark3` |
| `Card.UID` | uidlen bytes | same | same |
| `Card.ATQA` | 2 bytes, `atqa[0]atqa[1]` | same | same |
| `Card.SAK` | 1 byte | same | same |
| `Card.ATS` | – | – | written with length `sizeof(ats_len)`, i.e. **1 byte** (upstream quirk) |
| `Card.SIGNATURE` | – | – | 32 bytes |
| `blocks."N"` | 16 bytes per block, N = 0 … dumplen/16-1 | same | same |
| `SectorKeys` | KeyA, KeyB, AccessConditions, AccessConditionsText (derived from trailers) | same | same |

All hex is written uppercase without separators
([`JsonSaveBufAsHexCompact`, emvjson.c L107](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/emv/emvjson.c#L107-L113)).
`mfcard` and `mfc v2` are structurally identical; only the `FileType` string
differs (compared with the `mfcard` writer of
[v4.17140](https://github.com/RfidResearchGroup/proxmark3/blob/6ca0ce704afc400a9682f0ce7daff24c6857252c/client/src/fileutils.c)).

**Which version writes what** (verified by reading `fileutils.c` at every
release tag): up to and including **v4.17140** (2023-09-09) MIFARE Classic dumps
are saved as `mfcard`; from **v4.17511** (2023-11-13) onwards they are saved as
`mfc v2`. `mfc v3` has a writer and a loader but no caller in the client at the
pinned commit (GitHub code search finds `jsfMfc_v3` only in `fileutils.[ch]`).

**Loader** ([fileutils.c L2704-L2763](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/fileutils.c#L2704-L2763)), verified:

- `mfcard` (commented "depricated") and `mfc v2` share one code path.
- Blocks are read from index 0 upward and loading **stops at the first missing
  block**; a short block is zero-padded with a warning
  ([`load_file_sanity`](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/fileutils.c#L2605-L2615)).
  `Card` is not read for `mfcard`/`mfc v2`.
- Hex parsing skips spaces and tabs and accepts both letter cases; a value longer than the target buffer (more than 16 bytes for a block) is rejected
  ([`HexToBuffer`](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/emv/emvjson.c#L252-L276),
  [`param_gethex_to_eol`](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/util.c#L1032)).

**Where the card identity comes from in current Proxmark3** (verified):
`hf mf dump` calls
[`pm3_save_mf_dump`](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/fileutils.c#L4907-L4938),
which derives UID, SAK and ATQA **from block 0**, not from the anticollision
response: 4-byte UID if the BCC matches and `block0[6] & 0xC0 == 0`, 7-byte UID
if `block0[8] & 0xC0 == 0x40`, otherwise it warns and writes an empty UID. A
dump of a card with a non-standard block 0 can therefore carry `"UID": ""`.

**Unread data** (verified): the dump buffer is `calloc`ed
([cmdhfmf.c L1775](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/cmdhfmf.c#L1775))
and a block that fails to read is left as zeros, and unknown keys are written as
zeros. The JSON has no way to mark data as unknown.

**ATQA byte order** (verified): `iso14a_card_select_t.atqa[2]` holds the two
ATQA bytes in reception order, LSB first
([mifare.h](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/include/mifare.h#L52-L85));
the client displays them swapped (`atqa[1] atqa[0]`,
[cmdhf14a.c L722](https://github.com/RfidResearchGroup/proxmark3/blob/0b9597e8f3262a0b6f1f10fce2e60ad22b4ade16/client/src/cmdhf14a.c#L722)).
So a MIFARE Classic 1K (ATQA 0x0004) is stored as `"ATQA": "0400"`.

**Card sizes** (`hf mf dump --mini/--1k/--2k/--4k`): 20, 64, 128 and 256 blocks.
Sectors 0-31 have 4 blocks, sectors 32-39 (4K) have 16 blocks.

### 3.2 Flipper NFC file format

**File format version** (`Version:` header), verified in
[NfcFileFormats.md](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/documentation/file_formats/NfcFileFormats.md)
and [nfc_common.h](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/nfc_common.h#L12-L18):

| Version | Meaning | Written by | Read by current firmware |
| --- | --- | --- | --- |
| 1 | initial, deprecated | – | no |
| 2 | **ATQA LSB first** (`04 00` for 0x0004) | firmware of 2022, e.g. 0.68.1 | yes, legacy loader, no swap |
| 3 | ATQA MSB first (`00 04`) | firmware of 2023, e.g. 0.80.1 | yes, legacy loader, bytes swapped |
| 4 | unified: device types renamed (`UID` → `ISO14443-3A`) | current firmware | yes |

[`iso14443_3a_load`](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/protocols/iso14443_3a/iso14443_3a.c#L62-L100)
swaps ATQA only when `version > 2`; the saver writes MSB first. Minimum
supported version is 2
([nfc_device.c L342](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/nfc_device.c#L342-L347)).
Firmware 0.68.1 accepted **only** version 2
([L1116](https://github.com/flipperdevices/flipperzero-firmware/blob/5c52bb76217679db33b8cb6bff4273df11785388/lib/nfc/nfc_device.c#L1116));
0.80.1 accepted 2 and 3
([L1131-L1170](https://github.com/flipperdevices/flipperzero-firmware/blob/c41fe8e4e452b66cbd8486c39729990a5a319f9b/lib/nfc/nfc_device.c#L1131-L1170)).

**Consequence:** the converter's output (version 2 with ATQA copied from the
JSON) is **correct**: Proxmark3's LSB-first order is exactly what version 2
expects. Changing the header to 3 or 4 without swapping ATQA would produce a
wrong ATQA. Version 2 is also the only version every firmware since 2022 reads.
As corroborating evidence, a Flipper-generated version 2 file and this tool's
output for the same physical card in the local `tmp/` folder have identical
header lines and the same ATQA (contents not reproduced here).

**MIFARE Classic data format version** (`Data format version:`) is independent
of the file version. The current value is 2
([mf_classic.c L17](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/protocols/mf_classic/mf_classic.c#L17));
version 1 used key masks instead of `??`. With version 2, keys and block
read-state are derived from the block contents.

**MIFARE Classic rules** (verified in [mf_classic.c](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/protocols/mf_classic/mf_classic.c)):

- `Mifare Classic type` must be exactly `MINI` (20 blocks), `1K` (64) or `4K`
  (256). Any other value fails the load. There is no 2K type. `MINI` was added
  after 0.68.1 (0.68.1 knows only `1K`/`4K`).
- Exactly `Block 0` … `Block N-1` are read for the declared type; a missing
  line fails the load. Blocks are a flat list with no sector grouping.
- Each block is parsed at character positions `3*i`, `3*i+1`: 16 two-digit hex
  bytes separated by single spaces; either case is accepted. A byte that is not
  hex (conventionally `??`) is unknown. In a sector trailer, Key A, access bits
  and Key B are evaluated separately.
- UID must be 4, 7 or 10 bytes in current firmware
  ([iso14443_3a.c L128-L141](https://github.com/flipperdevices/flipperzero-firmware/blob/66613d2b46e4aa533aeaf8181d2a1e6566616a4e/lib/nfc/protocols/iso14443_3a/iso14443_3a.c#L128-L141)),
  but only 4 or 7 in 0.68.1 and 0.80.1. ATQA is read as 2 bytes, SAK as 1.
- SAK is not cross-checked against the declared type.

**Hypothesis H-1:** a block line shorter than 47 characters makes
`furi_string_get_char` index past the end of the string. Whether that asserts
or reads garbage depends on M\*LIB assertion settings; not tested on a device.

**Hypothesis H-2:** community firmware forks (Unleashed, Momentum, …) follow
the official loader. Not checked.

## 4. Compatibility matrix

Legend: ✅ supported and verified by tests · ⚠️ accepted but output is wrong or
lossy · ❌ rejected · ❓ uncertain.

| Input | 1. Current behavior | 2. Upstream says | 3. Required future support | 4. Unsupported / uncertain |
| --- | --- | --- | --- | --- |
| `mfcard`, 64 blocks (1K), 4- or 7-byte UID | ✅ exact golden output | Flipper v2, type `1K` | keep | – |
| `mfcard`, 256 blocks (4K) | ✅ exact golden output | type `4K`, 16-block sectors irrelevant to the flat list | keep | – |
| `mfc v2` (Proxmark3 ≥ v4.17511, Nov 2023) | ❌ "expecting Mifare card dump" (D-02) | same structure as `mfcard` | **accept** | – |
| `mfc v3` | ❌ (D-02) | adds `ATS` (1 byte) and `SIGNATURE` (32 bytes) | accept; warn that ATS/SIGNATURE are dropped | no Flipper field for the EV1 signature or ATS in a MIFARE Classic file |
| 20 blocks (Mini) | ⚠️ `0K`, file not loadable (D-04) | Flipper type `MINI` | write `MINI` | firmware 0.68.1 cannot read `MINI` |
| 128 blocks (2K) | ⚠️ `2K`, file not loadable (D-04) | no Flipper type | reject with a clear error | ❓ padding to 4K would misrepresent the card |
| other block counts, gaps | ⚠️ `0K` or "cannot find block N" | Proxmark3 loader stops at first gap | reject | ❓ partial dumps padded with `??` |
| empty `blocks` / no `Card` | ⚠️ exit 0, invalid file (D-03) | – | reject | – |
| block ≠ 16 bytes | ⚠️ written as is (D-05) | Proxmark3 zero-pads short blocks, rejects long ones | reject (or pad short ones, with a warning) | H-1 |
| UID not 4/7/10, ATQA ≠ 2, SAK ≠ 1 byte | ⚠️ written as is (D-06) | Flipper rejects | reject; warn for a 10-byte UID (C-4) | current Proxmark3 may write `"UID": ""` |
| UID differs from block 0 | written as is | Proxmark3 now derives UID from block 0 | ❓ warn | open question Q4 |
| zero-filled unread blocks / zero keys | written as known data | JSON cannot mark unknown data | document | ❓ cannot be detected reliably |
| `SectorKeys`, `AccessConditionsText` | ignored | redundant with trailers | keep ignoring | – |
| lowercase hex | ✅ decoded, written uppercase | both accepted upstream | keep | – |
| hex with spaces | ❌ | Proxmark3 accepts, never writes | ❓ optional | – |
| trailing data after JSON | ⚠️ ignored (D-09) | – | reject | – |
| Flipper output version | v2, ATQA LSB first ✅ | v2 readable by all firmware since 2022 | keep v2 by default | v4 needs ATQA swap and new device type names |

## 5. Findings

Severity: **High**: loss of user data or the main use case broken.
**Medium**: an invalid or truncated file reported as success. **Low**:
diagnostics, hardening, maintainability.

"Test" names the intended-behavior test in `main_defects_test.go` (build tag
`knowndefects`), which fails at the baseline. Every defect below was reproduced
unless marked "inspection".

**Status** (updated in Task 03):

| Status | Defects | Where |
| --- | --- | --- |
| Fixed in Task 02 | D-01, D-07, D-08, D-11, D-13 | [output-safety.md](output-safety.md) |
| Fixed in Task 03 | D-02, D-03, D-04, D-05, D-06, D-09, D-12, D-14, D-15, D-18 | [conversion.md](conversion.md) |
| Open | D-10, D-16, D-17, D-19 | `TestDefect…` in `main_defects_test.go` for D-10 and D-19 |

Intentionally unsupported, by design rather than as defects: MIFARE Classic 2K
dumps (rejected, Flipper has no 2K type), partial dumps (rejected, not
padded), `mfc v3` `Card.ATS` and `Card.SIGNATURE` (dropped with a warning) and
unread data that Proxmark3 stored as zeros (C-1, converted as is). Regression
tests for the fixed defects are in the default suite; `main_defects_test.go`
lists where each one went.

### D-01 Same input and output path destroys the dump: High (fixed in Task 02)

- **Reproduce:** `proxmark3-to-flipper -i d.json -o d.json` (also `./d.json` or a symlink to `d.json`).
- **Expected:** refuse; input untouched. **Actual:** exit 0; `d.json` now contains NFC text.
- **Root cause:** the input is fully parsed, then `os.Create` truncates the same file.
- **Fix:** compare `os.Stat` of input and an existing output with `os.SameFile` before writing; write via a temp file and rename (D-08).
- **Test:** `TestDefectD01_SamePathDestroysInput`; add a symlink and hard-link case. **Compatibility:** none.

### D-02 Dumps from Proxmark3 v4.17511 and later are rejected: High (fixed in Task 03)

- **Reproduce:** convert `testdata/proxmark3/mfc-v2-1k-uid4.json`.
- **Expected:** same output as for `mfcard`. **Actual:** `error: expecting Mifare card dump`, exit 1; the message is misleading for a MIFARE dump.
- **Root cause:** `FileType != "mfcard"` check; upstream renamed the type in 2023 (§3.1).
- **Fix:** accept `mfcard`, `mfc v2`, `mfc v3`; name the accepted types in the error. Do this **after** D-03 to D-06, so newly accepted files are validated.
- **Test:** `TestDefectD02_CurrentProxmark3FileTypes`. **Compatibility:** additive.

### D-03 Empty dump converted with exit 0: Medium (fixed in Task 03)

- **Reproduce:** `{"Created":"proxmark3","FileType":"mfcard"}`.
- **Actual:** exit 0, file with `UID: `, `ATQA: `, `SAK: `, `Mifare Classic type: 0K` and no blocks.
- **Root cause:** no presence checks; missing fields decode to empty values.
- **Fix:** require `Card` fields and a non-empty `blocks`. **Test:** `TestDefectD03_EmptyDumpAccepted`.

### D-04 Unsupported block counts produce unloadable files: Medium (fixed in Task 03: MINI written, 2K and other sizes rejected)

- **Reproduce:** convert `testdata/proxmark3/mfcard-mini-uid4.json` (20 blocks) or `mfcard-2k-uid4.json` (128).
- **Actual:** `Mifare Classic type: 0K` / `2K`, exit 0. Flipper accepts only `MINI`, `1K`, `4K`.
- **Fix:** map 20/64/256 to `MINI`/`1K`/`4K`; reject everything else (including 2K) with a message naming the block count.
- **Test:** `TestDefectD04_UnsupportedBlockCounts` (expected Mini output: `testdata/flipper/mfc-mini-uid4.expected.nfc`).
- **Compatibility:** files that were silently invalid now fail.

### D-05 Block length not validated: Medium (fixed in Task 03)

- **Reproduce:** a block of 0, 1, 15, 17 or 32 bytes.
- **Actual:** written as is (`Block 9: ` for an empty block). See H-1 for the device-side effect.
- **Root cause:** `// TODO: check block length`.
- **Fix:** require 16 bytes; decide whether to zero-pad short blocks like the Proxmark3 loader does (Q8). Proxmark3 itself rejects blocks longer than 16 bytes. **Test:** `TestDefectD05_BlockSizeNotValidated`.

### D-06 UID, ATQA and SAK lengths not validated: Medium (fixed in Task 03)

- **Reproduce:** UID `112233`, ATQA `04`, SAK `0800`, or empty values.
- **Actual:** written as is; Flipper rejects such files.
- **Fix:** UID 4/7/10 (warn that 10-byte UIDs need recent firmware, see C-4), ATQA 2, SAK 1. **Test:** `TestDefectD06_CardIdentityNotValidated`.

### D-07 Intermediate write errors are ignored: Medium (fixed in Task 02)

- **Reproduce:** `TestDefectD07_IntermediateWriteErrorIgnored` (a writer failing once).
- **Actual:** `writeNFC` returns nil; only the error of the last `Fprintf` is kept. Confirmed by `ineffassign`/SA4006.
- **Impact:** a transient failure (for example on a network or removable volume) yields a truncated file and exit 0. A persistent error such as a full disk is still reported, because the last write also fails (`TestWriteNFC_PersistentWriterError`).
- **Fix:** check every write, or write through `bufio.Writer` and check `Flush`.

### D-08 Close errors ignored, partial output left behind: Medium (inspection; fixed in Task 02)

- `defer nfcFile.Close()` discards the error; some file systems report write failures only on close.
- On a write error the partially written file remains, already replacing any previous file.
- **Fix:** write to a temp file in the target directory, `Sync`, `Close` (checked), then `os.Rename`; remove the temp file on failure.
- **Test:** requires an injectable file system or a writer seam; not reproducible portably at the baseline.

### D-09 Trailing data after the JSON document accepted: Low (fixed in Task 03)

- **Reproduce:** a valid dump followed by `garbage`, `}` or a second document.
- **Root cause:** a single `Decoder.Decode` call. **Fix:** after decoding the document, call `Decode` a second time and require it to return `io.EOF`. `Decoder.More` is not a substitute: it reports whether another element follows inside the current array or object, not whether the input ends after the document.
- **Test:** `TestDefectD09_TrailingDataAccepted`.

### D-10 Wrong diagnostic for missing `-o`; inconsistent exit codes: Low

- **Actual:** missing `-o` prints "please provide **input** Proxmark3 dump file in JSON format" (copy-paste error). Missing flags exit 1, flag syntax errors exit 2.
- **Fix:** message "please provide output Flipper NFC file"; exit 2 for all usage errors.
- **Test:** `TestDefectD10_UsageDiagnostics`. **Compatibility:** exit code changes for scripts.

### D-11 Existing output overwritten without notice: Low (fixed in Task 02: refused unless `-force`)

- **Reproduce:** `-o existing.nfc` replaces the file, exit 0.
- A Flipper-captured `.nfc` file can be irreplaceable. Options: refuse unless `-force`, or keep overwriting (like `cp`) but do it atomically. See Q2. No test until decided.

### D-12 Duplicate block keys accepted: Low (fixed in Task 03)

- `encoding/json` keeps the last value for a repeated key. **Test:** `TestDefectD12_DuplicateBlockKeys`. Fixing it requires token-level decoding of `blocks`.

### D-13 Output file is world-readable: Low (fixed in Task 02)

- Created with mode 0666 & umask (0644 typically) although it contains sector keys.
- **Fix:** create with 0600. **Test:** `TestDefectD13_OutputFilePermissions` (POSIX only).

### D-14 No input size limit: Low (fixed in Task 03: 1 MiB limit)

- **Measured:** a 93 MB file with 2,000,000 blocks used 470 MB RSS and produced a 125 MB `0K` file with exit 0.
- **Fix:** read through `io.LimitReader` (a 4K dump with `SectorKeys` is about 28 KB; 1 MiB is ample) and reject more than 256 blocks.

### D-15 Diagnostics echo raw card data: Low (fixed in Task 03)

- `cannot parse block 3 data: failed to parse hex data 'AAAAAAAAAA00FF078069BBBBBBBBBB0Z'` prints a sector trailer, including keys, to stderr (terminal history, CI logs).
- **Fix:** report the block index, character offset and length instead of the value.

### D-16 Global flag state and `os.Exit` prevent in-process testing: Low (maintainability)

- `parseArgs` registers flags on `flag.CommandLine` and replaces `flag.Usage`; a second call panics with "flag redefined". The CLI is therefore tested as a subprocess.
- **Fix:** `run(args []string, stdout, stderr io.Writer) int` with a local `flag.FlagSet`.

### D-17 Build metadata always "undefined": Low

- `Version`, `BuildTime` and `GitHash` are meant to be set with `-ldflags`, but no build script does it; there is no `-version` flag. Use `debug.ReadBuildInfo` as a fallback and add `-version`.

### D-18 Misleading diagnostic for non-numeric block keys: Low (fixed in Task 03)

- Keys `0`…`63` plus `foo` report "cannot find Mifare card data for block 64".
- **Test:** `TestDefectD18_NonNumericBlockKeyDiagnostic`.

### D-19 Positional arguments silently ignored: Low

- `-i a.json -o b.nfc extra.json` succeeds. **Test:** `TestDefectD19_PositionalArgumentsIgnored`.

### Compatibility limitations (not defects)

- **C-1:** Proxmark3 writes unread blocks and unknown keys as zeros (§3.1). The converter cannot tell them from real zeros, so Flipper treats them as known data and keys `000000000000`.
- **C-2:** `mfc v3` `ATS` and `SIGNATURE` have no place in a Flipper MIFARE Classic file.
- **C-3:** `SectorKeys` duplicates the trailers. If the two disagree, the trailer in `blocks` is what is converted.
- **C-4:** a 10-byte UID loads in current firmware but not in 0.68.1 or 0.80.1 (4 or 7 bytes only); `MINI` does not load in 0.68.1. The exact firmware versions where this changed were not determined.

## 6. Reproducing the findings

```bash
go test ./...                                              # baseline suite, passes
go test -tags knowndefects -run 'TestDefect' -v ./...      # intended behavior, fails at the baseline
```

Manual reproduction with the built CLI:

```bash
go build -o /tmp/p2f .
cp testdata/proxmark3/mfcard-1k-uid4.json /tmp/d.json
/tmp/p2f -i /tmp/d.json -o /tmp/d.json; head -1 /tmp/d.json                                  # D-01
/tmp/p2f -i testdata/proxmark3/mfc-v2-1k-uid4.json -o /tmp/v2.nfc                           # D-02
echo '{"Created":"proxmark3","FileType":"mfcard"}' > /tmp/e.json
/tmp/p2f -i /tmp/e.json -o /tmp/e.nfc; echo $?; cat /tmp/e.nfc                              # D-03
/tmp/p2f -i testdata/proxmark3/mfcard-mini-uid4.json -o /tmp/m.nfc; grep type /tmp/m.nfc     # D-04
/tmp/p2f -i testdata/proxmark3/mfcard-1k-uid4.json; echo $?                                  # D-10
```

## 7. Test suite

| File | Content |
| --- | --- |
| `main_test.go` | table-driven unit tests for hex formatting, parsing (fixtures, accepted and rejected inputs, `errors.Is`/`errors.As` on wrapped causes), writing (exact header, card type, golden files, determinism, writer errors), golden-file review, fuzz target |
| `main_cli_test.go` | end-to-end tests of the built binary: conversions, relative paths, `-h`, usage errors, input errors, missing output directory; checks exit status, stdout/stderr separation and that no output file is created on failure |
| `main_defects_test.go` | `knowndefects` build tag: one intended-behavior test per reproducible defect |
| `testdata/proxmark3/*.json` | synthetic dumps: 1K (4- and 7-byte UID), 4K, Mini, 2K, and the 1K card as `mfc v2` and `mfc v3` |
| `testdata/flipper/*.nfc` | expected outputs for 1K, 1K 7-byte UID, 4K, and Mini (`*.expected.nfc`, future behavior) |
| `testdata/gen_fixtures.go` | regenerates all fixtures (`go run testdata/gen_fixtures.go`); output is reproducible |

**Golden files are not snapshots.** The generator renders the JSON input and the
expected NFC file from the same synthetic card model, with its own
implementation of the version 2 layout; it shares no code with the converter.
`TestGoldenFiles` additionally parses every golden file with a strict reader
of the Flipper rules from §3.2 (header, UID/ATQA/SAK lengths, type ↔ block
count, ordered 16-byte blocks) and compares it field by field with its JSON
fixture. Mutating a golden file (swapping ATQA bytes, reordering two blocks)
was confirmed to fail the golden, review and CLI tests.

**Fixture content:** UIDs `11223344`, `A0A1A2A3`, `04112233445566`;
manufacturer bytes are ASCII `SYNTHFIX`; data block *i* holds bytes
*i*, *i*+1, …, *i*+15; trailers use keys `AA AA AA AA AA <sector>` and
`BB BB BB BB BB <sector>` with transport access bits `FF 07 80 69`. No real
card data, keys or credentials are included.

**Results** (Go 1.27.3, darwin/arm64):

| Command | Result |
| --- | --- |
| `gofmt -l .` | clean |
| `go vet ./...`, `go vet -tags knowndefects ./...` | ok (includes `stdversion`: no API newer than Go 1.19) |
| `go test ./...` | ok, 89 tests and subtests pass |
| `go test -race ./...`, `-count=3 -shuffle=on` | ok |
| `go test -tags knowndefects -run TestDefect ./...` | fails as intended: 13 tests, 49 failing tests and subtests |
| `GOTOOLCHAIN=go1.21.13 go test ./...` | ok (oldest toolchain `GOTOOLCHAIN` can download; Go 1.19 itself not tested) |
| `go test -fuzz FuzzParseProxmark3JSON -fuzztime 30s` | 812k executions, no failure |
| `go test -coverprofile` (in-process only) | 69.9% of statements; `main`, `run`, `parseArgs` run only in the subprocess |
| `CLI_GOCOVERDIR=… go test ./...` + `go tool covdata percent` | **96.8%** including the subprocess CLI runs |
| `golangci-lint run` (+ gosec, errorlint, revive, thelper, …) | only the baseline production issues listed in §1; in tests, gosec G204/G304 for building and running the test binary and reading fixtures (expected) |
| `staticcheck`, `govulncheck` | production SA4006 as in §1; no vulnerabilities |

Tests are deterministic, need no network or hardware, and write only to
`t.TempDir()`. The CLI tests build the binary once with the `go` command that
`go test` puts first on `PATH`.

**Remaining gaps:** close/sync errors and atomic replacement (D-08) need a seam
for fault injection; Windows behavior is not run (no CI yet); no hardware
validation; no fixture from a real Proxmark3 run (deliberately; a dump of a
blank test card produced in-house could be added later).

## 8. Open questions

- **Q1 Output version:** keep file version 2 (readable by all firmware since 2022, ATQA order already right) or offer version 4 (ATQA swapped, `Device type: Mifare Classic` unchanged)? Recommendation: keep 2 as the default; add an option only on demand.
- **Q2 Overwrite policy** (D-11): refuse unless `-force`, or overwrite atomically?
- **Q3 Unknown data** (C-1): mark all-zero trailer keys or zero blocks as `??`? There is no reliable signal; any heuristic needs an explicit opt-in.
- **Q4 UID source:** when `Card.UID` and block 0 disagree, which wins? Warn or fail?
- **Q5 2K:** confirm rejection (recommended) rather than conversion as 4K.
- **Q6 Go version:** `go 1.19` is long out of support. Raise it to a supported release when CI is introduced.
- **Q7 Hardware validation:** which firmware versions should be checked on a device before the first release?
- **Q8 Partial dumps:** Proxmark3 loads dumps with fewer blocks and zero-pads short blocks. Should the converter pad to the card size with `??` (keys unknown) and warn, or reject?

## 9. Recommended order for Task 02

1. **Testable entry point** (D-16): `run(args, stdout, stderr) int` with a local `FlagSet`, which also fixes D-10 and D-19. Move the CLI tests in-process and keep one subprocess smoke test.
2. **Safe output** (D-01, D-07, D-08, D-13, D-11 per Q2): same-file check, temp file + `Sync` + checked `Close` + `Rename`, mode 0600, every write checked.
3. **Strict input** (D-03, D-04, D-05, D-06, D-09, D-12, D-14, D-18): size limit, single document, field presence, lengths, block count → `MINI`/`1K`/`4K`.
4. **Newer Proxmark3 types** (D-02): accept `mfc v2` and `mfc v3`, using the existing fixtures and golden file.
5. **Diagnostics** (D-15, D-17): no raw data in errors, `-version`.
6. Promote each `TestDefect…` into the default suite as it is fixed; delete `main_defects_test.go` when empty.
7. Then CI (gofmt, vet, `test -race`, golangci-lint with a committed config, govulncheck, Linux/macOS/Windows), branch protection, and the release pipeline (Task 03+).

## 10. Recommended README structure

Not changed in this phase. Proposed structure for a later task:

1. Title, badges (CI, Go version, license, release)
2. One-sentence summary
3. Installation: release binaries (with checksum verification), `go install`
4. Usage: `-i`/`-o` example, exit codes, overwrite behavior
5. Supported inputs: Proxmark3 `FileType` values and versions, card sizes
6. Output: Flipper file format version 2, which firmware reads it, ATQA note
7. Limitations: lossy fields, unknown data, 2K, hardware validation status
8. Handling dumps safely: dumps contain keys; file permissions; do not attach dumps to issues
9. Development: tests, `knowndefects` tag, fixture generator
10. Contributing, security policy, license
