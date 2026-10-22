# proxmark3-to-flipper

`proxmark3-to-flipper` converts a MIFARE Classic dump made with a
[Proxmark3](https://github.com/RfidResearchGroup/proxmark3) into the `.nfc` file
format of the [Flipper Zero](https://flipper.net/), so a card read with the
Proxmark3 can be loaded and emulated on a Flipper.

It is a small command-line tool with no runtime dependencies. It checks the
whole dump before writing anything and never overwrites a file unless you ask
it to.

## Quick start

```sh
proxmark3-to-flipper -i hf-mf-01020304-dump.json -o my-card.nfc
```

Then copy `my-card.nfc` to the `nfc` folder on the Flipper's microSD card, for
example with [qFlipper](https://docs.flipper.net/zero/qflipper): open
**File manager → SD Card → nfc** and drag the file onto the folder, or
right-click it and choose **Upload here**. On the Flipper the card appears
under **NFC → Saved**.

## Getting a dump

With the Proxmark3 client ([RRG/Iceman](https://github.com/RfidResearchGroup/proxmark3)),
place the card on the antenna and run:

```
hf mf autopwn
```

This tries to recover all sector keys of the card; that does not succeed for
every card. When all keys are found, it saves the card as
`hf-mf-<UID>-dump.json` (plus a `.bin` copy and a key file). If you already
have the keys, `hf mf dump --keys hf-mf-<UID>-key.bin` produces the same JSON
file. Use
`--mini`, `--1k` or `--4k` for card sizes the client cannot detect.

> **Dumps are secrets.** A dump contains the card's sector keys and data,
> which may grant physical access. Do not attach dumps, or `.nfc` files made
> from them, to public issues, chats or repositories.

## Installation

Release binaries for Windows, macOS and Linux will be published on the
[Releases page](https://github.com/dimchansky/proxmark3-to-flipper/releases);
there is no release yet. Until then, install with Go 1.26 or later:

```sh
go install github.com/dimchansky/proxmark3-to-flipper@latest
```

The binary is placed in `$(go env GOPATH)/bin` (usually `~/go/bin`, or
`%USERPROFILE%\go\bin` on Windows); make sure that directory is on your `PATH`.

To build from a clone instead:

```sh
git clone https://github.com/dimchansky/proxmark3-to-flipper.git
cd proxmark3-to-flipper
go build
```

This creates `proxmark3-to-flipper` (`proxmark3-to-flipper.exe` on Windows) in
the current directory.

## Usage

```
proxmark3-to-flipper -i DUMP.json -o CARD.nfc [-force]
```

| Flag | Meaning |
| --- | --- |
| `-i FILE` | Proxmark3 JSON dump to read (required) |
| `-o FILE` | Flipper NFC file to write (required) |
| `-force` | replace `-o` if it already exists |
| `-version` | print the version and exit |
| `-h`, `-help` | print help and exit |

Flags may also be written with two dashes (`--force`).

- **Existing files are kept.** If the output exists, the command fails and
  leaves it unchanged; add `-force` to replace it. The input file is never
  modified, and an output path that refers to the input (directly, through a
  link or a different spelling) is refused even with `-force`.
- **Invalid input leaves the output alone.** A dump that fails validation
  never creates or changes the output file. If writing itself fails (a full
  disk, for example), the tool removes the incomplete file it created; the
  rare cases where cleanup is impossible are described in
  [docs/output-safety.md](docs/output-safety.md).
- **Exit status:** `0` on success, `1` if the conversion or writing the file
  fails, `2` for invalid flags or arguments.
- New output files are readable by their owner only on Linux and macOS. On
  Windows they inherit the folder's permissions.

The details of how the file is written, and what is guaranteed on each
platform, are in [docs/output-safety.md](docs/output-safety.md).

## Supported formats

| Proxmark3 `FileType` | Written by | |
| --- | --- | --- |
| `mfc v2` | current Proxmark3 clients (v4.17511, Nov 2023, and later) | supported |
| `mfcard` | older Proxmark3 clients | supported |
| `mfc v3` | | supported; ATS and signature are dropped with a warning |

| Card | Blocks | Flipper type |
| --- | --- | --- |
| MIFARE Classic Mini | 20 | `MINI` |
| MIFARE Classic 1K | 64 | `1K` |
| MIFARE Classic 4K | 256 | `4K` |

The output is a Flipper NFC file in format version 2, which every Flipper
firmware since 2022 can read. Other card families (Ultralight, NTAG, DESFire,
EM4100, …) are not supported.

## Limitations

- **MIFARE Classic 2K and incomplete dumps are rejected.** Flipper has no 2K
  card type, and missing blocks are not filled in.
- **Unread data is converted as zeros.** Proxmark3 saves blocks it could not
  read, and keys it did not find, as zeros, and the dump does not say which
  ones they are. The Flipper will treat them as real data.
- **Firmware differences.** Old firmware such as 0.68.1 cannot load `MINI`
  cards, and firmware 0.80.1 and earlier cannot load 10-byte UIDs.
- **ATS and signature** in `mfc v3` dumps have no place in a Flipper MIFARE
  Classic file and are dropped.
- **Not tested on hardware.** The conversion follows the Proxmark3 and Flipper
  source code; it has not yet been validated on devices.

[docs/conversion.md](docs/conversion.md) describes exactly what is accepted,
rejected and written, with references to the upstream sources.

## Development

```sh
go test ./...          # all tests; the CLI tests also build the binary
go test -race ./...
go vet ./...
golangci-lint run      # configuration in .golangci.yml
```

`testdata/` holds synthetic Proxmark3 dumps and the expected `.nfc` files;
`go run testdata/gen_fixtures.go` regenerates them. Pull requests run the same
checks on Linux, macOS and Windows. Never add real card dumps to the
repository.

## License

[Apache License 2.0](LICENSE)
