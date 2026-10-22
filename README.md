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
file. Use `--mini`, `--1k` or `--4k` for card sizes the client cannot detect.

> **Dumps are secrets.** A dump contains the card's sector keys and data,
> which may grant physical access. Do not attach dumps, or `.nfc` files made
> from them, to public issues, chats or repositories.

## Installation

### Prebuilt archives

Each release on the
[Releases page](https://github.com/dimchansky/proxmark3-to-flipper/releases)
has an archive for every supported system, and a checksum file. If the page
does not list a release yet, [install with Go](#with-go) instead.

| System | Archive |
| --- | --- |
| Windows, x64 | `proxmark3-to-flipper_VERSION_windows_amd64.zip` |
| Windows on Arm | `proxmark3-to-flipper_VERSION_windows_arm64.zip` |
| macOS, Apple silicon | `proxmark3-to-flipper_VERSION_macos_arm64.tar.gz` |
| macOS, Intel | `proxmark3-to-flipper_VERSION_macos_amd64.tar.gz` |
| Linux, x86-64 | `proxmark3-to-flipper_VERSION_linux_amd64.tar.gz` |
| Linux, 64-bit Arm (e.g. Raspberry Pi OS 64-bit) | `proxmark3-to-flipper_VERSION_linux_arm64.tar.gz` |
| Linux, 32-bit Arm (ARMv7) | `proxmark3-to-flipper_VERSION_linux_armv7.tar.gz` |

The binaries need Windows 10 or later and macOS 13 or later. Each archive
contains the executable, this README and the license.

Download the archive and `proxmark3-to-flipper_VERSION_checksums.txt` into one
folder, check the archive, and unpack it only if the check passes. Replace `VERSION` (for example
`1.0.0`) and the system name as needed.

**Linux:**

```sh
sha256sum --check --ignore-missing proxmark3-to-flipper_VERSION_checksums.txt &&
  tar -xzf proxmark3-to-flipper_VERSION_linux_amd64.tar.gz &&
  ./proxmark3-to-flipper -version
```

**macOS:**

```sh
shasum -a 256 --check --ignore-missing proxmark3-to-flipper_VERSION_checksums.txt &&
  tar -xzf proxmark3-to-flipper_VERSION_macos_arm64.tar.gz &&
  ./proxmark3-to-flipper -version
```

The binaries are not signed by Apple. If macOS refuses to open a file
downloaded with a browser, remove the quarantine flag after checking the
checksum: `xattr -d com.apple.quarantine proxmark3-to-flipper`.

**Windows (PowerShell):**

```powershell
$archive = "proxmark3-to-flipper_VERSION_windows_amd64.zip"
$entry = Select-String -SimpleMatch "  $archive" proxmark3-to-flipper_VERSION_checksums.txt
if ($entry -and (Get-FileHash $archive -Algorithm SHA256).Hash -eq $entry.Line.Split(" ")[0]) {
    Expand-Archive $archive -DestinationPath proxmark3-to-flipper
    .\proxmark3-to-flipper\proxmark3-to-flipper.exe -version
} else {
    Write-Error "Checksum missing or wrong: do not use $archive"
}
```

The archive is unpacked only if its checksum is listed and matches.

Move the executable to a folder on your `PATH` to run it from anywhere.

Releases are published as GitHub
[immutable releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases),
so with the [GitHub CLI](https://cli.github.com/) you can also check that a
downloaded file is exactly what was published:

```sh
gh release verify-asset vVERSION proxmark3-to-flipper_VERSION_linux_amd64.tar.gz --repo dimchansky/proxmark3-to-flipper
```

### With Go

With Go 1.26 or later:

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

Release archives are built by [GoReleaser](https://goreleaser.com/) from
`.goreleaser.yaml`. To build and check them locally without publishing:

```sh
goreleaser release --snapshot --clean
go run ./tools/verifydist -commit "$(git rev-parse HEAD)" -snapshot -smoke host
```

Pushing a `vX.Y.Z` tag runs `.github/workflows/release.yml`, which creates a
draft release; it is published by hand after review.

## License

[Apache License 2.0](LICENSE)
