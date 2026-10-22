# Output file safety

How `proxmark3-to-flipper` writes the `-o` file, what it guarantees and where
the guarantees end. Implemented in [`output.go`](../output.go), tested in
[`output_test.go`](../output_test.go) and [`main_cli_test.go`](../main_cli_test.go).

## Usage

```
proxmark3-to-flipper -i dump.json -o card.nfc          # fails if card.nfc exists
proxmark3-to-flipper -i dump.json -o card.nfc -force   # replaces card.nfc
```

**Compatibility change:** before this change an existing output was silently
overwritten. Now it is kept and the command fails with
`refusing to overwrite existing file (use -force to replace it)`. Scripts that
relied on overwriting must add `-force`. The exit code for this and every other
output error is 1.

## Strategy

The NFC file is rendered completely in memory first (a 4K card is about 15 KB),
so the only failures left when the output is touched are I/O errors.

1. **Input identity.** The input is opened and identified with `File.Stat`. If
   the output path exists, its identity (`os.Stat`, which follows symlinks) is
   compared with `os.SameFile`: device and inode on POSIX, volume serial and
   file index on Windows. A match is refused, with or without `-force`. This
   catches the same path, `./` and `..` aliases, case variants on
   case-insensitive filesystems, a symlink in either direction and hard links.
   If the output cannot be checked (for example, its path runs through a regular
   file), the command fails rather than assuming it is safe.
2. **Default: exclusive create.** The output is opened with
   `O_CREATE|O_EXCL` and mode `0600`, written, synced and closed. The kernel
   decides atomically whether the name is free, so an existing file, directory or
   symlink (even a dangling one) is never replaced or followed, also when it
   appears after step 1. There is no check-then-create window.
3. **`-force`: temporary file and rename.** The content is written to a new
   temporary file `.<name>.<random>.tmp` in the destination directory
   (`os.CreateTemp`, mode `0600`), synced and closed, and then `os.Rename`d over
   the destination. The destination is never deleted first.
4. **Errors and cleanup.** Every `Write` (including a short write), `Sync`,
   `Close` and `Rename` error is reported, and the command exits 1. The file the
   failed attempt created (the new output in step 2, the temporary file in step
   3) is removed. If removing it fails too, both errors are reported and the
   message names the file left behind.

Only the standard library's `O_EXCL`, `CreateTemp` and `Rename` are used. Hard
links (unavailable on FAT and exFAT) and platform-specific
rename-without-replace calls (`renameat2`, `renamex_np`) were avoided: they
would add dependencies and fallbacks for no gain over `O_EXCL`.

## Guarantees

Under the assumption that no other process changes the files involved while the
command runs:

| Guarantee | How |
| --- | --- |
| The input is never written | identity check before any write; the input is only opened for reading |
| An existing output is never changed without `-force` | `O_EXCL`; holds even against a concurrently created file |
| A conversion error never touches the output | rendering happens before any file is opened |
| A failed write never reports success | every write, sync, close and rename error is returned |
| A handled failure leaves no partial file | the file created by the failed attempt is removed, or the failure to remove it is reported |
| With `-force`, a failed replacement keeps the old file | the old file is only ever replaced by `rename`, never deleted |
| New output files are owner-only on POSIX | mode `0600` (further restricted by the umask, never widened) |

## Limits and platform differences

- **Concurrent modification.** The identity check is made once, before
  writing. It does not defend against another process swapping files during the
  run. Two cases stay safe anyway because of how the output is written: without
  `-force`, `O_EXCL` refuses a destination that appears later; with `-force`,
  `rename` replaces the destination *name*, so a symlink or hard link to the
  input created just before the rename is replaced and the input survives (both
  tested). Swapping a directory component of the path for a symlink to the
  input's directory between the check and the rename is not detected.
- **Crashes and signals.** Cleanup runs for handled errors only. If the process
  is killed or the machine loses power, the default mode can leave a partial
  output (written in one `write` call, so the window is small), and `-force` can
  leave a `.<name>.*.tmp` file; the destination itself is either the old or the
  new content.
- **Durability.** File contents are synced before close and before the rename.
  The directory is not synced, so after a power loss a fresh rename may not
  have been persisted: the old file is then still there.
- **POSIX `rename`** replaces the destination atomically. `-force` therefore
  replaces a read-only destination file (permission is checked on the
  directory), and the replacement gets mode `0600`: the old file's mode, owner,
  extended attributes and other hard links are not carried over.
- **Windows `rename`.** Go's `os.Rename` calls `MoveFileEx` with
  `MOVEFILE_REPLACE_EXISTING`. Microsoft does not document this as atomic;
  `ReplaceFile` is not used. The replacement either happens or the call fails
  with the old file still in place; this tool never deletes the destination
  itself. Observed in CI (`TestWriteOutputFile_ForcePlatformBehavior`, Windows
  Server 2025 runner, NTFS): replacing a read-only destination, or one that
  another process holds open, fails with "Access is denied" and the old file
  is kept. On Linux and macOS both replacements succeed. In all cases the test
  asserts that no data is lost and no temporary file remains.
- **Windows permissions.** Go uses only the owner-write bit of the mode on
  Windows, to set or clear the read-only attribute. The file is created
  writable and receives the ACLs inherited from its directory; `0600` does not
  restrict other accounts. Protect dumps by keeping them in a directory only
  you can access.
- **Network and removable filesystems** (SMB, NFS, FAT/exFAT on SD cards) may
  not provide atomic rename or reliable `fsync`. Errors they report are
  handled; guarantees they do not provide cannot be added by this tool.

## Tests

| Behavior | Tests |
| --- | --- |
| Same path, `./` and `..` aliases, case variants, symlinks both ways, hard links | `TestCheckOutputIsNotInput*`, `TestCLI_OutputIsInput` (with and without `-force`) |
| Existing output kept without `-force`, replaced with it | `TestWriteOutputFile_ExistingWithoutForce`, `TestWriteOutputFile_ExistingWithForce`, `TestCLI_ExistingOutput` |
| Dangling symlink not followed; `-force` replaces a link, not its target | `TestWriteOutputFile_Symlinks` |
| Destination created, or linked to the input, during the run | `TestWriteOutputFile_DestinationAppearsBeforeCreate`, `TestWriteOutputFile_DestinationLinkedBeforeRename` |
| Create, write (immediate, partial, short), sync, close and rename failures | `TestWriteOutputFile_InjectedFailures` |
| Cleanup failure reported | `TestWriteOutputFile_CleanupFailure` |
| Real rename failure keeps the destination | `TestWriteOutputFile_ReplaceFails` |
| Missing and read-only directories | `TestWriteOutputFile_MissingDirectory`, `TestWriteOutputFile_ReadOnlyDirectory` |
| Mode `0600` on POSIX, writable file on Windows | `TestWriteOutputFile_New`, `TestCLI_OutputPermissions` |
| No temporary files after success or handled failure | every test above checks the directory listing |

Failures are injected through the `fileOps` seam in `output.go`. The injected
operations wrap the real `*os.File`, so a "partial write" really leaves partial
data on disk and the cleanup is observed on the real filesystem.
