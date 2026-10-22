# Output file safety

How `proxmark3-to-flipper` writes the `-o` file, what it guarantees and where
the guarantees end. Implemented in [`output.go`](../output.go), tested in
[`output_test.go`](../output_test.go) and [`main_test.go`](../main_test.go).

## Usage

```
proxmark3-to-flipper -i dump.json -o card.nfc          # fails if card.nfc exists
proxmark3-to-flipper -i dump.json -o card.nfc -force   # replaces card.nfc
```

An existing output is kept, and the command fails with
`refusing to overwrite existing file (use -force to replace it)`. This and every
other output error exits with status 1.

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

The guarantees depend on how the run ends and on the platform. All of them
assume that no other process changes the files involved while the command runs
(see "Concurrent modification" below).

### Always, whatever the outcome

- The input file is only opened for reading. An output that is the input file
  is refused before anything is written.
- An invalid dump never touches the output: parsing and rendering finish before
  any output file is opened.
- Without `-force`, an existing output is never opened for writing, because the
  exclusive create fails. This also holds if the file appears during the run.
- With `-force`, the destination is never deleted or truncated. It changes only
  through `rename`.

### The command reports success (exit 0)

Every `Write`, `Sync`, `Close` and `Rename` call returned without error. On a
local POSIX filesystem the output then has the complete new content with mode
`0600`, minus any bits the umask removes. With `-force`, other processes see
either the old or the new file, never a partial one: POSIX specifies that
`rename` replaces the destination name atomically for concurrent observers. On
Windows the outcome after a successful replacement is the same, but see the
Windows notes below.

`Sync` asks the operating system to flush the file to storage: `fsync` on Linux,
`F_FULLFSYNC` on macOS, `FlushFileBuffers` on Windows. Success means the OS
accepted the request. It is not proof that every device or filesystem layer
(write caches, network servers, USB card readers) persisted the data.

### The command reports a failure (exit 1)

Any failed `Write` (including a short write), `Sync`, `Close` or `Rename` is
reported; a failure is never turned into success.

- **Without `-force`:** the new output file that the attempt created is
  removed. If removal also fails, both errors are printed and the leftover file
  is named.
- **With `-force`:** the temporary file is removed (or reported as left
  behind), and the destination keeps its previous content, because nothing
  wrote to it.

### The process is killed or the machine loses power

No cleanup runs, so nothing is promised beyond what the filesystem provides:

- Without `-force`, a partial output may remain. It is written with a single
  `write` call, so the window is small.
- With `-force`, a `.<name>.*.tmp` file may remain. Whether the destination
  then holds the old or the new content after a power loss depends on the
  filesystem's crash consistency for `rename`, which POSIX does not specify.
- The directory is not synced after the rename, so a rename made shortly before
  a power loss may not survive it.

### POSIX local filesystems (ext4, XFS, APFS, …)

`rename` replaces the destination in one step for other processes. `-force`
also replaces a read-only destination, because the permission check applies to
the directory. The replacement is a new file with mode `0600`: the old file's
mode, owner, extended attributes and other hard links are not carried over.

### Windows

- **Replacement.** Go's `os.Rename` calls `MoveFileEx` with
  `MOVEFILE_REPLACE_EXISTING`. Microsoft does not document this as atomic, and
  `ReplaceFile` is not used. This tool never deletes the destination itself, so
  a failed call leaves the old file in place. On NTFS, replacing a read-only
  destination, or one that another process holds open, fails with "Access is
  denied" and the old file is kept; Linux and macOS replace both.
  `TestWriteOutputFile_ForcePlatformBehavior` runs on every platform in CI and
  asserts that either outcome loses no data and leaves no temporary file.
- **Permissions.** Go uses only the owner-write bit of the mode on Windows, to
  set or clear the read-only attribute. The file is created writable and gets
  the ACLs inherited from its directory, so `0600` does not restrict other
  accounts. Keep dumps in a directory only you can access.

### Network and removable filesystems

SMB, NFS, FUSE and FAT/exFAT (for example, an SD card in a reader) may not make
`rename` atomic, may report write errors late or not at all, and may ignore
flush requests. Errors they do report are handled as above. Guarantees they do
not provide cannot be added by this tool. Prefer writing to a local disk and
copying the result.

### Concurrent modification

The identity check is made once, before writing; it does not defend against
another process swapping files during the run. Two cases stay safe anyway,
because of how the output is written (both tested):

- Without `-force`, `O_EXCL` refuses a destination that appears later.
- With `-force`, `rename` replaces the destination *name*, so a symlink or hard
  link to the input created just before the rename is replaced and the input
  survives.

Swapping a directory component of the output path for a symlink to the
input's directory, between the check and the rename, is not detected.

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
| Mode `0600` on POSIX (never wider, whatever the umask), writable file on Windows | `TestWriteOutputFile_New`, `TestCLI_OutputPermissions`, `TestCLI_OutputPermissionsUnderUmask` |
| No temporary files after success or handled failure | every test above checks the directory listing |

Failures are injected through the `fileOps` seam in `output.go`. The injected
operations wrap the real `*os.File`, so a "partial write" really leaves partial
data on disk and the cleanup is observed on the real filesystem.
