# `vlt`

A file vault for protecting files at rest.

## Threat model

- Protects files at rest when the vault is locked.
- Does **not** protect against malware or an unlocked session.
- Does **not** consider memory-based attacks if unlocked.
- File names, contents and directory structure are hidden. The number of
  files and their approximate sizes are not.
- Does **not** detect rollback: anyone who can write to the vault directory
  can swap in an older, valid copy of the manifest, header or an object.

## Usage

```sh
vlt init my.vault                          # prints the recovery key once
vlt add  my.vault report.pdf --as tax/2025.pdf
vlt add  my.vault ~/photos                 # directories: recursive, all or nothing
vlt ls   my.vault tax
vlt get  my.vault tax/2025.pdf -o out.pdf  # `-o -` for stdout
vlt get  my.vault photos -o restored/      # into a new directory
vlt mv   my.vault tax archive/tax
vlt rm   my.vault tax/2025.pdf             # `-r` for a directory
vlt fsck my.vault --verify                 # `gc` cleans up after crashes
```

Files keep their mtime and permission bits (never setuid/setgid). Symlinks
are skipped, and empty directories aren't stored.
