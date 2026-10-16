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
vlt ls   my.vault tax
vlt get  my.vault tax/2025.pdf -o out.pdf  # `-o -` for stdout
vlt rm   my.vault tax/2025.pdf
```
