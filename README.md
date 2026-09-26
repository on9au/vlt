# `vlt`

A file vault for protecting files at rest.

## Threat model

- Protects files at rest when the vault is locked.
- Does **not** protect against malware or an unlocked session.
- Does **not** consider memory-based attacks if unlocked.
