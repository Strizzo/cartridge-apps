# Cartridge Apps

The official, static app catalogue for CartridgeOS. No account, database, or hosted application server is required on the device. GitHub hosts this catalogue and each app's versioned release packages.

| App | Source and releases |
|---|---|
| Frequency | https://github.com/Strizzo/frequency-cartridge |
| Mission Control | https://github.com/Strizzo/mission-control-cartridge |
| Outside | https://github.com/Strizzo/outside-cartridge |

The Store in **CartridgeOS 0.6.0 or later** fetches [`catalog.json`](catalog.json). Its Ed25519 signature covers the exact UTF-8 `payload` string; the runtime pins the public key in `keys/cartridge-official-v1.pem`. Entries contain a versioned HTTPS package URL, SHA-256, byte size, minimum runtime version, and reviewed permissions. Each archive is a Lua cartridge with `cartridge.json` and `main.lua` at its root.

## Publishing an app update

1. Develop and test the app in its own repository. Bump `cartridge.json` and push a matching `vX.Y.Z` tag. Its workflow publishes the package, `release.json`, and checksums.
2. Review the release, then edit **apps.json** in this repository: repository, ID, version, package SHA-256 and size, source commit, and permissions. This explicit approval prevents an upstream release from silently becoming an official update.
3. Open a pull request. CI downloads the pinned package and validates its checksum, manifest, archive paths and permissions. Review/merge it to `main`.
4. When automatic signing is configured, the publish workflow signs the catalogue using the repository secret `CATALOG_SIGNING_KEY` and commits the resulting `catalog.json`. It never executes code from app packages. The device receives the new catalogue at its next Store refresh.

Maintainers can also run `python3 scripts/catalog.py` to validate without publishing, or `python3 scripts/catalog.py --verify` to verify the published signature and approved packages. Tests: `python3 -m unittest discover -s tests`. Requires Python 3.11+ and OpenSSL 3 for signing/verification; macOS Homebrew users can set `OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl`.

If no signing secret is configured, CI validates the index and leaves the existing locally signed catalogue in place. A maintainer signs locally with `python3 scripts/catalog.py --sign-key /path/to/private.pem`, verifies it, and commits `catalog.json`.

Private signing keys must never be committed. Rotating the pinned key requires a runtime update. This first version authenticates catalogue contents and packages; it does not implement TUF-style expiry or protection against replay of an older, correctly signed catalogue. GitHub availability is required for new installs; downloaded apps continue working offline to the extent their own services allow.

The repository and release workflows use GitHub's existing infrastructure and quotas. Paid apps, accounts, purchase receipts, reviews and analytics are outside this design.
