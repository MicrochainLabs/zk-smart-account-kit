# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are published automatically by `.github/workflows/release.yml` when the `version` in `package.json` is bumped and merged into `main` (contributor PRs go to `develop`).

## [Unreleased]

### Changed

- Upgraded Noir to `1.0.0-beta.22` and Barretenberg (`bb`, `@aztec/bb.js`) to `5.0.0-nightly.20260522`, with `@noir-lang/noir_js` `1.0.0-beta.22`.
- Circuits: Merkle path indices are now `bool` instead of `u1` (breaking ABI change for proof inputs); `binary_merkle_root` is replaced by the new `merkle_tree` lib (zk-kit `merkle-trees` v0.0.3); `poseidon` v0.3.0, `keccak256` v0.1.2.
- Generated HonkVerifiers now link an external `RelationsLib`; Ignition factory modules deploy and link it.
- Relicensed the project to Apache-2.0 (previously MIT `LICENSE` with mixed MIT/LGPL-3.0 SPDX headers).
- `foundry.toml` now pins solc `0.8.29`, `cancun` and the optimizer (`runs = 20`, matching Hardhat) so `forge build` succeeds.

### Added

- GitHub Actions CI (Noir tests, verifier generation, Solidity build) and release workflow.
- Issue and pull request templates, `CODE_OF_CONDUCT.md`, `NOTICE`, this changelog, README badges and package metadata.

## [0.0.1]

Initial pre-production version: labeled signer and labeled signer scope circuits, signer subset circuit, ERC-8039 verifier adapters and Nexus validators.
