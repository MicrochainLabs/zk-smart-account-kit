# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are published automatically by `.github/workflows/release.yml` when the `version` in `package.json` is bumped and merged into `main` (contributor PRs go to `develop`).

## [Unreleased]

### Changed

- Relicensed the project to Apache-2.0 (previously MIT `LICENSE` with mixed MIT/LGPL-3.0 SPDX headers).
- `foundry.toml` now pins solc `0.8.29`, `cancun` and the optimizer (`runs = 20`, matching Hardhat) so `forge build` succeeds.

### Added

- GitHub Actions CI (Noir tests, verifier generation, Solidity build) and release workflow.
- Issue and pull request templates, `CODE_OF_CONDUCT.md`, `NOTICE`, this changelog, README badges and package metadata.

## [0.0.1]

Initial pre-production version: labeled signer and labeled signer scope circuits, signer subset circuit, ERC-8039 verifier adapters and Nexus validators.
