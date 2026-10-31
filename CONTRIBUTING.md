# Contributing to zk-smart-account-kit

Thank you for your interest in contributing! This kit provides reusable Noir circuits and ERC-8039 verifier/validator contracts for privacy-preserving smart accounts — all contributions are welcome.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Running Tests](#running-tests)
- [Branching Model](#branching-model)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Good First Issues](#good-first-issues)

---

## Code of Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). By participating you agree to uphold it. Report unacceptable behavior to the maintainers at **security@microchainlabs.xyz**.

---

## Prerequisites

Install the following tools before starting:

| Tool | Version | Purpose |
|---|---|---|
| [Node.js](https://nodejs.org/) | v18+ | TypeScript tooling |
| [pnpm](https://pnpm.io/) | latest | Package manager |
| [Foundry](https://book.getfoundry.sh/getting-started/installation) (`forge`, `cast`) | latest | Solidity compilation & testing |
| [Nargo](https://noir-lang.org/docs/getting_started/installation/) | `1.0.0-beta.18` | Noir circuit compilation |
| [Barretenberg CLI](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg) (`bb`) | `3.0.0-nightly.20260102` | Proof generation & Solidity verifier generation |
| Git | any | Source control |

> **Note on Noir/bb versions**: The circuits currently target Noir `1.0.0-beta.18` (they do not yet compile with `beta.22`). CI pins the versions above (see `.github/workflows/ci.yml`); use `noirup -v 1.0.0-beta.18` and `bbup -v 3.0.0-nightly.20260102` locally.

---

## Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/MicrochainLabs/zk-smart-account-kit.git
cd zk-smart-account-kit

# 2. Install Node.js dependencies
pnpm install

# 3. Compile Noir circuits
cd noir
nargo compile --workspace
cd ..

# 4. Generate Solidity verifiers from the circuits
#    (required before compiling the contracts; noir/target is gitignored)
cd noir
for circuit in zk_labeled_signer zk_labeled_signer_scope zk_signer_subset; do
  bb write_vk -b "./target/${circuit}.json" -o "./target/${circuit}" --oracle_hash keccak
  bb write_solidity_verifier -k "./target/${circuit}/vk" -o "./target/${circuit}.sol"
done
cd ..

# 5. Compile Solidity contracts
npx hardhat compile
# or
forge build
```

---

## Project Structure

```
contracts/            Solidity smart contracts
  ERC1271/            Signature validation interface
  ERC8039/            Proof-system agnostic verifier adapters
  nexus/              Nexus (ERC-7579) validator modules and factories
noir/                 Noir workspace
  lib/                Reusable circuit libraries (zk_signer, zk_labels, zk_scope)
  circuits/           Executable circuits (zk_signers, zk_labeled_signer,
                      zk_labeled_signer_scope, zk_signer_subset, ...)
lib/                  Vendored Solidity dependencies
deploy/               Hardhat deployment scripts
ignition/             Hardhat Ignition deployment modules
zknexus/              Nexus integration TypeScript utilities
```

---

## Making Changes

### Solidity contracts

- Follow the existing style (no linter config yet — match surrounding code).
- All public/external functions should have corresponding tests.
- Do not change compiler version (`foundry.toml` / `hardhat.config.ts`) without discussion.

### Noir circuits (`noir/`)

- Changes to circuit logic **must** be reflected in the generated Solidity verifiers (see step 4 above); CI regenerates them from source.
- Circuit public inputs are part of the on-chain ABI — changes are breaking and require a discussion issue first.
- Test circuits with `nargo test --workspace` inside `noir/` before opening a PR.

### TypeScript (`zknexus/`, `deploy/`)

- The project uses `viem` for Ethereum interactions — do not introduce `ethers.js`.
- Follow existing patterns in `zknexus/zklabeled.ts`.

### Adding a new ERC-8039 verifier adapter

This is one of the most impactful contributions. To add support for a new proof system (Groth16, PLONK, SP1, etc.):

1. Create `contracts/ERC8039/YourSystemProofVerifier.sol` implementing `IERC8039`.
2. Deploy and register the verifier address with the factory.
3. Add integration tests in `test/`.
4. Update `README.md` to list the new proof system.

---

## Running Tests

```bash
# Noir circuit tests (run by CI)
cd noir && nargo test --workspace

# Solidity build (run by CI; needs the generated verifiers, see step 4)
forge build --sizes

# Hardhat / Foundry tests, once a test suite exists in test/
npx hardhat test
forge test
```

---

## Branching Model

| Branch | Purpose |
|---|---|
| `main` | Latest released code. Every release is a tagged commit (`vX.Y.Z`). Protected: no direct pushes. |
| `develop` | Integration branch for the next release. **All contributor PRs target this branch.** Protected: PR-only, CI and review required. |

Short-lived branches:

- `feat/*`, `fix/*`, `docs/*`, `test/*`, `chore/*`: branch from `develop`, merge back into `develop` via PR (squash-merge).
- `release/x.y.z` (maintainers): branch from `develop` to stabilise a release, then merge into `main`, tag, and merge back into `develop`.
- `hotfix/*` (maintainers): branch from `main` for urgent fixes (e.g. security), merge into `main`, tag a patch release, then merge back into `develop`.

Releases are cut by merging `develop` (or a `release/*` branch) into `main` with a merge commit. To release, bump `version` in `package.json` in the PR that goes to `main`. Once CI passes on `main`, the [Release workflow](.github/workflows/release.yml) creates the `vX.Y.Z` tag and a GitHub Release with auto-generated notes plus the compiled circuits and Solidity verifiers. If the version is unchanged (tag already exists), no release is created. Versions containing a hyphen (e.g. `2.1.0-rc.1`) are published as pre-releases. Security issues must **not** be reported through public PRs; see [SECURITY.md](./SECURITY.md).

---

## Submitting a Pull Request

1. **Fork** the repository and create a branch from `develop`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make your changes and **commit with clear messages**.
3. Ensure **all tests pass** before opening a PR.
4. Circuit changes: make sure `nargo test --workspace` and the verifier generation step pass (CI runs both).
5. Open a PR against `develop` and fill in the pull request template.
6. A maintainer will review and may request changes.

### Commit message conventions

```
feat: add Groth16 verifier adapter
fix: prevent duplicate signer addresses in circuit
docs: clarify state root construction
test: add threshold boundary tests
chore: update Noir dependencies
```

---

## Good First Issues

Look for issues labelled [`good first issue`](../../issues?q=label%3A%22good+first+issue%22) on GitHub. Some areas that are always welcome:

- Additional test coverage for edge cases in the Noir circuits
- CLI tooling to generate ZK proofs locally (wrapping `bb` and `nargo`)
- Testnet deployment scripts and documentation
- New ERC-8039 verifier adapters for additional proof systems
- Gas optimization in the Solidity verifier contracts
- Improving inline documentation

If you have an idea that doesn't have an issue yet, open one first to discuss before building.
