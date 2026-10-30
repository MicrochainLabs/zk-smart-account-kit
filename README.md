# zk-smart-account-kit

**Composable zero-knowledge primitives for smart accounts — built with Noir**

A suite of Noir circuit libraries and executable circuits for privacy-preserving identity, threshold signatures, and programmable access control. Designed to integrate natively with [Safe](https://safe.global) and [Nexus (ERC-7579)](https://erc7579.com) smart accounts via the [ERC-8039](https://eips.ethereum.org/EIPS/eip-8039) proof verification standard.

---

## Overview

Traditional smart account authorization leaks sensitive data on-chain: signer addresses, approval thresholds, and access policies are all publicly visible. This kit replaces those on-chain disclosures with zero-knowledge proofs.

Only a cryptographic commitment (a Merkle root called `stateRoot`) is stored on-chain. The ZK proof proves that the authorization policy was satisfied — without revealing which signers approved, what the full policy is, or any other sensitive details.

---

## Repository Structure

```
zk-smart-account-kit/
├── Nargo.toml                   # Noir workspace manifest
│
├── lib/                         # Reusable circuit libraries (type = "lib")
│   ├── zk_signer/               # ECDSA address recovery inside ZK
│   ├── zk_labels/               # Privacy-preserving identity / role naming
│   └── zk_scope/                # Programmable transaction access control
│
└── circuits/                    # Executable circuits (type = "bin")
    ├── zk_signers/                                  # Single-signer ECDSA authorization circuit
    ├── zk_label_binding/                            # Label-to-signer binding circuit
    └── zk_scope_validation/                         # Transaction scope policy circuit
```

> M-of-N threshold signature logic (`zk_multisig`) and the multi-sig circuits (`zk_multi_sig_ecdsa`, `zk_multi_sig_ecdsa_private_state_validation`, `zk_multi_sig_label_binding`) are no longer part of this kit. They live in the [microchain-zk-signers](https://github.com/MicrochainLabs/microchain-zk-signers) repository.

---

## Libraries

### `lib/zk_signer`

The cryptographic foundation. Verifies secp256k1 ECDSA signatures inside a Noir circuit, recovers the Ethereum address, and encodes it as a BN254 field element. Used by every other library and circuit in this kit.

**Key exports:**
- `verify_ecdsa_get_address(pubkey, sig, hash)` — ECDSA verification + address recovery
- `signer_leaf(address)` — Poseidon1 leaf hash of a signer address
- `address_to_field(address)` — 20-byte address → BN254 field element
- `cmp_gt(a, b)` — constant-time comparison (used for anti-replay ordering)

### `lib/zk_labels`

Binds human-readable labels (e.g. `"cfo"`, `"auditor"`, `"treasury"`) to Signer identifier(e.g. Ethereum addresse) in a Merkle tree. Proves label membership without revealing the full registry.

**Dependencies:** `binary_merkle_root`, `poseidon`

**Key exports:**
- `verify_label_membership(label, address, root, proof)` — Merkle membership proof
- `label_leaf(label, address)` — Poseidon leaf hash for a label-address binding

### `lib/zk_scope`

Defines per-account transaction authorization rules (allowed targets, calldata patterns, value ranges). Proves that a transaction complies with a committed policy without disclosing the full rule set.

---

## Circuits

| Circuit | Libraries used | Purpose |
|---|---|---|
| `zk_signers` | `zk_signer` | Prove a single authorized signer approved a transaction |
| `zk_label_binding` | `zk_signer`, `zk_labels` | Prove a label is bound to a signer in the registry |
| `zk_scope_validation` | `zk_scope` | Prove a transaction satisfies the committed scope policy |

---

## Smart Account Integration

The circuits in this kit produce proofs that are verified on-chain via the [ERC-8039](https://eips.ethereum.org/EIPS/eip-8039) interface — a proof-system-agnostic standard analogous to EIP-1271 for ZK proofs.

### Safe

Deploy a `ZKMultiSigEcdsaFactory` and use the resulting proxy as a Safe owner. The proxy stores `stateRoot` and `verifier` as immutables and delegates all calls to the singleton, which verifies the ZK proof via ERC-8039.

### Nexus (ERC-7579)

Install `ZKMultiSigValidator` as a validator module on any ERC-7579 account. Each account stores its own `stateRoot`. The module validates ERC-4337 `UserOperation`s by verifying a ZK proof.

> The multi-sig circuits and the Solidity adapter contracts live in the [microchain-zk-signers](https://github.com/MicrochainLabs/microchain-zk-signers) repository.

---

## Prerequisites

| Tool | Version | Install |
|---|---|---|
| [Noir / nargo](https://noir-lang.org) | `1.0.0-beta.18` | `noirup -v 1.0.0-beta.18` |
| [Barretenberg / bb](https://github.com/AztecProtocol/barretenberg) | `3.0.0-nightly.20260102` | `bbup -v 3.0.0-nightly.20260102` |

## Getting Started

### 1. Compile all circuits

```bash
# From the workspace root — compiles every lib and circuit
nargo build
```

### 2. Run tests

```bash
# Run all test functions across the workspace
nargo test

# Run tests for a single circuit with output
nargo test --package zk_signers --show-output
```

### 3. Generate the witness (execute)

The `Prover.toml` file in each circuit directory provides the private inputs.

```bash
cd circuits/zk_signers
nargo execute
# Produces: target/zk_signers.gz
```

### 4. Generate a proof

```bash
bb prove \
  -b ./target/zk_signers.json \
  -w ./target/zk_signers.gz \
  -o ./target/proof
# Produces: target/proof/proof
```

### 5. Generate the verification key (VK)

```bash
bb write_vk \
  -b ./target/zk_signers.json \
  -o ./target/vk
# Produces: target/vk/vk
```

### 6. Verify a proof

```bash
bb verify \
  -k ./target/vk/vk \
  -p ./target/proof/proof
# Exits 0 on success
```

### Full one-liner (build → witness → prove → write_vk → verify)

Replace `<circuit>` with any circuit name (e.g. `zk_signers`, `zk_scope_validation`, ...).

```bash
CIRCUIT=zk_signers
cd circuits/$CIRCUIT
nargo build
nargo execute
bb prove  -b ./target/$CIRCUIT.json -w ./target/$CIRCUIT.gz -o ./target/proof
bb write_vk -b ./target/$CIRCUIT.json -o ./target/vk
bb verify -k ./target/vk/vk -p ./target/proof/proof
```

---

## Proof System

All circuits target the **BN254** scalar field and use:

- **Poseidon1** for signer leaves; **Poseidon2** for state roots, label leaves, scope rule leaves
- **Binary Merkle Tree** (`binary_merkle_root`) for membership proofs
- **secp256k1** for ECDSA signature verification
- **UltraHonk / Barretenberg** as the default backend

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

[Microchain Labs](https://microchainlabs.xyz)
