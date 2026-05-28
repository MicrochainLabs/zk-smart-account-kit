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
│   ├── zk_multisig/             # M-of-N threshold signature logic
│   └── zk_scope/                # Programmable transaction access control
│
└── circuits/                    # Executable circuits (type = "bin")
    ├── zk_multi_sig_ecdsa/                          # Main threshold signature circuit
    ├── zk_multi_sig_ecdsa_private_state_validation/ # State commitment validation circuit
    ├── zk_label_binding/                            # Label-to-signer binding circuit
    ├── zk_multi_sig_label_binding/                  # Multi-sig + label binding combined
    └── zk_scope_validation/                         # Transaction scope policy circuit
```

---

## Libraries

### `lib/zk_signer`

The cryptographic foundation. Verifies secp256k1 ECDSA signatures inside a Noir circuit, recovers the Ethereum address, and encodes it as a BN254 field element. Used by every other library and circuit in this kit.

**Key exports:**
- `verify_ecdsa_get_address(pubkey, sig, hash)` — ECDSA verification + address recovery
- `signer_leaf(address)` — Poseidon2 leaf hash of a signer address
- `address_to_field(address)` — 20-byte address → BN254 field element
- `cmp_gt(a, b)` — constant-time comparison (used for anti-replay ordering)

### `lib/zk_labels`

Binds human-readable labels (e.g. `"cfo"`, `"auditor"`, `"treasury"`) to Ethereum addresses in a Merkle tree. Proves label membership without revealing the full registry.

**Dependencies:** `binary_merkle_root`, `poseidon`

**Key exports:**
- `verify_label_membership(label, address, root, proof)` — Merkle membership proof
- `label_leaf(label, address)` — Poseidon leaf hash for a label-address binding

### `lib/zk_multisig`

Implements M-of-N threshold signature logic. Verifies that M distinct authorized signers (from a committed signer set) have signed a given message, without revealing their identities.

**Key constants:**
- `MAX_SIGNERS = 5`, `MAX_THRESHOLD = 5`, `SIGNERS_MAX_DEPTH = 4`

**Key exports:**
- `compute_state_root(signers_root, threshold)` — reconstructs the on-chain `stateRoot`
- `verify_multisig(signers, sigs, hash, state_root, threshold)` — full M-of-N check

### `lib/zk_scope`

Defines per-address transaction authorization rules (allowed targets, calldata patterns, value ranges). Proves that a transaction complies with a committed policy without disclosing the full rule set.

---

## Circuits

| Circuit | Libraries used | Purpose |
|---|---|---|
| `zk_multi_sig_ecdsa` | `zk_signer`, `zk_multisig` | Prove M-of-N signers approved a transaction |
| `zk_multi_sig_ecdsa_private_state_validation` | `zk_signer`, `zk_multisig` | Prove a signer set + threshold commitment is valid |
| `zk_label_binding` | `zk_signer`, `zk_labels` | Prove a label is bound to a signer in the registry |
| `zk_multi_sig_label_binding` | `zk_signer`, `zk_labels`, `zk_multisig` | Prove M-of-N signers with label membership |
| `zk_scope_validation` | `zk_scope` | Prove a transaction satisfies the committed scope policy |

---

## Smart Account Integration

The circuits in this kit produce proofs that are verified on-chain via the [ERC-8039](https://eips.ethereum.org/EIPS/eip-8039) interface — a proof-system-agnostic standard analogous to EIP-1271 for ZK proofs.

### Safe

Deploy a `ZKMultiSigEcdsaFactory` and use the resulting proxy as a Safe owner. The proxy stores `stateRoot` and `verifier` as immutables and delegates all calls to the singleton, which verifies the ZK proof via ERC-8039.

### Nexus (ERC-7579)

Install `ZKMultiSigValidator` as a validator module on any ERC-7579 account. Each account stores its own `stateRoot`. The module validates ERC-4337 `UserOperation`s and EIP-1271 signatures by verifying a ZK proof.

> The Solidity adapter contracts live in the [microchain-zk-signers](https://github.com/microchainlabs/microchain-zk-signers) repository.

---

## Prerequisites

- [Noir](https://noir-lang.org) — tested with the version specified in each `Nargo.toml`
- [Barretenberg](https://github.com/AztecProtocol/barretenberg) (`bb`) for UltraHonk proving

## Getting Started

```bash
# Compile all circuits
nargo build

# Run tests (if any)
nargo test

# Compile a specific circuit
cd circuits/zk_multi_sig_ecdsa && nargo build

# Generate a proof (example)
cd circuits/zk_multi_sig_ecdsa
nargo execute
bb prove -b ./target/zk_multi_sig_ecdsa.json -w ./target/zk_multi_sig_ecdsa.gz -o ./target/proof
```

---

## Proof System

All circuits target the **BN254** scalar field and use:

- **Poseidon2** for hashing (signer leaves, state roots, label leaves)
- **LeanIMT / Binary Merkle Tree** for membership proofs
- **secp256k1** for ECDSA signature verification
- **UltraHonk / Barretenberg** as the default backend

---

## License

MIT — see [LICENSE](LICENSE)

---

## Author

[Microchain Labs](https://microchainlabs.xyz)
