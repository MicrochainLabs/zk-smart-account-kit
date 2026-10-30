# ZK Labeled Signer — CLI Reference

All commands run from the `microchain-zk-signers/` directory with:
```
npx hardhat <task> --network <network> [params]
```

Supported networks: `polygon`, `polygonAmoy`, `sepolia`, `base`, `arbitrum`, `optimism`, `scroll`, `buildbear`, `localhost`, …

---

## Prerequisites

### 1. Compile the Noir circuits
Both Honk verifier `.sol` files must exist before deploying contracts.

```bash
cd noir
nargo compile

# zk_labeled_signer verifier
bb write_vk -b target/zk_labeled_signer.json -o target/zk_labeled_signer_vk --oracle_hash keccak
bb write_solidity_verifier -k target/zk_labeled_signer_vk/vk -o target/zk_labeled_signer.sol

# zk_signer_subset verifier
bb write_vk -b target/zk_signer_subset.json -o target/zk_signer_subset_vk --oracle_hash keccak
bb write_solidity_verifier -k target/zk_signer_subset_vk/vk  -o target/zk_signer_subset.sol
```

> Note: newer `bb` releases (v3.x nightly) renamed the `contract` subcommand to
> `write_solidity_verifier`. Run `bb write_solidity_verifier --help` to confirm
> the flags available in your installed version (e.g. `-t/--verifier_target`
> to pick `evm` vs `evm-no-zk`, etc.) if the command above still errors.

### 2. Set private key variables
```bash
npx hardhat vars set DEPLOYER_PRIVATE_KEY
npx hardhat vars set SAFE_OWNER_PRIVATE_KEY   # used as relayer in sendZKLabeledNexusUserOp
```

---

## Step 1 — Deploy the factory and verifiers

Deploys all supporting contracts once per network:
- `HonkVerifier` for `zk_labeled_signer`
- `ZKLabeledSignerProofVerifier` (ERC-8039 adapter)
- `HonkVerifier` for `zk_signer_subset`
- `ZKSignerSubsetProofVerifier` (ERC-8039 adapter)
- `ZKLabeledSignerValidator` (ERC-7579 module)
- `ZKLabeledSignerValidatorFactory`

```bash
npx hardhat createZKLabeledFactory \
  --network polygon \
  --mainsigners '[{"label":"alice","address":"0xAlice"},{"label":"bob","address":"0xBob"}]' \
  --owner 0x<address_allowed_to_rotate_root>
```

**Parameters**

| Flag | Description |
|---|---|
| `--mainsigners` | JSON array `[{label, address}]` — the org-wide master signer list. The task builds the LeanIMT from this list and computes `initialMainSignersRoot` on-the-fly (it is **not** passed as a raw `bytes32`). |
| `--owner` | Address that can call `updateMainSignersRoot` on the factory later (e.g. a multisig). |

> The command prints the deployed addresses of all 6 contracts. **Save the `ZKLabeledSignerValidator` and `ZKLabeledSignerValidatorFactory` addresses** — they are needed in every subsequent command.

Alternatively, deploy with Ignition directly:
```bash
npx hardhat ignition deploy ignition/modules/zkLabeledSignerFactoryNexus.ts \
  --network polygon \
  --parameters '{"ZKLabeledSignerFactory_v1":{"initialMainSignersRoot":"0x...","owner":"0x..."}}'
```

---

## Step 2 — Create a smart account

Proves that the account's signers are a subset of the org-wide registry, then deploys a Nexus account pre-configured with `ZKLabeledSignerValidator`.

```bash
npx hardhat createZKLabeledNexusAccount \
  --network polygon \
  --factoryaddress   0x<ZKLabeledSignerValidatorFactory> \
  --validatoraddress 0x<ZKLabeledSignerValidator> \
  --mainsignersroot  0x<factory_mainSignersRoot> \
  --mainsigners      '[{"label":"alice","address":"0xAlice"},{"label":"bob","address":"0xBob"}]' \
  --subsetsigners    '[{"label":"alice","address":"0xAlice"}]' \
  --contacts         '[{"label":"treasury","address":"0xTreasury"},{"label":"carol","address":"0xCarol"}]' \
  --protocols        '[{"label":"uniswap-v3","address":"0xUniswap"}]'
```

**Parameters**

| Flag | Description |
|---|---|
| `--factoryaddress` | Deployed `ZKLabeledSignerValidatorFactory` address. |
| `--validatoraddress` | Deployed `ZKLabeledSignerValidator` address. |
| `--mainsignersroot` | The factory's current `mainSignersRoot`. Must match what was used at factory deployment (or the latest rotation). |
| `--mainsigners` | JSON array `[{label, address}]` — the **full** org-wide signer list (used to build the LeanIMT and generate membership proofs). Order does not matter. |
| `--subsetsigners` | JSON array `[{label, address}]` — this account's signers (max 5). Every entry must be present in `--mainsigners`. |
| `--contacts` | JSON array `[{label, address}]` — initial private contact book. |
| `--protocols` | JSON array `[{label, address}]` — initial public protocol list. |

> The command prints the deployed **account address** and transaction hash.

---

## Step 3 — Send a UserOperation

Generates a `zk_labeled_signer` proof and submits the UserOp through the EntryPoint.

The signer's private key never touches this command — sign the UserOp hash
**offline** (e.g. with the signer's own wallet) and pass the resulting
`--signature` and `--userophash` in. Use `computeLabeledUserOpHash` (below) to
obtain the hash to sign.

```bash
npx hardhat sendZKLabeledNexusUserOp \
  --network polygon \
  --account        0x<NexusAccountAddress> \
  --validator      0x<ZKLabeledSignerValidator> \
  --to             0x<CallTarget> \
  --value          0 \
  --data           0x \
  --signature      0x<SignatureOverUserOpHash> \
  --userophash     0x<UserOpHash> \
  --signerlabel    alice \
  --subsetsigners  '[{"label":"alice","address":"0xAlice"}]' \
  --registrytype   contacts \
  --registryentries '[{"label":"treasury","address":"0xTreasury"},{"label":"carol","address":"0xCarol"}]' \
  --destlabel      treasury
```

**Parameters**

| Flag | Description |
|---|---|
| `--account` | Deployed Nexus account address. |
| `--validator` | `ZKLabeledSignerValidator` address. |
| `--entrypoint` | *(optional)* EntryPoint v0.7 address. Auto-detected from the account if omitted. |
| `--to` | Call target address. Must be registered in the chosen registry under `--destlabel`. |
| `--value` | Value in wei, or decimal native token (e.g. `"0.01"`). |
| `--data` | Call data as hex (use `0x` for a plain transfer). |
| `--signature` | ECDSA signature produced by the signer over `--userophash`. The recovered address must match an entry in `--subsetsigners`. |
| `--userophash` | The UserOp hash `--signature` was produced over. Recomputed on-chain from the current nonce/callData and compared against this value — if the nonce changed since signing, the command fails with a hash mismatch error. |
| `--signerlabel` | The signer's label name in the `signersRoot` (must match the entry used at account creation). |
| `--subsetsigners` | JSON array — all signers in this account's subset, exactly as used at account creation. |
| `--registrytype` | `contacts` or `protocols` — which registry the destination belongs to. |
| `--registryentries` | JSON array of the full contact book **or** protocol list (whichever `--registrytype` selects), exactly as used at account creation. |
| `--destlabel` | The destination address's label in the chosen registry. |

---

## Utility commands

### Predict account address (no deployment)

```bash
npx hardhat computeZKLabeledNexusAddress \
  --network polygon \
  --factory          0x<ZKLabeledSignerValidatorFactory> \
  --validator        0x<ZKLabeledSignerValidator> \
  --subsetsignersroot 0x<bytes32> \
  --contactsroot     0x<bytes32> \
  --protocolsroot    0x<bytes32> \
  --index            0
```

### Read on-chain roots for an account

```bash
npx hardhat getZKLabeledNexusConfig \
  --network polygon \
  --validator 0x<ZKLabeledSignerValidator> \
  --account   0x<NexusAccountAddress>
```

### Full account status report

```bash
npx hardhat checkZKLabeledNexusAccount \
  --network polygon \
  --account   0x<NexusAccountAddress> \
  --validator 0x<ZKLabeledSignerValidator>
```

Prints: deployed ✓, validator installed ✓, initialized ✓, all three roots, current nonce, and native token balance.

### Compute UserOp hash (without proving)

Use this to get the hash the signer must sign **before** calling
`sendZKLabeledNexusUserOp` — sign it offline (e.g. `cast wallet sign --no-hash <hash> --private-key <key>`
or the signer's own wallet), then pass the resulting signature via `--signature`
and this hash via `--userophash`.

Useful for inspecting the hash before committing to proof generation.

```bash
npx hardhat computeLabeledUserOpHash \
  --network polygon \
  --account   0x<NexusAccountAddress> \
  --validator 0x<ZKLabeledSignerValidator> \
  --to        0x<CallTarget> \
  --value     0 \
  --data      0x
```

---

## Structured JSON input format

Labels and addresses are always passed as JSON arrays. Label strings are UTF-8, max **31 bytes**, zero-padded internally.

```json
[
  { "label": "alice",     "address": "0xAliceAddress" },
  { "label": "uniswap-v3","address": "0xUniswapAddress" }
]
```

Use single quotes around the JSON string on the command line to avoid shell escaping issues.

---

## Typical end-to-end flow

```
[One-time per network]
createZKLabeledFactory
        │
        ▼
[Once per team account]
createZKLabeledNexusAccount
        │
        ▼
[Per transaction]
sendZKLabeledNexusUserOp
```
