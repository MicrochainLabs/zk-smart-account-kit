# ZK Labeled Signer + Scope — CLI Reference

All commands run from the `microchain-zk-signers/` directory with:
```
npx hardhat <task> --network <network> [params]
```

Supported networks: `polygon`, `polygonAmoy`, `sepolia`, `base`, `arbitrum`, `optimism`, `scroll`, `buildbear`, `localhost`, …

This is the counterpart to [ZKLABELED_CLI.md](./ZKLABELED_CLI.md) for the
`zk_labeled_signer_scope` circuit/contract stack. The key difference: there is
no separate contacts/protocols registry — every destination is registered as a
**labeled scope rule** (label + target + allowed selector/value/calldata-param
constraints, or a wildcard meaning "no restriction") in a single **unified scope
tree** (`scopeRoot`).

> ⚠️ **Known gaps as of writing** — these commands are wired up but not yet
> runnable end-to-end:
> 1. The `zk_labeled_signer_scope` circuit is currently only compiled under
>    `zk-smart-account-kit/noir/target/zk_labeled_signer_scope.json`. It must be
>    copied/recompiled to `microchain-zk-signers/noir/target/zk_labeled_signer_scope.json`
>    before `sendZKLabeledScopeNexusUserOp` (or any direct call to
>    `proveLabeledSignerScopeTx`) can generate a proof.
> 2. No Solidity `HonkVerifier` has been generated yet for this circuit (see
>    Prerequisites below) — `createZKLabeledScopeFactory` will fail to compile
>    until `noir/target/zk_labeled_signer_scope.sol` exists.

---

## Prerequisites

### 1. Compile the Noir circuit and generate its Solidity verifier

```bash
cd noir
nargo compile

# zk_labeled_signer_scope verifier
bb write_vk -b target/zk_labeled_signer_scope.json -o target/zk_labeled_signer_scope_vk --oracle_hash keccak
bb write_solidity_verifier -k target/zk_labeled_signer_scope_vk/vk -o target/zk_labeled_signer_scope.sol
```

> Note: newer `bb` releases (v3.x nightly) renamed the `contract` subcommand to
> `write_solidity_verifier`. Run `bb write_solidity_verifier --help` to confirm
> the flags available in your installed version.

The `zk_signer_subset` verifier (used for account creation) is shared with the
plain ZK Labeled Signer stack — see [ZKLABELED_CLI.md](./ZKLABELED_CLI.md)'s
Prerequisites section if it hasn't been generated yet.

### 2. Set private key variables
```bash
npx hardhat vars set DEPLOYER_PRIVATE_KEY
npx hardhat vars set SAFE_OWNER_PRIVATE_KEY   # used as relayer in sendZKLabeledScopeNexusUserOp
```

---

## Step 1 — Deploy the factory and verifiers

Deploys all supporting contracts once per network:
- `HonkVerifier` for `zk_labeled_signer_scope`
- `ZKLabeledSignerScopeProofVerifier` (ERC-8039 adapter)
- `HonkVerifier` for `zk_signer_subset`
- `ZKSignerSubsetProofVerifier` (ERC-8039 adapter)
- `ZKLabeledSignerScopeValidator` (ERC-7579 module)
- `ZKLabeledSignerScopeValidatorFactory`

```bash
npx hardhat createZKLabeledScopeFactory \
  --network polygon \
  --mainsigners '[{"label":"alice","address":"0xAlice"},{"label":"bob","address":"0xBob"}]' \
  --owner 0x<address_allowed_to_rotate_root>
```

**Parameters**

| Flag | Description |
|---|---|
| `--mainsigners` | JSON array `[{label, address}]` — the org-wide master signer list. The task builds the tree from this list and computes `initialMainSignersRoot` on-the-fly (it is **not** passed as a raw `bytes32`). |
| `--owner` | Address that can call `updateMainSignersRoot` on the factory later (e.g. a multisig). |

> The command prints the deployed addresses of all 6 contracts. **Save the `ZKLabeledSignerScopeValidator` and `ZKLabeledSignerScopeValidatorFactory` addresses** — they are needed in every subsequent command.

Alternatively, deploy with Ignition directly:
```bash
npx hardhat ignition deploy ignition/modules/zkLabeledSignerScopeFactoryNexus.ts \
  --network polygon \
  --parameters '{"ZKLabeledSignerScopeFactory_v1":{"initialMainSignersRoot":"0x...","owner":"0x..."}}'
```

---

## Step 2 — Create a smart account

Proves that the account's signers are a subset of the org-wide registry, then deploys a Nexus account pre-configured with `ZKLabeledSignerScopeValidator`.

```bash
npx hardhat createZKLabeledScopeNexusAccount \
  --network polygon \
  --factoryaddress   0x<ZKLabeledSignerScopeValidatorFactory> \
  --validatoraddress 0x<ZKLabeledSignerScopeValidator> \
  --mainsignersroot  0x<factory_mainSignersRoot> \
  --mainsigners      '[{"label":"alice","address":"0xAlice"},{"label":"bob","address":"0xBob"}]' \
  --subsetsigners    '[{"label":"alice","address":"0xAlice"}]' \
  --scoperules       '[{"label":"treasury","target":"0xTreasury","selectorField":"0","valueMax":"340282366920938463463374607431768211455","constraints":[{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"}]}]'
```

**Parameters**

| Flag | Description |
|---|---|
| `--factoryaddress` | Deployed `ZKLabeledSignerScopeValidatorFactory` address. |
| `--validatoraddress` | Deployed `ZKLabeledSignerScopeValidator` address. |
| `--mainsignersroot` | The factory's current `mainSignersRoot`. Must match what was used at factory deployment (or the latest rotation). |
| `--mainsigners` | JSON array `[{label, address}]` — the **full** org-wide signer list. Order does not matter. |
| `--subsetsigners` | JSON array `[{label, address}]` — this account's signers (max 5). Every entry must be present in `--mainsigners`. |
| `--scoperules` | JSON array of `LabeledScopeRule` — the initial unified scope tree. Each entry is `{label, target, selectorField, valueMax, constraints}`. Use `selectorField: "0x100000000"` (the `WILDCARD_SELECTOR` sentinel, decimal `4294967296`) and `valueMax: "340282366920938463463374607431768211455"` (max u128, `WILDCARD_VALUE_MAX`) with all-`constraintType:0` constraints to register an **unrestricted** destination — this is the common case for a plain contact/protocol entry with no rule. |

> The command prints the deployed **account address** and transaction hash.

---

## Step 3 — Send a UserOperation

Generates a `zk_labeled_signer_scope` proof and submits the UserOp through the EntryPoint.

The signer's private key never touches this command — sign the UserOp hash
**offline** (e.g. with the signer's own wallet) and pass the resulting
`--signature` and `--userophash` in. Use `computeLabeledScopeUserOpHash` (below)
to obtain the hash to sign.

```bash
npx hardhat sendZKLabeledScopeNexusUserOp \
  --network polygon \
  --account        0x<NexusAccountAddress> \
  --validator      0x<ZKLabeledSignerScopeValidator> \
  --to             0x<CallTarget> \
  --value          0 \
  --data           0x \
  --signature      0x<SignatureOverUserOpHash> \
  --userophash     0x<UserOpHash> \
  --signerlabel    alice \
  --subsetsigners  '[{"label":"alice","address":"0xAlice"}]' \
  --destlabel      treasury \
  --rule           '{"label":"treasury","target":"0xTreasury","selectorField":"4294967296","valueMax":"340282366920938463463374607431768211455","constraints":[{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"}]}' \
  --scoperules     '[{"label":"treasury","target":"0xTreasury","selectorField":"4294967296","valueMax":"340282366920938463463374607431768211455","constraints":[{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"},{"constraintType":0,"value":"0"}]}]'
```

**Parameters**

| Flag | Description |
|---|---|
| `--account` | Deployed Nexus account address. |
| `--validator` | `ZKLabeledSignerScopeValidator` address. |
| `--entrypoint` | *(optional)* EntryPoint v0.7 address. Auto-detected from the account if omitted. |
| `--to` | Call target address. Must equal `rule.target`. |
| `--value` | Value in wei, or decimal native token (e.g. `"0.01"`). Becomes a PUBLIC circuit input, matched against `rule.valueMax` on-chain unless the rule is a wildcard. |
| `--data` | Call data as hex (use `0x` for a plain transfer). Its leading 4 bytes (if any) and up to 4 following 32-byte words are decoded here exactly like `ZKLabeledSignerScopeValidator._extractCallDetails` decodes them on-chain — keep this in sync if that on-chain extraction logic ever changes. |
| `--signature` | ECDSA signature produced by the signer over `--userophash`. The recovered address must match an entry in `--subsetsigners`. |
| `--userophash` | The UserOp hash `--signature` was produced over. Recomputed on-chain from the current nonce/callData and compared against this value — if the nonce changed since signing, the command fails with a hash mismatch error. |
| `--signerlabel` | The signer's label name in the `signersRoot` (must match the entry used at account creation). |
| `--subsetsigners` | JSON array — all signers in this account's subset, exactly as used at account creation. |
| `--destlabel` | The destination's label (private input) — must match `rule.label`. |
| `--rule` | JSON `LabeledScopeRule` — the specific rule this call is proven against. `rule.target` must equal `--to`. |
| `--scoperules` | JSON array of **every** `LabeledScopeRule` in the account's unified scope tree, exactly as used when `scopeRoot` was built — needed to rebuild the Merkle tree and locate `--rule`'s proof. |

---

## Utility commands

### Predict account address (no deployment)

```bash
npx hardhat computeZKLabeledScopeNexusAddress \
  --network polygon \
  --factory           0x<ZKLabeledSignerScopeValidatorFactory> \
  --validator         0x<ZKLabeledSignerScopeValidator> \
  --subsetsignersroot 0x<bytes32> \
  --scoperoot         0x<bytes32> \
  --index             0
```

### Read on-chain roots for an account

```bash
npx hardhat getZKLabeledScopeNexusConfig \
  --network polygon \
  --validator 0x<ZKLabeledSignerScopeValidator> \
  --account   0x<NexusAccountAddress>
```

### Full account status report

```bash
npx hardhat checkZKLabeledScopeNexusAccount \
  --network polygon \
  --account   0x<NexusAccountAddress> \
  --validator 0x<ZKLabeledSignerScopeValidator>
```

Prints: deployed ✓, validator installed ✓, initialized ✓, both roots, current nonce, and native token balance.

### Compute UserOp hash (without proving)

Use this to get the hash the signer must sign **before** calling
`sendZKLabeledScopeNexusUserOp` — sign it offline (e.g. `cast wallet sign --no-hash <hash> --private-key <key>`
or the signer's own wallet), then pass the resulting signature via `--signature`
and this hash via `--userophash`.

```bash
npx hardhat computeLabeledScopeUserOpHash \
  --network polygon \
  --account   0x<NexusAccountAddress> \
  --validator 0x<ZKLabeledSignerScopeValidator> \
  --to        0x<CallTarget> \
  --value     0 \
  --data      0x
```

---

## Structured JSON input formats

**Signers** (same format as the plain variant):
```json
[
  { "label": "alice", "address": "0xAliceAddress" },
  { "label": "bob",   "address": "0xBobAddress" }
]
```

**Labeled scope rules** — one entry per registered destination:
```json
[
  {
    "label": "treasury",
    "target": "0xTreasuryAddress",
    "selectorField": "4294967296",
    "valueMax": "340282366920938463463374607431768211455",
    "constraints": [
      { "constraintType": 0, "value": "0" },
      { "constraintType": 0, "value": "0" },
      { "constraintType": 0, "value": "0" },
      { "constraintType": 0, "value": "0" }
    ]
  }
]
```

- `selectorField: "4294967296"` (`0x100000000`, decimal for `WILDCARD_SELECTOR`) together
  with `valueMax: "340282366920938463463374607431768211455"` (max u128, `WILDCARD_VALUE_MAX`)
  and all `constraintType: 0` (`PARAM_UNCONSTRAINED`) registers a destination with **no
  restriction at all** — the common case for a plain contact/protocol entry.
- To restrict a destination to a specific function, set `selectorField` to the decimal
  value of the 4-byte selector (e.g. `"3364306470"` for `0xc84e1c96`) and set
  `constraintType`/`value` per parameter: `0` = unconstrained, `1` = exact match
  (`value` = required value), `2` = range max (`value` = maximum allowed).

Label strings are UTF-8, max **31 bytes**, zero-padded internally. Use single
quotes around JSON strings on the command line to avoid shell escaping issues.

---

## Typical end-to-end flow

```
[One-time per network]
createZKLabeledScopeFactory
        │
        ▼
[Once per team account]
createZKLabeledScopeNexusAccount
        │
        ▼
[Per transaction]
sendZKLabeledScopeNexusUserOp
```
