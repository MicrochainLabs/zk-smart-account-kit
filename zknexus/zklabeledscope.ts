/**
 * ZK Labeled Signer + Scope Module for Nexus Smart Accounts
 *
 * This module provides utilities for deploying and interacting with Nexus accounts
 * that use the ZKLabeledSignerScopeValidator for privacy-preserving, scope-restricted
 * label-based validation.
 *
 * Key concepts:
 *   - Each signer is associated with a (label, address) pair in a signers subset tree
 *     (exactly like ZKLabeledSignerValidator / zklabeled.ts).
 *   - Destinations are NOT stored in a separate contacts/protocols registry. Instead,
 *     each destination + scope rule (allowed selector / value / calldata-param
 *     constraints, or a wildcard sentinel meaning "no restriction") is a single leaf
 *     of a *unified* scope tree (`scopeRoot`). See docs/zk-labeled-signer-scope.md.
 *   - A transaction proof shows, in one proof:
 *       (1) the signer is a member of `signersRoot` (identity hidden), and
 *       (2) the call's destination/selector/value/params match a rule that is a
 *           member of `scopeRoot` (label hidden; rule fields are PUBLIC — extracted
 *           directly from the real on-chain calldata, not hashed).
 *   - Account creation requires a subset proof that the account's signers are all
 *     members of the organisation-wide `mainSignersRoot` — identical mechanism to
 *     the plain (non-scoped) variant, so `zk_signer_subset` proof generation is
 *     imported and reused as-is from ./zklabeled.
 *
 * Circuits used:
 *   - zk_labeled_signer_scope (noir/target/zk_labeled_signer_scope.json) — per-transaction proof
 *   - zk_signer_subset        (noir/target/zk_signer_subset.json)        — account-creation proof
 *
 * KNOWN GAP: the `zk_labeled_signer_scope` circuit currently only exists (compiled)
 * under zk-smart-account-kit/noir/target/zk_labeled_signer_scope.json — it has not yet
 * been vendored/compiled into this repo's noir/target/, and no Solidity HonkVerifier has
 * been codegen'd for it (see contracts/ERC8039/ZKLabeledSignerScopeProofVerifier.sol and
 * ignition/modules/zkLabeledSignerScopeFactoryNexus.ts for the same note). Proof
 * generation via `proveLabeledSignerScopeTx` below will throw ENOENT until the compiled
 * circuit JSON is placed at `noir/target/zk_labeled_signer_scope.json` (relative to
 * Hardhat's cwd), and factory deployment will fail to compile until the HonkVerifier
 * .sol exists.
 *
 * @module zklabeledscope
 */

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { vars } from "hardhat/config";
import { privateKeyToAccount } from "viem/accounts";
import {
    toHex, toBytes, recoverPublicKey, recoverAddress, hashMessage, Hex,
    createWalletClient, http, WalletClient, pad,
    createPublicClient, getContract, parseEther, concat,
    encodePacked, encodeAbiParameters, parseAbiParameters,
    PublicClient, parseAbi, formatEther,
    Hash, decodeEventLog, Address,
    walletActions
} from "viem";
import { poseidon } from "@iden3/js-crypto";
import { LeanIMT } from "@zk-kit/lean-imt";
import { join } from "path";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync } from "fs";
import assert from "assert";
import zkLabeledSignerScopeFactory from "../ignition/modules/zkLabeledSignerScopeFactoryNexus";
import zkLabeledSignerScopeValidatorRedeploy from "../ignition/modules/zkLabeledSignerScopeValidatorRedeploy";

import {
    MODULE_TYPE_VALIDATOR,
    LABEL_NAME_BYTES,
    SIGNERS_MAX_DEPTH,
    type LabeledSigner,
    computeLabelLeaf,
    buildSubsetRoot,
    getSubsetTreeProof,
    proveSignerSubset,
    computeLabeledUserOpHash as computeLabeledScopeUserOpHash,
} from "./zklabeled";

// Re-exported for convenience so callers only need to import from this module.
export type { LabeledSigner };
export { proveSignerSubset, computeLabeledScopeUserOpHash };

// ─────────────────────────────────────────────────────────────────────────────
// Constants (must match lib/zk_scope/src/lib.nr and
// circuits/zk_labeled_signer_scope/src/main.nr in zk-smart-account-kit/noir)
// ─────────────────────────────────────────────────────────────────────────────

/** Max depth of the unified scope tree (destinations + scope rules). */
export const SCOPE_MAX_DEPTH = 6;

/** Number of leading static calldata params supported by the circuit / on-chain extraction. */
export const MAX_PARAMS = 4;

/** Constraint-type sentinels (see ParamConstraintType in lib/zk_scope). */
export const PARAM_UNCONSTRAINED = 0;
export const PARAM_EXACT         = 1;
export const PARAM_RANGE_MAX     = 2;

/** Sentinel rule_selector meaning "no restriction at all" (see WILDCARD_SELECTOR in lib/zk_scope). */
export const WILDCARD_SELECTOR = 0x100000000n;

/** Sentinel rule_value_max paired with WILDCARD_SELECTOR (max u128). */
export const WILDCARD_VALUE_MAX = (1n << 128n) - 1n;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/** A single calldata-parameter constraint slot. */
export interface ParamConstraint {
    constraintType: number; // PARAM_UNCONSTRAINED | PARAM_EXACT | PARAM_RANGE_MAX
    value: bigint;
}

/**
 * A single leaf of the unified scope tree: a labeled destination together with
 * its scope rule. `selectorField === WILDCARD_SELECTOR` (with
 * `valueMax === WILDCARD_VALUE_MAX` and all constraints unconstrained) registers
 * a destination with NO restriction at all.
 */
export interface LabeledScopeRule {
    label:         string;  // destination's label name, max 31 bytes
    target:        string;  // destination address
    selectorField: bigint;  // WILDCARD_SELECTOR for an unrestricted destination
    valueMax:      bigint;  // WILDCARD_VALUE_MAX for an unrestricted destination
    constraints:   [ParamConstraint, ParamConstraint, ParamConstraint, ParamConstraint];
}

/** Per-account configuration stored on ZKLabeledSignerScopeValidator. */
export interface ZKLabeledSignerScopeConfig {
    signersRoot: string;  // bytes32 hex
    scopeRoot:   string;  // bytes32 hex
}

/** Parameters for creating a ZK Labeled Signer + Scope Nexus account. */
export interface CreateZKLabeledScopeAccountParams {
    subsetSignersRoot: string;  // bytes32 hex
    scopeRoot:         string;  // bytes32 hex
    subsetProof:       string;  // hex bytes — proof from zk_signer_subset circuit
    index?:            bigint;
}

// ─────────────────────────────────────────────────────────────────────────────
// Label / field helpers (duplicated from zklabeled.ts — not exported there —
// must match the Noir library implementations exactly)
// ─────────────────────────────────────────────────────────────────────────────

function labelToBytes(label: string): Uint8Array {
    const encoded = new TextEncoder().encode(label);
    const padded  = new Uint8Array(LABEL_NAME_BYTES);
    padded.set(encoded.slice(0, LABEL_NAME_BYTES));
    return padded;
}

function labelToField(labelBytes: Uint8Array): bigint {
    let result = 0n;
    for (let i = 0; i < LABEL_NAME_BYTES; i++) {
        result = result * 256n + BigInt(labelBytes[i]);
    }
    return result;
}

function addressToField(address: string): bigint {
    return BigInt(address);
}

/**
 * Convert a 4-byte function selector (e.g. "0xd0e30db0") to a field element.
 * The selector occupies the low 32 bits of the field.
 * Mirrors `selectorToField` in sdk/src/zk-scope/rule.ts and the on-chain
 * `_extractCallDetails`'s `txnSelectorField` derivation.
 */
export function selectorToField(selector: string): bigint {
    const hex = selector.startsWith("0x") ? selector.slice(2) : selector;
    return BigInt("0x" + hex.padStart(8, "0").slice(0, 8));
}

/** Hash function used for tree nodes (Poseidon2 on BN254). */
const poseidon2 = (a: bigint, b: bigint): bigint => poseidon.hash([a, b]);

// ─────────────────────────────────────────────────────────────────────────────
// Scope rule hashing (must match lib/zk_scope/src/lib.nr exactly)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Compute the Poseidon commitment to a set of parameter constraints.
 * Construction (must match `compute_params_hash` in Noir):
 *   c_i         = Poseidon2([constraint_type_i, value_i])
 *   h_lo        = Poseidon2([c_0, c_1])
 *   h_hi        = Poseidon2([c_2, c_3])
 *   params_hash = Poseidon2([h_lo, h_hi])
 */
export function computeParamsHash(
    constraints: [ParamConstraint, ParamConstraint, ParamConstraint, ParamConstraint]
): bigint {
    const c = constraints.map(con => poseidon.hash([BigInt(con.constraintType), BigInt(con.value)]));
    return poseidon.hash([
        poseidon.hash([c[0], c[1]]),
        poseidon.hash([c[2], c[3]]),
    ]);
}

/**
 * Compute the Merkle leaf for a labeled scope rule (unified scope tree).
 * Construction (must match `compute_labeled_rule_leaf` in Noir):
 *   identity          = Poseidon2([label, target])
 *   labeled_rule_leaf = Poseidon4([identity, selector, value_max, params_hash])
 */
export function computeLabeledRuleLeaf(rule: LabeledScopeRule): bigint {
    const labelField  = labelToField(labelToBytes(rule.label));
    const targetField = addressToField(rule.target);
    const paramsHash  = computeParamsHash(rule.constraints);
    const identity    = poseidon.hash([labelField, targetField]);
    return poseidon.hash([identity, BigInt(rule.selectorField), BigInt(rule.valueMax), paramsHash]);
}

/** Build a fully-unconstrained ParamConstraint slot (for padding). */
export function unconstrainedConstraint(): ParamConstraint {
    return { constraintType: PARAM_UNCONSTRAINED, value: 0n };
}

/** Build an exact-match ParamConstraint. */
export function exactMatchConstraint(value: bigint): ParamConstraint {
    return { constraintType: PARAM_EXACT, value };
}

/** Build a range-max ParamConstraint (param <= value). */
export function rangeMaxConstraint(max: bigint): ParamConstraint {
    return { constraintType: PARAM_RANGE_MAX, value: max };
}

/** Pad a list of constraints to exactly MAX_PARAMS slots (fill with unconstrained). */
export function padConstraints(
    constraints: ParamConstraint[]
): [ParamConstraint, ParamConstraint, ParamConstraint, ParamConstraint] {
    const padded = [...constraints];
    while (padded.length < MAX_PARAMS) padded.push(unconstrainedConstraint());
    return padded.slice(0, MAX_PARAMS) as [ParamConstraint, ParamConstraint, ParamConstraint, ParamConstraint];
}

/** Pad raw decoded calldata param values to exactly MAX_PARAMS entries (fill with 0n). */
export function padParamValues(values: bigint[]): bigint[] {
    return Array.from({ length: MAX_PARAMS }, (_, i) => values[i] ?? 0n);
}

/**
 * Build a LabeledScopeRule for a destination with NO restriction at all
 * (a wildcard leaf): `selectorField = WILDCARD_SELECTOR`, `valueMax =
 * WILDCARD_VALUE_MAX`, all constraints unconstrained.
 */
export function unrestrictedLabeledRule(label: string, target: string): LabeledScopeRule {
    return {
        label,
        target,
        selectorField: WILDCARD_SELECTOR,
        valueMax:      WILDCARD_VALUE_MAX,
        constraints:   padConstraints([]),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Unified scope tree helpers (LeanIMT)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a LeanIMT unified labeled scope tree from an ordered list of labeled
 * scope rules. Insertion order determines the Merkle path for each rule — use
 * a canonical ordering (e.g. sorted by target + selector) for deterministic roots.
 */
export function buildLabeledScopeTree(rules: LabeledScopeRule[]): LeanIMT {
    // @ts-ignore — LeanIMT type definitions expect a specific hash signature
    const tree = new LeanIMT(poseidon2);
    for (const r of rules) {
        tree.insert(computeLabeledRuleLeaf(r));
    }
    return tree;
}

/**
 * Generate a Merkle inclusion proof for `rule` in the given unified scope tree.
 * Returns siblings and indices padded to `maxDepth` for use in Noir circuits.
 */
function getLabeledScopeRuleProof(
    tree: LeanIMT,
    rule: LabeledScopeRule,
    maxDepth: number = SCOPE_MAX_DEPTH
): { siblings: bigint[]; indices: number[]; depth: number } {
    const leaf    = computeLabeledRuleLeaf(rule);
    const leafIdx = tree.indexOf(leaf);
    if (leafIdx === -1) {
        throw new Error(
            `Scope rule (label="${rule.label}", target=${rule.target}) not found in scope tree.\n` +
            `Ensure allScopeRules matches the full rule set used when the account's scopeRoot was built.`
        );
    }
    const proof = tree.generateProof(leafIdx);

    const siblings: bigint[] = [];
    const indices:  number[] = [];
    for (let i = 0; i < proof.siblings.length; i++) {
        siblings.push(proof.siblings[i]);
        indices.push((proof.index >> i) & 1);
    }

    return { siblings, indices, depth: proof.siblings.length };
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level ECDSA helpers (duplicated per the zknexus/*.ts convention)
// ─────────────────────────────────────────────────────────────────────────────

function extractCoordinates(pubKey: Hex): { x: number[]; y: number[] } {
    const bytes = toBytes(pubKey);
    // Uncompressed key: 0x04 || x (32 bytes) || y (32 bytes)
    return {
        x: Array.from(bytes.slice(1, 33)),
        y: Array.from(bytes.slice(33, 65)),
    };
}

function extractRS(sig: Hex): number[] {
    const bytes = toBytes(sig);
    return Array.from(bytes.slice(0, 64));  // r (32) || s (32)
}

function ensureHexPrefix(value: string): `0x${string}` {
    return value.startsWith("0x") ? (value as `0x${string}`) : `0x${value}`;
}

/** Pad an array to `length` with `fillValue` (right-pad). */
function padArray<T>(arr: T[], length: number, fillValue: T): T[] {
    const padded = [...arr];
    while (padded.length < length) padded.push(fillValue);
    return padded;
}

// ─────────────────────────────────────────────────────────────────────────────
// getConfig ABI (struct return — declared as a full JSON ABI item rather than
// via parseAbi's human-readable syntax, since ZKLabeledSignerScopeValidator's
// getConfig returns a Solidity struct `AccountConfig{signersRoot,scopeRoot}`,
// not a plain multi-value tuple like the non-scoped variant's getConfig).
// ─────────────────────────────────────────────────────────────────────────────

const getConfigAbi = [
    {
        type: "function",
        name: "getConfig",
        stateMutability: "view",
        inputs: [{ name: "smartAccount", type: "address" }],
        outputs: [
            {
                name: "",
                type: "tuple",
                components: [
                    { name: "signersRoot", type: "bytes32" },
                    { name: "scopeRoot",   type: "bytes32" },
                ],
            },
        ],
    },
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// ZKLabeledSignerScopeNexusHelper — on-chain read / write wrapper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Helper class for ZKLabeledSignerScopeValidator Nexus operations.
 * Wraps the factory and validator contract ABIs.
 */
export class ZKLabeledSignerScopeNexusHelper {
    private factoryAddress:   Address;
    private validatorAddress: Address;
    private publicClient:     PublicClient;
    private walletClient?:    WalletClient;

    constructor(
        factoryAddress:   string,
        validatorAddress: string,
        publicClient:     PublicClient,
        walletClient?:    WalletClient
    ) {
        this.factoryAddress   = factoryAddress   as Address;
        this.validatorAddress = validatorAddress as Address;
        this.publicClient     = publicClient;
        this.walletClient     = walletClient;
    }

    // ── Address prediction ────────────────────────────────────────────────────

    /**
     * Predict the CREATE2 address for a new ZK Labeled Signer + Scope Nexus account.
     * No proof needed — only the roots and index are used for the salt.
     */
    async computeAccountAddress(params: CreateZKLabeledScopeAccountParams): Promise<string> {
        const { subsetSignersRoot, scopeRoot, index = 0n } = params;

        const abi = parseAbi([
            "function computeAccountAddress(bytes32 subsetSignersRoot, bytes32 scopeRoot, uint256 index) view returns (address)"
        ]);

        const factory = getContract({
            address: this.factoryAddress,
            abi,
            client:  this.publicClient,
        });

        return await factory.read.computeAccountAddress([
            subsetSignersRoot as Hex,
            scopeRoot         as Hex,
            index,
        ]) as string;
    }

    // ── Account creation ──────────────────────────────────────────────────────

    /**
     * Deploy a new Nexus account with ZKLabeledSignerScopeValidator installed.
     * The factory verifies the subset proof before deployment.
     */
    async createAccount(params: CreateZKLabeledScopeAccountParams): Promise<{
        account:     string;
        transaction: Hash;
    }> {
        if (!this.walletClient) {
            throw new Error("Wallet client required for account creation");
        }

        const { subsetSignersRoot, scopeRoot, subsetProof, index = 0n } = params;

        const abi = parseAbi([
            "function createAccount(bytes32 subsetSignersRoot, bytes32 scopeRoot, bytes subsetProof, uint256 index) payable returns (address)"
        ]);

        const txHash = await this.walletClient.writeContract({
            address:      this.factoryAddress,
            abi,
            functionName: "createAccount",
            args: [
                subsetSignersRoot as Hex,
                scopeRoot         as Hex,
                subsetProof       as Hex,
                index,
            ],
            account: this.walletClient.account!,
            chain:   undefined,
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });

        // Extract account address from event
        const eventABI = parseAbi([
            "event ZKLabeledSignerScopeAccountCreated(address indexed account, bytes32 indexed subsetSignersRoot, bytes32 scopeRoot, uint256 index)"
        ]);

        let accountAddress: string | undefined;
        for (const log of receipt.logs) {
            try {
                const decoded = decodeEventLog({ abi: eventABI, data: log.data, topics: log.topics });
                if (decoded.eventName === "ZKLabeledSignerScopeAccountCreated") {
                    accountAddress = (decoded.args as any).account as string;
                    break;
                }
            } catch {
                continue;
            }
        }

        if (!accountAddress) {
            throw new Error("ZKLabeledSignerScopeAccountCreated event not found in receipt");
        }

        return { account: accountAddress, transaction: txHash };
    }

    // ── Validator state readers ───────────────────────────────────────────────

    /**
     * Read the two Merkle roots stored for a Nexus account on the validator.
     */
    async getConfiguration(accountAddress: string): Promise<ZKLabeledSignerScopeConfig> {
        const validator = getContract({
            address: this.validatorAddress,
            abi:     getConfigAbi,
            client:  this.publicClient,
        });

        const config = await validator.read.getConfig([accountAddress as Address]) as {
            signersRoot: string;
            scopeRoot:   string;
        };

        return { signersRoot: config.signersRoot, scopeRoot: config.scopeRoot };
    }

    /** Check whether the validator has been initialised for the account. */
    async isInitialized(accountAddress: string): Promise<boolean> {
        const abi = parseAbi([
            "function isInitialized(address smartAccount) view returns (bool)"
        ]);

        const validator = getContract({
            address: this.validatorAddress,
            abi,
            client:  this.publicClient,
        });

        return await validator.read.isInitialized([accountAddress as Address]) as boolean;
    }

    /** Read the immutable ERC-8039 proof verifier address from the validator. */
    async getProofVerifier(): Promise<string> {
        const abi = parseAbi(["function proofVerifier() view returns (address)"]);

        const validator = getContract({
            address: this.validatorAddress,
            abi,
            client:  this.publicClient,
        });

        return await validator.read.proofVerifier() as string;
    }

    // ── ERC-7579 module installation ─────────────────────────────────────────

    /**
     * Install the ZKLabeledSignerScopeValidator on an existing Nexus account.
     * The caller must be the account owner / controller.
     */
    async installValidator(
        nexusAccountAddress: Address,
        signersRoot: string,
        scopeRoot:   string,
    ): Promise<Hash> {
        if (!this.walletClient) {
            throw new Error("Wallet client required for validator installation");
        }

        const initData = this.encodeValidatorInitData(signersRoot, scopeRoot);

        const nexusABI = parseAbi([
            "function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external"
        ]);

        return await this.walletClient.writeContract({
            address:      nexusAccountAddress,
            abi:          nexusABI,
            functionName: "installModule",
            args:         [BigInt(MODULE_TYPE_VALIDATOR), this.validatorAddress, initData],
            account:      this.walletClient.account!,
            chain:        undefined,
        });
    }

    // ── Root management calls (via the account itself) ────────────────────────

    /** Encode the nonce with the validator address (Nexus nonce key convention). */
    encodeNonce(sequence: bigint, validatorAddress: string): bigint {
        return (BigInt(validatorAddress) << 64n) | (sequence & 0xFFFFFFFFFFFFFFFFn);
    }

    /** ABI-encode init data for `onInstall`. */
    encodeValidatorInitData(signersRoot: string, scopeRoot: string): Hex {
        return encodeAbiParameters(
            parseAbiParameters("bytes32, bytes32"),
            [signersRoot as Hex, scopeRoot as Hex]
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof generation — zk_labeled_signer_scope (per-transaction)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a `zk_labeled_signer_scope` proof for a single UserOperation.
 *
 * The signer proves:
 *   (1) They hold the ECDSA key for an address whose (label, address) is in `signersRoot`.
 *   (2) The call's destination, together with a private label and a matching scope
 *       rule, is a member of `scopeRoot` — and the transaction's ACTUAL selector,
 *       value, and decoded calldata params (all PUBLIC inputs) satisfy that rule's
 *       constraints (or the rule is a wildcard, in which case nothing is checked).
 *
 * @param txHash         UserOperation hash (32 bytes, raw/unprefixed).
 * @param signature      Signer's ECDSA signature over the EIP-191-prefixed `txHash`
 *                       (i.e. what a wallet's `personal_sign(txHash, address)` produces —
 *                       used to recover the address/public key, and fed as the circuit's
 *                       `txn_hash` public input, matching what
 *                       `ZKLabeledSignerScopeValidator._verifyProof` reconstructs on-chain).
 * @param signerLabel    Signer's label name in the signers subset tree.
 * @param subsetSigners  All signers in the account's subset (to rebuild the subset tree).
 * @param destAddress    Call target address (must match the actual UserOp calldata target,
 *                       and must equal `rule.target`).
 * @param destLabel      Destination's label name (private input; only its Poseidon
 *                       commitment together with `destAddress` is checked against `rule`).
 * @param rule           The specific LabeledScopeRule this call is proven against.
 * @param allScopeRules  The full unified scope rule set (to rebuild the tree and find `rule`'s proof).
 * @param txnSelector    The ACTUAL function selector of the call (hex, e.g. "0x00000000" for a
 *                       plain ETH transfer) — becomes a PUBLIC input, matched by
 *                       `ZKLabeledSignerScopeValidator._extractCallDetails` on-chain.
 * @param txnValue       The ACTUAL ETH value of the call, in wei — becomes a PUBLIC input.
 * @param paramValues    The ACTUAL decoded leading static calldata params (up to MAX_PARAMS) —
 *                       become PUBLIC inputs, zero-padded to MAX_PARAMS.
 * @param signersRoot    On-chain signersRoot from the validator config.
 * @param scopeRoot      On-chain scopeRoot from the validator config.
 *
 * @returns `{ proofData, scopeRoot, destAddressField, txnSelectorField, txnValueField,
 *   paramValues, zkProof, erc1271Signature }` where `zkProof` is the raw UltraHonk proof
 *   bytes — ready to be placed DIRECTLY in `PackedUserOperation.signature` (no abi.encode
 *   wrapper needed, unlike the plain zklabeled.ts variant), and `erc1271Signature` is
 *   `abi.encode(bytes zkProof, bytes32 destAddressField, bytes32 txnSelector, bytes32
 *   txnValue, bytes32[4] txnParams)` for `isValidSignatureWithSender` contexts.
 */
export async function proveLabeledSignerScopeTx(
    txHash:         Hex,
    signature:      Hex,
    signerLabel:    string,
    subsetSigners:  LabeledSigner[],
    destAddress:    string,
    destLabel:      string,
    rule:           LabeledScopeRule,
    allScopeRules:  LabeledScopeRule[],
    txnSelector:    Hex,
    txnValue:       bigint,
    paramValues:    bigint[],
    signersRoot:    Hex,
    scopeRoot:      Hex,
) {
    // ── EIP-191-prefix the UserOp hash — this is what wallets actually sign via
    //    `personal_sign`, and what ZKLabeledSignerScopeValidator._verifyProof decomposes
    //    into the circuit's txn_hash public input.
    const prefixedHash = hashMessage({ raw: toBytes(txHash) });

    // ── Recover signer address and public key from the pre-collected signature ─
    const signerAddress = await recoverAddress({ hash: prefixedHash, signature });
    const pubKeyHex     = await recoverPublicKey({ hash: prefixedHash, signature });

    const { x: pubkeyX, y: pubkeyY } = extractCoordinates(pubKeyHex);
    const sigRS = extractRS(signature);

    console.log("=== proveLabeledSignerScopeTx ===");
    console.log("  Signer address:", signerAddress);
    console.log("  Signer label:  ", signerLabel);
    console.log("  Destination:   ", destAddress, `(label: "${destLabel}")`);
    console.log("  Selector:      ", txnSelector);
    console.log("  Value:         ", txnValue.toString());

    // ── Build subset (signers) tree for the signer's membership proof ──────
    const subsetRoot          = buildSubsetRoot(subsetSigners);
    const computedSignersRoot = toHex(subsetRoot) as Hex;
    if (computedSignersRoot.toLowerCase() !== signersRoot.toLowerCase()) {
        throw new Error(
            `signersRoot mismatch!\n  Computed from subsetSigners: ${computedSignersRoot}\n  Expected on-chain: ${signersRoot}\n` +
            `Ensure subsetSigners exactly matches the list used when the account was created.`
        );
    }

    // Find this signer in the subset
    const signerLeaf         = computeLabelLeaf(signerLabel, signerAddress);
    const signerIdxInSubset  = subsetSigners.findIndex(
        s => computeLabelLeaf(s.label, s.address) === signerLeaf
    );
    if (signerIdxInSubset === -1) {
        throw new Error(
            `Signer "${signerLabel}" / ${signerAddress} not found in subsetSigners.\n` +
            `Available: ${subsetSigners.map(s => `${s.label}/${s.address}`).join(", ")}`
        );
    }

    const signerProof = getSubsetTreeProof(signerIdxInSubset, subsetSigners);

    // ── Build the unified scope tree for the rule's membership proof ───────
    if (rule.target.toLowerCase() !== destAddress.toLowerCase()) {
        throw new Error(
            `rule.target (${rule.target}) does not match destAddress (${destAddress})`
        );
    }

    const scopeTree         = buildLabeledScopeTree(allScopeRules);
    const computedScopeRoot = toHex(scopeTree.root) as Hex;
    if (computedScopeRoot.toLowerCase() !== scopeRoot.toLowerCase()) {
        throw new Error(
            `scopeRoot mismatch!\n  Computed from allScopeRules: ${computedScopeRoot}\n  Expected on-chain: ${scopeRoot}\n` +
            `Ensure allScopeRules exactly matches the rule set used when the account's scopeRoot was built.`
        );
    }

    const ruleProof = getLabeledScopeRuleProof(scopeTree, rule);

    // ── Compute public inputs ──────────────────────────────────────────────
    const destAddressField = addressToField(destAddress);
    const txnSelectorField = selectorToField(txnSelector);
    const paddedParams     = padParamValues(paramValues);
    const signersRootBigInt = BigInt(signersRoot);
    const scopeRootBigInt   = BigInt(scopeRoot);

    // ── Circuit inputs ─────────────────────────────────────────────────────
    const input = {
        // Signer private inputs
        pubkey: { x: pubkeyX, y: pubkeyY },
        signature: sigRS,
        signer_label_bytes:    Array.from(labelToBytes(signerLabel)),
        signer_proof_length:   signerProof.depth,
        signer_proof_indices:  padArray(signerProof.indices,                      SIGNERS_MAX_DEPTH, 0),
        signer_proof_siblings: padArray(signerProof.siblings.map(v => toHex(v)), SIGNERS_MAX_DEPTH, "0x0"),

        // Destination + scope rule private inputs
        dest_label_bytes: Array.from(labelToBytes(destLabel)),

        // Note: rule fields may arrive as JSON strings from the CLI (e.g. `"selectorField":"0"`)
        // rather than true `bigint`s. `toHex()` on a plain `string` UTF-8-encodes it instead of
        // converting a numeric value, so always normalize through `BigInt(...)` first.
        rule_selector:   toHex(BigInt(rule.selectorField)),
        rule_value_max:  toHex(BigInt(rule.valueMax)),
        rule_constraints: rule.constraints.map(c => ({
            constraint_type: Number(c.constraintType),
            value:           toHex(BigInt(c.value)),
        })),

        scope_proof_length:   ruleProof.depth,
        scope_proof_indices:  padArray(ruleProof.indices,                      SCOPE_MAX_DEPTH, 0),
        scope_proof_siblings: padArray(ruleProof.siblings.map(v => toHex(v)), SCOPE_MAX_DEPTH, "0x0"),

        // Public inputs
        // txn_hash is the EIP-191-prefixed hash (matches the on-chain validator's
        // decomposition of MessageHashUtils.toEthSignedMessageHash(userOpHash)).
        txn_hash:           Array.from(toBytes(prefixedHash)),
        signers_root:       toHex(signersRootBigInt),
        dest_address_field: toHex(destAddressField),
        txn_selector:       toHex(txnSelectorField),
        txn_value:          toHex(txnValue),
        param_values:       paddedParams.map(v => toHex(v)),
        scope_root:         toHex(scopeRootBigInt),
    };

    // ── Load circuit and generate proof ───────────────────────────────────
    const circuitPath     = join(process.cwd(), "noir", "target", "zk_labeled_signer_scope.json");
    const compiledCircuit = JSON.parse(readFileSync(circuitPath, "utf-8"));

    const api     = await Barretenberg.new({ threads: 1 });
    const backend = new UltraHonkBackend(compiledCircuit.bytecode, api);
    const noir    = new Noir(compiledCircuit);

    try {
        console.log("  Generating witness...");
        const { witness } = await noir.execute(input);

        console.log("  Generating labeled signer scope proof...");
        const t0        = Date.now();
        const proofData = await backend.generateProof(witness, { verifierTarget: "evm" });
        console.log(`  Proof generated in ${Date.now() - t0}ms (${proofData.proof.length} bytes)`);
        console.log(`  Public inputs: ${proofData.publicInputs.length}`);

        // Local verification
        const ok = await backend.verifyProof(proofData, { verifierTarget: "evm" });
        assert(ok, "Labeled signer scope proof local verification failed");
        console.log("  ✅ Labeled signer scope proof verified locally");

        // userOp.signature is simply the raw proof bytes — ZKLabeledSignerScopeValidator
        // extracts destAddressField/txnSelector/txnValue/txnParams directly from the real
        // UserOp callData, so no abi.encode wrapper is needed here (unlike the plain
        // zklabeled.ts variant's abi.encode(bytes, bytes32, bytes32)).
        const zkProof = toHex(proofData.proof) as Hex;

        // ERC-1271 contexts have no real calldata to extract from, so
        // isValidSignatureWithSender needs these fields supplied explicitly.
        const erc1271Signature = encodeAbiParameters(
            parseAbiParameters("bytes, bytes32, bytes32, bytes32, bytes32[4]"),
            [
                zkProof,
                pad(toHex(destAddressField), { size: 32 }) as Hex,
                pad(toHex(txnSelectorField), { size: 32 }) as Hex,
                pad(toHex(txnValue),         { size: 32 }) as Hex,
                paddedParams.map(v => pad(toHex(v), { size: 32 })) as [Hex, Hex, Hex, Hex],
            ]
        );

        return {
            proofData,
            scopeRoot,
            destAddressField: toHex(destAddressField) as Hex,
            txnSelectorField: toHex(txnSelectorField) as Hex,
            txnValueField:    toHex(txnValue) as Hex,
            paramValues:      paddedParams.map(v => toHex(v)) as Hex[],
            zkProof,
            erc1271Signature,
        };
    } finally {
        await api.destroy();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level Hardhat task helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Predict the address for a ZK Labeled Signer + Scope Nexus account.
 */
export async function computeZKLabeledScopeNexusAddress(
    hre:               HardhatRuntimeEnvironment,
    factoryAddress:    string,
    validatorAddress:  string,
    subsetSignersRoot: string,
    scopeRoot:         string,
    index:             string
) {
    const networkConfig = hre.network.config as any;
    const publicClient  = createPublicClient({ transport: http(networkConfig.url) });

    const helper  = new ZKLabeledSignerScopeNexusHelper(factoryAddress, validatorAddress, publicClient);
    const address = await helper.computeAccountAddress({
        subsetSignersRoot,
        scopeRoot,
        subsetProof: "0x",  // not used for address prediction
        index:       BigInt(index),
    });

    console.log("Computed Nexus account address:", address);
    console.log("\nParameters:");
    console.log("  Factory:            ", factoryAddress);
    console.log("  Validator:          ", validatorAddress);
    console.log("  Subset Signers Root:", subsetSignersRoot);
    console.log("  Scope Root:         ", scopeRoot);
    console.log("  Index:              ", index);

    return address;
}

/**
 * Read and print the ZKLabeledSignerScopeValidator configuration for a Nexus account.
 */
export async function getZKLabeledScopeNexusConfig(
    hre:              HardhatRuntimeEnvironment,
    validatorAddress: string,
    accountAddress:   string
) {
    const networkConfig = hre.network.config as any;
    const publicClient  = createPublicClient({ transport: http(networkConfig.url) });

    const helper = new ZKLabeledSignerScopeNexusHelper(
        "0x0000000000000000000000000000000000000000",
        validatorAddress,
        publicClient
    );

    console.log("Checking Nexus account:", accountAddress);

    const isInit = await helper.isInitialized(accountAddress);
    console.log("  Is initialized:", isInit);

    if (isInit) {
        const config = await helper.getConfiguration(accountAddress);
        console.log("  Signers Root:", config.signersRoot);
        console.log("  Scope Root:  ", config.scopeRoot);

        const verifier = await helper.getProofVerifier();
        console.log("  Proof Verifier:", verifier);

        return config;
    } else {
        console.log("  ⚠️  Account not initialized with ZKLabeledSignerScopeValidator");
    }
}

/**
 * Deploy the full ZK Labeled Signer + Scope factory stack via the
 * `zkLabeledSignerScopeFactoryNexus` Ignition module:
 *   ZKTranscriptLib (shared) → HonkVerifier (zk_labeled_signer_scope) → ZKLabeledSignerScopeProofVerifier
 *   → HonkVerifier (zk_signer_subset) → ZKSignerSubsetProofVerifier
 *   → ZKLabeledSignerScopeValidator → ZKLabeledSignerScopeValidatorFactory
 *
 * The organisation-wide `initialMainSignersRoot` is computed on-the-fly from
 * `mainSigners` (subset-tree root over the full signer list, same convention as
 * createZKLabeledSignerFactoryContract in zklabeled.ts) — it is not passed in directly.
 *
 * KNOWN GAP: this will fail to compile until `noir/target/zk_labeled_signer_scope.sol`
 * exists (see module-level doc comment above).
 *
 * @param hre          Hardhat runtime.
 * @param mainSigners  The full org-wide signer list (label + address pairs).
 * @param owner        Address authorised to rotate `mainSignersRoot` later (e.g. a multisig).
 */
export async function createZKLabeledSignerScopeFactoryContract(
    hre:         HardhatRuntimeEnvironment,
    mainSigners: LabeledSigner[],
    owner:       string,
) {
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const networkConfig = hre.network.config as any;
    const walletClient: WalletClient = createWalletClient({
        account,
        transport: http(networkConfig.url),
    });
    const mywalletAddress = walletClient.account!.address;
    console.log("My wallet address: ", mywalletAddress);

    if (!Array.isArray(mainSigners) || mainSigners.length === 0) {
        throw new Error("mainSigners must be a non-empty array of {label, address} objects");
    }

    // @ts-ignore — LeanIMT type definitions expect a specific hash signature
    const tree = new LeanIMT(poseidon2);
    for (const s of mainSigners) tree.insert(computeLabelLeaf(s.label, s.address));
    const initialMainSignersRoot = pad(toHex(tree.root), { size: 32 }) as Hex;

    console.log("\nMain signers:");
    mainSigners.forEach(s => console.log(`  ${s.label} → ${s.address}`));
    console.log("Computed mainSignersRoot:", initialMainSignersRoot);

    const result = await hre.ignition.deploy(zkLabeledSignerScopeFactory, {
        parameters: {
            ZKLabeledSignerScopeFactory_v1: {
                initialMainSignersRoot,
                owner,
            },
        },
    });

    console.log("\nZK Transcript Lib (shared):           ", result.zkTranscriptLib);
    console.log("Labeled Signer Scope HonkVerifier:      ", result.labeledSignerScopeHonkVerifier);
    console.log("ERC-8039 Labeled Signer Scope Verifier: ", result.erc8039LabeledSignerScope);
    console.log("Signer Subset HonkVerifier:             ", result.signerSubsetHonkVerifier);
    console.log("ERC-8039 Signer Subset Verifier:        ", result.erc8039SignerSubset);
    console.log("ZKLabeledSignerScopeValidator:           ", result.zkLabeledSignerScopeValidator);
    console.log("ZKLabeledSignerScopeValidatorFactory:    ", result.zkLabeledSignerScopeValidatorFactory);

    return result;
}

/**
 * Redeploy ONLY `ZKLabeledSignerScopeValidator` + `ZKLabeledSignerScopeValidatorFactory`
 * via the `zkLabeledSignerScopeValidatorRedeploy` Ignition module, reusing the
 * already-deployed ZKTranscriptLib / HonkVerifiers / ERC-8039 proof adapters
 * (`erc8039LabeledSignerScope` / `erc8039SignerSubset`) as-is.
 *
 * Use this when only the validator's Solidity logic changed and the
 * (expensive, unaffected) verifier stack must not be redeployed.
 *
 * @param hre                Hardhat runtime.
 * @param initialMainSignersRoot  Org-wide signer Merkle root — reuse the original
 *                                factory's value unless intentionally rotating it.
 * @param owner              Address authorised to rotate `mainSignersRoot` later.
 */
export async function createZKLabeledSignerScopeValidatorRedeploy(
    hre:                     HardhatRuntimeEnvironment,
    initialMainSignersRoot:  string,
    owner:                   string,
) {
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const networkConfig = hre.network.config as any;
    const walletClient: WalletClient = createWalletClient({
        account,
        transport: http(networkConfig.url),
    });
    const mywalletAddress = walletClient.account!.address;
    console.log("My wallet address: ", mywalletAddress);
    console.log("Reusing mainSignersRoot:", initialMainSignersRoot);

    const result = await hre.ignition.deploy(zkLabeledSignerScopeValidatorRedeploy, {
        parameters: {
            ZKLabeledSignerScopeValidatorRedeploy_v1: {
                initialMainSignersRoot,
                owner,
            },
        },
    });

    console.log("\nZKLabeledSignerScopeValidator (NEW):        ", result.zkLabeledSignerScopeValidator);
    console.log("ZKLabeledSignerScopeValidatorFactory (NEW): ", result.zkLabeledSignerScopeValidatorFactory);

    return result;
}

/**
 * Full account-creation flow:
 *   1. Build the main signers LeanIMT from `mainSigners`.
 *   2. Build the subset tree from `subsetSigners`.
 *   3. Build the unified labeled scope tree from `scopeRules`.
 *   4. Generate a `zk_signer_subset` proof.
 *   5. Deploy the Nexus account via the factory.
 *
 * @param hre              Hardhat runtime.
 * @param mainSigners      The full org-wide signer list used when the factory was deployed.
 * @param subsetSigners    This account's signers (up to 5, all must be in mainSigners).
 * @param scopeRules       Initial unified scope tree rules (labeled destinations + scope rules).
 * @param validatorAddress ZKLabeledSignerScopeValidator contract address.
 * @param factoryAddress   ZKLabeledSignerScopeValidatorFactory contract address.
 * @param mainSignersRoot  The factory's current mainSignersRoot (read from chain).
 */
export async function createZKLabeledScopeNexusAccount(
    hre:               HardhatRuntimeEnvironment,
    mainSigners:       LabeledSigner[],
    subsetSigners:     LabeledSigner[],
    scopeRules:        LabeledScopeRule[],
    validatorAddress:  string,
    factoryAddress:    string,
    mainSignersRoot:   string,
) {
    const pk      = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));

    const walletClient: WalletClient = createWalletClient({
        account,
        // @ts-ignore
        transport: http(hre.network.config.url),
    });
    const publicClient = await hre.viem.getPublicClient();

    console.log("Creating ZK Labeled Signer + Scope Nexus account...");
    console.log("  Factory:          ", factoryAddress);
    console.log("  Deployer:         ", account.address);
    console.log("  Subset signers:   ", subsetSigners.map(s => `${s.label}/${s.address}`).join(", "));
    console.log("  Scope rules:      ", scopeRules.length, "entries");

    // ── Build roots ────────────────────────────────────────────────────────
    const subsetRoot = buildSubsetRoot(subsetSigners);
    const scopeTree   = buildLabeledScopeTree(scopeRules);

    const subsetSignersRoot = pad(toHex(subsetRoot),   { size: 32 }) as Hex;
    const scopeRoot          = pad(toHex(scopeTree.root), { size: 32 }) as Hex;

    console.log("\n📊 Roots:");
    console.log("  Subset Signers Root:", subsetSignersRoot);
    console.log("  Scope Root:         ", scopeRoot);

    // ── Generate subset proof ──────────────────────────────────────────────
    console.log("\n🔐 Generating zk_signer_subset proof...");
    const subsetProofData = await proveSignerSubset(
        mainSigners,
        subsetSigners,
        mainSignersRoot as Hex,
    );
    console.log("✅ Subset proof generated");

    // ── Compute address before deploying ──────────────────────────────────
    const helper = new ZKLabeledSignerScopeNexusHelper(
        factoryAddress,
        validatorAddress,
        publicClient,
        walletClient,
    );

    const predictedAddress = await helper.computeAccountAddress({
        subsetSignersRoot,
        scopeRoot,
        subsetProof: toHex(subsetProofData.proof),
        index: 0n,
    });
    console.log("\n📍 Predicted account address:", predictedAddress);

    // ── Deploy ─────────────────────────────────────────────────────────────
    const { account: deployedAccount, transaction } = await helper.createAccount({
        subsetSignersRoot,
        scopeRoot,
        subsetProof: toHex(subsetProofData.proof),
        index: 0n,
    });

    console.log("\n✅ Nexus account created!");
    console.log("   Account address:", deployedAccount);
    console.log("   Transaction:    ", transaction);

    const receipt = await publicClient.waitForTransactionReceipt({ hash: transaction });
    console.log("   Gas used:       ", receipt.gasUsed.toString());
    console.log("   Block:          ", receipt.blockNumber.toString());

    return {
        account:     deployedAccount,
        transaction,
        subsetSignersRoot,
        scopeRoot,
    };
}

/**
 * End-to-end flow: build UserOp → generate ZK proof → submit via EntryPoint.
 *
 * @param hre               Hardhat runtime.
 * @param accountAddress    The deployed Nexus account.
 * @param validatorAddress  ZKLabeledSignerScopeValidator address.
 * @param entryPointAddress EntryPoint v0.7 address (pass "" to auto-detect).
 * @param to                Call target address.
 * @param value             Call value (decimal POL or integer wei string).
 * @param data              Call data (hex). Its leading 4 bytes (if any) are treated as
 *                          the function selector, and up to MAX_PARAMS 32-byte words
 *                          following it are treated as leading static params — this
 *                          MUST mirror `_extractCallDetails`'s assumptions on-chain.
 * @param signature         Signer's ECDSA signature over the UserOp hash (see `computeLabeledScopeUserOpHash`).
 * @param userOpHash        The UserOp hash that `signature` was produced over. Verified against the
 *                          freshly-computed hash before use — if the nonce changed since signing,
 *                          this will mismatch and the call throws.
 * @param signerLabel       Label of the signer in the signersRoot.
 * @param subsetSigners     All subset signers (to rebuild signersRoot proof).
 * @param destLabel         The destination's label (private input) in the unified scope tree.
 * @param rule              The specific LabeledScopeRule this call is proven against.
 * @param allScopeRules     The full unified scope rule set (to rebuild scopeRoot's tree).
 */
export async function sendZKLabeledScopeNexusUserOp(
    hre:               HardhatRuntimeEnvironment,
    accountAddress:    string,
    validatorAddress:  string,
    entryPointAddress: string,
    to:                string,
    value:             string,
    data:              string,
    signature:         Hex,
    userOpHash:        Hex,
    signerLabel:       string,
    subsetSigners:     LabeledSigner[],
    destLabel:         string,
    rule:              LabeledScopeRule,
    allScopeRules:     LabeledScopeRule[],
) {
    const pk      = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const relayer = privateKeyToAccount(ensureHexPrefix(pk));

    const networkConfig = hre.network.config as any;
    const publicClient  = createPublicClient({ transport: http(networkConfig.url) });
    const walletClient  = createWalletClient({
        account:   relayer,
        transport: http(networkConfig.url),
    }).extend(walletActions);

    const valueInWei = value.includes(".") ? parseEther(value) : BigInt(value);
    const dataBytes  = toBytes(data as Hex);

    // Mirror ZKLabeledSignerScopeValidator._extractCallDetails: leading 4-byte
    // selector (0 if absent) + up to MAX_PARAMS leading 32-byte static params.
    //
    // IMPORTANT: a param/selector is only treated as "present" when its FULL
    // byte range fits within `dataBytes` — a PARTIAL trailing word must be
    // treated as absent (0), never zero-padded. This mirrors a real, fixed bug
    // in `_extractCallDetails`: `calldataload` only zero-pads relative to the
    // END OF THE ENTIRE TRANSACTION calldata, not relative to a nested `bytes
    // calldata` slice's own logical length — reading past `userOp.callData`'s
    // declared length on-chain silently picks up real, unrelated bytes from
    // whatever else is encoded further along in the outer `handleOps(...)`
    // calldata (e.g. other UserOp fields, the ~9KB zkProof signature), NOT
    // zeros. The contract now explicitly bounds-checks each field the same
    // way this loop does — keep both in sync.
    const txnSelector: Hex = dataBytes.length >= 4
        ? toHex(dataBytes.slice(0, 4)) as Hex
        : "0x00000000";
    const paramValues: bigint[] = [];
    for (let i = 0; i < MAX_PARAMS; i++) {
        const start = 4 + i * 32;
        const end   = start + 32;
        if (dataBytes.length >= end) {
            paramValues.push(BigInt(toHex(dataBytes.slice(start, end))));
        } else {
            paramValues.push(0n);
        }
    }

    console.log("\n🚀 Preparing ZK Labeled Signer + Scope UserOperation...");
    console.log("   Account:    ", accountAddress);
    console.log("   To:         ", to);
    console.log("   Value:      ", valueInWei.toString(), "wei");
    console.log("   Selector:   ", txnSelector);
    console.log("   Validator:  ", validatorAddress);

    // ── Auto-detect EntryPoint ─────────────────────────────────────────────
    if (!entryPointAddress || entryPointAddress === "0x0000000000000000000000000000000000000000") {
        const accountABI      = parseAbi(["function entryPoint() external view returns (address)"]);
        const accountContract = getContract({ address: accountAddress as Address, abi: accountABI, client: publicClient });
        entryPointAddress     = await accountContract.read.entryPoint() as string;
    }
    console.log("   EntryPoint: ", entryPointAddress);

    // ── Verify validator is installed and initialized ──────────────────────
    const accountModABI = parseAbi([
        "function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext) external view returns (bool)"
    ]);
    const accountContract = getContract({ address: accountAddress as Address, abi: accountModABI, client: publicClient });
    const isInstalled     = await accountContract.read.isModuleInstalled([
        BigInt(MODULE_TYPE_VALIDATOR),
        validatorAddress as Address,
        "0x" as Hex,
    ]) as boolean;

    if (!isInstalled) {
        throw new Error(`ZKLabeledSignerScopeValidator is not installed on account ${accountAddress}`);
    }
    console.log("   ✅ Validator installed");

    const helper = new ZKLabeledSignerScopeNexusHelper("0x0000000000000000000000000000000000000000", validatorAddress, publicClient);
    const isInit = await helper.isInitialized(accountAddress);
    if (!isInit) {
        throw new Error(`ZKLabeledSignerScopeValidator is not initialized for account ${accountAddress}`);
    }
    console.log("   ✅ Validator initialized");

    // ── Read on-chain roots ────────────────────────────────────────────────
    const config = await helper.getConfiguration(accountAddress);
    console.log("\n🔐 On-chain roots:");
    console.log("   signersRoot:", config.signersRoot);
    console.log("   scopeRoot:  ", config.scopeRoot);

    // ── Build callData ─────────────────────────────────────────────────────
    const executionMode     = "0x0000000000000000000000000000000000000000000000000000000000000000" as Hex;
    const executionCalldata = concat([
        to as Hex,
        pad(toHex(valueInWei), { size: 32 }),
        data as Hex,
    ]);
    const callData = concat([
        "0xe9ae5c53" as Hex,
        encodeAbiParameters(parseAbiParameters("bytes32, bytes"), [executionMode, executionCalldata]),
    ]);

    // ── Nonce ──────────────────────────────────────────────────────────────
    const epNonceABI = parseAbi(["function getNonce(address,uint192) view returns (uint256)"]);
    const entryPoint = getContract({ address: entryPointAddress as Address, abi: epNonceABI, client: publicClient });
    const nonceKey   = BigInt(validatorAddress);
    const nonce      = await entryPoint.read.getNonce([accountAddress as Address, nonceKey]) as bigint;
    console.log("\n📋 Nonce:", nonce.toString());

    // ── Build UserOp skeleton (signature empty for hash computation) ───────
    const userOp = {
        sender:            accountAddress,
        nonce,
        initCode:          "0x" as Hex,
        callData,
        accountGasLimits:  encodePacked(["uint128", "uint128"], [BigInt(10_000_000), BigInt(3_000_000)]),
        preVerificationGas: BigInt(300_000),
        gasFees:           encodePacked(["uint128", "uint128"], [BigInt(3_000_000), BigInt(3_000_000)]),
        paymasterAndData:  "0x" as Hex,
        signature:         "0x" as Hex,
    };

    const epHashABI   = parseAbi([
        "function getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)) view returns (bytes32)"
    ]);
    const epContract  = getContract({ address: entryPointAddress as Address, abi: epHashABI, client: publicClient });
    const computedUserOpHash = await epContract.read.getUserOpHash([[
        userOp.sender, userOp.nonce, userOp.initCode, userOp.callData,
        userOp.accountGasLimits, userOp.preVerificationGas,
        userOp.gasFees, userOp.paymasterAndData, userOp.signature,
    ]]) as Hex;

    console.log("\n🔑 UserOp Hash:", computedUserOpHash);

    // ── Verify the pre-collected signature was made over the current hash ──
    if (computedUserOpHash.toLowerCase() !== userOpHash.toLowerCase()) {
        console.error("\n❌ HASH MISMATCH!");
        console.error("   Computed UserOp Hash:", computedUserOpHash);
        console.error("   Provided UserOp Hash:", userOpHash);
        console.error("   This usually means the nonce changed between signing and submission.");
        console.error("   Regenerate the signature with the current UserOp hash (see computeLabeledScopeUserOpHash).");
        throw new Error(`UserOp hash mismatch! Computed: ${computedUserOpHash}, Provided: ${userOpHash}`);
    }
    console.log("   ✅ UserOp hashes match!");

    // ── Generate ZK proof ──────────────────────────────────────────────────
    console.log("\n🔐 Generating zk_labeled_signer_scope proof...");
    const proveResult = await proveLabeledSignerScopeTx(
        computedUserOpHash,
        signature,
        signerLabel,
        subsetSigners,
        to,
        destLabel,
        rule,
        allScopeRules,
        txnSelector,
        valueInWei,
        paramValues,
        config.signersRoot as Hex,
        config.scopeRoot as Hex,
    );
    const {
        zkProof, proofData,
        destAddressField, txnSelectorField, txnValueField,
        paramValues: paddedParamValues, scopeRoot,
    } = proveResult;

    console.log(`  bb.js public inputs count: ${proofData.publicInputs.length} (circuit's own declared count; the on-chain HonkVerifier separately reads 16 "pairing point" field elements out of the proof bytes themselves, not from this array — see PAIRING_POINTS_SIZE in noir/target/zk_labeled_signer_scope.sol)`);

    // ── Diagnostic: replicate _extractCallDetails' exact assembly logic in JS
    // against the REAL `callData` bytes (not the CLI-derived --to/--data args),
    // to check whether it matches what proveLabeledSignerScopeTx assumed. A
    // mismatch here would mean the proof was built against different values
    // than what the on-chain validator actually extracts from the real
    // UserOperation calldata.
    {
        const loadWord = (byteOffset: number, byteLen: number): Hex => {
            const bytes  = toBytes(callData);
            const out    = new Uint8Array(byteLen);
            for (let i = 0; i < byteLen; i++) {
                const srcIdx = byteOffset + i;
                out[i] = srcIdx < bytes.length ? bytes[srcIdx] : 0;
            }
            return toHex(out);
        };
        const realDestAddressField = pad(loadWord(100, 20), { size: 32 });
        const realTxnValueField    = pad(loadWord(120, 32), { size: 32 });
        const realTxnSelectorField = pad(loadWord(152, 4),  { size: 32 });
        const realParams: Hex[] = [
            pad(loadWord(156, 32), { size: 32 }),
            pad(loadWord(188, 32), { size: 32 }),
            pad(loadWord(220, 32), { size: 32 }),
            pad(loadWord(252, 32), { size: 32 }),
        ];
        console.log("\n🔬 JS-side replication of _extractCallDetails(callData) vs. CLI-derived fields:");
        console.log(`   destAddressField  real=${realDestAddressField}  cli=${pad(destAddressField, { size: 32 })}  match=${realDestAddressField.toLowerCase() === pad(destAddressField, { size: 32 }).toLowerCase()}`);
        console.log(`   txnValueField     real=${realTxnValueField}  cli=${pad(txnValueField, { size: 32 })}  match=${realTxnValueField.toLowerCase() === pad(txnValueField, { size: 32 }).toLowerCase()}`);
        console.log(`   txnSelectorField  real=${realTxnSelectorField}  cli=${pad(txnSelectorField, { size: 32 })}  match=${realTxnSelectorField.toLowerCase() === pad(txnSelectorField, { size: 32 }).toLowerCase()}`);
        paddedParamValues.forEach((v, i) => {
            console.log(`   txnParams[${i}]       real=${realParams[i]}  cli=${pad(v, { size: 32 })}  match=${realParams[i].toLowerCase() === pad(v, { size: 32 }).toLowerCase()}`);
        });
    }

    // ── Diagnostic: call the deployed HonkVerifier directly (bypassing the
    // validator's try/catch, which normally swallows any revert reason and
    // reports it to EntryPoint as a generic AA24 signature error). This lets
    // us see the *real* reason the proof fails to verify on-chain, if it does.
    try {
        const proofVerifierAddress = await helper.getProofVerifier();
        const adapterAbi = parseAbi([
            "function honkVerifier() view returns (address)",
        ]);
        const adapter = getContract({ address: proofVerifierAddress as Address, abi: adapterAbi, client: publicClient });
        const honkVerifierAddress = await adapter.read.honkVerifier() as Address;

        // Mirrors ZKLabeledSignerScopeValidator._verifyProof's pub[] construction exactly.
        const ethSignedHash = hashMessage({ raw: toBytes(computedUserOpHash) });
        const hashBytesPub: Hex[] = Array.from(toBytes(ethSignedHash)).map(
            (b) => pad(toHex(b), { size: 32 }) as Hex
        );
        const pub: Hex[] = [
            ...hashBytesPub,
            pad(config.signersRoot as Hex, { size: 32 }) as Hex,
            pad(destAddressField, { size: 32 }) as Hex,
            pad(txnSelectorField, { size: 32 }) as Hex,
            pad(txnValueField, { size: 32 }) as Hex,
            ...paddedParamValues.map((v) => pad(v, { size: 32 }) as Hex),
            pad(scopeRoot as Hex, { size: 32 }) as Hex,
        ];
        console.log(`  Reconstructed pub[] length: ${pub.length} (expect 41)`);

        const honkVerifierAbi = parseAbi([
            "function verify(bytes proof, bytes32[] publicInputs) returns (bool)",
            "error ProofLengthWrong()",
            "error ProofLengthWrongWithLogN(uint256 logN, uint256 actualLength, uint256 expectedLength)",
            "error PublicInputsLengthWrong()",
            "error SumcheckFailed()",
            "error ShpleminiFailed()",
            "error GeminiChallengeInSubgroup()",
            "error ConsistencyCheckFailed()",
        ]);
        try {
            const verified = await publicClient.readContract({
                address:      honkVerifierAddress,
                abi:          honkVerifierAbi,
                functionName: "verify",
                args:         [zkProof, pub],
            });
            console.log(`  🔎 Direct HonkVerifier.verify() result: ${verified}`);
        } catch (e) {
            console.log(`  🔎 Direct HonkVerifier.verify() reverted:`, e instanceof Error ? e.message : e);
        }

        // Diagnostic layer 1b: call the ERC-8039 adapter's verifyProof() directly —
        // this exercises the exact same abi.encode(pub)/abi.decode(...) roundtrip
        // that _verifyProof performs (unlike the raw honkVerifier.verify() call
        // above, which skips that roundtrip entirely), surfacing any decode-side
        // revert (e.g. InvalidPublicInputsLength) that the validator's try/catch
        // would otherwise swallow.
        const adapterVerifyAbi = parseAbi([
            "function verifyProof(bytes publicInputs, bytes proof) view returns (bytes4)",
            "error InvalidPublicInputsLength(uint256 got, uint256 expected)",
        ]);
        try {
            const encodedPub = encodeAbiParameters(parseAbiParameters("bytes32[]"), [pub]);
            const magic = await publicClient.readContract({
                address:      proofVerifierAddress as Address,
                abi:          adapterVerifyAbi,
                functionName: "verifyProof",
                args:         [encodedPub, zkProof],
            });
            console.log(`  🔎 Direct adapter.verifyProof() result: ${magic}`);
        } catch (e) {
            console.log(`  🔎 Direct adapter.verifyProof() reverted:`, e instanceof Error ? e.message : e);
        }

        // Diagnostic layer 2: call the validator module's validateUserOp() directly
        // with the exact same PackedUserOperation, bypassing EntryPoint and the
        // smart account's own module-dispatch entirely. If this returns 0 (success)
        // but the real handleOps still fails with AA24, the bug is NOT in the
        // validator/circuit at all — it's in how the account or EntryPoint routes
        // to this module (nonce key, module lookup, etc).
        const validatorAbiForUserOp = parseAbi([
            "function validateUserOp((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes) userOp, bytes32 userOpHash) returns (uint256)",
        ]);

        // Diagnostic: re-read getConfig() FRESH, right before the validateUserOp
        // call, to check whether cfg.signersRoot/scopeRoot (read live from storage
        // inside validateUserOp) still match the `config.signersRoot`/`scopeRoot`
        // values that were read ~17+ seconds earlier (before proof generation) and
        // baked into `pub[]` for the adapter/honkVerifier diagnostics above. If they
        // differ, the account's roots changed on-chain in between, and the proof
        // (built against the OLD roots) would correctly fail validateUserOp's LIVE
        // check while still passing the standalone adapter call (which takes pub[]
        // as an explicit argument, not from storage).
        try {
            const freshConfig = await helper.getConfiguration(accountAddress);
            const rootsMatch =
                freshConfig.signersRoot.toLowerCase() === (config.signersRoot as string).toLowerCase() &&
                freshConfig.scopeRoot.toLowerCase()   === (config.scopeRoot as string).toLowerCase();
            console.log(`  🔬 Fresh getConfig() re-read: signersRoot=${freshConfig.signersRoot} scopeRoot=${freshConfig.scopeRoot} (matches config used to build pub[]: ${rootsMatch})`);
        } catch (e) {
            console.log("  ⚠️  Fresh getConfig() re-read failed:", e instanceof Error ? e.message : e);
        }

        // NOTE: validateUserOp is a non-view function (unlike the adapter/verifier
        // calls above). Some RPC providers apply a much lower default eth_call gas
        // cap to non-view functions than to view ones, which could cause a silent
        // out-of-gas swallowed by _verifyProof's try/catch.
        try {
            const validationResult = await publicClient.readContract({
                address:      validatorAddress as Address,
                abi:          validatorAbiForUserOp,
                functionName: "validateUserOp",
                args: [
                    [
                        userOp.sender as Address,
                        userOp.nonce,
                        userOp.initCode,
                        userOp.callData,
                        userOp.accountGasLimits,
                        userOp.preVerificationGas,
                        userOp.gasFees,
                        userOp.paymasterAndData,
                        zkProof,
                    ],
                    computedUserOpHash,
                ],
            });
            console.log(`  🔎 Direct Validator.validateUserOp() result: ${validationResult} (0 = success, 1 = VALIDATION_FAILED)`);
        } catch (e) {
            console.log(`  🔎 Direct Validator.validateUserOp() reverted:`, e instanceof Error ? e.message : e);
        }
    } catch (e) {
        console.log("  ⚠️  Diagnostic verify call setup failed:", e instanceof Error ? e.message : e);
    }

    // userOp.signature is the raw proof bytes directly — no abi.encode wrapper needed.
    userOp.signature = zkProof;

    // ── Submit UserOp ──────────────────────────────────────────────────────
    console.log("\n📤 Sending UserOperation...");

    const epCallABI = parseAbi([
        "function handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[], address) payable",
        // EntryPoint v0.7 errors — declared here so viem can decode the actual
        // failure reason instead of just showing the raw 4-byte selector.
        "error FailedOp(uint256 opIndex, string reason)",
        "error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner)",
    ]);

    try {
        const txHash = await walletClient.writeContract({
            address:      entryPointAddress as Address,
            abi:          epCallABI,
            functionName: "handleOps",
            args: [
                [[
                    userOp.sender as Address,
                    userOp.nonce,
                    userOp.initCode,
                    userOp.callData,
                    userOp.accountGasLimits,
                    userOp.preVerificationGas,
                    userOp.gasFees,
                    userOp.paymasterAndData,
                    userOp.signature,
                ]],
                relayer.address,
            ],
            chain: undefined,
        });

        console.log("   Transaction hash:", txHash);
        const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
        console.log("   Gas used:        ", receipt.gasUsed.toString());
        console.log("   Status:          ", receipt.status);

        if (receipt.status === "reverted") {
            // Try to decode revert reason
            const revertABI = parseAbi([
                "event UserOperationRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason)",
                "event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)"
            ]);
            for (const log of receipt.logs) {
                try {
                    const decoded = decodeEventLog({ abi: revertABI, data: log.data, topics: log.topics });
                    if (decoded.eventName === "UserOperationRevertReason") {
                        console.error("   Revert reason:", (decoded.args as any).revertReason);
                    }
                } catch { /* not this event */ }
            }
            throw new Error(`UserOp reverted. TX: ${txHash}`);
        }

        console.log("\n✅ UserOperation executed successfully!");
        return { userOpHash, txHash, receipt };

    } catch (error: any) {
        console.error("\n❌ UserOperation failed!");

        // viem decodes EntryPoint's FailedOp/FailedOpWithRevert (declared in epCallABI
        // above) into error.cause.data.errorName/args when it can match the ABI.
        const revertError = typeof error?.walk === "function"
            ? error.walk((e: any) => e?.data?.errorName === "FailedOp" || e?.data?.errorName === "FailedOpWithRevert")
            : undefined;
        const decoded = revertError?.data;
        if (decoded?.errorName === "FailedOp") {
            const [opIndex, reason] = decoded.args as [bigint, string];
            console.error(`   EntryPoint FailedOp(opIndex=${opIndex}): ${reason}`);
        } else if (decoded?.errorName === "FailedOpWithRevert") {
            const [opIndex, reason, inner] = decoded.args as [bigint, string, Hex];
            console.error(`   EntryPoint FailedOpWithRevert(opIndex=${opIndex}): ${reason}`);
            console.error(`   Inner revert data: ${inner}`);
        }

        const msg: string = error?.message ?? "";
        if (msg.includes("AA24")) {
            console.error("   AA24 — ZK proof verification failed on-chain.");
            console.error("   Check that the signersRoot, scopeRoot, and circuit artifacts are all in sync,");
            console.error("   and that the selector/value/params supplied to the CLI exactly match the");
            console.error("   real UserOp calldata (see _extractCallDetails's static-params assumption).");
        } else if (msg.includes("AA25")) {
            console.error("   AA25 — Invalid nonce. The nonce changed between signing and submission.");
        } else if (msg.includes("AA23") || msg.includes("AA13")) {
            console.error("   AA23/AA13 — validateUserOp reverted. This usually means the ZK proof or");
            console.error("   ECDSA signature verification failed inside ZKLabeledSignerScopeValidator, or the");
            console.error("   account/validator ran out of the allotted verification gas.");
        }
        throw error;
    }
}

/**
 * Print a detailed status report for a ZK Labeled Signer + Scope Nexus account.
 */
export async function checkZKLabeledScopeNexusAccount(
    hre:              HardhatRuntimeEnvironment,
    accountAddress:   string,
    validatorAddress: string,
) {
    const publicClient = await hre.viem.getPublicClient();

    console.log("\n🔍 ZK Labeled Signer + Scope Nexus Account Status");
    console.log("   Account:  ", accountAddress);
    console.log("   Validator:", validatorAddress);

    // Deployment check
    const code = await publicClient.getBytecode({ address: accountAddress as Address });
    if (!code || code.length <= 2) {
        console.error("   ❌ Account has not been deployed yet!");
        return;
    }
    console.log("\n📦 Account deployed: ✅");

    // Module installation
    const accountABI = parseAbi([
        "function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext) external view returns (bool)"
    ]);
    const accountContract = getContract({ address: accountAddress as Address, abi: accountABI, client: publicClient });
    const isInstalled     = await accountContract.read.isModuleInstalled([
        BigInt(MODULE_TYPE_VALIDATOR),
        validatorAddress as Address,
        "0x" as Hex,
    ]) as boolean;
    console.log(`\n🔧 Validator installed: ${isInstalled ? "✅" : "❌"}`);
    if (!isInstalled) return;

    // Roots
    const helper = new ZKLabeledSignerScopeNexusHelper("0x0000000000000000000000000000000000000000", validatorAddress, publicClient);
    const isInit = await helper.isInitialized(accountAddress);
    console.log(`\n🔐 Validator initialized: ${isInit ? "✅" : "❌"}`);

    if (isInit) {
        const config = await helper.getConfiguration(accountAddress);
        console.log("   Signers Root:", config.signersRoot);
        console.log("   Scope Root:  ", config.scopeRoot);
    }

    // Nonce
    const entryPointAddress = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
    const epABI             = parseAbi(["function getNonce(address,uint192) view returns (uint256)"]);
    const ep                = getContract({ address: entryPointAddress as Address, abi: epABI, client: publicClient });
    const nonce             = await ep.read.getNonce([accountAddress as Address, BigInt(validatorAddress)]) as bigint;
    console.log("\n🔢 Current nonce:", nonce.toString());

    // Balance
    const balance = await publicClient.getBalance({ address: accountAddress as Address });
    console.log(`\n💰 Balance: ${formatEther(balance)} POL${balance === 0n ? " ⚠️  Fund account for gas" : ""}`);

    console.log("\n✅ Status check complete");
}

export default ZKLabeledSignerScopeNexusHelper;
