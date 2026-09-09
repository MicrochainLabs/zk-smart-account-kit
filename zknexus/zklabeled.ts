/**
 * ZK Labeled Signer Module for Nexus Smart Accounts
 *
 * This module provides utilities for deploying and interacting with Nexus accounts
 * that use the ZKLabeledSignerValidator for privacy-preserving label-based validation.
 *
 * Key concepts:
 *   - Each signer is associated with a (label, address) pair in a signers label tree.
 *   - Contacts and protocols are stored in separate label trees (contactsRoot, protocolsRoot).
 *   - A transaction proof shows that the signer is in signersRoot AND the destination
 *     is in contactsRoot or protocolsRoot — without revealing the label names.
 *   - Account creation requires a subset proof that the account's signers are all
 *     members of the organisation-wide mainSignersRoot.
 *
 * Circuit circuits used:
 *   - zk_labeled_signer  (noir/target/zk_labeled_signer.json)  — per-transaction proof
 *   - zk_signer_subset   (noir/target/zk_signer_subset.json)   — account-creation proof
 *
 * @module zklabeled
 */

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { vars } from "hardhat/config";
import { privateKeyToAccount } from "viem/accounts";
import {
    toHex, toBytes, recoverPublicKey, recoverAddress, hashMessage, Hex,
    createWalletClient, http, WalletClient, pad, bytesToHex,
    createPublicClient, getContract, parseEther, concat,
    encodePacked, encodeAbiParameters, parseAbiParameters,
    PublicClient, Account, Chain, Transport, parseAbi, formatEther,
    Hash, TransactionReceipt, decodeEventLog, Address,
    walletActions
} from "viem";
import { poseidon } from "@iden3/js-crypto";
import { LeanIMT } from "@zk-kit/lean-imt";
import { join } from "path";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { readFileSync } from "fs";
import assert from "assert";
import zkLabeledSignerFactory from "../ignition/modules/zkLabeledSignerFactoryNexus";

// ─────────────────────────────────────────────────────────────────────────────
// Constants (must match the Noir circuit constants)
// ─────────────────────────────────────────────────────────────────────────────

export const MODULE_TYPE_VALIDATOR = 1;
export const VALIDATION_SUCCESS    = 0;
export const VALIDATION_FAILED     = 1;

/** Max label size in bytes (UTF-8, zero-padded). Matches LABEL_NAME_BYTES in zk_labels. */
export const LABEL_NAME_BYTES = 31;

/** Max depth of the label registry (contacts / protocols) Merkle tree. */
export const LABELS_MAX_DEPTH = 4;

/** Max depth of the signers Merkle tree. */
export const SIGNERS_MAX_DEPTH = 4;

/** Maximum signers in one subset account. */
export const MAX_SUBSET_SIGNERS = 5;

/** Leaves in the complete-binary subset tree (depth 3 → 2^3 = 8). */
const SUBSET_TREE_LEAVES = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/** A named signer entry in a label tree. */
export interface LabeledSigner {
    label:   string;  // UTF-8 label name, max 31 bytes
    address: string;  // Ethereum address (checksummed or lowercase hex)
}

/** A named address entry in a contacts / protocols label tree. */
export interface LabeledEntry {
    label:   string;  // UTF-8 label name, max 31 bytes
    address: string;  // Ethereum address
}

/** Per-account configuration stored on ZKLabeledSignerValidator. */
export interface ZKLabeledSignerConfig {
    signersRoot:   string;  // bytes32 hex
    contactsRoot:  string;  // bytes32 hex
    protocolsRoot: string;  // bytes32 hex
}

/** Parameters for creating a ZK Labeled Signer Nexus account. */
export interface CreateZKLabeledAccountParams {
    subsetSignersRoot: string;  // bytes32 hex
    contactsRoot:      string;  // bytes32 hex
    protocolsRoot:     string;  // bytes32 hex
    subsetProof:       string;  // hex bytes — proof from zk_signer_subset circuit
    index?:            bigint;
}

// ─────────────────────────────────────────────────────────────────────────────
// Label / field helpers (must match the Noir library implementations exactly)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Encode a label string as a 31-byte UTF-8 array (zero-padded on the right).
 * Labels longer than 31 bytes are silently truncated.
 */
function labelToBytes(label: string): Uint8Array {
    const encoded = new TextEncoder().encode(label);
    const padded  = new Uint8Array(LABEL_NAME_BYTES);
    padded.set(encoded.slice(0, LABEL_NAME_BYTES));
    return padded;
}

/**
 * Convert a 31-byte label array to a BN254 field element (big-endian).
 * Mirrors `label_to_field` in `zk_labels/src/lib.nr`.
 */
function labelToField(labelBytes: Uint8Array): bigint {
    let result = 0n;
    for (let i = 0; i < LABEL_NAME_BYTES; i++) {
        result = result * 256n + BigInt(labelBytes[i]);
    }
    return result;
}

/**
 * Convert an Ethereum address to a BN254 field element (uint160).
 * Mirrors `address_to_field` in `zk_signer/src/lib.nr`.
 */
function addressToField(address: string): bigint {
    return BigInt(address);
}

/**
 * Compute a label commitment leaf:
 *   leaf = Poseidon2( Poseidon1(label_field), Poseidon1(address_field) )
 * Mirrors `label_leaf` in `zk_labels/src/lib.nr`.
 */
export function computeLabelLeaf(label: string, address: string): bigint {
    const labelField   = labelToField(labelToBytes(label));
    const addressField = addressToField(address);
    const labelHash    = poseidon.hash([labelField]);
    const addressHash  = poseidon.hash([addressField]);
    return poseidon.hash([labelHash, addressHash]);
}

/** Hash function used for tree nodes (Poseidon2 on BN254). */
const poseidon2 = (a: bigint, b: bigint): bigint => poseidon.hash([a, b]);

// ─────────────────────────────────────────────────────────────────────────────
// Subset tree helpers (complete binary tree, depth 3, 8 leaves)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build the 8-leaf complete-binary-tree root used as `subsetSignersRoot`.
 * Leaf layout: [signer0, signer1, ..., signerN, 0, 0, ...] (unused slots = 0).
 * Mirrors `build_subset_root` in `zk_signer_subset/src/main.nr`.
 */
export function buildSubsetRoot(subsetSigners: LabeledSigner[]): bigint {
    const leaves: bigint[] = new Array(SUBSET_TREE_LEAVES).fill(0n);
    for (let i = 0; i < Math.min(subsetSigners.length, MAX_SUBSET_SIGNERS); i++) {
        leaves[i] = computeLabelLeaf(subsetSigners[i].label, subsetSigners[i].address);
    }
    // Level 2 (4 pairs → 4 nodes)
    const n: bigint[] = [];
    for (let i = 0; i < 4; i++) {
        n.push(poseidon2(leaves[2 * i], leaves[2 * i + 1]));
    }
    // Level 1 (2 pairs → 2 nodes)
    const m: bigint[] = [];
    for (let i = 0; i < 2; i++) {
        m.push(poseidon2(n[2 * i], n[2 * i + 1]));
    }
    // Root
    return poseidon2(m[0], m[1]);
}

/**
 * Generate a Merkle inclusion proof for a leaf at `leafIndex` in the 8-leaf
 * complete-binary subset tree.
 *
 * Returns `{ siblings, indices }` padded to `SIGNERS_MAX_DEPTH` elements so
 * the arrays can be passed directly to the Noir circuit.
 */
export function getSubsetTreeProof(
    leafIndex: number,
    subsetSigners: LabeledSigner[]
): { siblings: bigint[]; indices: number[]; depth: number } {
    if (leafIndex < 0 || leafIndex >= SUBSET_TREE_LEAVES) {
        throw new Error(`Leaf index ${leafIndex} out of range [0, ${SUBSET_TREE_LEAVES - 1}]`);
    }

    const leaves: bigint[] = new Array(SUBSET_TREE_LEAVES).fill(0n);
    for (let i = 0; i < Math.min(subsetSigners.length, MAX_SUBSET_SIGNERS); i++) {
        leaves[i] = computeLabelLeaf(subsetSigners[i].label, subsetSigners[i].address);
    }

    // Build all levels explicitly so we can extract siblings
    const level0 = leaves;  // 8 leaves
    const level1: bigint[] = [];
    for (let i = 0; i < 4; i++) {
        level1.push(poseidon2(level0[2 * i], level0[2 * i + 1]));
    }
    const level2: bigint[] = [];
    for (let i = 0; i < 2; i++) {
        level2.push(poseidon2(level1[2 * i], level1[2 * i + 1]));
    }

    // Path from leaf to root (depth = 3)
    const siblings: bigint[] = [];
    const indices:  number[] = [];

    // Step 0 — leaf level
    const isRight0 = leafIndex % 2 === 1;
    siblings.push(isRight0 ? level0[leafIndex - 1] : level0[leafIndex + 1]);
    indices.push(isRight0 ? 1 : 0);

    // Step 1 — level 1
    const idx1     = Math.floor(leafIndex / 2);
    const isRight1 = idx1 % 2 === 1;
    siblings.push(isRight1 ? level1[idx1 - 1] : level1[idx1 + 1]);
    indices.push(isRight1 ? 1 : 0);

    // Step 2 — level 2
    const idx2     = Math.floor(idx1 / 2);
    const isRight2 = idx2 % 2 === 1;
    siblings.push(isRight2 ? level2[idx2 - 1] : level2[idx2 + 1]);
    indices.push(isRight2 ? 1 : 0);

    return { siblings, indices, depth: 3 };
}

// ─────────────────────────────────────────────────────────────────────────────
// LeanIMT helpers (for main signers tree and contact / protocol registries)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a LeanIMT whose leaves are label commitments for the given entries.
 * Insertion order follows the order of `entries`; sort externally if determinism
 * across calls is required.
 */
export function buildLabeledTree(entries: LabeledEntry[]): LeanIMT {
    // @ts-ignore — LeanIMT type definitions expect a specific hash signature
    const tree = new LeanIMT(poseidon2);
    for (const e of entries) {
        tree.insert(computeLabelLeaf(e.label, e.address));
    }
    return tree;
}

/**
 * Generate a Merkle inclusion proof for `entry` in the given LeanIMT.
 * Returns siblings and indices padded to `maxDepth` for use in Noir circuits.
 */
function getLabeledEntryProof(
    tree: LeanIMT,
    entry: LabeledEntry,
    maxDepth: number = LABELS_MAX_DEPTH
): { siblings: bigint[]; indices: number[]; depth: number } {
    const leaf  = computeLabelLeaf(entry.label, entry.address);
    const leafIdx = tree.indexOf(leaf);
    if (leafIdx === -1) {
        throw new Error(
            `Entry "${entry.label}" / ${entry.address} not found in label tree`
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
// Low-level ECDSA helpers (shared with zknexus.ts pattern)
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
// ZKLabeledNexusHelper — on-chain read / write wrapper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Helper class for ZKLabeledSignerValidator Nexus operations.
 * Wraps the factory and validator contract ABIs.
 */
export class ZKLabeledNexusHelper {
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
     * Predict the CREATE2 address for a new ZK Labeled Signer Nexus account.
     * No proof needed — only the roots and index are used for the salt.
     */
    async computeAccountAddress(params: CreateZKLabeledAccountParams): Promise<string> {
        const { subsetSignersRoot, contactsRoot, protocolsRoot, index = 0n } = params;

        const abi = parseAbi([
            "function computeAccountAddress(bytes32 subsetSignersRoot, bytes32 contactsRoot, bytes32 protocolsRoot, uint256 index) view returns (address)"
        ]);

        const factory = getContract({
            address: this.factoryAddress,
            abi,
            client:  this.publicClient,
        });

        return await factory.read.computeAccountAddress([
            subsetSignersRoot as Hex,
            contactsRoot      as Hex,
            protocolsRoot     as Hex,
            index,
        ]) as string;
    }

    // ── Account creation ──────────────────────────────────────────────────────

    /**
     * Deploy a new Nexus account with ZKLabeledSignerValidator installed.
     * The factory verifies the subset proof before deployment.
     */
    async createAccount(params: CreateZKLabeledAccountParams): Promise<{
        account:     string;
        transaction: Hash;
    }> {
        if (!this.walletClient) {
            throw new Error("Wallet client required for account creation");
        }

        const { subsetSignersRoot, contactsRoot, protocolsRoot, subsetProof, index = 0n } = params;

        const abi = parseAbi([
            "function createAccount(bytes32 subsetSignersRoot, bytes32 contactsRoot, bytes32 protocolsRoot, bytes subsetProof, uint256 index) payable returns (address)"
        ]);

        const txHash = await this.walletClient.writeContract({
            address:      this.factoryAddress,
            abi,
            functionName: "createAccount",
            args: [
                subsetSignersRoot as Hex,
                contactsRoot      as Hex,
                protocolsRoot     as Hex,
                subsetProof       as Hex,
                index,
            ],
            account: this.walletClient.account!,
            chain:   undefined,
        });

        const receipt = await this.publicClient.waitForTransactionReceipt({ hash: txHash });

        // Extract account address from event
        const eventABI = parseAbi([
            "event ZKLabeledSignerAccountCreated(address indexed account, bytes32 indexed subsetSignersRoot, bytes32 contactsRoot, bytes32 protocolsRoot, uint256 index)"
        ]);

        let accountAddress: string | undefined;
        for (const log of receipt.logs) {
            try {
                const decoded = decodeEventLog({ abi: eventABI, data: log.data, topics: log.topics });
                if (decoded.eventName === "ZKLabeledSignerAccountCreated") {
                    accountAddress = (decoded.args as any).account as string;
                    break;
                }
            } catch {
                continue;
            }
        }

        if (!accountAddress) {
            throw new Error("ZKLabeledSignerAccountCreated event not found in receipt");
        }

        return { account: accountAddress, transaction: txHash };
    }

    // ── Validator state readers ───────────────────────────────────────────────

    /**
     * Read the three Merkle roots stored for a Nexus account on the validator.
     */
    async getConfiguration(accountAddress: string): Promise<ZKLabeledSignerConfig> {
        const abi = parseAbi([
            "function getConfig(address smartAccount) view returns (bytes32 signersRoot, bytes32 contactsRoot, bytes32 protocolsRoot)"
        ]);

        const validator = getContract({
            address: this.validatorAddress,
            abi,
            client:  this.publicClient,
        });

        const [signersRoot, contactsRoot, protocolsRoot] =
            await validator.read.getConfig([accountAddress as Address]) as [string, string, string];

        return { signersRoot, contactsRoot, protocolsRoot };
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
     * Install the ZKLabeledSignerValidator on an existing Nexus account.
     * The caller must be the account owner / controller.
     */
    async installValidator(
        nexusAccountAddress: Address,
        signersRoot:   string,
        contactsRoot:  string,
        protocolsRoot: string,
    ): Promise<Hash> {
        if (!this.walletClient) {
            throw new Error("Wallet client required for validator installation");
        }

        const initData = encodeAbiParameters(
            parseAbiParameters("bytes32, bytes32, bytes32"),
            [signersRoot as Hex, contactsRoot as Hex, protocolsRoot as Hex]
        );

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
    encodeValidatorInitData(
        signersRoot:   string,
        contactsRoot:  string,
        protocolsRoot: string,
    ): Hex {
        return encodeAbiParameters(
            parseAbiParameters("bytes32, bytes32, bytes32"),
            [signersRoot as Hex, contactsRoot as Hex, protocolsRoot as Hex]
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof generation — zk_signer_subset (account creation)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a `zk_signer_subset` proof proving that every signer in
 * `subsetSigners` is a member of `mainSignersRoot`.
 *
 * @param mainSigners      The full org-wide signer list (builds the main LeanIMT).
 * @param subsetSigners    The account's signer subset (up to MAX_SUBSET_SIGNERS=5).
 * @param mainSignersRoot  The on-chain mainSignersRoot from the factory.
 *
 * @returns ProofData containing `proof` (UltraHonk bytes) and `publicInputs`.
 */
export async function proveSignerSubset(
    mainSigners:     LabeledSigner[],
    subsetSigners:   LabeledSigner[],
    mainSignersRoot: Hex,
) {
    if (subsetSigners.length === 0 || subsetSigners.length > MAX_SUBSET_SIGNERS) {
        throw new Error(`subsetSigners must have 1–${MAX_SUBSET_SIGNERS} entries`);
    }

    // ── Build main signers LeanIMT ─────────────────────────────────────────
    // @ts-ignore
    const mainTree = new LeanIMT(poseidon2);
    for (const s of mainSigners) {
        mainTree.insert(computeLabelLeaf(s.label, s.address));
    }

    // Verify caller-supplied mainSignersRoot matches what we computed
    const computedMainRoot = toHex(mainTree.root) as Hex;
    if (computedMainRoot.toLowerCase() !== mainSignersRoot.toLowerCase()) {
        throw new Error(
            `mainSignersRoot mismatch!\n  Computed: ${computedMainRoot}\n  Provided: ${mainSignersRoot}\n` +
            `Ensure mainSigners matches the full list used when the factory was deployed.`
        );
    }

    // ── Build subset root ──────────────────────────────────────────────────
    const subsetRoot = buildSubsetRoot(subsetSigners);

    // ── Collect proof inputs for each signer ──────────────────────────────
    const nilProof = {
        length:   0,
        indices:  padArray([] as number[],  LABELS_MAX_DEPTH, 0),
        siblings: padArray([] as string[],  LABELS_MAX_DEPTH, "0x0"),
    };

    const signerLabelBytes:   number[][] = [];
    const signerAddressBytes: number[][] = [];
    const isActive:           boolean[]  = [];
    const mainProofLengths:   number[]   = [];
    const mainProofIndices:   number[][] = [];
    const mainProofSiblings:  string[][] = [];

    for (let i = 0; i < MAX_SUBSET_SIGNERS; i++) {
        if (i < subsetSigners.length) {
            const s    = subsetSigners[i];
            const leaf = computeLabelLeaf(s.label, s.address);
            const idx  = mainTree.indexOf(leaf);

            if (idx === -1) {
                throw new Error(
                    `Subset signer "${s.label}" / ${s.address} not found in mainSigners tree.\n` +
                    `Add this signer to mainSigners before proving.`
                );
            }

            const proof = getLabeledEntryProof(mainTree, s, LABELS_MAX_DEPTH);

            signerLabelBytes.push(Array.from(labelToBytes(s.label)));
            signerAddressBytes.push(Array.from(toBytes(s.address as Hex)));
            isActive.push(true);
            mainProofLengths.push(proof.depth);
            mainProofIndices.push(padArray(proof.indices, LABELS_MAX_DEPTH, 0));
            mainProofSiblings.push(padArray(proof.siblings.map(v => toHex(v)), LABELS_MAX_DEPTH, "0x0"));
        } else {
            // Inactive (padding) slot
            signerLabelBytes.push(Array.from(new Uint8Array(LABEL_NAME_BYTES)));
            signerAddressBytes.push(Array.from(new Uint8Array(20)));
            isActive.push(false);
            mainProofLengths.push(nilProof.length);
            mainProofIndices.push(nilProof.indices);
            mainProofSiblings.push(nilProof.siblings);
        }
    }

    // ── Circuit inputs ─────────────────────────────────────────────────────
    const input = {
        signer_label_bytes:   signerLabelBytes,
        signer_address_bytes: signerAddressBytes,
        is_active:            isActive,
        main_proof_lengths:   mainProofLengths,
        main_proof_indices:   mainProofIndices,
        main_proof_siblings:  mainProofSiblings,
        main_signers_root:    toHex(mainTree.root),
        subset_signers_root:  toHex(subsetRoot),
    };

    console.log("=== proveSignerSubset ===");
    console.log("  Main root:     ", toHex(mainTree.root));
    console.log("  Subset root:   ", toHex(subsetRoot));
    console.log("  Active signers:", subsetSigners.length);

    // ── Load circuit and generate proof ───────────────────────────────────
    const circuitPath = join(process.cwd(), "noir", "target", "zk_signer_subset.json");
    const compiledCircuit = JSON.parse(readFileSync(circuitPath, "utf-8"));

    const api     = await Barretenberg.new({ threads: 1 });
    const backend = new UltraHonkBackend(compiledCircuit.bytecode, api);
    const noir    = new Noir(compiledCircuit);

    try {
        console.log("  Generating witness...");
        const { witness } = await noir.execute(input);

        console.log("  Generating proof...");
        const t0        = Date.now();
        const proofData = await backend.generateProof(witness, { verifierTarget: "evm" });
        console.log(`  Proof generated in ${Date.now() - t0}ms (${proofData.proof.length} bytes)`);

        // Local verification
        const ok = await backend.verifyProof(proofData, { verifierTarget: "evm" });
        assert(ok, "Subset proof local verification failed");
        console.log("  ✅ Subset proof verified locally");

        return proofData;
    } finally {
        await api.destroy();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof generation — zk_labeled_signer (per-transaction)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Generate a `zk_labeled_signer` proof for a single UserOperation.
 *
 * The signer proves:
 *   (1) They hold the ECDSA key for an address whose (label, address) is in `signersRoot`.
 *   (2) The call target's (label, address) is in `registryRoot` (contacts or protocols).
 *
 * @param txHash          UserOperation hash (32 bytes, raw/unprefixed).
 * @param signature       Signer's ECDSA signature over the EIP-191-prefixed `txHash`
 *                        (i.e. what a wallet's `personal_sign(txHash, address)` produces —
 *                        used to recover the address and public key, and fed as the
 *                        circuit's `txn_hash` public input, matching what
 *                        `ZKLabeledSignerValidator._verifyProof` reconstructs on-chain).
 * @param signerLabel     Signer's label name in the signers tree.
 * @param subsetSigners   All signers in the account's subset (to rebuild the subset tree).
 * @param destAddress     Call target address (must match the actual UserOp calldata target).
 * @param destLabel       Destination's label in the registry tree.
 * @param registryEntries Entries in the relevant registry (contacts or protocols list).
 * @param signersRoot     On-chain signersRoot from the validator config.
 * @param registryRoot    Either contactsRoot or protocolsRoot from the validator config.
 *
 * @returns `{ proofData, registryRoot, destAddressField, encodedSignature }`
 *   where `encodedSignature = abi.encode(bytes proof, bytes32 registryRoot, bytes32 destAddressField)`
 *   ready to be placed in `PackedUserOperation.signature`.
 */
export async function proveLabeledSignerTx(
    txHash:          Hex,
    signature:       Hex,
    signerLabel:     string,
    subsetSigners:   LabeledSigner[],
    destAddress:     string,
    destLabel:       string,
    registryEntries: LabeledEntry[],
    signersRoot:     Hex,
    registryRoot:    Hex,
) {
    // ── EIP-191-prefix the UserOp hash — this is what wallets actually sign via
    //    `personal_sign`, and what ZKLabeledSignerValidator._verifyProof now decomposes
    //    into the circuit's txn_hash public input (see the on-chain EIP-191 prefix fix).
    const prefixedHash = hashMessage({ raw: toBytes(txHash) });

    // ── Recover signer address and public key from the pre-collected signature ─
    const signerAddress = await recoverAddress({ hash: prefixedHash, signature });
    const pubKeyHex     = await recoverPublicKey({ hash: prefixedHash, signature });

    const { x: pubkeyX, y: pubkeyY } = extractCoordinates(pubKeyHex);
    const sigRS                        = extractRS(signature);

    console.log("=== proveLabeledSignerTx ===");
    console.log("  Signer address:", signerAddress);
    console.log("  Signer label:  ", signerLabel);
    console.log("  Destination:   ", destAddress, `(label: "${destLabel}")`);

    // ── Build subset (signers) tree for the signer's membership proof ──────
    const subsetRoot     = buildSubsetRoot(subsetSigners);
    const computedSignersRoot = toHex(subsetRoot) as Hex;
    if (computedSignersRoot.toLowerCase() !== signersRoot.toLowerCase()) {
        throw new Error(
            `signersRoot mismatch!\n  Computed from subsetSigners: ${computedSignersRoot}\n  Expected on-chain: ${signersRoot}\n` +
            `Ensure subsetSigners exactly matches the list used when the account was created.`
        );
    }

    // Find this signer in the subset
    const signerEntry: LabeledSigner = { label: signerLabel, address: signerAddress };
    const signerLeaf                  = computeLabelLeaf(signerLabel, signerAddress);
    const signerIdxInSubset = subsetSigners.findIndex(
        s => computeLabelLeaf(s.label, s.address) === signerLeaf
    );
    if (signerIdxInSubset === -1) {
        throw new Error(
            `Signer "${signerLabel}" / ${signerAddress} not found in subsetSigners.\n` +
            `Available: ${subsetSigners.map(s => `${s.label}/${s.address}`).join(", ")}`
        );
    }

    const signerProof = getSubsetTreeProof(signerIdxInSubset, subsetSigners);

    // ── Build registry tree for the destination's membership proof ─────────
    const registryTree = buildLabeledTree(registryEntries);
    const computedRegistryRoot = toHex(registryTree.root) as Hex;
    if (computedRegistryRoot.toLowerCase() !== registryRoot.toLowerCase()) {
        throw new Error(
            `registryRoot mismatch!\n  Computed from registryEntries: ${computedRegistryRoot}\n  Expected on-chain: ${registryRoot}\n` +
            `Ensure registryEntries exactly matches the list used when the account was created.`
        );
    }

    const destEntry: LabeledEntry = { label: destLabel, address: destAddress };
    const destProof = getLabeledEntryProof(registryTree, destEntry, LABELS_MAX_DEPTH);

    // ── Compute public inputs ──────────────────────────────────────────────
    const destAddressField = addressToField(destAddress);
    const signersRootBigInt  = BigInt(signersRoot);
    const registryRootBigInt = BigInt(registryRoot);

    // ── Circuit inputs ─────────────────────────────────────────────────────
    const input = {
        // Signer private inputs
        pubkey: { x: pubkeyX, y: pubkeyY },
        signature: sigRS,
        signer_label_bytes:    Array.from(labelToBytes(signerLabel)),
        signer_proof_length:   signerProof.depth,
        signer_proof_indices:  padArray(signerProof.indices,                        SIGNERS_MAX_DEPTH, 0),
        signer_proof_siblings: padArray(signerProof.siblings.map(v => toHex(v)),   SIGNERS_MAX_DEPTH, "0x0"),

        // Destination private inputs
        dest_address_bytes:        Array.from(toBytes(destAddress as Hex)),
        dest_label_bytes:          Array.from(labelToBytes(destLabel)),
        dest_label_proof_length:   destProof.depth,
        dest_label_proof_indices:  padArray(destProof.indices,                       LABELS_MAX_DEPTH, 0),
        dest_label_proof_siblings: padArray(destProof.siblings.map(v => toHex(v)), LABELS_MAX_DEPTH, "0x0"),

        // Public inputs
        // txn_hash is the EIP-191-prefixed hash (matches the on-chain validator's
        // decomposition of MessageHashUtils.toEthSignedMessageHash(userOpHash)).
        txn_hash:           Array.from(toBytes(prefixedHash)),
        signers_root:       toHex(signersRootBigInt),
        registry_root:      toHex(registryRootBigInt),
        dest_address_field: toHex(destAddressField),
    };

    // ── Load circuit and generate proof ───────────────────────────────────
    const circuitPath     = join(process.cwd(), "noir", "target", "zk_labeled_signer.json");
    const compiledCircuit = JSON.parse(readFileSync(circuitPath, "utf-8"));

    const api     = await Barretenberg.new({ threads: 1 });
    const backend = new UltraHonkBackend(compiledCircuit.bytecode, api);
    const noir    = new Noir(compiledCircuit);

    try {
        console.log("  Generating witness...");
        const { witness } = await noir.execute(input);

        console.log("  Generating labeled signer proof...");
        const t0        = Date.now();
        const proofData = await backend.generateProof(witness, { verifierTarget: "evm" });
        console.log(`  Proof generated in ${Date.now() - t0}ms (${proofData.proof.length} bytes)`);
        console.log(`  Public inputs: ${proofData.publicInputs.length}`);

        // Local verification
        const ok = await backend.verifyProof(proofData, { verifierTarget: "evm" });
        assert(ok, "Labeled signer proof local verification failed");
        console.log("  ✅ Labeled signer proof verified locally");

        // Encode the UserOp signature:
        //   abi.encode(bytes zkProof, bytes32 registryRoot, bytes32 destAddressField)
        const encodedSignature = encodeAbiParameters(
            parseAbiParameters("bytes, bytes32, bytes32"),
            [
                toHex(proofData.proof),
                registryRoot,
                pad(toHex(destAddressField), { size: 32 }) as Hex,
            ]
        );

        return {
            proofData,
            registryRoot,
            destAddressField: toHex(destAddressField) as Hex,
            encodedSignature,
        };
    } finally {
        await api.destroy();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High-level Hardhat task helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Predict the address for a ZK Labeled Signer Nexus account.
 */
export async function computeZKLabeledNexusAddress(
    hre:               HardhatRuntimeEnvironment,
    factoryAddress:    string,
    validatorAddress:  string,
    subsetSignersRoot: string,
    contactsRoot:      string,
    protocolsRoot:     string,
    index:             string
) {
    const networkConfig = hre.network.config as any;
    const publicClient  = createPublicClient({ transport: http(networkConfig.url) });

    const helper  = new ZKLabeledNexusHelper(factoryAddress, validatorAddress, publicClient);
    const address = await helper.computeAccountAddress({
        subsetSignersRoot,
        contactsRoot,
        protocolsRoot,
        subsetProof: "0x",  // not used for address prediction
        index:       BigInt(index),
    });

    console.log("Computed Nexus account address:", address);
    console.log("\nParameters:");
    console.log("  Factory:           ", factoryAddress);
    console.log("  Validator:         ", validatorAddress);
    console.log("  Subset Signers Root:", subsetSignersRoot);
    console.log("  Contacts Root:     ", contactsRoot);
    console.log("  Protocols Root:    ", protocolsRoot);
    console.log("  Index:             ", index);

    return address;
}

/**
 * Read and print the ZKLabeledSignerValidator configuration for a Nexus account.
 */
export async function getZKLabeledNexusConfig(
    hre:              HardhatRuntimeEnvironment,
    validatorAddress: string,
    accountAddress:   string
) {
    const networkConfig = hre.network.config as any;
    const publicClient  = createPublicClient({ transport: http(networkConfig.url) });

    const helper = new ZKLabeledNexusHelper(
        "0x0000000000000000000000000000000000000000",
        validatorAddress,
        publicClient
    );

    console.log("Checking Nexus account:", accountAddress);

    const isInit = await helper.isInitialized(accountAddress);
    console.log("  Is initialized:", isInit);

    if (isInit) {
        const config = await helper.getConfiguration(accountAddress);
        console.log("  Signers Root:  ", config.signersRoot);
        console.log("  Contacts Root: ", config.contactsRoot);
        console.log("  Protocols Root:", config.protocolsRoot);

        const verifier = await helper.getProofVerifier();
        console.log("  Proof Verifier:", verifier);

        return config;
    } else {
        console.log("  ⚠️  Account not initialized with ZKLabeledSignerValidator");
    }
}

/**
 * Deploy the full ZK Labeled Signer factory stack via the `zkLabeledSignerFactoryNexus`
 * Ignition module:
 *   ZKTranscriptLib (shared) → HonkVerifier (zk_labeled_signer) → ZKLabeledSignerProofVerifier
 *   → HonkVerifier (zk_signer_subset) → ZKSignerSubsetProofVerifier
 *   → ZKLabeledSignerValidator → ZKLabeledSignerValidatorFactory
 *
 * The organisation-wide `initialMainSignersRoot` is computed on-the-fly from
 * `mainSigners` (LeanIMT root) — it is not passed in directly.
 *
 * @param hre          Hardhat runtime.
 * @param mainSigners  The full org-wide signer list (label + address pairs).
 * @param owner        Address authorised to rotate `mainSignersRoot` later (e.g. a multisig).
 */
export async function createZKLabeledSignerFactoryContract(
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

    const tree = buildLabeledTree(mainSigners);
    const initialMainSignersRoot = pad(toHex(tree.root), { size: 32 }) as Hex;

    console.log("\nMain signers:");
    mainSigners.forEach(s => console.log(`  ${s.label} → ${s.address}`));
    console.log("Computed mainSignersRoot:", initialMainSignersRoot);

    const result = await hre.ignition.deploy(zkLabeledSignerFactory, {
        parameters: {
            ZKLabeledSignerFactory_v1: {
                initialMainSignersRoot,
                owner,
            },
        },
    });

    console.log("\nZK Transcript Lib (shared):        ", result.zkTranscriptLib);
    console.log("Labeled Signer HonkVerifier:        ", result.labeledSignerHonkVerifier);
    console.log("ERC-8039 Labeled Signer Verifier:   ", result.erc8039LabeledSigner);
    console.log("Signer Subset HonkVerifier:         ", result.signerSubsetHonkVerifier);
    console.log("ERC-8039 Signer Subset Verifier:    ", result.erc8039SignerSubset);
    console.log("ZKLabeledSignerValidator:           ", result.zkLabeledSignerValidator);
    console.log("ZKLabeledSignerValidatorFactory:    ", result.zkLabeledSignerValidatorFactory);

    return result;
}

/**
 * Full account-creation flow:
 *   1. Build the main signers LeanIMT from `mainSigners`.
 *   2. Build the subset tree from `subsetSigners`.
 *   3. Build contacts and protocols label trees.
 *   4. Generate a `zk_signer_subset` proof.
 *   5. Deploy the Nexus account via the factory.
 *
 * @param hre              Hardhat runtime.
 * @param mainSigners      The full org-wide signer list used when the factory was deployed.
 * @param subsetSigners    This account's signers (up to 5, all must be in mainSigners).
 * @param contacts         Initial contact book (label → address).
 * @param protocols        Initial protocol list (label → address).
 * @param validatorAddress ZKLabeledSignerValidator contract address.
 * @param factoryAddress   ZKLabeledSignerValidatorFactory contract address.
 * @param mainSignersRoot  The factory's current mainSignersRoot (read from chain).
 */
export async function createZKLabeledNexusAccount(
    hre:               HardhatRuntimeEnvironment,
    mainSigners:       LabeledSigner[],
    subsetSigners:     LabeledSigner[],
    contacts:          LabeledEntry[],
    protocols:         LabeledEntry[],
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

    console.log("Creating ZK Labeled Signer Nexus account...");
    console.log("  Factory:          ", factoryAddress);
    console.log("  Deployer:         ", account.address);
    console.log("  Subset signers:   ", subsetSigners.map(s => `${s.label}/${s.address}`).join(", "));
    console.log("  Contacts:         ", contacts.length, "entries");
    console.log("  Protocols:        ", protocols.length, "entries");

    // ── Build roots ────────────────────────────────────────────────────────
    const subsetRoot  = buildSubsetRoot(subsetSigners);
    const contactsTree  = buildLabeledTree(contacts);
    const protocolsTree = buildLabeledTree(protocols);

    const subsetSignersRoot = pad(toHex(subsetRoot), { size: 32 }) as Hex;
    const contactsRoot      = pad(toHex(contactsTree.root), { size: 32 }) as Hex;
    const protocolsRoot     = pad(toHex(protocolsTree.root), { size: 32 }) as Hex;

    console.log("\n📊 Roots:");
    console.log("  Subset Signers Root:", subsetSignersRoot);
    console.log("  Contacts Root:      ", contactsRoot);
    console.log("  Protocols Root:     ", protocolsRoot);

    // ── Generate subset proof ──────────────────────────────────────────────
    console.log("\n🔐 Generating zk_signer_subset proof...");
    const subsetProofData = await proveSignerSubset(
        mainSigners,
        subsetSigners,
        mainSignersRoot as Hex,
    );
    console.log("✅ Subset proof generated");

    // ── Compute address before deploying ──────────────────────────────────
    const helper = new ZKLabeledNexusHelper(
        factoryAddress,
        validatorAddress,
        publicClient,
        walletClient,
    );

    const predictedAddress = await helper.computeAccountAddress({
        subsetSignersRoot,
        contactsRoot,
        protocolsRoot,
        subsetProof: toHex(subsetProofData.proof),
        index: 0n,
    });
    console.log("\n📍 Predicted account address:", predictedAddress);

    // ── Deploy ─────────────────────────────────────────────────────────────
    const { account: deployedAccount, transaction } = await helper.createAccount({
        subsetSignersRoot,
        contactsRoot,
        protocolsRoot,
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
        contactsRoot,
        protocolsRoot,
    };
}

/**
 * Compute and sign the UserOp hash for a labeled signer account.
 * Call this to collect the ECDSA signature before generating the ZK proof.
 *
 * NOTE: For ZKLabeledSignerValidator the ZK proof covers the full transaction,
 * so a single call to `sendZKLabeledNexusUserOp` handles both signing and proof
 * generation.  This function is provided for cases where you want to inspect or
 * log the UserOp hash before committing to proof generation.
 */
export async function computeLabeledUserOpHash(
    hre:              HardhatRuntimeEnvironment,
    accountAddress:   string,
    validatorAddress: string,
    to:               string,
    value:            string,
    data:             string,
) {
    const networkConfig = hre.network.config as any;
    const publicClient  = createPublicClient({ transport: http(networkConfig.url) });

    const valueInWei = value.includes(".") ? parseEther(value) : BigInt(value);

    // Determine EntryPoint
    const accountABI = parseAbi(["function entryPoint() external view returns (address)"]);
    const accountContract = getContract({
        address: accountAddress as Address,
        abi:     accountABI,
        client:  publicClient,
    });
    const entryPointAddress = await accountContract.read.entryPoint() as Address;

    // Build callData (ERC-7579 single execute)
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

    // Nonce
    const entryPointABI = parseAbi(["function getNonce(address,uint192) view returns (uint256)"]);
    const entryPoint    = getContract({ address: entryPointAddress, abi: entryPointABI, client: publicClient });
    const nonceKey      = BigInt(validatorAddress);
    const nonce         = await entryPoint.read.getNonce([accountAddress as Address, nonceKey]) as bigint;

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

    const epHashABI = parseAbi([
        "function getUserOpHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)) view returns (bytes32)"
    ]);
    const epContract  = getContract({ address: entryPointAddress, abi: epHashABI, client: publicClient });
    const userOpHash  = await epContract.read.getUserOpHash([[
        userOp.sender, userOp.nonce, userOp.initCode, userOp.callData,
        userOp.accountGasLimits, userOp.preVerificationGas,
        userOp.gasFees, userOp.paymasterAndData, userOp.signature,
    ]]) as Hex;

    console.log("\n🔑 UserOp Hash:", userOpHash);
    console.log("   EntryPoint:  ", entryPointAddress);
    console.log("   Nonce:       ", nonce.toString());

    return { userOpHash, userOp, entryPointAddress };
}

/**
 * End-to-end flow: build UserOp → generate ZK proof → submit via EntryPoint.
 *
 * @param hre               Hardhat runtime.
 * @param accountAddress    The deployed Nexus account.
 * @param validatorAddress  ZKLabeledSignerValidator address.
 * @param entryPointAddress EntryPoint v0.7 address (pass "" to auto-detect).
 * @param to                Call target address.
 * @param value             Call value (decimal POL or integer wei string).
 * @param data              Call data (hex).
 * @param signature         Signer's ECDSA signature over the UserOp hash (see `computeLabeledUserOpHash`).
 * @param userOpHash        The UserOp hash that `signature` was produced over. Verified against the
 *                          freshly-computed hash before use — if the nonce changed since signing,
 *                          this will mismatch and the call throws.
 * @param signerLabel       Label of the signer in the signersRoot.
 * @param subsetSigners     All subset signers (to rebuild signersRoot proof).
 * @param registryType      "contacts" | "protocols" — which tree to prove against.
 * @param registryEntries   The contact book OR protocol list used at account creation.
 * @param destLabel         The destination's label in the chosen registry.
 */
export async function sendZKLabeledNexusUserOp(
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
    registryType:      "contacts" | "protocols",
    registryEntries:   LabeledEntry[],
    destLabel:         string,
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

    console.log("\n🚀 Preparing ZK Labeled Signer UserOperation...");
    console.log("   Account:    ", accountAddress);
    console.log("   To:         ", to);
    console.log("   Value:      ", valueInWei.toString(), "wei");
    console.log("   Validator:  ", validatorAddress);
    console.log("   Registry:   ", registryType);

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
        throw new Error(`ZKLabeledSignerValidator is not installed on account ${accountAddress}`);
    }
    console.log("   ✅ Validator installed");

    const helper     = new ZKLabeledNexusHelper("0x0000000000000000000000000000000000000000", validatorAddress, publicClient);
    const isInit     = await helper.isInitialized(accountAddress);
    if (!isInit) {
        throw new Error(`ZKLabeledSignerValidator is not initialized for account ${accountAddress}`);
    }
    console.log("   ✅ Validator initialized");

    // ── Read on-chain roots ────────────────────────────────────────────────
    const config = await helper.getConfiguration(accountAddress);
    console.log("\n🔐 On-chain roots:");
    console.log("   signersRoot:  ", config.signersRoot);
    console.log("   contactsRoot: ", config.contactsRoot);
    console.log("   protocolsRoot:", config.protocolsRoot);

    const registryRoot = (registryType === "contacts"
        ? config.contactsRoot
        : config.protocolsRoot) as Hex;

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
        console.error("   Regenerate the signature with the current UserOp hash (see computeLabeledUserOpHash).");
        throw new Error(`UserOp hash mismatch! Computed: ${computedUserOpHash}, Provided: ${userOpHash}`);
    }
    console.log("   ✅ UserOp hashes match!");

    // ── Generate ZK proof ──────────────────────────────────────────────────
    console.log("\n🔐 Generating zk_labeled_signer proof...");
    const { encodedSignature } = await proveLabeledSignerTx(
        computedUserOpHash,
        signature,
        signerLabel,
        subsetSigners,
        to,
        destLabel,
        registryEntries,
        config.signersRoot as Hex,
        registryRoot,
    );

    userOp.signature = encodedSignature;

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
            console.error("   Check that the signersRoot, contactsRoot/protocolsRoot, and circuit artifacts are all in sync.");
        } else if (msg.includes("AA25")) {
            console.error("   AA25 — Invalid nonce. The nonce changed between signing and submission.");
        } else if (msg.includes("AA21")) {
            console.error(`   AA21 — Account ${accountAddress} has insufficient balance for gas.`);
        } else if (msg.includes("AA23") || msg.includes("AA13")) {
            console.error("   AA23/AA13 — validateUserOp reverted. This usually means the ZK proof or");
            console.error("   ECDSA signature verification failed inside ZKLabeledSignerValidator, or the");
            console.error("   account/validator ran out of the allotted verification gas.");
        }
        throw error;
    }
}

/**
 * Print a detailed status report for a ZK Labeled Signer Nexus account.
 */
export async function checkZKLabeledNexusAccount(
    hre:              HardhatRuntimeEnvironment,
    accountAddress:   string,
    validatorAddress: string,
) {
    const publicClient = await hre.viem.getPublicClient();

    console.log("\n🔍 ZK Labeled Signer Nexus Account Status");
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
    const helper = new ZKLabeledNexusHelper("0x0000000000000000000000000000000000000000", validatorAddress, publicClient);
    const isInit = await helper.isInitialized(accountAddress);
    console.log(`\n🔐 Validator initialized: ${isInit ? "✅" : "❌"}`);

    if (isInit) {
        const config = await helper.getConfiguration(accountAddress);
        console.log("   Signers Root:  ", config.signersRoot);
        console.log("   Contacts Root: ", config.contactsRoot);
        console.log("   Protocols Root:", config.protocolsRoot);
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

export default ZKLabeledNexusHelper;
