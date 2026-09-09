// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ZK Labeled Signer Validator
// Privacy-preserving validator that requires:
//   1. An authorized signer (identity hidden via ZK) signed the transaction.
//   2. The call destination is registered in either the Contacts or Protocols
//      label tree (label name hidden via ZK).
//
// Developed by Microchain Labs

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IValidator } from "@biconomy/nexus/interfaces/modules/IValidator.sol";
import {
    MODULE_TYPE_VALIDATOR,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED,
    ERC1271_MAGICVALUE,
    ERC1271_INVALID
} from "@biconomy/nexus/types/Constants.sol";
import { IERC8039, ERC8039Constants } from "../../../ERC8039/IERC8039.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title ZKLabeledSignerValidator
/// @notice ERC-7579 validator module for Nexus smart accounts.
///
/// @dev Combines two zero-knowledge checks in a single proof:
///
///   SIGNER CHECK — the user holds a private key whose address is in the
///   authorized `signersRoot` Merkle tree, without revealing which signer acted.
///
///   DESTINATION CHECK — the call target is registered under some label (a contact
///   name or a protocol name) in either the `contactsRoot` or `protocolsRoot` tree,
///   without revealing the label name.
///
/// The smart account stores three on-chain commitments:
///   • signersRoot   — who is authorized to send transactions
///   • contactsRoot  — private address book (name → Ethereum address)
///   • protocolsRoot — allowed on-chain protocols (name → contract address)
///
/// Each user operation carries a ZK proof together with the `registryRoot` the
/// prover committed to (contacts or protocols) and the `destAddressField` they
/// proved membership for.  The validator:
///   1. Checks `registryRoot ∈ { contactsRoot, protocolsRoot }`.
///   2. Checks `destAddressField` matches the actual call target extracted from calldata.
///   3. Verifies the ZK proof against the expected public inputs.
///
/// Public inputs layout (35 × bytes32):
///   [0..31]  txn_hash bytes  (EIP-191-prefixed userOpHash decomposed into 32 byte-fields —
///            i.e. keccak256("\x19Ethereum Signed Message:\n32" + userOpHash), matching what
///            wallets produce via `personal_sign`)
///   [32]     signersRoot
///   [33]     registryRoot    (contacts or protocols — checked on-chain)
///   [34]     destAddressField (address_to_field of the call target)
///
/// @author Microchain Labs
contract ZKLabeledSignerValidator is IValidator {
    // ─────────────────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Per-account configuration
    struct AccountConfig {
        /// @dev Merkle root of the signers label tree — leaf = Poseidon2(Poseidon1(label), Poseidon1(address)).
        ///      Same leaf format as the contacts and protocols trees; no separate address-only tree is needed.
        bytes32 signersRoot;
        /// @dev Merkle root of the Contacts label tree (contact name → address)
        bytes32 contactsRoot;
        /// @dev Merkle root of the Public Protocols label tree (protocol name → address)
        bytes32 protocolsRoot;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice The ERC-8039 proof verifier for `zk_labeled_signer` proofs
    address public immutable proofVerifier;

    /// @notice Per smart-account configuration; zero signersRoot = not initialized
    mapping(address => AccountConfig) private _configs;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    event LabeledSignerConfigured(
        address indexed smartAccount,
        bytes32 signersRoot,
        bytes32 contactsRoot,
        bytes32 protocolsRoot
    );

    event ContactsRootUpdated(address indexed smartAccount, bytes32 newContactsRoot);
    event ProtocolsRootUpdated(address indexed smartAccount, bytes32 newProtocolsRoot);
    event SignersRootUpdated(address indexed smartAccount, bytes32 newSignersRoot);

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    error ZeroAddressNotAllowed();
    error ZeroRootNotAllowed();
    error InvalidData();
    error ModuleAlreadyInitialized();
    error ModuleNotInitialized();
    error InvalidRegistryRoot();
    error InvalidDestinationAddress();
    error ProofVerificationFailed();
    error CallDataTooShort();

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /// @param _proofVerifier ERC-8039 verifier for `zk_labeled_signer` Honk proofs
    constructor(address _proofVerifier) {
        if (_proofVerifier == address(0)) revert ZeroAddressNotAllowed();
        proofVerifier = _proofVerifier;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC-7579 lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Install the module on a smart account.
    /// @dev `data` must be `abi.encode(bytes32 signersRoot, bytes32 contactsRoot, bytes32 protocolsRoot)`.
    ///      All three roots must be non-zero; the module does not require a ZK proof at
    ///      installation time — the smart account owner is trusted to supply valid roots.
    function onInstall(bytes calldata data) external override {
        if (data.length == 0) revert InvalidData();
        if (_isInitialized(msg.sender)) revert ModuleAlreadyInitialized();

        (bytes32 signersRoot, bytes32 contactsRoot, bytes32 protocolsRoot) =
            abi.decode(data, (bytes32, bytes32, bytes32));

        if (signersRoot   == bytes32(0)) revert ZeroRootNotAllowed();
        if (contactsRoot  == bytes32(0)) revert ZeroRootNotAllowed();
        if (protocolsRoot == bytes32(0)) revert ZeroRootNotAllowed();

        _configs[msg.sender] = AccountConfig({
            signersRoot:   signersRoot,
            contactsRoot:  contactsRoot,
            protocolsRoot: protocolsRoot
        });

        emit LabeledSignerConfigured(msg.sender, signersRoot, contactsRoot, protocolsRoot);
    }

    /// @notice Uninstall the module from a smart account, clearing all stored roots.
    function onUninstall(bytes calldata) external override {
        delete _configs[msg.sender];
        emit LabeledSignerConfigured(msg.sender, bytes32(0), bytes32(0), bytes32(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Root management (callable only by the smart account itself)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Replace the authorized signers tree root.
    function updateSignersRoot(bytes32 newRoot) external {
        if (!_isInitialized(msg.sender)) revert ModuleNotInitialized();
        if (newRoot == bytes32(0)) revert ZeroRootNotAllowed();
        _configs[msg.sender].signersRoot = newRoot;
        emit SignersRootUpdated(msg.sender, newRoot);
    }

    /// @notice Replace the Contacts label tree root.
    function updateContactsRoot(bytes32 newRoot) external {
        if (!_isInitialized(msg.sender)) revert ModuleNotInitialized();
        if (newRoot == bytes32(0)) revert ZeroRootNotAllowed();
        _configs[msg.sender].contactsRoot = newRoot;
        emit ContactsRootUpdated(msg.sender, newRoot);
    }

    /// @notice Replace the Public Protocols label tree root.
    function updateProtocolsRoot(bytes32 newRoot) external {
        if (!_isInitialized(msg.sender)) revert ModuleNotInitialized();
        if (newRoot == bytes32(0)) revert ZeroRootNotAllowed();
        _configs[msg.sender].protocolsRoot = newRoot;
        emit ProtocolsRootUpdated(msg.sender, newRoot);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // View helpers
    // ─────────────────────────────────────────────────────────────────────────

    function isInitialized(address smartAccount) external view returns (bool) {
        return _isInitialized(smartAccount);
    }

    function getConfig(address smartAccount) external view returns (AccountConfig memory) {
        return _configs[smartAccount];
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC-7579 validation
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Validate a user operation using a `zk_labeled_signer` proof.
    ///
    /// @dev `userOp.signature` must be:
    ///   `abi.encode(bytes zkProof, bytes32 registryRoot, bytes32 destAddressField)`
    ///
    ///   • `zkProof`          — UltraHonk proof bytes produced by the `zk_labeled_signer` circuit
    ///   • `registryRoot`     — the label tree the prover committed to (contacts or protocols)
    ///   • `destAddressField` — `address_to_field(destination)` as committed in the proof;
    ///                          equals `uint256(uint160(destination))` for a 20-byte address
    ///
    /// Validation steps:
    ///   1. `registryRoot ∈ { contactsRoot, protocolsRoot }`.
    ///   2. `destAddressField` matches the target extracted from `userOp.callData`.
    ///   3. ZK proof verification with expected public inputs.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external override returns (uint256) {
        AccountConfig storage cfg = _configs[userOp.sender];
        if (cfg.signersRoot == bytes32(0)) return VALIDATION_FAILED;

        (bytes memory zkProof, bytes32 registryRoot, bytes32 destAddressField) =
            abi.decode(userOp.signature, (bytes, bytes32, bytes32));

        // 1. Registry root must be one of the two allowed trees.
        if (registryRoot != cfg.contactsRoot && registryRoot != cfg.protocolsRoot) {
            return VALIDATION_FAILED;
        }

        // 2. Destination address field must match the actual call target in calldata.
        //    This prevents the prover from proving membership for address A while the
        //    account actually executes a call to unregistered address B.
        address callTarget = _extractCallTarget(userOp.callData);
        bytes32 expectedDestField = bytes32(uint256(uint160(callTarget)));
        if (destAddressField != expectedDestField) return VALIDATION_FAILED;

        // 3. Verify the ZK proof.
        if (!_verifyProof(userOpHash, cfg.signersRoot, registryRoot, destAddressField, zkProof)) {
            return VALIDATION_FAILED;
        }

        return VALIDATION_SUCCESS;
    }

    /// @notice ERC-1271 signature validation (e.g. for Safe compatibility).
    ///
    /// @dev `data` must be `abi.encode(bytes zkProof, bytes32 registryRoot, bytes32 destAddressField)`.
    ///      Destination–calldata matching is skipped because there is no UserOperation calldata
    ///      available in ERC-1271 context; the proof itself binds the destination to `hash`.
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    ) external view override returns (bytes4) {
        AccountConfig storage cfg = _configs[sender];
        if (cfg.signersRoot == bytes32(0)) return ERC1271_INVALID;

        (bytes memory zkProof, bytes32 registryRoot, bytes32 destAddressField) =
            abi.decode(data, (bytes, bytes32, bytes32));

        if (registryRoot != cfg.contactsRoot && registryRoot != cfg.protocolsRoot) {
            return ERC1271_INVALID;
        }

        if (!_verifyProof(hash, cfg.signersRoot, registryRoot, destAddressField, zkProof)) {
            return ERC1271_INVALID;
        }

        return ERC1271_MAGICVALUE;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC-7579 metadata
    // ─────────────────────────────────────────────────────────────────────────

    function name() external pure returns (string memory) {
        return "ZKLabeledSignerValidator";
    }

    function version() external pure returns (string memory) {
        return "0.1.0";
    }

    function isModuleType(uint256 typeId) external pure returns (bool) {
        return typeId == MODULE_TYPE_VALIDATOR;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _isInitialized(address account) internal view returns (bool) {
        return _configs[account].signersRoot != bytes32(0);
    }

    /// @dev Build the public inputs array expected by the `zk_labeled_signer` circuit
    ///      and invoke the ERC-8039 verifier.
    ///
    ///      The signer proves knowledge of a signature over the *EIP-191-prefixed*
    ///      userOpHash (`keccak256("\x19Ethereum Signed Message:\n32" + userOpHash)`),
    ///      matching what wallets produce via `personal_sign` — raw/blind hash signing
    ///      (`eth_sign`) is disabled in MetaMask and virtually all other wallets, so the
    ///      contract must hash the same way the wallet actually signs, not the raw hash.
    ///
    ///      Public inputs layout (35 elements):
    ///        [0..31]  txn_hash bytes decomposed as individual field elements
    ///        [32]     signersRoot
    ///        [33]     registryRoot
    ///        [34]     destAddressField
    function _verifyProof(
        bytes32 userOpHash,
        bytes32 signersRoot,
        bytes32 registryRoot,
        bytes32 destAddressField,
        bytes memory zkProof
    ) internal view returns (bool) {
        // 35 public inputs: 32 txn_hash bytes + signersRoot + registryRoot + destAddressField
        bytes32[] memory pub = new bytes32[](35);

        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);

        // Decompose the 32-byte EIP-191-prefixed hash into 32 individual byte-fields.
        // Each byte occupies its own field element (the circuit represents Hash as [u8; 32]).
        for (uint256 i = 0; i < 32; i++) {
            pub[i] = bytes32(uint256(uint8(ethSignedHash[i])));
        }

        pub[32] = signersRoot;
        pub[33] = registryRoot;
        pub[34] = destAddressField;

        bytes memory encodedInputs = abi.encode(pub);

        try IERC8039(proofVerifier).verifyProof(encodedInputs, zkProof) returns (bytes4 magic) {
            return magic == ERC8039Constants.PROOF_MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /// @dev Extract the call target address from a Nexus ERC-7579 `execute()` calldata.
    ///
    ///      Nexus callData layout for a SINGLE execution:
    ///        [0..3]    execute() selector  (4 bytes)
    ///        [4..35]   ModeCode            (bytes32, 32 bytes)
    ///        [36..67]  ABI offset for executionCalldata  (32 bytes, value = 64)
    ///        [68..99]  length of executionCalldata       (32 bytes)
    ///        [100..119] target address    (first 20 bytes of packed executionCalldata)
    ///        [120..151] call value        (uint256, 32 bytes)
    ///        [152+]    inner calldata
    ///
    ///      The target is the first 20 bytes of executionCalldata (packed, not ABI-encoded).
    function _extractCallTarget(bytes calldata callData) internal pure returns (address target) {
        // Minimum: selector(4) + ModeCode(32) + offset(32) + length(32) + target(20) = 120 bytes
        if (callData.length < 120) revert CallDataTooShort();
        assembly {
            // calldataload reads 32 bytes; target is the 20 left-most bytes at offset 100.
            // Shift right 12 bytes (96 bits) to place the address in the low 20 bytes.
            target := shr(96, calldataload(add(callData.offset, 100)))
        }
    }
}
