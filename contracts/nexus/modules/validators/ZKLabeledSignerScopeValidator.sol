// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

// ZK Labeled Signer + Scope Validator
// Privacy-preserving validator that requires, in a single ZK proof:
//   1. An authorized signer (identity hidden via ZK) signed the transaction.
//   2. The call destination, together with a private label and a scope rule
//      (selector / value / calldata-param constraints, or a wildcard sentinel
//      meaning "no restriction"), forms a single leaf in the account's
//      unified scope tree. See docs/zk-labeled-signer-scope.md.
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

/// @title ZKLabeledSignerScopeValidator
/// @notice ERC-7579 validator module for Nexus smart accounts, backed by the
///         `zk_labeled_signer_scope` circuit.
///
/// @dev Combines two zero-knowledge checks in a single proof:
///
///   SIGNER CHECK — the user holds a private key whose address is in the
///   authorized `signersRoot` Merkle tree, without revealing which signer acted.
///
///   SCOPE CHECK — the call destination, together with a private label and a
///   matching scope rule, forms a single leaf in the unified `scopeRoot` tree
///   (see lib/zk_scope's `compute_labeled_rule_leaf` / `verify_labeled_scope_membership`
///   in zk-smart-account-kit). A rule with `selector == WILDCARD_SELECTOR` means
///   "no restriction"; any other rule constrains the transaction's selector,
///   value, and decoded calldata parameters.
///
/// The smart account stores two on-chain commitments:
///   • signersRoot — who is authorized to send transactions
///   • scopeRoot   — the unified destination + scope-rule tree
///
/// Public inputs layout (41 × bytes32), matches the circuit's `pub` parameters
/// exactly (circuits/zk_labeled_signer_scope/src/main.nr in zk-smart-account-kit):
///   [0..31]  txn_hash bytes  (EIP-191-prefixed userOpHash decomposed into 32 byte-fields —
///            i.e. keccak256("\x19Ethereum Signed Message:\n32" + userOpHash), matching what
///            wallets produce via `personal_sign`)
///   [32]     signersRoot
///   [33]     destAddressField  (address_to_field of the call target)
///   [34]     txnSelector       (occupies the low 32 bits of the field)
///   [35]     txnValue          (ETH value in wei)
///   [36..39] txnParams         (4 decoded calldata parameters, extracted directly from
///            the real on-chain calldata by `_extractCallDetails` — see its NatSpec for
///            the static-leading-params-only assumption)
///   [40]     scopeRoot
///
/// @author Microchain Labs
contract ZKLabeledSignerScopeValidator is IValidator {
    // ─────────────────────────────────────────────────────────────────────────
    // Types
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Per-account configuration
    struct AccountConfig {
        /// @dev Merkle root of the signers label tree — leaf = Poseidon2(Poseidon1(label), Poseidon1(address)).
        bytes32 signersRoot;
        /// @dev Merkle root of the unified destination + scope-rule tree (see
        ///      docs/zk-labeled-signer-scope.md — one leaf per registered
        ///      destination/rule, wildcard leaves for unrestricted destinations).
        bytes32 scopeRoot;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Storage
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice The ERC-8039 proof verifier for `zk_labeled_signer_scope` proofs
    address public immutable proofVerifier;

    /// @notice Per smart-account configuration; zero signersRoot = not initialized
    mapping(address => AccountConfig) private _configs;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    event LabeledSignerScopeConfigured(
        address indexed smartAccount,
        bytes32 signersRoot,
        bytes32 scopeRoot
    );

    event ScopeRootUpdated(address indexed smartAccount, bytes32 newScopeRoot);
    event SignersRootUpdated(address indexed smartAccount, bytes32 newSignersRoot);

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    error ZeroAddressNotAllowed();
    error ZeroRootNotAllowed();
    error InvalidData();
    error ModuleAlreadyInitialized();
    error ModuleNotInitialized();
    error ProofVerificationFailed();
    error CallDataTooShort();

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /// @param _proofVerifier ERC-8039 verifier for `zk_labeled_signer_scope` Honk proofs
    constructor(address _proofVerifier) {
        if (_proofVerifier == address(0)) revert ZeroAddressNotAllowed();
        proofVerifier = _proofVerifier;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC-7579 lifecycle
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Install the module on a smart account.
    /// @dev `data` must be `abi.encode(bytes32 signersRoot, bytes32 scopeRoot)`.
    ///      Both roots must be non-zero; the module does not require a ZK proof at
    ///      installation time — the smart account owner is trusted to supply valid roots.
    function onInstall(bytes calldata data) external override {
        if (data.length == 0) revert InvalidData();
        if (_isInitialized(msg.sender)) revert ModuleAlreadyInitialized();

        (bytes32 signersRoot, bytes32 scopeRoot) = abi.decode(data, (bytes32, bytes32));

        if (signersRoot == bytes32(0)) revert ZeroRootNotAllowed();
        if (scopeRoot   == bytes32(0)) revert ZeroRootNotAllowed();

        _configs[msg.sender] = AccountConfig({
            signersRoot: signersRoot,
            scopeRoot:   scopeRoot
        });

        emit LabeledSignerScopeConfigured(msg.sender, signersRoot, scopeRoot);
    }

    /// @notice Uninstall the module from a smart account, clearing all stored roots.
    function onUninstall(bytes calldata) external override {
        delete _configs[msg.sender];
        emit LabeledSignerScopeConfigured(msg.sender, bytes32(0), bytes32(0));
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

    /// @notice Replace the unified scope tree root.
    /// @dev See "Operational note: tightening restrictions on an already-wildcard
    ///      destination" in docs/zk-labeled-signer-scope.md — the SDK should always
    ///      rebuild the entire tree from the canonical rule list rather than trying
    ///      to patch individual leaves, to avoid leaving a stale wildcard leaf behind.
    function updateScopeRoot(bytes32 newRoot) external {
        if (!_isInitialized(msg.sender)) revert ModuleNotInitialized();
        if (newRoot == bytes32(0)) revert ZeroRootNotAllowed();
        _configs[msg.sender].scopeRoot = newRoot;
        emit ScopeRootUpdated(msg.sender, newRoot);
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

    /// @notice Validate a user operation using a `zk_labeled_signer_scope` proof.
    ///
    /// @dev `userOp.signature` is simply the raw UltraHonk proof bytes produced by
    ///      the `zk_labeled_signer_scope` circuit — no other caller-supplied data is
    ///      needed. `destAddressField`, `txnSelector`, `txnValue` AND the 4 decoded
    ///      calldata `txnParams` are all derived directly from the actual
    ///      UserOperation callData on-chain (see `_extractCallDetails`), exactly like
    ///      `ZKLabeledSignerValidator._extractCallTarget` does for the plain
    ///      (non-scoped) circuit. This prevents a prover from proving a proof about
    ///      a destination/selector/value/params tuple that differs from what the
    ///      account actually executes — every public input is either read from
    ///      storage (`signersRoot`/`scopeRoot`) or extracted from real calldata,
    ///      with nothing left for the caller to supply and no need for an on-chain
    ///      Poseidon/BN254 implementation to recompute a commitment hash.
    ///
    ///      Extraction assumes the inner calldata's leading parameters are static
    ///      ABI types (address/uintN/bool/bytesN) occupying one 32-byte slot each —
    ///      see `_extractCallDetails`.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external override returns (uint256) {
        AccountConfig storage cfg = _configs[userOp.sender];
        if (cfg.signersRoot == bytes32(0)) return VALIDATION_FAILED;

        (
            bytes32 destAddressField,
            bytes32 txnSelectorField,
            bytes32 txnValueField,
            bytes32[4] memory txnParams
        ) = _extractCallDetails(userOp.callData);

        if (!_verifyProof(
            userOpHash,
            cfg.signersRoot,
            destAddressField,
            txnSelectorField,
            txnValueField,
            txnParams,
            cfg.scopeRoot,
            userOp.signature
        )) {
            return VALIDATION_FAILED;
        }

        return VALIDATION_SUCCESS;
    }

    /// @notice ERC-1271 signature validation (e.g. for Safe compatibility).
    ///
    /// @dev `data` must be:
    ///   `abi.encode(bytes zkProof, bytes32 destAddressField, bytes32 txnSelector,
    ///               bytes32 txnValue, bytes32[4] txnParams)`.
    ///      Destination/selector/value/params matching is skipped because there is
    ///      no UserOperation calldata available in ERC-1271 context; the proof itself
    ///      binds these values to `hash`.
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    ) external view override returns (bytes4) {
        AccountConfig storage cfg = _configs[sender];
        if (cfg.signersRoot == bytes32(0)) return ERC1271_INVALID;

        (
            bytes memory zkProof,
            bytes32 destAddressField,
            bytes32 txnSelectorField,
            bytes32 txnValueField,
            bytes32[4] memory txnParams
        ) = abi.decode(data, (bytes, bytes32, bytes32, bytes32, bytes32[4]));

        if (!_verifyProof(
            hash,
            cfg.signersRoot,
            destAddressField,
            txnSelectorField,
            txnValueField,
            txnParams,
            cfg.scopeRoot,
            zkProof
        )) {
            return ERC1271_INVALID;
        }

        return ERC1271_MAGICVALUE;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC-7579 metadata
    // ─────────────────────────────────────────────────────────────────────────

    function name() external pure returns (string memory) {
        return "ZKLabeledSignerScopeValidator";
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

    /// @dev Build the public inputs array expected by the `zk_labeled_signer_scope`
    ///      circuit and invoke the ERC-8039 verifier.
    ///
    ///      The signer proves knowledge of a signature over the *EIP-191-prefixed*
    ///      userOpHash (`keccak256("\x19Ethereum Signed Message:\n32" + userOpHash)`),
    ///      matching what wallets produce via `personal_sign`.
    ///
    ///      Public inputs layout (41 elements):
    ///        [0..31]  txn_hash bytes decomposed as individual field elements
    ///        [32]     signersRoot
    ///        [33]     destAddressField
    ///        [34]     txnSelector
    ///        [35]     txnValue
    ///        [36..39] txnParams (4 decoded calldata parameters)
    ///        [40]     scopeRoot
    function _verifyProof(
        bytes32 userOpHash,
        bytes32 signersRoot,
        bytes32 destAddressField,
        bytes32 txnSelectorField,
        bytes32 txnValueField,
        bytes32[4] memory txnParams,
        bytes32 scopeRoot,
        bytes memory zkProof
    ) internal view returns (bool) {
        // 41 public inputs: 32 txn_hash bytes + signersRoot + destAddressField +
        // txnSelector + txnValue + 4 txnParams + scopeRoot
        bytes32[] memory pub = new bytes32[](41);

        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);

        // Decompose the 32-byte EIP-191-prefixed hash into 32 individual byte-fields.
        for (uint256 i = 0; i < 32; i++) {
            pub[i] = bytes32(uint256(uint8(ethSignedHash[i])));
        }

        pub[32] = signersRoot;
        pub[33] = destAddressField;
        pub[34] = txnSelectorField;
        pub[35] = txnValueField;
        pub[36] = txnParams[0];
        pub[37] = txnParams[1];
        pub[38] = txnParams[2];
        pub[39] = txnParams[3];
        pub[40] = scopeRoot;

        bytes memory encodedInputs = abi.encode(pub);

        try IERC8039(proofVerifier).verifyProof(encodedInputs, zkProof) returns (bytes4 magic) {
            return magic == ERC8039Constants.PROOF_MAGIC_VALUE;
        } catch {
            return false;
        }
    }

    /// @dev Extract the call target/selector/value/params from a Nexus ERC-7579
    ///      `execute()` calldata, already Field-encoded and ready to place directly
    ///      into the public inputs array.
    ///
    ///      Nexus callData layout for a SINGLE execution:
    ///        [0..3]     execute() selector       (4 bytes)
    ///        [4..35]    ModeCode                 (bytes32, 32 bytes)
    ///        [36..67]   ABI offset for executionCalldata (32 bytes, value = 64)
    ///        [68..99]   length of executionCalldata      (32 bytes)
    ///        [100..119] target address            (first 20 bytes of packed executionCalldata)
    ///        [120..151] call value                (uint256, 32 bytes)
    ///        [152..155] inner function selector    (first 4 bytes of inner calldata,
    ///                   OPTIONAL — absent for a plain ETH transfer with empty
    ///                   inner calldata, in which case total callData.length == 152)
    ///        [156..187] inner calldata param[0]    (32-byte word)
    ///        [188..219] inner calldata param[1]    (32-byte word)
    ///        [220..251] inner calldata param[2]    (32-byte word)
    ///        [252..283] inner calldata param[3]    (32-byte word)
    ///
    ///      `destAddressField` = `address_to_field(target)` = `uint256(uint160(target))`.
    ///      `txnSelectorField` occupies the low 32 bits of the field, matching the
    ///      SDK's `selectorToField` (sdk/src/zk-scope/rule.ts).
    ///      `txnValueField` is the raw 32-byte value word, matching `txn_value` used
    ///      directly as a Field element in the circuit.
    ///      `txnParams[i]` is the raw 32-byte word at its slot, used directly as a
    ///      Field element — this only works for STATIC leading ABI parameters
    ///      (address/uintN/bool/bytesN), which occupy their full 32-byte slot as-is
    ///      with no offset/length indirection. Dynamic types (bytes/string/arrays) or
    ///      parameters beyond the first 4 are NOT supported by this extraction and
    ///      must be registered as `PARAM_UNCONSTRAINED` in the scope rule.
    ///
    ///      A plain ETH transfer (no inner calldata, e.g. Nexus's `executionCalldata`
    ///      is just `abi.encodePacked(target, value)` with nothing appended) is only
    ///      152 bytes total — there is no byte range `[152..155]` (or beyond) to read
    ///      a selector/params from. The same holds for calls with fewer than 4 static
    ///      parameters.
    ///
    ///      IMPORTANT (fixed real bug — see git history): `calldataload` only
    ///      zero-pads relative to the end of the ENTIRE transaction calldata
    ///      (`msg.data.length`), NOT relative to this `callData` slice's own
    ///      logical/ABI length. `callData` is a nested `bytes` parameter embedded
    ///      inside the much larger `handleOps(...)` calldata (which also contains
    ///      other UserOp fields and the — often several-KB — proof bytes in
    ///      `userOp.signature`). Reading past `callData.length` therefore does NOT
    ///      return zero; it silently reads real, unrelated bytes belonging to
    ///      whatever else is encoded further along in the outer calldata. Each
    ///      optional field below is now explicitly bounds-checked against
    ///      `callData.length` and left at its default zero value (Solidity
    ///      zero-initializes the `txnParams` memory array on allocation) when the
    ///      full 32-byte word isn't actually present, instead of relying on
    ///      `calldataload`'s auto zero-pad (which only applies at the true end of
    ///      the transaction, not at this slice's boundary). Callers that want to
    ///      allow plain transfers to a destination must register that
    ///      destination's scope rule with `rule_selector == 0` (or a wildcard leaf).
    function _extractCallDetails(bytes calldata callData)
        internal
        pure
        returns (
            bytes32 destAddressField,
            bytes32 txnSelectorField,
            bytes32 txnValueField,
            bytes32[4] memory txnParams
        )
    {
        // Minimum: selector(4) + ModeCode(32) + offset(32) + length(32) + target(20)
        //        + value(32) = 152 bytes. The 4-byte inner selector at [152..155] and
        // the param slots at [156..283] are all OPTIONAL (absent/short for a plain
        // ETH transfer or a call with fewer than 4 static params) — each is
        // explicitly bounds-checked below rather than assumed zero-padded.
        if (callData.length < 152) revert CallDataTooShort();
        assembly {
            // target is the 20 left-most bytes at offset 100; shift right 12 bytes
            // (96 bits) to place the address in the low 20 bytes.
            destAddressField := shr(96, calldataload(add(callData.offset, 100)))
            // value occupies the full 32-byte word at offset 120 already.
            txnValueField := calldataload(add(callData.offset, 120))

            // Each optional field is only read when callData.length actually
            // covers its FULL byte range — otherwise it's left at 0 (the safe,
            // originally-intended default for a short/absent field).
            if iszero(lt(callData.length, 156)) {
                // inner selector is the 4 left-most bytes at offset 152; shift
                // right 28 bytes (224 bits) to place it in the low 4 bytes.
                txnSelectorField := shr(224, calldataload(add(callData.offset, 152)))
            }
            if iszero(lt(callData.length, 188)) {
                mstore(txnParams, calldataload(add(callData.offset, 156)))
            }
            if iszero(lt(callData.length, 220)) {
                mstore(add(txnParams, 32), calldataload(add(callData.offset, 188)))
            }
            if iszero(lt(callData.length, 252)) {
                mstore(add(txnParams, 64), calldataload(add(callData.offset, 220)))
            }
            if iszero(lt(callData.length, 284)) {
                mstore(add(txnParams, 96), calldataload(add(callData.offset, 252)))
            }
        }
    }
}
