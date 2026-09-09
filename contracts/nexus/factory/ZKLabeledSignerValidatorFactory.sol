// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// ZK Labeled Signer Validator Factory
// Deploys Nexus smart accounts pre-configured with the ZKLabeledSignerValidator.
//
// At deployment time the factory enforces a *subset proof*: the caller must supply
// a ZK proof (circuit: zk_signer_subset) that every signer in the new account's
// `subsetSignersRoot` is a member of the organisation-wide `mainSignersRoot`.
// Only after the proof is verified does the factory initialise and deploy the account.
//
// The `mainSignersRoot` is owner-governed: the deploying organisation can rotate it
// when team membership changes (onboarding / offboarding).  Existing accounts are
// unaffected — the root is only checked at account *creation* time.
//
// Ownership (the address authorised to rotate `mainSignersRoot`) uses OpenZeppelin's
// Ownable2Step: transferring ownership requires the new owner to explicitly accept via
// acceptOwnership(), preventing accidental loss of control to a mistyped/unreachable
// address and allowing recovery if the current owner key needs to be rotated out.
//
// Developed by Microchain Labs

import { Ownable }      from "@openzeppelin/contracts/access/Ownable.sol";
import { Ownable2Step } from "@openzeppelin/contracts/access/Ownable2Step.sol";
import { NexusBootstrap } from "@biconomy/nexus/utils/NexusBootstrap.sol";
import { ProxyLib }       from "@biconomy/nexus/lib/ProxyLib.sol";
import { IERC8039, ERC8039Constants } from "../../ERC8039/IERC8039.sol";

/// @title ZKLabeledSignerValidatorFactory
/// @notice Factory for creating Nexus accounts with the ZKLabeledSignerValidator module.
///
/// @dev Deployment flow:
///   1.  Caller provides:
///         • subsetSignersRoot  — Merkle root of the new account's signer set
///         • contactsRoot       — Merkle root of the account's contacts label tree
///         • protocolsRoot      — Merkle root of the account's protocols label tree
///         • subsetProof        — UltraHonk proof for `zk_signer_subset`
///         • index              — nonce for deterministic address derivation
///
///   2.  The factory verifies the subset proof against the current `mainSignersRoot`
///       using the ERC-8039 verifier (ZKSignerSubsetProofVerifier).
///       Public inputs supplied to the verifier:
///         [0]  mainSignersRoot     (owner-governed — current value at call time)
///         [1]  subsetSignersRoot   (provided by the caller)
///
///   3.  On success the factory deploys a Nexus proxy and calls
///       ZKLabeledSignerValidator.onInstall with:
///         abi.encode(subsetSignersRoot, contactsRoot, protocolsRoot)
///
/// @author Microchain Labs
contract ZKLabeledSignerValidatorFactory is Ownable2Step {
    // ─────────────────────────────────────────────────────────────────────────
    // Immutable state
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Nexus account implementation address (ERC-1967 proxy target)
    address public immutable ACCOUNT_IMPLEMENTATION;

    /// @notice ZKLabeledSignerValidator module address
    address public immutable ZK_LABELED_SIGNER_VALIDATOR;

    /// @notice Bootstrapper used to initialise a freshly-deployed Nexus account
    NexusBootstrap public immutable BOOTSTRAPPER;

    /// @notice ERC-8039 verifier for the `zk_signer_subset` circuit
    address public immutable SUBSET_PROOF_VERIFIER;

    // ─────────────────────────────────────────────────────────────────────────
    // Mutable state
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Organisation-wide master signer registry root.
    ///         All smart account signer subsets must be drawn from this registry.
    ///         Rotatable by the owner (see {Ownable2Step}) when team membership
    ///         changes — existing accounts are unaffected because the root is
    ///         only enforced at creation time.
    bytes32 public mainSignersRoot;

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Emitted when a new account is deployed via this factory
    /// @param account           Deployed Nexus account address
    /// @param subsetSignersRoot Signer set committed to for this account
    /// @param contactsRoot      Contacts label tree root
    /// @param protocolsRoot     Protocols label tree root
    /// @param index             Deployment nonce used for CREATE2 salt
    event ZKLabeledSignerAccountCreated(
        address indexed account,
        bytes32 indexed subsetSignersRoot,
        bytes32 contactsRoot,
        bytes32 protocolsRoot,
        uint256 index
    );

    /// @notice Emitted when the org-wide signer registry root is rotated
    /// @param oldRoot The previous mainSignersRoot value
    /// @param newRoot The new mainSignersRoot value
    event MainSignersRootUpdated(bytes32 indexed oldRoot, bytes32 indexed newRoot);

    // ─────────────────────────────────────────────────────────────────────────
    // Errors
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Thrown when a zero address is provided to the constructor
    error ZeroAddressNotAllowed();

    /// @notice Thrown when a zero bytes32 value is provided where a root is expected
    error InvalidRoot();

    /// @notice Thrown when the subset ZK proof fails verification
    error InvalidSubsetProof();

    /// @notice Thrown when the proof bytes are empty
    error EmptyProof();

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    /// @param implementation           Nexus account implementation contract
    /// @param zkLabeledSignerValidator ZKLabeledSignerValidator module
    /// @param bootstrapper             NexusBootstrap helper contract
    /// @param subsetProofVerifier      ERC-8039 verifier for zk_signer_subset
    /// @param initialMainSignersRoot   Initial org-wide signer registry root
    /// @param owner                    Address authorised to rotate mainSignersRoot
    ///                                 (recommended: a multisig/timelock, not an EOA)
    constructor(
        address        implementation,
        address        zkLabeledSignerValidator,
        NexusBootstrap bootstrapper,
        address        subsetProofVerifier,
        bytes32        initialMainSignersRoot,
        address        owner
    ) Ownable(owner) {
        require(
            implementation           != address(0) &&
            zkLabeledSignerValidator != address(0) &&
            address(bootstrapper)    != address(0) &&
            subsetProofVerifier      != address(0),
            ZeroAddressNotAllowed()
        );
        require(initialMainSignersRoot != bytes32(0), InvalidRoot());

        ACCOUNT_IMPLEMENTATION      = implementation;
        ZK_LABELED_SIGNER_VALIDATOR = zkLabeledSignerValidator;
        BOOTSTRAPPER                = bootstrapper;
        SUBSET_PROOF_VERIFIER       = subsetProofVerifier;
        mainSignersRoot             = initialMainSignersRoot;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Governance
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Rotate the organisation-wide master signer registry root.
    ///
    /// @dev Call this when the master signer list changes (onboarding / offboarding).
    ///      Existing accounts are unaffected — the root is only checked at account
    ///      creation time.  After the update, new account deployments must prove
    ///      subset membership against the new root.
    ///
    /// @param newRoot The new Merkle root of the master signer registry
    function updateMainSignersRoot(bytes32 newRoot) external onlyOwner {
        require(newRoot != bytes32(0), InvalidRoot());
        bytes32 oldRoot = mainSignersRoot;
        mainSignersRoot = newRoot;
        emit MainSignersRootUpdated(oldRoot, newRoot);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Account creation
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Deploy a new Nexus account whose signer set is proven to be a
    ///         subset of MAIN_SIGNERS_ROOT.
    ///
    /// @param subsetSignersRoot  Merkle root of the new account's signer subset
    /// @param contactsRoot       Merkle root of the account's contacts label tree
    /// @param protocolsRoot      Merkle root of the account's protocols label tree
    /// @param subsetProof        UltraHonk proof for circuit `zk_signer_subset`
    /// @param index              Nonce for deterministic address derivation (CREATE2)
    /// @return account           Address of the deployed Nexus account
    function createAccount(
        bytes32 subsetSignersRoot,
        bytes32 contactsRoot,
        bytes32 protocolsRoot,
        bytes calldata subsetProof,
        uint256 index
    )
        external
        payable
        returns (address payable account)
    {
        require(subsetSignersRoot != bytes32(0), InvalidRoot());
        require(contactsRoot      != bytes32(0), InvalidRoot());
        require(protocolsRoot     != bytes32(0), InvalidRoot());
        require(subsetProof.length > 0,          EmptyProof());

        // ── Step 1: verify the subset ZK proof ──────────────────────────────
        //
        // Public inputs for zk_signer_subset (2 × bytes32):
        //   [0]  mainSignersRoot     (org-wide — current value, owner-governed)
        //   [1]  subsetSignersRoot   (supplied by the caller)
        //
        // Reading mainSignersRoot once into a local variable ensures the proof is
        // verified against the same root that was current when the tx was submitted,
        // even if the owner rotates it in the same block (re-entrancy safe).
        bytes32 currentMainRoot = mainSignersRoot;
        bytes32[] memory inputs = new bytes32[](2);
        inputs[0] = currentMainRoot;
        inputs[1] = subsetSignersRoot;

        bytes4 result = IERC8039(SUBSET_PROOF_VERIFIER).verifyProof(
            abi.encode(inputs),
            subsetProof
        );
        require(result == ERC8039Constants.PROOF_MAGIC_VALUE, InvalidSubsetProof());

        // ── Step 2: deploy the Nexus account ─────────────────────────────────
        //
        // Deterministic salt binds all three roots + the caller-chosen index.
        bytes32 salt = keccak256(
            abi.encodePacked(subsetSignersRoot, contactsRoot, protocolsRoot, index)
        );

        // ZKLabeledSignerValidator.onInstall expects:
        //   abi.decode(data, (bytes32, bytes32, bytes32))
        //   → (signersRoot, contactsRoot, protocolsRoot)
        bytes memory validatorInitData = abi.encode(
            subsetSignersRoot,
            contactsRoot,
            protocolsRoot
        );

        bytes memory initData = abi.encode(
            address(BOOTSTRAPPER),
            abi.encodeCall(
                BOOTSTRAPPER.initNexusWithSingleValidatorNoRegistry,
                (ZK_LABELED_SIGNER_VALIDATOR, validatorInitData)
            )
        );

        bool alreadyDeployed;
        (alreadyDeployed, account) = ProxyLib.deployProxy(
            ACCOUNT_IMPLEMENTATION,
            salt,
            initData
        );

        if (!alreadyDeployed) {
            emit ZKLabeledSignerAccountCreated(
                account,
                subsetSignersRoot,
                contactsRoot,
                protocolsRoot,
                index
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Address prediction
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Compute the deterministic address a new account will be deployed at.
    ///
    /// @param subsetSignersRoot  Merkle root of the account's signer subset
    /// @param contactsRoot       Merkle root of the account's contacts label tree
    /// @param protocolsRoot      Merkle root of the account's protocols label tree
    /// @param index              Nonce for deterministic address derivation
    /// @return expectedAddress   The address where the account will be deployed
    function computeAccountAddress(
        bytes32 subsetSignersRoot,
        bytes32 contactsRoot,
        bytes32 protocolsRoot,
        uint256 index
    )
        external
        view
        returns (address payable expectedAddress)
    {
        bytes32 salt = keccak256(
            abi.encodePacked(subsetSignersRoot, contactsRoot, protocolsRoot, index)
        );

        bytes memory validatorInitData = abi.encode(
            subsetSignersRoot,
            contactsRoot,
            protocolsRoot
        );

        bytes memory initData = abi.encode(
            address(BOOTSTRAPPER),
            abi.encodeCall(
                BOOTSTRAPPER.initNexusWithSingleValidatorNoRegistry,
                (ZK_LABELED_SIGNER_VALIDATOR, validatorInitData)
            )
        );

        return ProxyLib.predictProxyAddress(ACCOUNT_IMPLEMENTATION, salt, initData);
    }
}
