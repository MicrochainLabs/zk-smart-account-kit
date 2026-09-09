import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

/**
 * Deployment module for the ZK Labeled Signer + Scope Factory pattern
 *
 * Deploys, in order:
 *   1. ZKTranscriptLib   — shared library, deployed once and reused for both HonkVerifiers
 *                          below (Noir codegens an identical copy of this library into every
 *                          circuit's .sol file; Hardhat Ignition/solc link libraries by bare
 *                          name, so one deployment can be linked into both artifacts).
 *   2. HonkVerifier      — barretenberg UltraHonk verifier for zk_labeled_signer_scope
 *   3. ZKLabeledSignerScopeProofVerifier — ERC-8039 adapter for zk_labeled_signer_scope
 *   4. HonkVerifier      — barretenberg UltraHonk verifier for zk_signer_subset
 *   5. ZKSignerSubsetProofVerifier  — ERC-8039 adapter for zk_signer_subset
 *   6. ZKLabeledSignerScopeValidator     — ERC-7579 validator module
 *   7. ZKLabeledSignerScopeValidatorFactory — account factory (requires subset proof at deploy time)
 *
 * Required ignition parameters (pass via --parameters or programmatic deploy):
 *   initialMainSignersRoot  — bytes32 org-wide signer Merkle root (governs which
 *                              signer subsets are authorised to create accounts)
 *   owner                   — address authorised to rotate mainSignersRoot later
 *
 * KNOWN GAP (as of this module's creation): `noir/target/zk_labeled_signer_scope.sol`
 * does not exist yet in this workspace — the `zk_labeled_signer_scope` circuit currently
 * only lives (compiled) under zk-smart-account-kit/noir/target/. Generating its Solidity
 * HonkVerifier requires running `nargo compile` + `bb write_vk` + `bb write_solidity_verifier`
 * for that circuit and placing the output at the path referenced below (see the same gap
 * documented in contracts/ERC8039/ZKLabeledSignerScopeProofVerifier.sol and repo memory).
 * Deploying this module will fail to compile until that file exists.
 *
 * To deploy:
 *   npx hardhat ignition deploy ignition/modules/zkLabeledSignerScopeFactoryNexus.ts \
 *     --network <network> \
 *     --parameters '{"ZKLabeledSignerScopeFactory_v1":{"initialMainSignersRoot":"0x...","owner":"0x..."}}'
 *
 * Or use the hardhat task:
 *   npx hardhat createZKLabeledScopeFactory \
 *     --network <network> \
 *     --mainsigners '[{"label":"alice","address":"0x..."}]' \
 *     --owner 0x...
 */
export default buildModule("ZKLabeledSignerScopeFactory_v1", (m) => {

  // ============================================================================
  // CONFIGURATION: Nexus deployed contracts (same across all deployments)
  // ============================================================================

  // Nexus account implementation address
  const NEXUS_IMPLEMENTATION_ADDRESS = "0x000000000032ddc454c3bdcba80484ad5a798705";

  // NexusBootstrap contract address
  const NEXUS_BOOTSTRAP_ADDRESS = "0x00000000006efb61d8c9546ff1b500de3f244ea7";

  // ============================================================================
  // Deployment-time parameters (must be supplied by the caller)
  // ============================================================================

  // Org-wide master signer registry root — set once at factory deployment.
  // Rotate later via factory.updateMainSignersRoot(newRoot).
  const initialMainSignersRoot = m.getParameter<string>("initialMainSignersRoot");

  // Address authorised to call updateMainSignersRoot on the factory.
  const owner = m.getParameter<string>("owner");

  // ============================================================================
  // 1. ZKTranscriptLib (shared)
  // ============================================================================
  //
  // Noir/barretenberg codegens a byte-for-byte identical copy of ZKTranscriptLib
  // into every circuit's generated .sol file (see zkLabeledSignerFactoryNexus.ts
  // for the verified `diff` claim across other circuit pairs). Hardhat/solc link
  // libraries into a contract's bytecode purely by bare name (ignition-core's
  // linkLibraries keys on `artifact.linkReferences` by library name, not by which
  // source file produced the linked address), so a single deployment can be
  // linked into both HonkVerifier artifacts below.

  const zkTranscriptLib = m.library(
    "noir/target/zk_labeled_signer_scope.sol:ZKTranscriptLib",
    { id: "zkTranscriptLib" }
  );

  // ============================================================================
  // 2. HonkVerifier for zk_labeled_signer_scope
  // ============================================================================

  const labeledSignerScopeHonkVerifier = m.contract(
    "noir/target/zk_labeled_signer_scope.sol:HonkVerifier",
    [],
    {
      id: "labeledSignerScopeHonkVerifier",
      libraries: { ZKTranscriptLib: zkTranscriptLib },
    }
  );

  // ERC-8039 adapter — wraps the HonkVerifier with the expected interface
  const erc8039LabeledSignerScope = m.contract(
    "ZKLabeledSignerScopeProofVerifier",
    [labeledSignerScopeHonkVerifier],
    { id: "erc8039LabeledSignerScope" }
  );

  // ============================================================================
  // 3. HonkVerifier for zk_signer_subset
  // ============================================================================

  const signerSubsetHonkVerifier = m.contract(
    "noir/target/zk_signer_subset.sol:HonkVerifier",
    [],
    {
      id: "signerSubsetHonkVerifier",
      libraries: { ZKTranscriptLib: zkTranscriptLib },
    }
  );

  // ERC-8039 adapter
  const erc8039SignerSubset = m.contract(
    "ZKSignerSubsetProofVerifier",
    [signerSubsetHonkVerifier],
    { id: "erc8039SignerSubset" }
  );

  // ============================================================================
  // 4. ZKLabeledSignerScopeValidator (ERC-7579 module)
  // ============================================================================

  const zkLabeledSignerScopeValidator = m.contract(
    "ZKLabeledSignerScopeValidator",
    [erc8039LabeledSignerScope]
  );

  // ============================================================================
  // 5. ZKLabeledSignerScopeValidatorFactory
  // ============================================================================

  const zkLabeledSignerScopeValidatorFactory = m.contract(
    "ZKLabeledSignerScopeValidatorFactory",
    [
      NEXUS_IMPLEMENTATION_ADDRESS,   // Nexus account implementation
      zkLabeledSignerScopeValidator,  // ERC-7579 validator module
      NEXUS_BOOTSTRAP_ADDRESS,        // NexusBootstrap helper
      erc8039SignerSubset,            // ERC-8039 subset proof verifier
      initialMainSignersRoot,         // org-wide master signer root
      owner,                          // address allowed to rotate root
    ]
  );

  return {
    zkTranscriptLib,
    labeledSignerScopeHonkVerifier,
    erc8039LabeledSignerScope,
    signerSubsetHonkVerifier,
    erc8039SignerSubset,
    zkLabeledSignerScopeValidator,
    zkLabeledSignerScopeValidatorFactory,
  };
});
