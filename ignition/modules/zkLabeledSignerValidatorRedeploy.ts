import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

/**
 * Redeploy-only module: ZKLabeledSignerValidator + ZKLabeledSignerValidatorFactory
 *
 * Use this instead of `zkLabeledSignerFactoryNexus.ts` when ONLY the validator's
 * Solidity logic changed (e.g. the EIP-191 prefixing fix for `_verifyProof`) and
 * the underlying ZKTranscriptLib / HonkVerifiers / ERC-8039 proof adapters are
 * unchanged and must NOT be redeployed (they're expensive and their bytecode is
 * unaffected by this bug).
 *
 * Rather than re-running `zkLabeledSignerFactoryNexus.ts` (which would NOT
 * actually redeploy the validator anyway — Ignition tracks futures by id and
 * would just reuse the recorded result for `ZKLabeledSignerFactory_v1#ZKLabeledSignerValidator`
 * even though the Solidity source changed), this module points at the
 * already-deployed verifier addresses via `m.contractAt(...)` and only
 * deploys the two contracts that actually need new bytecode:
 *   1. ZKLabeledSignerValidator        — the contract with the fix
 *   2. ZKLabeledSignerValidatorFactory — must be redeployed too because it
 *      stores the validator address as an immutable set once in its constructor
 *      (ZK_LABELED_SIGNER_VALIDATOR), so it has to be pointed at the new validator.
 *
 * Existing addresses reused as-is (from
 * ignition/deployments/chain-137/deployed_addresses.json,
 * module `ZKLabeledSignerFactory_v1`):
 *   erc8039LabeledSigner (ZKLabeledSignerProofVerifier) — 0x7Cce0Ad131a74100eCf1445D25630eD833b90339
 *   erc8039SignerSubset  (ZKSignerSubsetProofVerifier)  — 0x9a5FB6cAFF95af77609b119A47B7F71469c89c0E
 *
 * NOTE: any smart accounts already created via the OLD factory keep using the
 * OLD validator (the one without the fix) until they uninstall/reinstall the
 * validator module — redeploying this does not retroactively patch them.
 *
 * Required ignition parameters:
 *   initialMainSignersRoot — bytes32 org-wide signer Merkle root (reuse the
 *                             same value the original factory was deployed with,
 *                             unless you intend to rotate it at the same time)
 *   owner                  — address authorised to rotate mainSignersRoot later
 *
 * To deploy:
 *   npx hardhat ignition deploy ignition/modules/zkLabeledSignerValidatorRedeploy.ts \
 *     --network <network> \
 *     --parameters '{"ZKLabeledSignerValidatorRedeploy_v1":{"initialMainSignersRoot":"0x...","owner":"0x..."}}'
 */
export default buildModule("ZKLabeledSignerValidatorRedeploy_v1", (m) => {

  // ============================================================================
  // CONFIGURATION: Nexus deployed contracts (same across all deployments)
  // ============================================================================

  const NEXUS_IMPLEMENTATION_ADDRESS = "0x000000000032ddc454c3bdcba80484ad5a798705";
  const NEXUS_BOOTSTRAP_ADDRESS = "0x00000000006efb61d8c9546ff1b500de3f244ea7";

  // ============================================================================
  // EXISTING contracts — reused as-is, NOT redeployed.
  // ============================================================================

  const erc8039LabeledSigner = m.contractAt(
    "ZKLabeledSignerProofVerifier",
    "0x7Cce0Ad131a74100eCf1445D25630eD833b90339"
  );

  const erc8039SignerSubset = m.contractAt(
    "ZKSignerSubsetProofVerifier",
    "0x9a5FB6cAFF95af77609b119A47B7F71469c89c0E"
  );

  // ============================================================================
  // Deployment-time parameters
  // ============================================================================

  const initialMainSignersRoot = m.getParameter<string>("initialMainSignersRoot");
  const owner = m.getParameter<string>("owner");

  // ============================================================================
  // 1. ZKLabeledSignerValidator (fixed: EIP-191-prefixed userOpHash)
  // ============================================================================

  const zkLabeledSignerValidator = m.contract(
    "ZKLabeledSignerValidator",
    [erc8039LabeledSigner]
  );

  // ============================================================================
  // 2. ZKLabeledSignerValidatorFactory (redeployed: validator address is immutable)
  // ============================================================================

  const zkLabeledSignerValidatorFactory = m.contract(
    "ZKLabeledSignerValidatorFactory",
    [
      NEXUS_IMPLEMENTATION_ADDRESS,  // Nexus account implementation
      zkLabeledSignerValidator,       // NEW ERC-7579 validator module
      NEXUS_BOOTSTRAP_ADDRESS,        // NexusBootstrap helper
      erc8039SignerSubset,            // existing ERC-8039 subset proof verifier
      initialMainSignersRoot,         // org-wide master signer root
      owner,                          // address allowed to rotate root
    ]
  );

  return {
    zkLabeledSignerValidator,
    zkLabeledSignerValidatorFactory,
  };
});
