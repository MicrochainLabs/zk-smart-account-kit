use zk_signer::{PubKey, Signature, Hash, is_nil_pubkey};
use zk_labels::{verify_label_membership, LABELS_MAX_DEPTH, LABEL_NAME_BYTES};
use zk_multisig::{verify_multi_sig, SIGNERS_MAX_DEPTH, MAX_SIGNERS};

/// Combined circuit: proves M-of-N multi-sig authorization AND that every
/// active signer holds a specific label (role, name, tag, permission, etc.)
/// in the label registry - atomically.
///
/// Security argument: both the multi-sig path and the label-binding path use
/// the SAME address derivation (from `zk_signer::verify_ecdsa_get_address`).
/// The addresses returned by `verify_multi_sig` and passed to
/// `verify_role_membership` are linked by construction - not by assertion -
/// so an attacker cannot mix-and-match proofs from different signers.
///
/// Public inputs (39 Fields total):
///   txn_hash[32]           - transaction being authorized (32 x u8 = 32 Fields)
///   on_chain_state_root    - stateRoot committing to (signers_root, threshold)
///   registry_root          - registryRoot committing to the full label registry
///   label_commitments[5]   - per-signer Poseidon2(label_hash, addr_hash)
///                            (0 for inactive/NIL slots)
fn main(
    // -- Multi-sig private inputs -----------------------------------------------
    signers: [PubKey; MAX_SIGNERS],
    threshold: u8,
    signers_root: Field,
    signer_proof_lengths: [u32; MAX_SIGNERS],
    signer_proof_indices: [[u1; SIGNERS_MAX_DEPTH]; MAX_SIGNERS],
    signer_proof_siblings: [[Field; SIGNERS_MAX_DEPTH]; MAX_SIGNERS],
    signatures: [Signature; MAX_SIGNERS],

    // -- Label-binding private inputs (one set per signer slot) --------------
    label_names: [[u8; LABEL_NAME_BYTES]; MAX_SIGNERS],
    label_proof_lengths: [u32; MAX_SIGNERS],
    label_proof_indices: [[u1; LABELS_MAX_DEPTH]; MAX_SIGNERS],
    label_proof_siblings: [[Field; LABELS_MAX_DEPTH]; MAX_SIGNERS],

    // -- Public inputs ----------------------------------------------------------
    txn_hash: pub Hash,
    on_chain_state_root: pub Field,
    registry_root: pub Field,
    label_commitments: pub [Field; MAX_SIGNERS],
) {
    // Step 1 - Verify M-of-N multi-sig.
    // Returns address_fields[MAX_SIGNERS]: address_to_field(address) for active
    // slots, 0 for NIL slots (G-point pubkey = empty slot sentinel).
    let address_fields = verify_multi_sig(
        signers, signatures, txn_hash, threshold, signers_root,
        signer_proof_lengths, signer_proof_indices, signer_proof_siblings,
        on_chain_state_root,
    );

    // Step 2 - For each active signer, verify label membership in registry_root.
    // We gate on `!is_nil_pubkey(signers[i])` - the same condition used
    // internally by verify_multi_sig - so the label proof is only required
    // for slots that actually contributed a signature.
    for i in 0..MAX_SIGNERS {
        if !is_nil_pubkey(signers[i]) {
            let commitment = verify_label_membership(
                label_names[i],
                address_fields[i],
                registry_root,
                label_proof_lengths[i],
                label_proof_indices[i],
                label_proof_siblings[i],
            );
            assert(label_commitments[i] == commitment);
        }
    }
}
