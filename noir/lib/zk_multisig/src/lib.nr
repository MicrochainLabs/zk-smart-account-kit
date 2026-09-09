use poseidon::poseidon::bn254::hash_1 as poseidon1;
use poseidon::poseidon::bn254::hash_2 as poseidon2;
use binary_merkle_root::binary_merkle_root;
use zk_signer::{
    PubKey, Signature, Hash, Address,
    is_nil_pubkey, verify_ecdsa_get_address, signer_leaf, address_to_field, cmp_gt,
};

// --- Constants ----------------------------------------------------------------

pub global SIGNERS_MAX_DEPTH: u32 = 4;
pub global MAX_SIGNERS: u32 = 5;
// Invariant: MAX_THRESHOLD <= MAX_SIGNERS must always hold.
// MAX_THRESHOLD is the policy ceiling (can be set lower for tighter access control).
// MAX_SIGNERS is the structural ceiling (array sizes are fixed to this value).
pub global MAX_THRESHOLD: u8 = 5;
pub global MICROCHAIN_OWNERSHIP_STATE_MAX_DEPTH: u32 = 1;

// --- State root ---------------------------------------------------------------

/// Compute the expected on-chain stateRoot from (signers_root, threshold):
///   state_root = binary_merkle_root(poseidon2, signers_root, depth=1, [0], [poseidon1(threshold)])
///
/// This matches the computation in ZKMultiSigEcdsaSingleton / ZKMultiSigValidator.
pub fn compute_state_root(signers_root: Field, threshold: u8) -> Field {
    let threshold_hash = poseidon1([threshold as Field]);
    binary_merkle_root(
        poseidon2,
        signers_root,
        MICROCHAIN_OWNERSHIP_STATE_MAX_DEPTH,
        [0],
        [threshold_hash],
    )
}

// --- Multi-sig verification ---------------------------------------------------

/// Verify M-of-N ECDSA multi-signatures and the on-chain stateRoot.
///
/// For each active signer slot (pubkey != G-point sentinel):
///   1. ECDSA signature verifies against txn_hash
///   2. Derived Ethereum address is in the authorized signers Merkle tree
///   3. Signers appear in strictly increasing address order (anti-replay)
///   4. At least `threshold` active signatures have been verified
///   5. The provided on_chain_state_root matches compute_state_root(signers_root, threshold)
///
/// Returns `address_fields[MAX_SIGNERS]` where each element is the address
/// converted to a Field for the active slot, or 0 for NIL/empty slots.
/// These values are used by the combined circuit to link role proofs to the
/// exact same addresses - the linkage is by construction, not by assertion.
pub fn verify_multi_sig(
    signers: [PubKey; MAX_SIGNERS],
    signatures: [Signature; MAX_SIGNERS],
    txn_hash: Hash,
    threshold: u8,
    signers_root: Field,
    proof_lengths: [u32; MAX_SIGNERS],
    proof_indices: [[u1; SIGNERS_MAX_DEPTH]; MAX_SIGNERS],
    proof_siblings: [[Field; SIGNERS_MAX_DEPTH]; MAX_SIGNERS],
    on_chain_state_root: Field,
) -> [Field; MAX_SIGNERS] {
    // Verify the on-chain state root commits to (signers_root, threshold)
    assert(on_chain_state_root == compute_state_root(signers_root, threshold));

    let mut curr_owner: Address = [0; 20];
    let mut num_verified: u32 = 0;
    let mut address_fields: [Field; MAX_SIGNERS] = [0; MAX_SIGNERS];

    for i in 0..MAX_SIGNERS {
        if !is_nil_pubkey(signers[i]) {
            // 1. Verify ECDSA and derive Ethereum address
            let address = verify_ecdsa_get_address(signers[i], signatures[i], txn_hash);

            // 2. Strictly increasing order - prevents same signer appearing twice
            assert(cmp_gt(address, curr_owner));
            curr_owner = address;

            // 3. Verify signer address is a member of the authorized signers tree
            let leaf       = signer_leaf(address);
            let merkle_root = binary_merkle_root(
                poseidon2,
                leaf,
                proof_lengths[i],
                proof_indices[i],
                proof_siblings[i],
            );
            assert(signers_root == merkle_root);

            address_fields[i] = address_to_field(address);
            num_verified += 1;
        }
    }

    assert(num_verified >= threshold as u32);

    address_fields
}
