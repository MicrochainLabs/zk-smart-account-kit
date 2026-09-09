use poseidon::poseidon::bn254::hash_2 as poseidon2;
use binary_merkle_root::binary_merkle_root;
use zk_signer::address_to_field;
use zk_labels::{label_leaf, label_to_field, LABELS_MAX_DEPTH, LABEL_NAME_BYTES};

// Constants

/// Maximum number of signers in a smart account's signer subset.
pub global MAX_SUBSET_SIGNERS: u32 = 5;

/// The subset tree is a complete binary Merkle tree of depth 3, giving 8 leaf
/// slots (2^3).  Unused slots receive leaf = 0.
pub global SUBSET_TREE_DEPTH: u32 = 3;

// Subset root builder

/// Compute the root of a complete binary Merkle tree (depth = 3, 8 leaves)
/// using Poseidon2 for every internal node.
///
///   Level 1 (4 nodes): poseidon2(leaves[2i], leaves[2i+1])  for i in 0..4
///   Level 2 (2 nodes): poseidon2(L1[2j],    L1[2j+1])      for j in 0..2
///   Root:              poseidon2(L2[0],      L2[1])
///
/// Inactive/empty leaf slots must be set to 0 by the prover.
pub fn build_subset_root(leaves: [Field; 8]) -> Field {
    let n0 = poseidon2([leaves[0], leaves[1]]);
    let n1 = poseidon2([leaves[2], leaves[3]]);
    let n2 = poseidon2([leaves[4], leaves[5]]);
    let n3 = poseidon2([leaves[6], leaves[7]]);

    let m0 = poseidon2([n0, n1]);
    let m1 = poseidon2([n2, n3]);

    poseidon2([m0, m1])
}


// Main circuit

/// ZK Signer Subset Proof
///
/// Proves at deployment time that every signer committed in a smart account's
/// `subset_signers_root` is a member of the organisation-wide `main_signers_root`.
///
/// ## Security guarantee
/// The circuit (a) verifies each active signer's Merkle membership in the main
/// tree and (b) re-derives the subset root deterministically from exactly those
/// leaves.  It is therefore impossible to construct a valid proof for a subset
/// that contains any signer not registered in the main tree.
///
/// ## Public inputs  (verified on-chain by the factory contract)
///   main_signers_root   - org-wide master signer registry root (stored in factory)
///   subset_signers_root - signer root that will be stored in the smart account
///
/// ## Private inputs  (per signer slot i in 0..MAX_SUBSET_SIGNERS)
///   signer_label_bytes[i]     - UTF-8 label name, zero-padded to LABEL_NAME_BYTES
///   signer_address_bytes[i]   - raw 20-byte Ethereum address
///   is_active[i]              - true iff this slot contains a real signer
///   main_proof_lengths[i]     - Merkle proof depth in the main tree
///   main_proof_indices[i]     - left/right bit per level (length LABELS_MAX_DEPTH)
///   main_proof_siblings[i]    - sibling hash per level   (length LABELS_MAX_DEPTH)
fn main(
    signer_label_bytes:   [[u8; LABEL_NAME_BYTES]; MAX_SUBSET_SIGNERS],
    signer_address_bytes: [[u8; 20]; MAX_SUBSET_SIGNERS],
    is_active:            [bool; MAX_SUBSET_SIGNERS],
    main_proof_lengths:   [u32; MAX_SUBSET_SIGNERS],
    main_proof_indices:   [[u1; LABELS_MAX_DEPTH]; MAX_SUBSET_SIGNERS],
    main_proof_siblings:  [[Field; LABELS_MAX_DEPTH]; MAX_SUBSET_SIGNERS],
    // Public inputs
    main_signers_root:   pub Field,
    subset_signers_root: pub Field,
) {
    //  Step 1: verify each active signer membership in the main tree 
    let mut leaves: [Field; 8] = [0; 8];

    for i in 0..MAX_SUBSET_SIGNERS {
        let label_field = label_to_field(signer_label_bytes[i]);
        let addr_field  = address_to_field(signer_address_bytes[i]);
        let leaf        = label_leaf(label_field, addr_field);

        // Compute the root implied by this leaf + its Merkle proof path.
        // For inactive slots the proof inputs are arbitrary; the conditional
        // assertion below makes the check a no-op for those slots.
        let implied_root = binary_merkle_root(
            poseidon2,
            leaf,
            main_proof_lengths[i],
            main_proof_indices[i],
            main_proof_siblings[i],
        );

        // Conditional membership check:
        let expected_root = if is_active[i] { main_signers_root } else { implied_root };
        assert(implied_root == expected_root);

        // Include the leaf in the subset tree iff the slot is active.
        leaves[i] = if is_active[i] { leaf } else { 0 };
    }

    // Step 2: rebuild the subset root and assert it matches the public input 
    let computed_subset_root = build_subset_root(leaves);
    assert(computed_subset_root == subset_signers_root);
}