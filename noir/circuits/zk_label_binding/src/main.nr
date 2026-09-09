use zk_signer::address_to_field;
use zk_labels::{verify_label_membership, LABELS_MAX_DEPTH, LABEL_NAME_BYTES, label_leaf, label_to_field};
use poseidon::poseidon::bn254::hash_2 as poseidon2;

/// Proves that (label_bytes, address) is a member of the registry Merkle tree
/// rooted at `registry_root`, without revealing the label or address on-chain.
/// The label can be a role, name, tag, permission, group, or any custom attribute
/// encoded as a UTF-8 string up to 31 bytes.
///
/// Public inputs:
///   registry_root     - the on-chain commitment to the full label registry
///   label_commitment  - Poseidon2(label_hash, address_hash), a compact
///                       link to other proofs without revealing label or address
fn main(
    // Private inputs
    address_bytes: [u8; 20],
    label_bytes: [u8; LABEL_NAME_BYTES],
    merkle_proof_length: u32,
    merkle_proof_indices: [u1; LABELS_MAX_DEPTH],
    merkle_proof_siblings: [Field; LABELS_MAX_DEPTH],
    // Public inputs
    registry_root: pub Field,
    label_commitment: pub Field,
) {
    let address_field = address_to_field(address_bytes);
    let commitment = verify_label_membership(
        label_bytes,
        address_field,
        registry_root,
        merkle_proof_length,
        merkle_proof_indices,
        merkle_proof_siblings,
    );
    assert(label_commitment == commitment);
}

#[test]
fn test_main() {
    // Label: "admin" (5 ASCII bytes), zero-padded to 31 bytes (big-endian)
    let label_bytes: [u8; LABEL_NAME_BYTES] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110
    ];

    // Arbitrary address
    let address_bytes: [u8; 20] = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ];

    let label_field = label_to_field(label_bytes);
    let address_field = address_to_field(address_bytes);
    let commitment = label_leaf(label_field, address_field);

    // Single-leaf registry: proof_length = 0 => binary_merkle_root returns the leaf itself,
    // so registry_root == label_commitment == commitment.
    // In production, registry_root != label_commitment: the root commits to many leaves
    // and a real Merkle proof (proof_length > 0, siblings) links the leaf to the root.
    main(
        address_bytes,
        label_bytes,
        0,
        [0, 0, 0, 0],
        [0, 0, 0, 0],
        commitment, // registry_root (== leaf only because proof_length = 0)
        commitment, // label_commitment
    )
}

#[test]
fn test_main_multi_leaf() {
    // Leaf 0: "admin" at address_0 - the membership we prove
    let label0_bytes: [u8; LABEL_NAME_BYTES] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110
    ]; // "admin"
    let address0_bytes: [u8; 20] = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ];

    // Leaf 1: "operator" at address_1 - a sibling leaf, not proven
    let label1_bytes: [u8; LABEL_NAME_BYTES] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 111, 112, 101, 114, 97, 116, 111, 114
    ]; // "operator"
    let address1_bytes: [u8; 20] = [
        0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    ];

    let leaf0 = label_leaf(label_to_field(label0_bytes), address_to_field(address0_bytes));
    let leaf1 = label_leaf(label_to_field(label1_bytes), address_to_field(address1_bytes));

    // 2-leaf tree: leaf0 is the left child (index 0), leaf1 is the right child.
    // registry_root = poseidon2([leaf0, leaf1]), which is distinct from both leaves.
    let registry_root = poseidon2([leaf0, leaf1]);
    assert(registry_root != leaf0); // root != label_commitment

    main(
        address0_bytes,
        label0_bytes,
        1,               // proof_length = 1 (depth-1 tree)
        [0, 0, 0, 0],    // index[0] = 0: leaf0 is the left child
        [leaf1, 0, 0, 0], // sibling at depth 0 is leaf1; unused slots are 0
        registry_root,
        leaf0,           // label_commitment = leaf0; registry_root != leaf0
    )
}
