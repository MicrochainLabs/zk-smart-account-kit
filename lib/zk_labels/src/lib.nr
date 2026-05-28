use poseidon::poseidon::bn254::hash_1 as poseidon1;
use poseidon::poseidon::bn254::hash_2 as poseidon2;
use binary_merkle_root::binary_merkle_root;

// --- Constants ----------------------------------------------------------------

/// Maximum Merkle tree depth for the label registry (supports up to 2^4 = 16 labels).
pub global LABELS_MAX_DEPTH: u32 = 4;

/// Label names are encoded as UTF-8 and right-padded with zeros to exactly 31 bytes.
/// 31 bytes = 248 bits, which fits in a single BN254 scalar field element (~254 bits).
/// Labels can represent roles, names, tags, permissions, groups, or any custom attribute.
pub global LABEL_NAME_BYTES: u32 = 31;

// --- Field conversion --------------------------------------------------------

/// Convert a label byte array to a Field element using big-endian byte order.
/// Labels are UTF-8 strings zero-padded to exactly LABEL_NAME_BYTES bytes.
pub fn label_to_field(label_bytes: [u8; LABEL_NAME_BYTES]) -> Field {
    let mut result: Field = 0;
    let mut v: Field = 1;
    for i in 0..LABEL_NAME_BYTES {
        result += label_bytes[LABEL_NAME_BYTES - 1 - i] as Field * v;
        v *= 256;
    }
    result
}

// --- Label commitment leaf -----------------------------------------------------

/// Compute the label commitment (Merkle leaf):
///   Poseidon2(Poseidon1(label_field), Poseidon1(address_field))
///
/// This binding is both the leaf in the registry Merkle tree and the
/// public output published on-chain - it links the label to the address without
/// revealing either value. The label can be a role, name, tag, permission, etc.
pub fn label_leaf(label_field: Field, address_field: Field) -> Field {
    let label_hash   = poseidon1([label_field]);
    let address_hash = poseidon1([address_field]);
    poseidon2([label_hash, address_hash])
}

// --- Label membership proof ----------------------------------------------------

/// Prove that (label_bytes, address_field) is a member of the Merkle tree
/// rooted at `registry_root`. Returns the label_commitment (leaf hash).
///
/// The label can be a role, name, tag, permission, group, or any custom attribute
/// encoded as a UTF-8 string up to 31 bytes.
///
/// Asserts:
///   1. The Merkle proof is valid: the leaf belongs to registry_root.
///
/// The caller is responsible for asserting the returned commitment matches
/// the expected public output.
pub fn verify_label_membership(
    label_bytes: [u8; LABEL_NAME_BYTES],
    address_field: Field,
    registry_root: Field,
    proof_length: u32,
    proof_indices: [u1; LABELS_MAX_DEPTH],
    proof_siblings: [Field; LABELS_MAX_DEPTH],
) -> Field {
    // Convert label bytes to Field (big-endian 31-byte integer)
    let label_field = label_to_field(label_bytes);

    // Compute leaf = Poseidon2(Poseidon1(label_field), Poseidon1(address_field))
    let commitment = label_leaf(label_field, address_field);

    // Verify Merkle membership proof
    let computed_root = binary_merkle_root(
        poseidon2,
        commitment,
        proof_length,
        proof_indices,
        proof_siblings,
    );
    assert(computed_root == registry_root);

    commitment
}
