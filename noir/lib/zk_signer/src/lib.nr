use dep::std;
use poseidon::poseidon::bn254::hash_1 as poseidon1;
use poseidon::poseidon::bn254::hash_2 as poseidon2;
use binary_merkle_root::binary_merkle_root;
use keccak256::keccak256;

// --- Constants ---------------------------------------------------------------

/// Depth of the binary Merkle signers tree.
/// Supports up to 2^SIGNERS_MAX_DEPTH authorized signers.
pub global SIGNERS_MAX_DEPTH: u32 = 4;

// --- Types --------------------------------------------------------------------

pub type Address = [u8; 20];
pub type Signature = [u8; 64];
pub type Hash = [u8; 32];

pub struct PubKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

// --- NIL sentinel - secp256k1 generator point G -------------------------------

/// Returns true when the pubkey is the secp256k1 generator point G,
/// which is used as the "empty slot" sentinel in multi-sig arrays.
pub fn is_nil_pubkey(pubkey: PubKey) -> bool {
    let g_x: [u8; 32] = [121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7,
                           2, 155, 252, 219,  45, 206,  40, 217, 89, 242, 129, 91, 22, 248, 23, 152];
    let g_y: [u8; 32] = [ 72,  58, 218, 119,  38, 163, 196, 101, 93, 164, 251, 252, 14,  17,  8, 168,
                          253,  23, 180,  72, 166, 133,  84,  25, 156, 71, 208, 143, 251, 16, 212, 184];
    (pubkey.x == g_x) & (pubkey.y == g_y)
}

// --- Field conversion ---------------------------------------------------------

/// Convert a byte array to a Field element using big-endian byte order.
pub fn bytes_to_field<let N: u32>(bytes: [u8; N]) -> Field {
    let mut result: Field = 0;
    let mut v: Field = 1;
    for i in 0..N {
        result += bytes[N - 1 - i] as Field * v;
        v *= 256;
    }
    result
}

/// Convert a 20-byte Ethereum address to a Field element.
pub fn address_to_field(address: Address) -> Field {
    let mut result: Field = 0;
    let mut v: Field = 1;
    for k in 0..20 {
        result += address[19 - k] as Field * v;
        v *= 256 as Field;
    }
    result
}

// --- Merkle leaf --------------------------------------------------------------

/// Compute the signer's Merkle leaf: Poseidon1(address_as_field).
pub fn signer_leaf(address: Address) -> Field {
    poseidon1([address_to_field(address)])
}

// --- ECDSA verification -------------------------------------------------------

/// Verify an secp256k1 ECDSA signature and return the signer's 20-byte
/// Ethereum address (keccak256 of uncompressed pubkey, last 20 bytes).
/// Asserts signature validity - panics if verification fails.
pub fn verify_ecdsa_get_address(pubkey: PubKey, sig: Signature, msg_hash: Hash) -> Address {
    assert(std::ecdsa_secp256k1::verify_signature(pubkey.x, pubkey.y, sig, msg_hash));

    let mut uncompressed_pubkey: [u8; 64] = [0; 64];
    for j in 0..32 {
        uncompressed_pubkey[j]      = pubkey.x[j];
        uncompressed_pubkey[j + 32] = pubkey.y[j];
    }
    let pubkey_hash = keccak256(uncompressed_pubkey, 64);

    let mut address: Address = [0; 20];
    for j in 0..20 {
        address[j] = pubkey_hash[j + 12];
    }
    address
}

// --- Anti-replay ordering -----------------------------------------------------

/// Return true if a > b (big-endian byte comparison).
/// Used to enforce strictly increasing signer address order, preventing
/// the same signature from being counted twice.
pub fn cmp_gt<let N: u32>(a: [u8; N], b: [u8; N]) -> bool {
    let mut result = false;
    let mut done = false;
    for i in 0..N {
        if !done {
            if a[i] > b[i] {
                result = true;
                done = true;
            } else if a[i] < b[i] {
                result = false;
                done = true;
            }
        }
    }
    result
}

// --- Single-signer proof -----------------------------------------------------

/// Verify a single-signer proof for smart account tx authentication:
///   1. ECDSA signature over txn_hash is valid for the given pubkey
///   2. The derived Ethereum address is a member of the authorized signers tree
///
/// Public inputs (checked on-chain): txn_hash, signers_root.
/// Private witness (zero-knowledge): pubkey, signature, Merkle proof.
pub fn verify_single_signer(
    pubkey:         PubKey,
    signature:      Signature,
    txn_hash:       Hash,
    signers_root:   Field,
    proof_length:   u32,
    proof_index:    [u1; SIGNERS_MAX_DEPTH],
    proof_siblings: [Field; SIGNERS_MAX_DEPTH],
) {
    // 1. Verify ECDSA - derives the signer's Ethereum address
    let address = verify_ecdsa_get_address(pubkey, signature, txn_hash);

    // 2. Compute the Poseidon leaf for this address
    let leaf = signer_leaf(address);

    // 3. Verify Merkle membership in the signers tree
    let computed_root = binary_merkle_root(
        poseidon2,
        leaf,
        proof_length,
        proof_index,
        proof_siblings,
    );
    assert(signers_root == computed_root);
}
