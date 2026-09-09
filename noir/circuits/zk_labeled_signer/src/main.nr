use zk_signer::{verify_ecdsa_get_address, SIGNERS_MAX_DEPTH, PubKey, Signature, Hash, address_to_field};
use zk_signer::address_to_field as addr_to_f;
use zk_labels::{verify_label_membership, LABELS_MAX_DEPTH, LABEL_NAME_BYTES, label_leaf, label_to_field};

/// ZK Labeled Signer
///
/// Combines two ZK statements into one atomic proof:
///
///   1. SIGNER AUTHORIZATION - the prover holds a secp256k1 private key whose
///      derived Ethereum address is registered under `signer_label_bytes` in the
///      `signers_root` label tree.  Both the signer's label name and address are
///      private witnesses, only the tree root is public.
///
///   2. DESTINATION AUTHORIZATION - the destination address (`dest_address_bytes`)
///      is registered under `dest_label_bytes` in the `registry_root` label tree.
///      The registry can be either:
///        - Contacts Tree  maps contact names  (e.g. "alice")      to Ethereum addresses
///        - Protocols Tree maps protocol names (e.g. "uniswap-v3") to contract addresses
///      The on-chain validator identifies the tree by matching `registry_root` against
///      its stored `contactsRoot` and `protocolsRoot`.
///
/// UNIFIED LEAF FORMAT
///   All three trees (signers, contacts, protocols) use the same leaf formula:
///     leaf = Poseidon2(Poseidon1(label_field), Poseidon1(address_field))
///   This means there is only one kind of label tree.  The smart account stores
///   three roots but no separate "address-only" structure is needed anywhere.
///
/// PRIVACY MODEL
///   - The signer's label name and Ethereum address are never revealed on-chain.
///   - The destination's label name and Ethereum address are never revealed on-chain.
///   - Only `dest_address_field` (already visible in calldata) is a public input.
///
/// SECURITY BINDING
///   - `txn_hash` is the ERC-4337 userOpHash; the ECDSA signature over it binds
///     the proof to this specific transaction and prevents replay.
///   - `dest_address_field` is the public encoding of `dest_address_bytes`; the
///     validator checks it equals the calldata target, preventing a prover from
///     proving membership of address A while the account calls address B.
///
/// Public inputs (35 Field elements):
///   txn_hash[0..31]    - 32 byte-fields (userOpHash, also signed by the prover)
///   signers_root       - Merkle root of the signers label tree (label -> address)
///   registry_root      - Merkle root of the destination label tree (contacts or protocols)
///   dest_address_field - address_to_field(dest_address_bytes), checked on-chain
fn main(
    // Signer private inputs
    pubkey:                 PubKey,
    signature:              Signature,
    signer_label_bytes:     [u8; LABEL_NAME_BYTES],   // e.g. "treasury-lead" - never public
    signer_proof_length:    u32,
    signer_proof_indices:   [u1; SIGNERS_MAX_DEPTH],
    signer_proof_siblings:  [Field; SIGNERS_MAX_DEPTH],

    // Destination label private inputs
    dest_address_bytes:     [u8; 20],
    dest_label_bytes:       [u8; LABEL_NAME_BYTES],   // e.g. "alice" or "uniswap-v3" - never public
    dest_label_proof_length:   u32,
    dest_label_proof_indices:  [u1; LABELS_MAX_DEPTH],
    dest_label_proof_siblings: [Field; LABELS_MAX_DEPTH],

    // Public inputs
    txn_hash:           pub Hash,
    signers_root:       pub Field,
    registry_root:      pub Field,
    dest_address_field: pub Field,
) {
    // Step 1: ECDSA verification
    // Verify the signature over txn_hash and derive the signer's Ethereum address.
    // Panics if the signature is invalid.
    let signer_address = verify_ecdsa_get_address(pubkey, signature, txn_hash);
    let signer_addr_field = address_to_field(signer_address);

    // Step 2: Signer label authorization
    // Prove that (signer_label_bytes, signer_address) is a leaf in signers_root.
    // The signer label name and address are both private witnesses.
    // Leaf = Poseidon2(Poseidon1(label_field), Poseidon1(signer_addr_field))
    let _signer_commitment = verify_label_membership(
        signer_label_bytes,
        signer_addr_field,
        signers_root,
        signer_proof_length,
        signer_proof_indices,
        signer_proof_siblings,
    );

    // Step 3: Destination label authorization
    // Prove that (dest_label_bytes, dest_address_bytes) is a leaf in registry_root.
    let dest_addr_field = address_to_field(dest_address_bytes);
    let _dest_commitment = verify_label_membership(
        dest_label_bytes,
        dest_addr_field,
        registry_root,
        dest_label_proof_length,
        dest_label_proof_indices,
        dest_label_proof_siblings,
    );

    // Step 4: Bind private dest_address_bytes to public dest_address_field
    // Prevents proving membership of address A while the calldata calls address B.
    assert(dest_addr_field == dest_address_field);
}

// Tests

#[test]
fn test_single_contact_call() {
    // -- Signer: Hardhat account #0 - 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 --
    let pubkey = PubKey {
        x: [131,24,83,91,84,16,93,74,122,174,96,192,143,196,95,150,
            135,24,27,79,223,198,37,189,26,117,63,167,57,127,237,117],
        y: [ 53,71,241,28,168,105,102,70,242,243,172,176,142, 49,  1,106,
            250,194,62,99, 12, 93, 17,245,159, 97,254,245,123, 13, 42,165],
    };

    let signature: Signature = [
        250,120,197,144, 95,176,185,214,  6,110,245, 49,249, 98,166, 43,
        198,239, 13, 94,181,158,203, 19, 64, 86,210,  6,247, 90,174,215,
        120,  9, 38,255, 38,  1,169, 53,194,199,151,  7,217,225,121,153,
         72,201,241,157,205,222, 30,  9, 14,144, 59, 25,160,121, 35,208
    ];

    // DEMO_TXN_HASH = 0xdeadbeef padded to 32 bytes big-endian
    let txn_hash: Hash = [
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,222,173,190,239
    ];

    // Signer label: "ceo" - 3 bytes, right-aligned in 31-byte array
    let signer_label_bytes: [u8; LABEL_NAME_BYTES] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 101, 111  // "ceo"
    ];
    // Hardhat #0 address bytes
    let signer_address_bytes: [u8; 20] = [
        0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6, 0xF4, 0xce,
        0x6a, 0xB8, 0x82, 0x72, 0x79, 0xcf, 0xfF, 0xb9, 0x22, 0x66
    ];

    // Build signers_root: single-leaf label tree (depth 0: root == leaf)
    // leaf = Poseidon2(Poseidon1(label_to_field("ceo")), Poseidon1(address_to_field(signer)))
    let signer_label_field = label_to_field(signer_label_bytes);
    let signer_addr_field  = addr_to_f(signer_address_bytes);
    let signers_root = label_leaf(signer_label_field, signer_addr_field);

    let signer_proof_length:   u32       = 0;
    let signer_proof_indices:  [u1; 4]   = [0, 0, 0, 0];
    let signer_proof_siblings: [Field; 4] = [0, 0, 0, 0];

    // Destination: "alice" contact at address 0xdeadbeef...0001
    // dest_label_bytes = "alice" (5 bytes) zero-padded to 31 bytes, right-aligned
    let dest_label_bytes: [u8; LABEL_NAME_BYTES] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 108, 105, 99, 101  // "alice"
    ];
    let dest_address_bytes: [u8; 20] = [
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    ];

    // Build registry_root: single-leaf contacts tree (depth 0: root == leaf)
    let dest_label_field = label_to_field(dest_label_bytes);
    let dest_addr_field  = addr_to_f(dest_address_bytes);
    let registry_root    = label_leaf(dest_label_field, dest_addr_field);

    let dest_label_proof_length:   u32       = 0;
    let dest_label_proof_indices:  [u1; 4]   = [0, 0, 0, 0];
    let dest_label_proof_siblings: [Field; 4] = [0, 0, 0, 0];

    let dest_address_field = dest_addr_field;

    main(
        pubkey,
        signature,
        signer_label_bytes,
        signer_proof_length,
        signer_proof_indices,
        signer_proof_siblings,
        dest_address_bytes,
        dest_label_bytes,
        dest_label_proof_length,
        dest_label_proof_indices,
        dest_label_proof_siblings,
        txn_hash,
        signers_root,
        registry_root,
        dest_address_field,
    );
}
