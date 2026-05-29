use zk_signer::{verify_single_signer, SIGNERS_MAX_DEPTH, PubKey, Signature, Hash};

/// ZK Signers
///
/// Proves two things in zero-knowledge:
///   1. The prover knows a private key that produced `signature` over `txn_hash`
///   2. The derived Ethereum address is authorized (member of `signers_root` tree)
///
/// Used by smart accounts to authenticate transactions from any member of a
/// pre-committed signers set, without revealing which specific signer authorized it.
///
/// Public inputs (verified on-chain by the EVM verifier contract):
///   - txn_hash    : the transaction hash that was signed
///   - signers_root: the Merkle root of authorized signers stored in the smart account
///
/// Private witness (hidden from verifier ? zero-knowledge):
///   - pubkey         : secp256k1 public key of the signer
///   - signature      : r ++ s ECDSA signature (64 bytes, low-S, no Ethereum prefix)
///   - proof_length   : depth of the Merkle inclusion proof
///   - proof_index    : bit-path from leaf to root (little-endian bit array)
///   - proof_siblings : sibling hashes along the Merkle path

fn main(
    // ?? Private witness ????????????????????????????????????????????????????
    pubkey:         PubKey,
    signature:      Signature,
    proof_length:   u32,
    proof_index:    [u1; SIGNERS_MAX_DEPTH],
    proof_siblings: [Field; SIGNERS_MAX_DEPTH],

    // ?? Public inputs ??????????????????????????????????????????????????????
    txn_hash:     pub Hash,
    signers_root: pub Field,
) {
    verify_single_signer(
        pubkey,
        signature,
        txn_hash,
        signers_root,
        proof_length,
        proof_index,
        proof_siblings,
    );
}

//
// Single-signer tree containing only Hardhat #0 (CEO).
//
// Tree layout:
//   leaf = Poseidon1(address_to_field(0xf39f?2266))
//        = 7883074409468045280407067478175608582487155714151013737870117867970375847717
//   signers_root = leaf  (LeanIMT with 1 entry: root == leaf)
//
// ECDSA: raw secp256k1 over DEMO_TXN_HASH = 0x00?00deadbeef (32 bytes big-endian)
// Computed with @noble/curves/secp256k1 from Hardhat #0 private key.

#[test]
fn test_ceo_single_signer() {
    let pubkey = PubKey {
        x: [131,24,83,91,84,16,93,74,122,174,96,192,143,196,95,150,
            135,24,27,79,223,198,37,189,26,117,63,167,57,127,237,117],
        y: [53,71,241,28,168,105,102,70,242,243,172,176,142,49,1,106,
            250,194,62,99,12,93,17,245,159,97,254,245,123,13,42,165],
    };

    let signature: Signature = [
        250,120,197,144,95,176,185,214,6,110,245,49,249,98,166,43,
        198,239,13,94,181,158,203,19,64,86,210,6,247,90,174,215,
        120,9,38,255,38,1,169,53,194,199,151,7,217,225,121,153,
        72,201,241,157,205,222,30,9,14,144,59,25,160,121,35,208
    ];

    // DEMO_TXN_HASH = 0xdeadbeef padded to 32 bytes big-endian
    let txn_hash: Hash = [
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,222,173,190,239
    ];

    // 1-signer tree: root == leaf (depth = 0, no siblings)
    let signers_root: Field = 7883074409468045280407067478175608582487155714151013737870117867970375847717;
    let proof_length: u32 = 0;
    let proof_index:    [u1; 4] = [0, 0, 0, 0];
    let proof_siblings: [Field; 4] = [0, 0, 0, 0];

    main(pubkey, signature, proof_length, proof_index, proof_siblings, txn_hash, signers_root);
}
