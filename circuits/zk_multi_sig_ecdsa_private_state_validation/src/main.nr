use zk_multisig::{compute_state_root, MAX_SIGNERS, MAX_THRESHOLD};

fn main(
    signers_root: Field,
    threshold: u8,
    on_chain_state_root: pub Field,
) {
    assert(MAX_THRESHOLD as u32 <= MAX_SIGNERS, "Misconfiguration: MAX_THRESHOLD exceeds MAX_SIGNERS");
    assert(signers_root != 0, "Signers root cannot be zero");
    assert(threshold > 0, "Threshold must be greater than 0");
    assert(threshold <= MAX_THRESHOLD, "Threshold exceeds maximum allowed");
    assert(threshold as u32 <= MAX_SIGNERS, "Threshold cannot exceed number of signers");
    assert(on_chain_state_root == compute_state_root(signers_root, threshold));
}

#[test]
fn test_main() {
    //nargo test --show-output

    let threshold = 2;
    let signers_root = 16223743289759414337474221898890222788896083712324022742978151074941795950178;
    
    // Compute state root (signers_root + threshold)
    let state_root = 10223786790855367822232839749406742084971735911793673331153158573476372880461;

    main(signers_root, threshold, state_root)
}