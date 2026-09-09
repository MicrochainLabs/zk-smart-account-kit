use zk_signer::{verify_ecdsa_get_address, SIGNERS_MAX_DEPTH, PubKey, Signature, Hash, address_to_field};
use zk_signer::address_to_field as addr_to_f;
use zk_labels::{verify_label_membership, LABEL_NAME_BYTES, label_leaf, label_to_field};
use zk_scope::{
    verify_labeled_scope_membership,
    compute_labeled_rule_leaf,
    compute_params_hash,
    SCOPE_MAX_DEPTH,
    MAX_PARAMS,
    ParamConstraint,
    PARAM_UNCONSTRAINED,
    WILDCARD_SELECTOR,
};

/// ZK Labeled Signer + Scope (unified destination/scope tree)
///
/// Combines two ZK statements into one atomic proof:
///
///   1. SIGNER AUTHORIZATION - the prover holds a secp256k1 private key whose
///      derived Ethereum address is registered under `signer_label_bytes` in
///      the `signers_root` label tree. Both the signer's label name and
///      address are private witnesses, only the tree root is public.
///
///   2. DESTINATION + SCOPE AUTHORIZATION - the destination address
///      (`dest_address_field`, already public) together with its label,
///      matches a single leaf in the unified `scope_root` tree. There is no
///      separate destination registry tree anymore: a leaf commits
///      (label, target, selector, value_max, params_hash), where
///      `selector = WILDCARD_SELECTOR` means "no restriction" - any
///      registered contact/protocol with no scope rule simply gets a
///      wildcard leaf, and any restrictive rule uses a real selector, value
///      bound, and parameter constraints enforced exactly like a plain
///      scope-only proof.
///
/// PRIVACY MODEL
///   - The signer's label name and Ethereum address are never revealed on-chain.
///   - The destination's label name is never revealed on-chain.
///   - `dest_address_field` and the decoded calldata `param_values` are public
///     inputs - this reveals nothing that isn't already visible on-chain
///     anyway (the UserOperation's calldata is public regardless of what the
///     circuit treats as public/private witnesses). Making them public lets
///     the validator contract extract and bind them directly from the real
///     calldata, instead of trusting a caller-supplied commitment hash.
///
/// SECURITY BINDING
///   - `txn_hash` is the ERC-4337 userOpHash; the ECDSA signature over it binds
///     the proof to this specific transaction and prevents replay.
///   - `dest_address_field` is used directly as both the transaction target and
///     the rule's target inside the unified leaf hash, so there is nothing
///     left to separately bind - a mismatched destination simply fails to
///     produce a leaf that belongs to `scope_root`.
///   - `param_values` are public and extracted directly from on-chain calldata
///     by the validator contract (fixed-offset slots, static types only) -
///     there is no separate hash commitment to keep in sync with the real
///     calldata, so a prover cannot supply param values that differ from
///     what the account actually executes.
///
/// Public inputs (41 Field elements):
///   txn_hash[0..31]    - 32 byte-fields (userOpHash, also signed by the prover)
///   signers_root       - Merkle root of the signers label tree (label -> address)
///   dest_address_field - transaction target address, as a BN254 field element
///   txn_selector       - 4-byte function selector, right-padded to 32 bytes
///   txn_value          - ETH value in wei, as a field element
///   param_values[0..3] - decoded calldata parameters (static, leading params only)
///   scope_root         - on-chain Merkle root of the unified scope/registry tree
fn main(
    // Signer private inputs
    pubkey:                PubKey,
    signature:             Signature,
    signer_label_bytes:    [u8; LABEL_NAME_BYTES],   // e.g. "treasury-lead" - never public
    signer_proof_length:   u32,
    signer_proof_indices:  [u1; SIGNERS_MAX_DEPTH],
    signer_proof_siblings: [Field; SIGNERS_MAX_DEPTH],

    // Destination label - private, only used inside the unified leaf hash
    dest_label_bytes: [u8; LABEL_NAME_BYTES],   // e.g. "alice" or "uniswap-v3" - never public

    // Matching scope rule - private (selector = WILDCARD_SELECTOR for "no restriction")
    rule_selector:    Field,
    rule_value_max:   Field,
    rule_constraints: [ParamConstraint; MAX_PARAMS],

    // Merkle proof for the unified scope tree - private
    scope_proof_length:   u32,
    scope_proof_indices:  [u1; SCOPE_MAX_DEPTH],
    scope_proof_siblings: [Field; SCOPE_MAX_DEPTH],

    // Public inputs
    txn_hash:           pub Hash,
    signers_root:       pub Field,
    dest_address_field: pub Field,
    txn_selector:       pub Field,
    txn_value:          pub Field,
    param_values:       pub [Field; MAX_PARAMS],
    scope_root:         pub Field,
) {
    // Step 1: ECDSA verification
    // Verify the signature over txn_hash and derive the signer's Ethereum address.
    // Panics if the signature is invalid.
    let signer_address = verify_ecdsa_get_address(pubkey, signature, txn_hash);
    let signer_addr_field = address_to_field(signer_address);

    // Step 2: Signer label authorization
    // Prove that (signer_label_bytes, signer_address) is a leaf in signers_root.
    // Leaf = Poseidon2(Poseidon1(label_field), Poseidon1(signer_addr_field))
    let _signer_commitment = verify_label_membership(
        signer_label_bytes,
        signer_addr_field,
        signers_root,
        signer_proof_length,
        signer_proof_indices,
        signer_proof_siblings,
    );

    // Step 3: Unified destination + scope-rule authorization
    // Prove that (dest_label, dest_address_field, rule_*) is a leaf in scope_root,
    // and - unless rule_selector is the WILDCARD_SELECTOR sentinel - that the
    // transaction satisfies the rule's selector/value/param constraints.
    let dest_label_field = label_to_field(dest_label_bytes);
    verify_labeled_scope_membership(
        dest_address_field,
        txn_selector,
        txn_value,
        dest_label_field,
        dest_address_field,
        rule_selector,
        rule_value_max,
        rule_constraints,
        param_values,
        scope_root,
        scope_proof_length,
        scope_proof_indices,
        scope_proof_siblings,
    );
}

// -- Tests -----------------------------------------------------------------------

// Hardhat account #0 - 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
global TEST_PUBKEY: PubKey = PubKey {
    x: [131,24,83,91,84,16,93,74,122,174,96,192,143,196,95,150,
        135,24,27,79,223,198,37,189,26,117,63,167,57,127,237,117],
    y: [ 53,71,241,28,168,105,102,70,242,243,172,176,142, 49,  1,106,
        250,194,62,99, 12, 93, 17,245,159, 97,254,245,123, 13, 42,165],
};

global TEST_SIGNATURE: Signature = [
    250,120,197,144, 95,176,185,214,  6,110,245, 49,249, 98,166, 43,
    198,239, 13, 94,181,158,203, 19, 64, 86,210,  6,247, 90,174,215,
    120,  9, 38,255, 38,  1,169, 53,194,199,151,  7,217,225,121,153,
     72,201,241,157,205,222, 30,  9, 14,144, 59, 25,160,121, 35,208
];

// DEMO_TXN_HASH = 0xdeadbeef padded to 32 bytes big-endian
global TEST_TXN_HASH: Hash = [
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,222,173,190,239
];

// Signer label: "ceo" - 3 bytes, right-aligned in 31-byte array
global TEST_SIGNER_LABEL_BYTES: [u8; LABEL_NAME_BYTES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99, 101, 111  // "ceo"
];

// Hardhat #0 address bytes
global TEST_SIGNER_ADDRESS_BYTES: [u8; 20] = [
    0xf3, 0x9F, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xF6, 0xF4, 0xce,
    0x6a, 0xB8, 0x82, 0x72, 0x79, 0xcf, 0xfF, 0xb9, 0x22, 0x66
];

// Destination label: "alice" - 5 bytes, right-aligned in 31-byte array
global TEST_DEST_LABEL_BYTES: [u8; LABEL_NAME_BYTES] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 97, 108, 105, 99, 101  // "alice"
];

// Wildcard value_max sentinel: max u128 (2^128 - 1). Combined with
// WILDCARD_SELECTOR and all-PARAM_UNCONSTRAINED constraints, this means the
// leaf's own selector/value/param checks are skipped entirely by the circuit.
global TEST_WILDCARD_VALUE_MAX: Field = 0xffffffffffffffffffffffffffffffff;

#[test]
fn test_labeled_signer_with_scope_rule() {
    // -- Signer setup (single-leaf signers tree: depth 0, root == leaf) --
    let signer_label_field = label_to_field(TEST_SIGNER_LABEL_BYTES);
    let signer_addr_field  = addr_to_f(TEST_SIGNER_ADDRESS_BYTES);
    let signers_root = label_leaf(signer_label_field, signer_addr_field);

    // -- Destination + restrictive rule: allow only selector 0x12345678,
    //    value <= 1 ETH, param[0] exact match --
    let dest_label_field   = label_to_field(TEST_DEST_LABEL_BYTES);
    let dest_address_field = 0xdeadbeef00000000000000000000000000000001;
    let rule_selector:  Field = 0x12345678;
    let rule_value_max: Field = 1_000_000_000_000_000_000;
    let rule_constraints: [ParamConstraint; MAX_PARAMS] = [
        ParamConstraint { constraint_type: 1, value: 0xA0b8 }, // PARAM_EXACT
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
    ];
    let param_values: [Field; MAX_PARAMS] = [0xA0b8, 500, 0, 0];

    let params_hash = compute_params_hash(rule_constraints);
    let scope_root = compute_labeled_rule_leaf(
        dest_label_field,
        dest_address_field,
        rule_selector,
        rule_value_max,
        params_hash,
    );

    main(
        TEST_PUBKEY,
        TEST_SIGNATURE,
        TEST_SIGNER_LABEL_BYTES,
        0,
        [0; SIGNERS_MAX_DEPTH],
        [0; SIGNERS_MAX_DEPTH],
        TEST_DEST_LABEL_BYTES,
        rule_selector,
        rule_value_max,
        rule_constraints,
        0,
        [0; SCOPE_MAX_DEPTH],
        [0; SCOPE_MAX_DEPTH],
        TEST_TXN_HASH,
        signers_root,
        dest_address_field,
        rule_selector, // txn_selector matches the rule
        500,           // txn_value (< value_max)
        param_values,
        scope_root,
    );
}

#[test(should_fail_with = "Scope: rule not in scope tree")]
fn test_fails_when_scope_rule_missing() {
    let signer_label_field = label_to_field(TEST_SIGNER_LABEL_BYTES);
    let signer_addr_field  = addr_to_f(TEST_SIGNER_ADDRESS_BYTES);
    let signers_root = label_leaf(signer_label_field, signer_addr_field);

    let dest_address_field = 0xdeadbeef00000000000000000000000000000001;
    let rule_selector:  Field = 0x12345678;
    let rule_value_max: Field = 1_000_000_000_000_000_000;
    let rule_constraints: [ParamConstraint; MAX_PARAMS] = [
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
    ];
    let param_values: [Field; MAX_PARAMS] = [0, 0, 0, 0];

    // scope_root does NOT match the leaf this rule/label/target would produce.
    let scope_root: Field = 0x1;

    main(
        TEST_PUBKEY,
        TEST_SIGNATURE,
        TEST_SIGNER_LABEL_BYTES,
        0,
        [0; SIGNERS_MAX_DEPTH],
        [0; SIGNERS_MAX_DEPTH],
        TEST_DEST_LABEL_BYTES,
        rule_selector,
        rule_value_max,
        rule_constraints,
        0,
        [0; SCOPE_MAX_DEPTH],
        [0; SCOPE_MAX_DEPTH],
        TEST_TXN_HASH,
        signers_root,
        dest_address_field,
        rule_selector,
        0,
        param_values,
        scope_root,
    );
}

#[test]
fn test_labeled_signer_with_wildcard_destination() {
    // -- Signer setup (single-leaf signers tree) --
    let signer_label_field = label_to_field(TEST_SIGNER_LABEL_BYTES);
    let signer_addr_field  = addr_to_f(TEST_SIGNER_ADDRESS_BYTES);
    let signers_root = label_leaf(signer_label_field, signer_addr_field);

    // -- Destination registered with a WILDCARD leaf: no restriction at all --
    let dest_label_field   = label_to_field(TEST_DEST_LABEL_BYTES);
    let dest_address_field = 0xdeadbeef00000000000000000000000000000002;
    let rule_constraints: [ParamConstraint; MAX_PARAMS] = [
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
    ];
    let params_hash = compute_params_hash(rule_constraints);
    let scope_root = compute_labeled_rule_leaf(
        dest_label_field,
        dest_address_field,
        WILDCARD_SELECTOR,
        TEST_WILDCARD_VALUE_MAX,
        params_hash,
    );

    // Any selector/value/calldata is accepted for a wildcard destination.
    let txn_selector: Field = 0x99999999;
    let txn_value:    Field = 42_000_000_000_000_000_000; // above any "normal" bound
    let param_values: [Field; MAX_PARAMS] = [1, 2, 3, 4];  // arbitrary, never checked

    main(
        TEST_PUBKEY,
        TEST_SIGNATURE,
        TEST_SIGNER_LABEL_BYTES,
        0,
        [0; SIGNERS_MAX_DEPTH],
        [0; SIGNERS_MAX_DEPTH],
        TEST_DEST_LABEL_BYTES,
        WILDCARD_SELECTOR,
        TEST_WILDCARD_VALUE_MAX,
        rule_constraints,
        0,
        [0; SCOPE_MAX_DEPTH],
        [0; SCOPE_MAX_DEPTH],
        TEST_TXN_HASH,
        signers_root,
        dest_address_field,
        txn_selector,
        txn_value,
        param_values,
        scope_root,
    );
}

#[test(should_fail_with = "Scope: rule not in scope tree")]
fn test_fails_claiming_wildcard_when_actually_restricted() {
    // A restrictive rule leaf is what's actually committed to scope_root...
    let dest_label_field   = label_to_field(TEST_DEST_LABEL_BYTES);
    let dest_address_field = 0xdeadbeef00000000000000000000000000000003;
    let real_rule_selector: Field = 0x12345678;
    let real_rule_value_max: Field = 1_000_000_000_000_000_000;
    let real_rule_constraints: [ParamConstraint; MAX_PARAMS] = [
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
    ];
    let real_params_hash = compute_params_hash(real_rule_constraints);
    let scope_root = compute_labeled_rule_leaf(
        dest_label_field,
        dest_address_field,
        real_rule_selector,
        real_rule_value_max,
        real_params_hash,
    );

    // ...but the prover tries to claim it is unrestricted (WILDCARD_SELECTOR).
    // The wildcard leaf's hash does not match what's in the tree, so this fails
    // the same way a missing rule would.
    let signer_label_field = label_to_field(TEST_SIGNER_LABEL_BYTES);
    let signer_addr_field  = addr_to_f(TEST_SIGNER_ADDRESS_BYTES);
    let signers_root = label_leaf(signer_label_field, signer_addr_field);

    main(
        TEST_PUBKEY,
        TEST_SIGNATURE,
        TEST_SIGNER_LABEL_BYTES,
        0,
        [0; SIGNERS_MAX_DEPTH],
        [0; SIGNERS_MAX_DEPTH],
        TEST_DEST_LABEL_BYTES,
        WILDCARD_SELECTOR,
        TEST_WILDCARD_VALUE_MAX,
        real_rule_constraints,
        0,
        [0; SCOPE_MAX_DEPTH],
        [0; SCOPE_MAX_DEPTH],
        TEST_TXN_HASH,
        signers_root,
        dest_address_field,
        0x99999999,
        0,
        [0, 0, 0, 0],
        scope_root,
    );
}
