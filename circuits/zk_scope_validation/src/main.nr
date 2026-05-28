use zk_scope::{
    verify_scope_membership,
    compute_params_hash,
    compute_rule_leaf,
    compute_calldata_hash,
    SCOPE_MAX_DEPTH,
    MAX_PARAMS,
    ParamConstraint,
    PARAM_UNCONSTRAINED,
    PARAM_EXACT,
    PARAM_RANGE_MAX,
};

/// Proves that a transaction (txn_target, txn_selector, txn_value, txn_calldata_hash)
/// satisfies at least one rule in the private scope policy committed on-chain as scope_root.
///
/// Public inputs (in order — match the TypeScript SDK and ERC-8039 adapter):
///   [0] txn_target        — target contract address as a BN254 field element
///   [1] txn_selector      — 4-byte function selector right-padded to 32 bytes
///   [2] txn_value         — ETH value in wei as a field element
///   [3] txn_calldata_hash — Poseidon commitment to decoded calldata parameters
///   [4] scope_root        — on-chain Merkle root of the scope rule registry
///
/// Private inputs:
///   rule_*      — the matching scope rule (target, selector, value_max, constraints)
///   param_values — decoded calldata parameters (zero-padded to MAX_PARAMS)
///   proof_*     — Merkle membership proof for the rule
fn main(
    // ── Private: matching rule ──────────────────────────────────────────────
    rule_target:      Field,
    rule_selector:    Field,
    rule_value_max:   Field,
    rule_constraints: [ParamConstraint; MAX_PARAMS],

    // ── Private: decoded calldata ───────────────────────────────────────────
    param_values: [Field; MAX_PARAMS],

    // ── Private: Merkle proof for the rule ──────────────────────────────────
    proof_length:   u32,
    proof_indices:  [u1; SCOPE_MAX_DEPTH],
    proof_siblings: [Field; SCOPE_MAX_DEPTH],

    // ── Public: transaction details ─────────────────────────────────────────
    txn_target:        pub Field,
    txn_selector:      pub Field,
    txn_value:         pub Field,
    txn_calldata_hash: pub Field,

    // ── Public: on-chain commitment ─────────────────────────────────────────
    scope_root: pub Field,
) {
    verify_scope_membership(
        txn_target,
        txn_selector,
        txn_value,
        txn_calldata_hash,
        rule_target,
        rule_selector,
        rule_value_max,
        rule_constraints,
        param_values,
        scope_root,
        proof_length,
        proof_indices,
        proof_siblings,
    );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn test_single_rule_exact_params() {
    // Rule: allow call to 0xUniswapRouter.swap() with exact tokenIn = USDC
    // We use small dummy addresses and values for simplicity.

    // target = address(0xDEAD) as Field
    let target_field: Field = 0xDEAD;
    // selector = bytes4(0xd0e30db0) — Uniswap deposit() as a dummy
    let selector_field: Field = 0xd0e30db0;
    // value_max = 1 ETH in wei
    let value_max: Field = 1_000_000_000_000_000_000;

    // Param 0: exact match — tokenIn == 0xUSDC (dummy)
    // Params 1-3: unconstrained
    let constraints: [ParamConstraint; MAX_PARAMS] = [
        ParamConstraint { constraint_type: PARAM_EXACT,         value: 0xA0b8 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
    ];

    let param_values: [Field; MAX_PARAMS] = [0xA0b8, 500, 0, 0];

    // Compute what the circuit will derive
    let params_hash   = compute_params_hash(constraints);
    let rule_leaf     = compute_rule_leaf(target_field, selector_field, value_max, params_hash);
    let calldata_hash = compute_calldata_hash(param_values);

    // Single-rule registry: proof_length = 0 => binary_merkle_root returns leaf itself
    let scope_root = rule_leaf;

    main(
        target_field,
        selector_field,
        value_max,
        constraints,
        param_values,
        0,
        [0; SCOPE_MAX_DEPTH],
        [0; SCOPE_MAX_DEPTH],
        target_field,
        selector_field,
        500, // txn_value (< value_max)
        calldata_hash,
        scope_root,
    )
}

#[test]
fn test_single_rule_range_param() {
    let target_field:  Field = 0xCAFE;
    let selector_field: Field = 0x12345678;
    let value_max: Field = 0; // no ETH transfer

    // Param 0: range max — amount <= 100_000
    let constraints: [ParamConstraint; MAX_PARAMS] = [
        ParamConstraint { constraint_type: PARAM_RANGE_MAX,     value: 100_000 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
        ParamConstraint { constraint_type: PARAM_UNCONSTRAINED, value: 0 },
    ];

    let param_values: [Field; MAX_PARAMS] = [50_000, 0, 0, 0];

    let params_hash   = compute_params_hash(constraints);
    let rule_leaf     = compute_rule_leaf(target_field, selector_field, value_max, params_hash);
    let calldata_hash = compute_calldata_hash(param_values);
    let scope_root    = rule_leaf;

    main(
        target_field,
        selector_field,
        value_max,
        constraints,
        param_values,
        0,
        [0; SCOPE_MAX_DEPTH],
        [0; SCOPE_MAX_DEPTH],
        target_field,
        selector_field,
        0,
        calldata_hash,
        scope_root,
    )
}
