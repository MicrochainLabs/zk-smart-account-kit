use poseidon::poseidon::bn254::hash_2 as poseidon2;
use poseidon::poseidon::bn254::hash_4 as poseidon4;
use binary_merkle_root::binary_merkle_root;

// --- Constants ----------------------------------------------------------------

/// Maximum Merkle tree depth for the scope rule registry (supports up to 2^6 = 64 rules).
pub global SCOPE_MAX_DEPTH: u32 = 6;

/// Maximum number of parameter constraints per scope rule.
/// Parameters beyond this count are treated as unconstrained.
pub global MAX_PARAMS: u32 = 4;

// --- Constraint types ---------------------------------------------------------

/// Constraint type: no restriction on the parameter value.
pub global PARAM_UNCONSTRAINED: u8 = 0;

/// Constraint type: parameter must equal exactly the committed value.
pub global PARAM_EXACT: u8 = 1;

/// Constraint type: parameter must be <= the committed value (u128 comparison).
/// Suitable for ETH amounts, token amounts, and timestamps.
pub global PARAM_RANGE_MAX: u8 = 2;

// --- Types --------------------------------------------------------------------

/// A single constraint on one decoded calldata parameter.
pub struct ParamConstraint {
    /// Constraint type: 0 = unconstrained, 1 = exact, 2 = range_max.
    pub constraint_type: u8,
    /// The reference value for the constraint (exact match target or range upper bound).
    pub value: Field,
}

// --- Hashing ------------------------------------------------------------------

/// Compute the Poseidon commitment to the full set of parameter constraints.
///
/// Layout (chained poseidon2 over all constraint fields):
///   c_i  = poseidon2([constraint_type_i as Field, value_i])
///   h_lo = poseidon2([c_0, c_1])
///   h_hi = poseidon2([c_2, c_3])
///   params_hash = poseidon2([h_lo, h_hi])
///
/// This must exactly match `computeParamsHash` in the TypeScript SDK.
pub fn compute_params_hash(constraints: [ParamConstraint; MAX_PARAMS]) -> Field {
    let c0 = poseidon2([constraints[0].constraint_type as Field, constraints[0].value]);
    let c1 = poseidon2([constraints[1].constraint_type as Field, constraints[1].value]);
    let c2 = poseidon2([constraints[2].constraint_type as Field, constraints[2].value]);
    let c3 = poseidon2([constraints[3].constraint_type as Field, constraints[3].value]);
    poseidon2([poseidon2([c0, c1]), poseidon2([c2, c3])])
}

/// Compute the Poseidon commitment to the decoded calldata parameter values.
///
/// Layout:
///   h_lo = poseidon2([p_0, p_1])
///   h_hi = poseidon2([p_2, p_3])
///   calldata_hash = poseidon2([h_lo, h_hi])
///
/// This must exactly match `computeCalldataHash` in the TypeScript SDK.
pub fn compute_calldata_hash(param_values: [Field; MAX_PARAMS]) -> Field {
    poseidon2([
        poseidon2([param_values[0], param_values[1]]),
        poseidon2([param_values[2], param_values[3]]),
    ])
}

/// Compute the Merkle leaf for a scope rule.
///
///   rule_leaf = poseidon4([target, selector, value_max, params_hash])
///
/// The leaf commits to the full rule specification without revealing it.
pub fn compute_rule_leaf(
    target:      Field,
    selector:    Field,
    value_max:   Field,
    params_hash: Field,
) -> Field {
    poseidon4([target, selector, value_max, params_hash])
}

// --- Constraint checking ------------------------------------------------------

/// Verify that a single decoded parameter satisfies its constraint.
///
/// - UNCONSTRAINED (0): always passes — no assertion emitted.
/// - EXACT (1): param_value == constraint.value.
/// - RANGE_MAX (2): param_value (as u128) <= constraint.value (as u128).
fn check_param_constraint(param_value: Field, constraint: ParamConstraint) {
    if constraint.constraint_type == PARAM_EXACT {
        assert(param_value == constraint.value, "Scope: param exact match failed");
    }
    if constraint.constraint_type == PARAM_RANGE_MAX {
        assert(
            param_value as u128 <= constraint.value as u128,
            "Scope: param range max exceeded",
        );
    }
}

// --- Membership verification --------------------------------------------------

/// Full scope membership verification.
///
/// Proves that the transaction (txn_target, txn_selector, txn_value, txn_calldata_hash)
/// satisfies at least one rule committed in the scope Merkle tree rooted at `scope_root`.
///
/// Asserts (in order):
///   1. The rule leaf belongs to the scope_root (Merkle membership).
///   2. rule.target   == txn_target
///   3. rule.selector == txn_selector
///   4. txn_value (u128) <= rule.value_max (u128)
///   5. For each param_i: param_values[i] satisfies rule_constraints[i].
///   6. Poseidon(param_values) == txn_calldata_hash (calldata commitment).
///
/// All rule fields and param_values are private inputs — the verifier only
/// learns that *some* rule in the committed scope was satisfied.
pub fn verify_scope_membership(
    // Public transaction details
    txn_target:        Field,
    txn_selector:      Field,
    txn_value:         Field,
    txn_calldata_hash: Field,
    // Private rule fields
    rule_target:       Field,
    rule_selector:     Field,
    rule_value_max:    Field,
    rule_constraints:  [ParamConstraint; MAX_PARAMS],
    // Private decoded calldata
    param_values:      [Field; MAX_PARAMS],
    // On-chain scope root and Merkle proof
    scope_root:        Field,
    proof_length:      u32,
    proof_indices:     [u1; SCOPE_MAX_DEPTH],
    proof_siblings:    [Field; SCOPE_MAX_DEPTH],
) {
    // 1. Rule Merkle membership
    let params_hash = compute_params_hash(rule_constraints);
    let rule_leaf   = compute_rule_leaf(rule_target, rule_selector, rule_value_max, params_hash);
    let computed_root = binary_merkle_root(
        poseidon2,
        rule_leaf,
        proof_length,
        proof_indices,
        proof_siblings,
    );
    assert(computed_root == scope_root, "Scope: rule not in scope tree");

    // 2. Target match
    assert(rule_target == txn_target, "Scope: target mismatch");

    // 3. Selector match
    assert(rule_selector == txn_selector, "Scope: selector mismatch");

    // 4. Value bound
    assert(
        txn_value as u128 <= rule_value_max as u128,
        "Scope: transaction value exceeds rule maximum",
    );

    // 5. Parameter constraints
    for i in 0..MAX_PARAMS {
        check_param_constraint(param_values[i], rule_constraints[i]);
    }

    // 6. Calldata commitment
    let computed_calldata_hash = compute_calldata_hash(param_values);
    assert(computed_calldata_hash == txn_calldata_hash, "Scope: calldata hash mismatch");
}
