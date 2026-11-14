use poseidon::poseidon::bn254::hash_2 as poseidon2;
use poseidon::poseidon::bn254::hash_4 as poseidon4;
use merkle_tree::merkle_root_with_depth;

// --- Constants ----------------------------------------------------------------

/// Maximum Merkle tree depth for the scope rule registry (supports up to 2^6 = 64 rules).
pub global SCOPE_MAX_DEPTH: u32 = 6;

/// Maximum number of parameter constraints per scope rule.
/// Parameters beyond this count are treated as unconstrained.
pub global MAX_PARAMS: u32 = 4;

/// Sentinel `selector` value meaning "no function-selector restriction" (a
/// wildcard / fully-unrestricted entry). Chosen outside the 32-bit range of
/// real 4-byte function selectors (0x00000000..=0xFFFFFFFF) so it can never
/// collide with a genuine selector - the same pattern as `PARAM_UNCONSTRAINED`
/// below, applied to the rule's selector field instead of a param.
pub global WILDCARD_SELECTOR: Field = 0x100000000;

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

/// Compute the Merkle leaf for a LABELED scope rule - a rule entry that also
/// carries a private label (contact/protocol name), used by the unified scope
/// tree (see `verify_labeled_scope_membership` below).
///
///   identity          = poseidon2([label, target])
///   labeled_rule_leaf = poseidon4([identity, selector, value_max, params_hash])
///
/// `identity` groups the label together with the target FIRST - the label
/// identifies WHICH destination this is (the same way `label_leaf` in
/// zk_labels binds a label to an address), and the rule fields are then
/// layered on top of that identity, exactly mirroring `compute_rule_leaf`
/// above (which is `poseidon4([target, selector, value_max, params_hash])`)
/// but with `identity` standing in for the raw `target`. A destination with
/// multiple rules (e.g. Uniswap's several permitted selectors) has multiple
/// leaves that all share the same `identity` - the label is bound to the
/// destination, not to any one specific rule.
/// The label is never revealed on-chain - only used, alongside every other
/// field, to compute this leaf.
pub fn compute_labeled_rule_leaf(
    label:       Field,
    target:      Field,
    selector:    Field,
    value_max:   Field,
    params_hash: Field,
) -> Field {
    let identity = poseidon2([label, target]);
    poseidon4([identity, selector, value_max, params_hash])
}

// --- Constraint checking ------------------------------------------------------

/// Verify that a single decoded parameter satisfies its constraint.
///
/// - UNCONSTRAINED (0): always passes - no assertion emitted.
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
/// All rule fields and param_values are private inputs - the verifier only
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
    proof_indices:     [bool; SCOPE_MAX_DEPTH],
    proof_siblings:    [Field; SCOPE_MAX_DEPTH],
) {
    // 1. Rule Merkle membership
    let params_hash = compute_params_hash(rule_constraints);
    let rule_leaf   = compute_rule_leaf(rule_target, rule_selector, rule_value_max, params_hash);
    let computed_root = merkle_root_with_depth(
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

// --- Unified (labeled) scope membership ----------------------------------------
//
// `verify_scope_membership` above always enforces the selector/value/param
// checks - it can only express "this transaction matches this specific rule."
// It cannot express "this destination is a known contact/protocol with NO
// restriction at all" without a second, separately-maintained tree (the
// non-membership / Indexed Merkle Tree approach this library used to have).
//
// `verify_labeled_scope_membership` folds BOTH destination registration
// (formerly a separate label tree - contacts/protocols) and scope rules into
// ONE tree. A leaf commits (label, target, selector, value_max, params_hash);
// a destination that should remain unrestricted simply gets a leaf with
// `selector = WILDCARD_SELECTOR` (any value_max/constraints are then ignored -
// convention: value_max = max u128, constraints = all PARAM_UNCONSTRAINED).
// A restrictive rule uses a real selector, and the selector/value/param/
// calldata checks are enforced exactly as in `verify_scope_membership`.
//
// Because "is this destination restricted" is now read directly off the
// MATCHED leaf (part of what's committed in scope_root) rather than a
// free-standing prover-supplied witness, there is nothing left to keep in
// sync across trees: one tree, one root, no drift.

/// Full unified scope membership verification (label + rule in one tree).
///
/// Asserts (in order):
///   1. The labeled rule leaf belongs to scope_root (Merkle membership).
///   2. rule.target == txn_target.
///   3. If rule.selector != WILDCARD_SELECTOR (a real, restrictive rule):
///        a. rule.selector == txn_selector
///        b. txn_value (u128) <= rule.value_max (u128)
///        c. each param_values[i] satisfies rule_constraints[i]
///      Otherwise (a wildcard/unrestricted entry) none of these are enforced -
///      the transaction may use any selector, value, or calldata.
///
/// `param_values` are PUBLIC in the labeled-scope circuit (see
/// `zk_labeled_signer_scope/main.nr`) rather than hashed into a separate
/// `txn_calldata_hash` commitment - the validator contract extracts them
/// directly from the real on-chain calldata (fixed-offset slots, static
/// types only), so there is nothing left to bind via a hash: a mismatched
/// param value simply isn't the value that was actually used on-chain.
///
/// `rule_label` is a private witness only used inside the leaf hash - it is
/// never compared against anything else, it just needs to match whatever
/// label the destination was originally registered under.
pub fn verify_labeled_scope_membership(
    // Public transaction details
    txn_target:        Field,
    txn_selector:      Field,
    txn_value:         Field,
    // Private rule fields
    rule_label:        Field,
    rule_target:       Field,
    rule_selector:     Field,
    rule_value_max:    Field,
    rule_constraints:  [ParamConstraint; MAX_PARAMS],
    // Decoded calldata parameters - public, see doc comment above.
    param_values:      [Field; MAX_PARAMS],
    // On-chain scope root and Merkle proof
    scope_root:        Field,
    proof_length:      u32,
    proof_indices:     [bool; SCOPE_MAX_DEPTH],
    proof_siblings:    [Field; SCOPE_MAX_DEPTH],
) {
    // 1. Labeled rule Merkle membership
    let params_hash = compute_params_hash(rule_constraints);
    let rule_leaf   = compute_labeled_rule_leaf(rule_label, rule_target, rule_selector, rule_value_max, params_hash);
    let computed_root = merkle_root_with_depth(
        rule_leaf,
        proof_length,
        proof_indices,
        proof_siblings,
    );
    assert(computed_root == scope_root, "Scope: rule not in scope tree");

    // 2. Target match - always enforced, wildcard or not.
    assert(rule_target == txn_target, "Scope: target mismatch");

    // 3. Restrictive-rule checks, skipped entirely for a wildcard entry.
    if rule_selector != WILDCARD_SELECTOR {
        assert(rule_selector == txn_selector, "Scope: selector mismatch");

        assert(
            txn_value as u128 <= rule_value_max as u128,
            "Scope: transaction value exceeds rule maximum",
        );

        for i in 0..MAX_PARAMS {
            check_param_constraint(param_values[i], rule_constraints[i]);
        }
    }
}
