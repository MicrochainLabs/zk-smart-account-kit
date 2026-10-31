use poseidon::poseidon::bn254::hash_2 as poseidon2;
use trees::merkle::MerkleTree;
use trees::types::{Calculator, MT_Creator};

/// Compute a Poseidon2 Merkle root from a leaf with a variable proof depth, using the
/// zk-kit `MerkleTree` implementation one level at a time.
/// Levels at or above `depth` are skipped, so `depth = 0` returns the leaf itself.
///
///   indices[i]  - true if the node at level i is the right child
///   siblings[i] - sibling hash at level i
pub fn merkle_root_with_depth<let N: u32>(
    leaf: Field,
    depth: u32,
    indices: [bool; N],
    siblings: [Field; N],
) -> Field {
    let tree: MerkleTree<Field> = MerkleTree::new(poseidon2);
    let mut node = leaf;
    for i in 0..N {
        if i < depth {
            node = tree.calculate_root(node, indices[i] as Field, [siblings[i]]);
        }
    }
    node
}

#[test]
fn test_depth_zero_returns_leaf() {
    assert(merkle_root_with_depth(7, 0, [true, true], [1, 2]) == 7);
}

#[test]
fn test_index_selects_child_side_and_depth_skips_levels() {
    let (leaf, s0, s1) = (11, 22, 33);
    let n0_left = poseidon2([leaf, s0]);
    let n0_right = poseidon2([s0, leaf]);

    assert(merkle_root_with_depth(leaf, 1, [false, true], [s0, s1]) == n0_left);
    assert(merkle_root_with_depth(leaf, 1, [true, true], [s0, s1]) == n0_right);
    assert(merkle_root_with_depth(leaf, 2, [false, true], [s0, s1]) == poseidon2([s1, n0_left]));
}
