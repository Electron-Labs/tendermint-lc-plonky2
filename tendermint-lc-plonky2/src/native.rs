use sha2::Digest;

pub fn sha256_native(input: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    hash_bytes.to_vec()
}

pub fn leaf_hash_native(input: Vec<u8>) -> Vec<u8> {
    let mut padded = (0..input.len() + 1).map(|_| 0u8).collect::<Vec<u8>>();
    (0..input.len()).for_each(|i| padded[1 + i] = input[i]);
    sha256_native(&padded)
}

pub fn inner_hash_native(leaf1: Vec<u8>, leaf2: Vec<u8>) -> Vec<u8> {
    let mut padded = (0..leaf1.len() + leaf2.len() + 1)
        .map(|_| 1u8)
        .collect::<Vec<u8>>();
    (0..leaf1.len()).for_each(|i| padded[1 + i] = leaf1[i]);
    (0..leaf2.len()).for_each(|i| padded[1 + leaf1.len() + i] = leaf2[i]);
    sha256_native(&padded)
}

pub fn get_validators_hash_native(leaves_hash: &Vec<Vec<u8>>) -> (Vec<u8>, usize) {
    let mut items = leaves_hash.clone();
    let mut size = items.len();
    let mut n_hashes = 0;

    while size != 1 {
        let mut rp = 0;
        let mut wp = 0;
        while rp < size {
            if rp + 1 < size {
                items[wp] = inner_hash_native(items[rp].clone(), items[rp + 1].clone());
                n_hashes += 1;
                rp += 2;
            } else {
                items[wp] = items[rp].clone();
                rp += 1;
            }
            wp += 1;
        }
        size = wp;
    }

    (items[0].clone(), n_hashes)
}

// getSplitPoint returns the largest power of 2 less than n_leaves
pub fn get_split_point(n_leaves: f32) -> u32 {
    n_leaves.log2().floor().exp2() as u32
}

pub fn get_tree_root_from_sub_trees(sub_tree_roots: Vec<(usize, Vec<u8>)>) -> (Vec<u8>, usize) {
    let mut n_hashes = 0;
    let mut tree_root = sub_tree_roots[0].1.clone();
    for i in 1..sub_tree_roots.len() {
        tree_root = inner_hash_native(sub_tree_roots[i].1.clone(), tree_root);
        n_hashes += 1;
    }
    (tree_root, n_hashes)
}

pub fn get_sub_tree_roots(
    prev_sub_tree_roots: Vec<(usize, Vec<u8>)>,
    new_elm: Vec<u8>,
) -> (Vec<(usize, Vec<u8>)>, usize) {
    let mut sub_tree_roots: Vec<(usize, Vec<u8>)> = vec![];
    let mut cur_size: usize = 1;
    let mut tree_root: Vec<u8> = new_elm;
    let mut last_index: usize = prev_sub_tree_roots.len();
    let mut n_hashes = 0;

    for i in 0..prev_sub_tree_roots.len() {
        if cur_size == prev_sub_tree_roots[i].0 {
            tree_root = inner_hash_native(prev_sub_tree_roots[i].1.clone(), tree_root);
            n_hashes += 1;
            cur_size += prev_sub_tree_roots[i].0;
        } else {
            last_index = i;
            break;
        }
    }

    sub_tree_roots.push((cur_size, tree_root.clone()));

    for j in last_index..prev_sub_tree_roots.len() {
        sub_tree_roots.push(prev_sub_tree_roots[j].clone());
    }
    (sub_tree_roots, n_hashes)
}

pub fn get_validators_hash_range_native(
    leaves: &Vec<Vec<u8>>,
    min_n_validators: usize,
    max_n_validators: usize,
) -> Vec<Vec<u8>> {
    assert!(min_n_validators <= max_n_validators);
    assert!(leaves.len() == max_n_validators);

    let leaves_hash = leaves
        .iter()
        .map(|elm| leaf_hash_native(elm.clone()))
        .collect::<Vec<Vec<u8>>>();
    let mut prev_sub_tree_roots: Vec<(usize, Vec<u8>)> = vec![];
    let mut n_hashes = leaves_hash.len();

    let mut right_leaves_hash = leaves_hash[..min_n_validators].to_vec();

    while right_leaves_hash.len() != 0 {
        let split_point = get_split_point(right_leaves_hash.len() as f32) as usize;
        let (root_hash, _n) =
            get_validators_hash_native(&right_leaves_hash[..split_point].to_vec());
        n_hashes += _n;
        prev_sub_tree_roots.push((split_point, root_hash));
        right_leaves_hash = right_leaves_hash[split_point..].to_vec();
    }
    prev_sub_tree_roots.reverse();

    let mut validators_hash_range = Vec::with_capacity(max_n_validators - min_n_validators + 1);
    let (mut tree_root, _n) = get_tree_root_from_sub_trees(prev_sub_tree_roots.clone());
    n_hashes += _n;
    println!(
        "n_validators={:?}, n_hashes={:?}",
        min_n_validators, n_hashes
    );
    validators_hash_range.push(tree_root);

    for n_validators in min_n_validators..max_n_validators {
        let (sub_tree_roots, _n1) = get_sub_tree_roots(
            prev_sub_tree_roots.clone(),
            leaves_hash[n_validators].clone(),
        );
        let _n2;
        (tree_root, _n2) = get_tree_root_from_sub_trees(sub_tree_roots.clone());
        validators_hash_range.push(tree_root);
        prev_sub_tree_roots = sub_tree_roots;
        println!(
            "n_validators={:?}, n_hashes={:?}",
            n_validators + 1,
            _n1 + _n2
        );
        n_hashes += _n1 + _n2;
    }

    println!("Total hashes={:?}", n_hashes);

    validators_hash_range
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::test_utils::get_test_inputs_native_data;

    #[test]
    fn test_validators_hash() {
        let t = get_test_inputs_native_data();
        let leaves_hash = t
            .validators
            .iter()
            .map(|elm| leaf_hash_native(elm.clone()))
            .collect::<Vec<Vec<u8>>>();
        let (computed, _) = get_validators_hash_native(&leaves_hash);
        assert!(computed == t.validators_hash);
    }

    #[test]
    fn test_get_validators_hash_range_native() {
        let t = get_test_inputs_native_data();
        let z = 20;
        let max_n_validators = t.validators.len();
        let min_n_validators = t.validators.len() - z;

        let validators = t.validators.clone();

        let validators_hash_range =
            get_validators_hash_range_native(&validators, min_n_validators, max_n_validators);
        assert!(validators_hash_range[z] == t.validators_hash);
    }
}
