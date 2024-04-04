// Merkle Tree gadgets following RFC-6962

use crate::native::get_split_point;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::BigUintTarget,
    hash::{sha256::CircuitBuilderHashSha2, CircuitBuilderHash, Hash256Target},
    u32::{
        arithmetic_u32::CircuitBuilderU32,
        binary_u32::{Bin32Target, CircuitBuilderBU32},
    },
};
use std::array::IntoIter;

pub struct Sha256_1Block {
    pub input: Vec<BoolTarget>,
    pub result: Vec<BoolTarget>,
}

pub struct Sha256_2Block {
    pub input: Vec<Vec<BoolTarget>>,
    pub result: Vec<BoolTarget>,
}

pub struct MerkleTree1BlockLeaf {
    pub leaves_padded: Vec<Vec<BoolTarget>>, // shaBlock(0x00 || leaf)
    pub root: Vec<BoolTarget>,
}

pub const SHA_BLOCK_BITS: usize = 512;

pub fn get_256_bool_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..256)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect::<Vec<BoolTarget>>()
}

pub fn get_512_bool_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..512)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect::<Vec<BoolTarget>>()
}

pub fn get_sha_block_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..SHA_BLOCK_BITS)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect::<Vec<BoolTarget>>()
}

pub fn get_sha_2_block_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..SHA_BLOCK_BITS * 2)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect::<Vec<BoolTarget>>()
}

pub fn get_sha_2block_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..SHA_BLOCK_BITS * 2)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect::<Vec<BoolTarget>>()
}

pub fn get_sha_512_2_block_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..SHA_BLOCK_BITS * 4)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect::<Vec<BoolTarget>>()
}

// toggle between bits order in HashInputTarget/Hash256Target and normal
pub fn get_formatted_hash_256_bools(input: &Vec<BoolTarget>) -> Vec<BoolTarget> {
    let mut output: Vec<BoolTarget> = Vec::with_capacity(input.len());
    input.chunks(32).for_each(|elm| {
        let mut bits_32 = elm.to_vec();
        bits_32.reverse();
        output.extend(bits_32);
    });
    output
}

// left - 256bits, where all bits are in the same order as in Hash256Target
// right - 256bits, where all bits are in the same order as in Hash256Target
// order of bits in Hash256Target:
//  * each u32 limb is in big endian
//  * all bits in any byte are stored in reversed order
// result - padded(0x01 || left || right)
pub fn two_to_one_pad_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: &Vec<BoolTarget>,
    right: &Vec<BoolTarget>,
) -> Vec<BoolTarget> {
    assert_eq!(left.len(), 256);
    assert_eq!(right.len(), 256);
    let result = get_sha_2block_target(builder);
    let one_bool_target = builder._true();
    let zero_bool_target = builder._false();

    // prefix '0x01'
    builder.connect(result[24].target, one_bool_target.target);
    (25..25 + 7).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
    });

    // append remaining `left`
    left.chunks(32).enumerate().for_each(|(i, items)| {
        items.iter().skip(8).enumerate().for_each(|(j, &elm)| {
            builder.connect(result[i * 32 + j].target, elm.target);
        });

        items.iter().take(8).enumerate().for_each(|(j, &elm)| {
            builder.connect(result[(i + 1) * 32 + 24 + j].target, elm.target);
        });
    });

    // append remaining `right`
    right.chunks(32).enumerate().for_each(|(i, items)| {
        items.iter().skip(8).enumerate().for_each(|(j, &elm)| {
            builder.connect(result[256 + i * 32 + j].target, elm.target);
        });

        items.iter().take(8).enumerate().for_each(|(j, &elm)| {
            builder.connect(result[256 + (i + 1) * 32 + 24 + j].target, elm.target);
        });
    });

    // append zeros
    (512..535).for_each(|i| builder.connect(result[i].target, zero_bool_target.target));

    // append 1 bit
    builder.connect(result[535].target, one_bool_target.target);

    (544..SHA_BLOCK_BITS * 2 - 64).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
    });

    // append big-endian u64 bit len
    // message len = 8 + 256 + 256 = 520 bits
    // bytearray = [0, 0, 0, 0, 0, 0, 2, 8]
    //
    // append [0, 0, 0, 0]
    (960..SHA_BLOCK_BITS * 2 - 32).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
    });

    let mut idx = 992;

    // append [8] - byte
    (idx..idx + 3).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
        idx += 1;
    });
    builder.connect(result[idx].target, one_bool_target.target);
    idx += 1;
    (idx..idx + 4).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
        idx += 1;
    });

    // append [2] - byte
    builder.connect(result[idx].target, zero_bool_target.target);
    idx += 1;
    builder.connect(result[idx].target, one_bool_target.target);
    idx += 1;
    (idx..idx + 6).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
        idx += 1;
    });

    // append [0, 0]
    (idx..SHA_BLOCK_BITS * 2).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
    });

    result
}

pub fn biguint_hash_to_bool_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &BigUintTarget,
) -> Vec<BoolTarget> {
    let mut hash_bool: Vec<BoolTarget> = Vec::with_capacity(256);
    input.limbs.iter().for_each(|&u32_elm| {
        let bin32_target = builder.convert_u32_bin32(u32_elm);
        hash_bool.extend(bin32_target.bits);
    });

    hash_bool
}

pub fn hash256_to_bool_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &Hash256Target,
) -> Vec<BoolTarget> {
    let mut hash_bool: Vec<BoolTarget> = Vec::with_capacity(256);
    input.iter().for_each(|&u32_elm| {
        let bin32_target = builder.convert_u32_bin32(u32_elm);
        hash_bool.extend(bin32_target.bits);
    });

    hash_bool
}

/// resulting bits are in Hash256Target order
pub fn sha256_n_block_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input_padded: &Vec<BoolTarget>,
    n_block: usize,
) -> Vec<BoolTarget> {
    assert_eq!(input_padded.len() / n_block, SHA_BLOCK_BITS);

    let hash_input_target = builder.add_virtual_hash_input_target(n_block, SHA_BLOCK_BITS);

    input_padded
        .chunks(32)
        .enumerate()
        .for_each(|(i, bits_32)| {
            let mut bits: Vec<BoolTarget> = vec![];
            bits_32.chunks(8).rev().for_each(|bits_8| {
                assert_eq!(bits_8.len(), 8);
                (0..8).for_each(|k| bits.push(bits_8[7 - k]));
            });
            let bin32 = Bin32Target { bits };
            let u32_target = builder.convert_bin32_u32(bin32);
            builder.connect_u32(hash_input_target.input.get_limb(i), u32_target);
        });

    let hash = builder.hash_sha256(&hash_input_target);

    biguint_hash_to_bool_targets(builder, &hash)
}

/// - left - 256bits, where all bits are in the same order as in Hash256Target
/// - right - 256bits, where all bits are in the same order as in Hash256Target
/// - order of bits in Hash256Target:
///     - each u32 limb is in big endian
///     - all bits in any byte are stored in reversed order
/// - resulting bits are in Hash256Target order
pub fn sha256_2_block_two_to_one_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: &Vec<BoolTarget>,
    right: &Vec<BoolTarget>,
) -> BigUintTarget {
    assert_eq!(left.len(), 256);
    assert_eq!(right.len(), 256);
    let input_padded = two_to_one_pad_target(builder, left, right);

    let hash_input_target = builder.add_virtual_hash_input_target(2, SHA_BLOCK_BITS);

    input_padded
        .chunks(32)
        .enumerate()
        .for_each(|(i, bits_32)| {
            let bin32 = Bin32Target {
                bits: bits_32.to_vec(),
            };
            let u32_target = builder.convert_bin32_u32(bin32);
            builder.connect_u32(hash_input_target.input.get_limb(i), u32_target);
        });

    let hash = builder.hash_sha256(&hash_input_target);
    hash
}

pub fn get_tree_root_from_sub_trees<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    sub_tree_roots: Vec<(usize, Vec<BoolTarget>)>,
) -> Vec<BoolTarget> {
    let mut tree_root = sub_tree_roots[0].1.clone();
    for i in 1..sub_tree_roots.len() {
        let hash = &sha256_2_block_two_to_one_hash_target(
            builder,
            &sub_tree_roots[i].1.clone(),
            &tree_root.clone(),
        );
        tree_root = biguint_hash_to_bool_targets(builder, hash);
    }
    tree_root
}

/// Example:<br>
/// - 150 leaves<br>
/// Sub trees -> 128+16+4+2<br>
/// - 149 leaves<br>
/// Sub trees -> 128+16+4+1<br>
pub fn get_sub_tree_roots<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    prev_sub_tree_roots: Vec<(usize, Vec<BoolTarget>)>,
    new_elm: Vec<BoolTarget>,
) -> Vec<(usize, Vec<BoolTarget>)> {
    let mut sub_tree_roots: Vec<(usize, Vec<BoolTarget>)> = vec![];
    let mut cur_size: usize = 1;
    let mut tree_root: Vec<BoolTarget> = new_elm;
    let mut last_index: usize = prev_sub_tree_roots.len();

    for i in 0..prev_sub_tree_roots.len() {
        if cur_size == prev_sub_tree_roots[i].0 {
            let hash = &sha256_2_block_two_to_one_hash_target(
                builder,
                &prev_sub_tree_roots[i].1.clone(),
                &tree_root.clone(),
            );
            tree_root = biguint_hash_to_bool_targets(builder, hash);
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
    sub_tree_roots
}

/// return array of validators hash for the range [min_n_validators, max_n_validators] using minimal number of hashes
pub fn get_validators_hash_range<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    max_validators_leaves_padded: &Vec<Vec<BoolTarget>>,
    min_n_validators: usize,
    max_n_validators: usize,
) -> Vec<Vec<BoolTarget>> {
    assert!(min_n_validators <= max_n_validators);
    assert!(max_validators_leaves_padded.len() == max_n_validators);

    let leaves_hashes = max_validators_leaves_padded
        .iter()
        .map(|elm| sha256_n_block_hash_target(builder, &elm, 1))
        .collect::<Vec<Vec<BoolTarget>>>();
    let mut prev_sub_tree_roots: Vec<(usize, Vec<BoolTarget>)> = vec![];

    let mut right_leaves_hashes = leaves_hashes[..min_n_validators].to_vec();

    while right_leaves_hashes.len() != 0 {
        let split_point = get_split_point(right_leaves_hashes.len() as f32) as usize;
        let root_hash =
            merkle_1_block_leaf_root(builder, &right_leaves_hashes[..split_point].to_vec());
        prev_sub_tree_roots.push((split_point, root_hash));
        right_leaves_hashes = right_leaves_hashes[split_point..].to_vec();
    }
    prev_sub_tree_roots.reverse(); // putting rightmost subtree first

    let mut validators_hash_range = Vec::with_capacity(max_n_validators - min_n_validators + 1);
    let mut tree_root = get_tree_root_from_sub_trees(builder, prev_sub_tree_roots.clone());
    validators_hash_range.push(tree_root);

    for n_validators in min_n_validators..max_n_validators {
        let sub_tree_roots = get_sub_tree_roots(
            builder,
            prev_sub_tree_roots.clone(),
            leaves_hashes[n_validators].clone(),
        );
        tree_root = get_tree_root_from_sub_trees(builder, sub_tree_roots.clone());
        validators_hash_range.push(tree_root);
        prev_sub_tree_roots = sub_tree_roots;
    }

    validators_hash_range
}

pub fn merkle_1_block_leaf_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaves_hashes: &Vec<Vec<BoolTarget>>,
) -> Vec<BoolTarget> {
    let mut items = leaves_hashes.clone();
    let mut size = items.len();

    while size != 1 {
        let mut rp = 0; // read position
        let mut wp = 0; // write position
        while rp < size {
            if rp + 1 < size {
                let hash = &sha256_2_block_two_to_one_hash_target(
                    builder,
                    &items[rp].clone(),
                    &items[rp + 1].clone(),
                );
                items[wp] = biguint_hash_to_bool_targets(builder, hash);
                rp += 2;
            } else {
                items[wp] = items[rp].clone();
                rp += 1;
            }
            wp += 1;
        }
        size = wp;
    }

    items[0].clone()
}

pub fn header_merkle_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaves_padded: IntoIter<Vec<BoolTarget>, 14>,
) -> Vec<BoolTarget> {
    let mut items = leaves_padded
        .enumerate()
        .map(|(i, elm)| {
            if i != 4 {
                return sha256_n_block_hash_target(builder, &elm, 1);
            } else {
                return sha256_n_block_hash_target(builder, &elm, 2);
            }
        })
        .collect::<Vec<Vec<BoolTarget>>>();
    let mut size = items.len();

    while size != 1 {
        let mut rp = 0; // read position
        let mut wp = 0; // write position
        while rp < size {
            if rp + 1 < size {
                let hash = &sha256_2_block_two_to_one_hash_target(
                    builder,
                    &items[rp].clone(),
                    &items[rp + 1].clone(),
                );
                items[wp] = biguint_hash_to_bool_targets(builder, hash);
                rp += 2;
            } else {
                items[wp] = items[rp].clone();
                rp += 1;
            }
            wp += 1;
        }
        size = wp;
    }

    items[0].clone()
}

pub fn verify_next_validators_hash_merkle_proof<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf_padded: &Vec<BoolTarget>,
    proof: &Vec<Vec<BoolTarget>>,
    root: &Hash256Target,
) {
    let mut hash = sha256_n_block_hash_target(builder, &leaf_padded, 1);

    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &hash,
        &get_formatted_hash_256_bools(&proof[0]),
    );
    hash = biguint_hash_to_bool_targets(builder, &hash_biguint);
    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &hash,
        &get_formatted_hash_256_bools(&proof[1]),
    );
    hash = biguint_hash_to_bool_targets(builder, &hash_biguint);
    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &hash,
        &get_formatted_hash_256_bools(&proof[2]),
    );
    hash = biguint_hash_to_bool_targets(builder, &hash_biguint);
    let computed_root = sha256_2_block_two_to_one_hash_target(
        builder,
        &get_formatted_hash_256_bools(&proof[3]),
        &hash,
    );

    (0..computed_root.num_limbs())
        .for_each(|i| builder.connect_u32(computed_root.get_limb(i), root[i]));
}

#[cfg(test)]
mod tests {
    use super::{
        biguint_hash_to_bool_targets, get_256_bool_target, sha256_2_block_two_to_one_hash_target,
        sha256_n_block_hash_target, two_to_one_pad_target, BoolTarget, SHA_BLOCK_BITS,
    };
    use crate::native::bytes_to_bool;
    use crate::tests::test_utils::*;
    use plonky2::{
        iop::{witness::PartialWitness, witness::WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::{
        hash::{
            sha256::WitnessHashSha2,
            {CircuitBuilderHash, WitnessHash},
        },
        u32::binary_u32::CircuitBuilderBU32,
    };
    use tracing::info;
    use tracing_test::traced_test;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    pub fn prove_and_verify(data: CircuitData<F, C, D>, witness: PartialWitness<F>) {
        let start_time = std::time::Instant::now();
        let proof = data.prove(witness).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        info!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }
    #[traced_test]
    #[test]
    fn test_two_to_one_pad_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let left = [
            118, 110, 67, 134, 204, 97, 211, 117, 174, 233, 216, 70, 45, 239, 157, 3, 26, 3, 96, 3,
            69, 64, 208, 252, 33, 94, 182, 37, 54, 252, 129, 141,
        ];
        let right = [
            10, 34, 10, 32, 232, 220, 244, 245, 129, 135, 207, 5, 177, 141, 204, 198, 208, 136, 74,
            224, 139, 244, 169, 141, 136, 113, 125, 15, 255, 146, 162, 182,
        ];

        let left_hash_target = builder.add_virtual_hash256_target();
        let right_hash_target = builder.add_virtual_hash256_target();
        witness.set_hash256_target(&left_hash_target, &left);
        witness.set_hash256_target(&right_hash_target, &right);

        let left_hash_bool_target = get_256_bool_target(&mut builder);
        let right_hash_bool_target = get_256_bool_target(&mut builder);

        left_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bin32_target = builder.convert_u32_bin32(u32_elm);
                (0..32).for_each(|j| {
                    builder.connect(
                        left_hash_bool_target[i * 32 + j].target,
                        bin32_target.bits[j].target,
                    )
                });
            });
        right_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bin32_target = builder.convert_u32_bin32(u32_elm);
                (0..32).for_each(|j| {
                    builder.connect(
                        right_hash_bool_target[i * 32 + j].target,
                        bin32_target.bits[j].target,
                    )
                });
            });

        let mut input = [1].to_vec();
        input.extend(left);
        input.extend(right);
        let hash_input_target = builder.add_virtual_hash_input_target(2, SHA_BLOCK_BITS);
        witness.set_sha256_input_target(&hash_input_target, &input);

        let computed = two_to_one_pad_target(
            &mut builder,
            &left_hash_bool_target,
            &right_hash_bool_target,
        );

        hash_input_target
            .input
            .limbs
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bits = builder.convert_u32_bin32(u32_elm).bits;
                (0..32).for_each(|j| builder.connect(computed[i * 32 + j].target, bits[j].target));
            });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_sha256_1_block_hash_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let input_bytes = [
            10, 34, 10, 32, 232, 220, 244, 245, 129, 135, 207, 5, 177, 141, 204, 198, 208, 136, 74,
            224, 139, 244, 169, 141, 136, 113, 125, 15, 255, 146, 162, 182, 244, 87, 77, 71, 16,
            151, 152, 176, 10,
        ];
        let input_padded = get_n_sha_blocks_for_leaf(bytes_to_bool(input_bytes.to_vec()), 1); // prefixes with a 0 byte

        let expected_hash = [
            118, 110, 67, 134, 204, 97, 211, 117, 174, 233, 216, 70, 45, 239, 157, 3, 26, 3, 96, 3,
            69, 64, 208, 252, 33, 94, 182, 37, 54, 252, 129, 141,
        ];
        let expected_hash_target = builder.add_virtual_hash256_target();
        witness.set_hash256_target(&expected_hash_target, &expected_hash);

        let bool_target = (0..input_padded.len())
            .map(|_| builder.add_virtual_bool_target_unsafe())
            .collect::<Vec<BoolTarget>>();
        (0..input_padded.len())
            .for_each(|i| witness.set_bool_target(bool_target[i], input_padded[i]));

        let computed = sha256_n_block_hash_target(&mut builder, &bool_target, 1);

        expected_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bin32_target = builder.convert_u32_bin32(u32_elm);
                (0..32).for_each(|j| {
                    builder.connect(computed[i * 32 + j].target, bin32_target.bits[j].target)
                });
            });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_sha256_2_block_two_to_one_hash_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let left = [
            118, 110, 67, 134, 204, 97, 211, 117, 174, 233, 216, 70, 45, 239, 157, 3, 26, 3, 96, 3,
            69, 64, 208, 252, 33, 94, 182, 37, 54, 252, 129, 141,
        ];
        let right = [
            82, 251, 173, 136, 116, 129, 108, 57, 48, 31, 45, 44, 237, 140, 190, 115, 78, 147, 125,
            31, 107, 167, 107, 96, 3, 186, 65, 10, 253, 13, 18, 33,
        ];

        let left_hash_target = builder.add_virtual_hash256_target();
        let right_hash_target = builder.add_virtual_hash256_target();
        witness.set_hash256_target(&left_hash_target, &left);
        witness.set_hash256_target(&right_hash_target, &right);

        let left_hash_bool_target = get_256_bool_target(&mut builder);
        let right_hash_bool_target = get_256_bool_target(&mut builder);

        left_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bin32_target = builder.convert_u32_bin32(u32_elm);
                (0..32).for_each(|j| {
                    builder.connect(
                        left_hash_bool_target[i * 32 + j].target,
                        bin32_target.bits[j].target,
                    )
                });
            });
        right_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bin32_target = builder.convert_u32_bin32(u32_elm);
                (0..32).for_each(|j| {
                    builder.connect(
                        right_hash_bool_target[i * 32 + j].target,
                        bin32_target.bits[j].target,
                    )
                });
            });

        let expected_hash = [
            225, 126, 120, 210, 162, 135, 97, 200, 152, 47, 214, 52, 215, 155, 240, 166, 112, 135,
            22, 217, 163, 159, 187, 30, 44, 99, 157, 30, 203, 243, 12, 208,
        ];
        let expected_hash_target = builder.add_virtual_hash256_target();
        witness.set_hash256_target(&expected_hash_target, &expected_hash);

        let hash_biguint = sha256_2_block_two_to_one_hash_target(
            &mut builder,
            &left_hash_bool_target,
            &right_hash_bool_target,
        );
        let computed = biguint_hash_to_bool_targets(&mut builder, &hash_biguint);

        expected_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bits = builder.convert_u32_bin32(u32_elm).bits;
                (0..32).for_each(|j| builder.connect(computed[i * 32 + j].target, bits[j].target));
            });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
