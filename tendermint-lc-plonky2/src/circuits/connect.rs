use core::hash;

use bitvec::index;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{biguint::{BigUintTarget, CircuitBuilderBiguint}, hash::{sha256::CircuitBuilderHashSha2, CircuitBuilderHash}, u32::arithmetic_u32::CircuitBuilderU32};

use crate::config_data::*;
use super::merkle_targets::sha256_n_block_hash_target;

pub fn connect_timestamp<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    header_time_padded: &Vec<BoolTarget>,
    header_timestamp: &BigUintTarget,
    c: &Config,
) {
    let mut header_timestamp_bits = builder.split_le_base::<2>(header_timestamp.get_limb(0).0, 32);
    let next_bits = builder.split_le_base::<2>(header_timestamp.get_limb(1).0, 32);
    (0..32).for_each(|i| header_timestamp_bits.push(next_bits[i]));

    // 7 bits from each of 5 consecutive bytes in `header_time_padded` starting from the 3rd byte makes up the `header_timestamp_bits`
    // `header_time_padded` contains timestamp in LEB128 format
    let offset = 16;
    (0..c.TIMESTAMP_BITS.div_ceil(c.LEB128_GROUP_SIZE)).for_each(|j| {
        (0..7).for_each(|k| {
            builder.connect(
                header_time_padded[offset + j * 8 + k + 1].target,
                header_timestamp_bits[j * 7 + 7 - 1 - k],
            );
        })
    });
}

pub fn connect_pub_keys_and_vps<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pub_keys: &Vec<Vec<BoolTarget>>,
    validators_padded: &Vec<Vec<BoolTarget>>,
    vps: &Vec<BigUintTarget>,
    c: &Config,
) {
    let _vps = (0..c.N_VALIDATORS)
        .map(|_| {
            builder.add_virtual_biguint_target(
                (c.VP_BITS.div_ceil(c.LEB128_GROUP_SIZE) * 8).div_ceil(32),
            )
        })
        .collect::<Vec<BigUintTarget>>();

    (0..c.N_VALIDATORS).for_each(|i| builder.connect_biguint(&_vps[i], &vps[i]));

    // 7 bits from each of 10 consecutive bytes in `validators_padded[i]` starting from the 39th byte makes up the `vp_bits`
    // `validators_padded[i]` contains voting power in LEB128 format
    (0..c.N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(validators_padded[i][40 + j].target, pub_keys[i][j].target)
        });
        let mut vp_bits = builder.split_le_base::<2>(_vps[i].get_limb(0).0, 32);
        let mut next_bits = builder.split_le_base::<2>(_vps[i].get_limb(1).0, 32);
        (0..32).for_each(|i| vp_bits.push(next_bits[i]));
        next_bits = builder.split_le_base::<2>(_vps[i].get_limb(2).0, 32);
        (0..32).for_each(|i| vp_bits.push(next_bits[i]));
        let offset = (37 + 1) * 8; // add 1 for 0 byte prefix
        (0..c.VP_BITS.div_ceil(c.LEB128_GROUP_SIZE)).for_each(|j| {
            (0..7).for_each(|k| {
                builder.connect(
                    validators_padded[i][offset + j * 8 + k + 1].target,
                    vp_bits[j * 7 + 7 - 1 - k],
                );
            })
        });
    });
}

pub fn connect_last_ed25519<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F,D>,
    untrusted_validator_hashes: &Vec<BigUintTarget>,
    signature_indicies: &Vec<Target>,
    signatures_padded: &Vec<Vec<BoolTarget>>,
    c: &Config
) {
    let mut concat_hash256_target = builder.add_virtual_hash256_target();

    let mut untrusted_validator_hashes_columns: Vec<Vec<Target>> = vec![];
    (0..8).for_each(|i| {
        let mut untrusted_validator_hash_column: Vec<Target> = vec![];
        (0..c.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|j| {
            untrusted_validator_hash_column.push(untrusted_validator_hashes[j].get_limb(i).0);
        });
        untrusted_validator_hashes_columns.push(untrusted_validator_hash_column);
    });

    //connect concat_hash256_target to  untrusted_validator_hashes at index signature[0]
    for i in 0..8 {
        let index_vaue: Target = signature_indicies[0];
        let vh_ci = builder.random_access(index_vaue, untrusted_validator_hashes_columns[i].clone());
        builder.connect(concat_hash256_target[i].0, vh_ci);
    }

    for i in 1..c.N_SIGNATURE_INDICES-1 {
        let hash256_target = builder.add_virtual_hash256_target();
        let random_index_vaue: Target = signature_indicies[i];
        for j in 0..8 {
            let vh_ci = builder.random_access(random_index_vaue, untrusted_validator_hashes_columns[j].clone());
            builder.connect(hash256_target[j].0, vh_ci);
        }
        concat_hash256_target = builder.two_to_one_sha256(concat_hash256_target, hash256_target);
    }


    //concatating signatures
    let mut signature_hashes: Vec<BigUintTarget> = vec![];
    for i in 0..signature_indicies.len(){
        signature_hashes.push(sha256_n_block_hash_target(builder, &signatures_padded[i] , 2));
    }

    let mut concat_hash256_target = builder.add_virtual_hash256_target();

    for i in 0..8 {
        builder.connect(concat_hash256_target[i].0, signature_hashes[0].get_limb(i).0);
    }

    for i in 1..c.N_SIGNATURE_INDICES-1 {
        let hash256_target = builder.add_virtual_hash256_target();
        for j in 0..8 {
            builder.connect(hash256_target[j].0, signature_hashes[i].get_limb(j).0);
        }
        concat_hash256_target = builder.two_to_one_sha256(concat_hash256_target, hash256_target);
    }
}
