use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::biguint::{BigUintTarget, CircuitBuilderBiguint};
use plonky2_ed25519::gadgets::eddsa::verify_using_preprocessed_sha_block;
use std::cmp::min;

use crate::config_data::*;

// returns pub_keys corresponding to top `N_SIGNATURE_INDICES` signatures in constrained manner (to be used for signature verification)
pub fn get_random_access_pub_keys<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pub_keys: &Vec<Vec<BoolTarget>>,
    signature_indices: &Vec<Target>,
    c: &Config,
) -> Vec<Vec<BoolTarget>> {
    // prepares pub_keys columns
    let mut pub_keys_columns: Vec<Vec<Target>> = vec![];
    (0..256).for_each(|i| {
        let mut pub_keys_column: Vec<Target> = vec![];
        (0..c.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|j| {
            pub_keys_column.push(pub_keys[j][i].target);
        });
        pub_keys_columns.push(pub_keys_column);
    });

    let mut random_access_pub_keys: Vec<Vec<BoolTarget>> =
        Vec::with_capacity(c.SIGNATURE_INDICES_DOMAIN_SIZE);

    (0..c.N_SIGNATURE_INDICES).for_each(|i| {
        let mut random_access_pub_key: Vec<BoolTarget> = Vec::with_capacity(256);
        (0..256).for_each(|j| {
            let value = builder.random_access(signature_indices[i], pub_keys_columns[j].clone());
            let bool_value = builder.add_virtual_bool_target_unsafe();
            builder.connect(bool_value.target, value);

            random_access_pub_key.push(bool_value);
        });
        random_access_pub_keys.push(random_access_pub_key);
    });

    random_access_pub_keys
}

pub fn constrain_sign_message<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    messages_padded: &Vec<Vec<BoolTarget>>,
    signatures: &Vec<Vec<BoolTarget>>,
    untrusted_pub_keys: &Vec<Vec<BoolTarget>>,
    header_hash: &Vec<BoolTarget>,
    height: &BigUintTarget,
    signature_indices: &Vec<Target>,

    c: &Config,
) {
    let zero_pub_key = (0..256)
        .map(|_| builder._false())
        .collect::<Vec<BoolTarget>>();
    let mut untrusted_pub_keys =
        untrusted_pub_keys[0..min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)].to_vec();
    (c.N_VALIDATORS..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|_| {
        untrusted_pub_keys.push(zero_pub_key.clone());
    });

    let pub_keys = get_random_access_pub_keys(builder, &untrusted_pub_keys, &signature_indices, c);

    for j in 0..messages_padded.len() {
        let message = &messages_padded[j];
        let signature = &signatures[j];
        let pub_key = &pub_keys[j];
        // Connect signature_r
        (0..256).for_each(|i| builder.connect(message[i].target, signature[i].target));

        // Connect public key
        (0..256).for_each(|i| builder.connect(message[256 + i].target, pub_key[i].target));

        // connect header hash in message
        // header hash takes the position at [640, 640+256)
        (0..256).for_each(|i| builder.connect(message[640 + i].target, header_hash[i].target));

        // connect header height in message
        // header height takes the position at [544, 544+64)
        let offset = 544;
        (0..2).for_each(|i| {
            let height_bits = builder.split_le_base::<2>(height.get_limb(i).0, 32);
            (0..4).for_each(|j| {
                (0..8).for_each(|k| {
                    builder.connect(
                        message[offset + i * 32 + j * 8 + k].target,
                        height_bits[j * 8 + 7 - k],
                    );
                })
            });
        });
        // TODO Verify signatures using plonky2_ed25519
        if j == 0 {
            verify_using_preprocessed_sha_block(builder, message, pub_key, signature);
        }
    }
}

pub fn constrain_timestamp<F: RichField + Extendable<D>, const D: usize>(
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

pub fn constrain_pub_keys_vps<F: RichField + Extendable<D>, const D: usize>(
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
