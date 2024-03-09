use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::biguint::BigUintTarget;
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

pub fn verify_signatures<F: RichField + Extendable<D>, const D: usize>(
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

        // ** Connect public key **
        (0..256).for_each(|i| builder.connect(message[256 + i].target, pub_key[i].target));

        // ** connect header height in message **
        // header height takes the position at [544, 544+64)
        let height_offset = 544;
        (0..2).for_each(|i| {
            let height_bits = builder.split_le_base::<2>(height.get_limb(i).0, 32);
            (0..4).for_each(|j| {
                (0..8).for_each(|k| {
                    builder.connect(
                        message[height_offset + i * 32 + j * 8 + k].target,
                        height_bits[j * 8 + 7 - k],
                    );
                })
            });
        });

        // ** connect header hash in message **
        let zero_round_header_hash_offset = 256 + 256 + (1 + 15) * 8;
        let non_zero_round_header_hash_offset = 256 + 256 + (1 + 15 + 9) * 8;
        // find if the round is 0
        let mut is_non_zero_round = builder._true();
        let twenty_five: Vec<Target> = vec![
            builder._false().target,
            builder._false().target,
            builder._false().target,
            builder._true().target,
            builder._true().target,
            builder._false().target,
            builder._false().target,
            builder._true().target,
        ];
        // find out if it is a non-zero round number
        (0..twenty_five.len()).for_each(|i| {
            let is_equal = builder.is_equal(twenty_five[i], message[608 + i].target);
            is_non_zero_round = builder.and(is_non_zero_round, is_equal);
        });
        let is_zero_round = builder.not(is_non_zero_round);

        // connect header hash
        (0..header_hash.len()).for_each(|i| {
            // Case 1: non-zero round
            let a = builder.mul(header_hash[i].target, is_non_zero_round.target);
            let b = builder.mul(
                message[non_zero_round_header_hash_offset + i].target,
                is_non_zero_round.target,
            );
            builder.connect(a, b);

            // Case 2: zero round
            let a = builder.mul(header_hash[i].target, is_zero_round.target);
            let b = builder.mul(
                message[zero_round_header_hash_offset + i].target,
                is_zero_round.target,
            );
            builder.connect(a, b);
        });

        // TODO: chain id index varies due to milliseconds part in timestamp
        // // ** connect chain id in message **
        // let chain_id_target = c
        //     .CHAIN_ID
        //     .iter()
        //     .map(|&elm| builder.constant_bool(elm))
        //     .collect::<Vec<BoolTarget>>();
        // let zero_round_chain_id_offset = zero_round_header_hash_offset + 85 * 8;
        // let non_zero_round_chain_id_offset = non_zero_round_header_hash_offset + 85 * 8;
        // (0..chain_id_target.len()).for_each(|i| {
        //     // Case 1: non-zero round
        //     let a = builder.mul(header_hash[i].target, is_non_zero_round.target);
        //     let b = builder.mul(
        //         message[non_zero_round_chain_id_offset + i].target,
        //         is_non_zero_round.target,
        //     );
        //     builder.connect(a, b);

        //     // Case 2: zero round
        //     let a = builder.mul(chain_id_target[i].target, is_zero_round.target);
        //     let b = builder.mul(
        //         message[zero_round_chain_id_offset + i].target,
        //         is_zero_round.target,
        //     );
        //     builder.connect(a, b);
        // });

        verify_using_preprocessed_sha_block(builder, message, pub_key, signature);
    }
}
