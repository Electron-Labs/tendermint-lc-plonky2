use super::merkle_targets::{
    get_256_bool_target, get_formatted_hash_256_bools, get_sha_2_block_target,
    get_sha_512_2_block_target, get_sha_block_target, hash256_to_bool_targets, header_merkle_root,
    merkle_1_block_leaf_root, SHA_BLOCK_BITS,
};
use num::{BigUint, FromPrimitive};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::hash::{CircuitBuilderHash, Hash256Target, WitnessHash};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint},
    u32::arithmetic_u32::CircuitBuilderU32,
};
use plonky2_ed25519::gadgets::eddsa::verify_using_preprocessed_sha_block;
use std::array::IntoIter;
use std::cmp::min;

use crate::config_data::*;
use crate::input_types::HeaderPadded;
// TODO: constrain non-repetition of indices

// TODO: pass reference of targets instead of connecting to the struct
// TODO: restructure something like
// * validators_quorum.rs
// * update_validity.rs
// * connect.rs

pub struct VerifySignatures {
    pub signatures: Vec<Vec<BoolTarget>>,
    pub messaged_padded: Vec<Vec<BoolTarget>>,
    pub pub_keys: Vec<Vec<BoolTarget>>,
}

// TODO: use BlockIDFlag: https://pkg.go.dev/github.com/tendermint/tendermint@v0.35.9/types#BlockIDFlag

#[derive(Clone)]
pub struct HeaderPaddedTarget {
    pub version: Vec<BoolTarget>,
    pub chain_id: Vec<BoolTarget>,
    pub height: Vec<BoolTarget>,
    pub time: Vec<BoolTarget>,
    pub last_block_id: Vec<BoolTarget>,
    pub last_commit_hash: Vec<BoolTarget>,
    pub data_hash: Vec<BoolTarget>,
    pub validators_hash: Vec<BoolTarget>,
    pub next_validators_hash: Vec<BoolTarget>,
    pub consensus_hash: Vec<BoolTarget>,
    pub app_hash: Vec<BoolTarget>,
    pub last_results_hash: Vec<BoolTarget>,
    pub evidence_hash: Vec<BoolTarget>,
    pub proposer_address: Vec<BoolTarget>,
}

impl IntoIterator for HeaderPaddedTarget {
    type Item = Vec<BoolTarget>;
    type IntoIter = IntoIter<Vec<BoolTarget>, 14>;

    fn into_iter<'a>(self) -> Self::IntoIter {
        std::iter::IntoIterator::into_iter([
            self.version,
            self.chain_id,
            self.height,
            self.time,
            self.last_block_id,
            self.last_commit_hash,
            self.data_hash,
            self.validators_hash,
            self.next_validators_hash,
            self.consensus_hash,
            self.app_hash,
            self.last_results_hash,
            self.evidence_hash,
            self.proposer_address,
        ])
    }
}

/* indices */
/* `signature_indices` */
// - first `N_SIGNATURE_INDICES` indices of non-null signatures, where `SIGNATURE_INDICES_DOMAIN_SIZE-1` >= index >=0, for each index
// - unlike intersect indices, no reserved index here (assuming there will always be atleast `N_SIGNATURE_INDICES` non-null signatures)

/* `untrusted_intersect_indices` and `trusted_next_intersect_indices `*/
// - contains indices for common public keys in untrusted_validators and trusted_mext_validators
// - For instance, an index pair (i, j) suggests ith pub key in untrusted vals == jth pub key in trusted next_vals
// - arrays of length `N_INTERSECTION_INDICES`, where `INTERSECTION_INDICES_DOMAIN_SIZE-2` >= index >=0, for each index
// - index `INTERSECTION_INDICES_DOMAIN_SIZE-1` is reserved to represent null
// - `untrusted_intersect_indices` must be a subset of `signature_indices`, except for index `INTERSECTION_INDICES_DOMAIN_SIZE-1`

// TODO: need multiple arrays in case 1 array fails to accomodate for sufficient common vals?

// TODO: add trusted_next_validators_hash leaf proof against trusted hash

pub struct ProofTarget {
    pub sign_messages_padded: Vec<Vec<BoolTarget>>,
    pub signatures: Vec<Vec<BoolTarget>>,

    pub untrusted_hash: Hash256Target,
    pub untrusted_height: BigUintTarget,
    pub untrusted_timestamp: BigUintTarget, // Unix timestamps in seconds
    pub untrusted_validators_padded: Vec<Vec<BoolTarget>>,
    pub untrusted_validator_pub_keys: Vec<Vec<BoolTarget>>,
    pub untrusted_validator_vps: Vec<BigUintTarget>,
    pub untrusted_header_padded: HeaderPaddedTarget,

    pub trusted_hash: Hash256Target,
    pub trusted_height: BigUintTarget,
    pub trusted_timestamp: BigUintTarget, // Unix timestamps in seconds
    pub trusted_next_validators_padded: Vec<Vec<BoolTarget>>,
    pub trusted_next_validator_pub_keys: Vec<Vec<BoolTarget>>,
    pub trusted_next_validator_vps: Vec<BigUintTarget>,
    pub trusted_header_padded: HeaderPaddedTarget,

    pub signature_indices: Vec<Target>,
    pub untrusted_intersect_indices: Vec<Target>,
    pub trusted_next_intersect_indices: Vec<Target>,
}

// Checks trustLevel ([1/3, 1]) of trustedHeaderVals (or trustedHeaderNextVals) signed correctly
pub fn constrain_trusted_quorum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    untrusted_validators_pub_keys: &Vec<Vec<BoolTarget>>,
    trusted_next_validators_pub_keys: &Vec<Vec<BoolTarget>>,
    trusted_next_validator_vp: &Vec<BigUintTarget>,
    signature_indices: &Vec<Target>,
    untrusted_intersect_indices: &Vec<Target>,
    trusted_next_intersect_indices: &Vec<Target>,
    c: &Config,
) {
    let zero_pub_key = (0..256)
        .map(|_| builder._false())
        .collect::<Vec<BoolTarget>>();

    let mut zero_vp = builder.constant_biguint(&BigUint::from_u64(0).unwrap());
    // making zero_vp equivalent 64 bit target
    zero_vp.limbs.push(builder.constant_u32(0));
    zero_vp.limbs.push(builder.constant_u32(0));

    let mut untrusted_validator_pub_keys = untrusted_validators_pub_keys
        [0..min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)]
        .to_vec();
    (min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)..c.INTERSECTION_INDICES_DOMAIN_SIZE)
        .for_each(|_| {
            untrusted_validator_pub_keys.push(zero_pub_key.clone());
        });

    let mut trusted_next_validator_pub_keys = trusted_next_validators_pub_keys
        [0..min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)]
        .to_vec();
    (min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)..c.INTERSECTION_INDICES_DOMAIN_SIZE)
        .for_each(|_| {
            trusted_next_validator_pub_keys.push(zero_pub_key.clone());
        });

    let mut trusted_next_validator_vp = trusted_next_validator_vp[0..c.N_VALIDATORS].to_vec();

    (c.N_VALIDATORS..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|_| {
        trusted_next_validator_vp.push(zero_vp.clone());
    });

    let signature_indices = signature_indices[0..c.N_SIGNATURE_INDICES].to_vec();
    let untrusted_intersect_indices =
        untrusted_intersect_indices[0..c.N_INTERSECTION_INDICES].to_vec();
    let trusted_next_intersect_indices =
        trusted_next_intersect_indices[0..c.N_INTERSECTION_INDICES].to_vec();

    let zero_bool_target = builder._false();
    let three_big_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap());
    let null_idx = builder.constant(F::from_canonical_u16(
        (c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u16,
    ));

    let mut total_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut intersection_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());

    // `untrusted_intersect_indices` must be a subset of `signature_indices`, except for reserved index
    untrusted_intersect_indices
        .iter()
        .for_each(|&untrusted_idx| {
            let is_reserved_index = builder.is_equal(untrusted_idx, null_idx);
            // constrain only if its a non-reserved index
            let enable_constraint = builder.not(is_reserved_index);

            let mut is_untrusted_in_signature = builder._false();
            signature_indices.iter().for_each(|&signature_idx| {
                let is_equal = builder.is_equal(untrusted_idx, signature_idx);
                is_untrusted_in_signature = builder.or(is_untrusted_in_signature, is_equal);
            });
            let a = builder.mul(is_untrusted_in_signature.target, enable_constraint.target);
            builder.connect(a, enable_constraint.target);
        });

    // compute total voting power
    (0..c.N_VALIDATORS)
        .for_each(|i| total_vp = builder.add_biguint(&total_vp, &trusted_next_validator_vp[i]));

    // prepares voting power columns
    // because random_access_index wont work on BigUintTarget so need to split it into limbs
    let trusted_validator_vp_columns = vec![
        trusted_next_validator_vp[..c.INTERSECTION_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        trusted_next_validator_vp[..c.INTERSECTION_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];
    // split pub keys columns to use random_access_index
    let mut untrusted_pub_keys_columns: Vec<Vec<Target>> = vec![];
    let mut trusted_pub_keys_columns: Vec<Vec<Target>> = vec![];
    (0..256).for_each(|i| {
        let mut untrusted_pub_key_column: Vec<Target> = vec![];
        let mut trusted_pub_key_column: Vec<Target> = vec![];
        (0..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|j| {
            untrusted_pub_key_column.push(untrusted_validator_pub_keys[j][i].target);
            trusted_pub_key_column.push(trusted_next_validator_pub_keys[j][i].target);
        });
        untrusted_pub_keys_columns.push(untrusted_pub_key_column);
        trusted_pub_keys_columns.push(trusted_pub_key_column);
    });

    (0..c.N_INTERSECTION_INDICES).for_each(|i| {
        let random_access_index = trusted_next_intersect_indices[i];
        let is_reserved_index = builder.is_equal(random_access_index, null_idx);
        // constrain only if its a non-reserved index
        let enable_constraint = builder.not(is_reserved_index);

        // compute intersection voting power in trusted
        let mut vp = builder.add_virtual_biguint_target(c.VP_BITS.div_ceil(32));
        let vp_c0 =
            builder.random_access(random_access_index, trusted_validator_vp_columns[0].clone());
        let vp_c1 =
            builder.random_access(random_access_index, trusted_validator_vp_columns[1].clone());
        builder.connect(vp.get_limb(0).0, vp_c0);
        builder.connect(vp.get_limb(1).0, vp_c1);
        vp = builder.mul_biguint_by_bool(&vp, enable_constraint);
        intersection_vp = builder.add_biguint(&intersection_vp, &vp);

        // ensure intersection pub keys
        (0..256).for_each(|j| {
            let untrusted_key = builder.random_access(
                untrusted_intersect_indices[i],
                untrusted_pub_keys_columns[j].clone(),
            );
            let trusted_key = builder.random_access(
                trusted_next_intersect_indices[i],
                trusted_pub_keys_columns[j].clone(),
            );
            let a = builder.mul(untrusted_key, enable_constraint.target);
            let b = builder.mul(trusted_key, enable_constraint.target);
            builder.connect(a, b);
        });
    });

    // ensures 3 * intersection_vp > total_vp
    let three_times_intersection_vp = builder.mul_biguint(&intersection_vp, &three_big_target);
    let comparison = builder.cmp_biguint(&three_times_intersection_vp, &total_vp);
    builder.connect(comparison.target, zero_bool_target.target);
}

// Ensure that +2/3 of new validators signed correctly.
pub fn constrain_untrusted_quorum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    untrusted_validator_vp: &Vec<BigUintTarget>,
    signature_indices: &Vec<Target>,
    c: &Config,
) {
    let mut zero_vp = builder.constant_biguint(&BigUint::from_u64(0).unwrap());
    // making zero_vp equivalent 64 bit target
    zero_vp.limbs.push(builder.constant_u32(0));
    zero_vp.limbs.push(builder.constant_u32(0));

    let mut untrusted_validator_vp = untrusted_validator_vp[0..c.N_VALIDATORS].to_vec();

    (c.N_VALIDATORS..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|_| {
        untrusted_validator_vp.push(zero_vp.clone());
    });
    let signature_indices = signature_indices[0..c.N_SIGNATURE_INDICES].to_vec();

    let mut total_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut quorum_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let three_big_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap());
    let two_big_target = builder.constant_biguint(&BigUint::from_u64(2).unwrap());
    let zero_bool_target = builder._false();

    // compute total voting power
    (0..c.N_VALIDATORS)
        .for_each(|i| total_vp = builder.add_biguint(&total_vp, &untrusted_validator_vp[i]));

    // prepares voting power columns
    let untrusted_validator_vp_columns = vec![
        untrusted_validator_vp[..c.SIGNATURE_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        untrusted_validator_vp[..c.SIGNATURE_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];

    (0..c.N_SIGNATURE_INDICES).for_each(|i| {
        let random_access_index = signature_indices[i];

        // compute intersection voting power in trusted
        let vp = builder.add_virtual_biguint_target(c.VP_BITS.div_ceil(32));
        let vp_c0 = builder.random_access(
            random_access_index,
            untrusted_validator_vp_columns[0].clone(),
        );
        let vp_c1 = builder.random_access(
            random_access_index,
            untrusted_validator_vp_columns[1].clone(),
        );
        builder.connect(vp.get_limb(0).0, vp_c0);
        builder.connect(vp.get_limb(1).0, vp_c1);
        quorum_vp = builder.add_biguint(&quorum_vp, &vp);
    });

    // ensures 3 * quorum vp > 2 * total_vp
    let three_times_quorum_vp = builder.mul_biguint(&quorum_vp, &three_big_target);
    let two_times_total_vp = builder.mul_biguint(&total_vp, &two_big_target);
    let comparison = builder.cmp_biguint(&three_times_quorum_vp, &two_times_total_vp);
    builder.connect(comparison.target, zero_bool_target.target);
    // TODO: Current nibiru is failing in this function for above connect.
    // Try changing heights
}

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

// TODO: ?
// pub fn add_virtual_verify_signatures_target<F: RichField + Extendable<D>, const D: usize>(
//     builder: &mut CircuitBuilder<F, D>,
// ) -> VerifySignatures {
//     let signatures = (0..c.N_VALIDATORS)
//         .map(|_| {
//             (0..SIGNATURE_BITS)
//                 .map(|_| builder.add_virtual_bool_target_unsafe())
//                 .collect()
//         })
//         .collect::<Vec<Vec<BoolTarget>>>();
//     let verify = (0..c.N_VALIDATORS)
//         .map(|_| builder.add_virtual_bool_target_unsafe())
//         .collect::<Vec<BoolTarget>>();

//     VerifySignatures { signatures, verify }
// }

pub fn constrain_update_validity<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    untrusted_height: &BigUintTarget,
    trusted_height: &BigUintTarget,
    untrusted_timestamp: &BigUintTarget,
    trusted_timestamp: &BigUintTarget,
    untrusted_version_padded: &Vec<BoolTarget>,
    untrusted_chain_id_padded: &Vec<BoolTarget>,
    c: &Config,
) {
    let two_big_target = builder.constant_biguint(&BigUint::from_i8(2).unwrap());
    let one_bool_target = builder._true();

    // ensures untrusted height >= trusted height + 2
    let trusted_height_plus_two = builder.add_biguint(&trusted_height, &two_big_target);
    let result = builder.cmp_biguint(&trusted_height_plus_two, &untrusted_height);
    builder.connect(result.target, one_bool_target.target);

    // ensures trusted height + trusting period >= untrusted height
    let trusting_period_seconds =
        builder.constant_biguint(&BigUint::from_usize(c.TRUSTING_PERIOD).unwrap());
    let untrusted_max_allowed_timestamp =
        builder.add_biguint(&trusted_timestamp, &trusting_period_seconds);
    let result = builder.cmp_biguint(&untrusted_timestamp, &untrusted_max_allowed_timestamp);
    builder.connect(result.target, one_bool_target.target);

    // ensure correct version block
    let version_block = c
        .VERSION_BLOCK
        .iter()
        .map(|&elm| builder.constant_bool(elm))
        .collect::<Vec<BoolTarget>>();
    (0..version_block.len()).for_each(|i| {
        builder.connect(
            untrusted_version_padded[16 + i].target,
            version_block[i].target,
        )
    });

    // ensure correct chain id
    let chain_id = c
        .CHAIN_ID
        .iter()
        .map(|&elm| builder.constant_bool(elm))
        .collect::<Vec<BoolTarget>>();
    (0..chain_id.len()).for_each(|i| {
        builder.connect(untrusted_chain_id_padded[24 + i].target, chain_id[i].target)
    });
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

pub fn add_virtual_header_padded_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> HeaderPaddedTarget {
    let version_padded = get_sha_block_target(builder);
    let chain_id_padded = get_sha_block_target(builder);
    let height_padded = get_sha_block_target(builder);
    let time_padded = get_sha_block_target(builder);
    let last_block_id_padded = get_sha_2_block_target(builder);
    let last_commit_hash_padded = get_sha_block_target(builder);
    let data_hash_padded = get_sha_block_target(builder);
    let validators_hash_padded = get_sha_block_target(builder);
    let next_validators_hash_padded = get_sha_block_target(builder);
    let consensus_hash_padded = get_sha_block_target(builder);
    let app_hash_padded = get_sha_block_target(builder);
    let last_results_hash_padded = get_sha_block_target(builder);
    let evidence_hash_padded = get_sha_block_target(builder);
    let proposer_address_padded = get_sha_block_target(builder);

    HeaderPaddedTarget {
        version: version_padded,
        chain_id: chain_id_padded,
        height: height_padded,
        time: time_padded,
        last_block_id: last_block_id_padded,
        last_commit_hash: last_commit_hash_padded,
        data_hash: data_hash_padded,
        validators_hash: validators_hash_padded,
        next_validators_hash: next_validators_hash_padded,
        consensus_hash: consensus_hash_padded,
        app_hash: app_hash_padded,
        last_results_hash: last_results_hash_padded,
        evidence_hash: evidence_hash_padded,
        proposer_address: proposer_address_padded,
    }
}

pub fn add_virtual_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    c: &Config,
) -> ProofTarget {
    let sign_messages_padded = (0..c.N_SIGNATURE_INDICES)
        .map(|_| get_sha_512_2_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let signatures = (0..c.N_VALIDATORS)
        .map(|_| {
            (0..c.SIGNATURE_BITS)
                .map(|_| builder.add_virtual_bool_target_unsafe())
                .collect()
        })
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_hash = builder.add_virtual_hash256_target();
    let untrusted_height = builder.add_virtual_biguint_target(c.HEIGHT_BITS.div_ceil(32));
    let untrusted_timestamp = builder.add_virtual_biguint_target(
        (c.TIMESTAMP_BITS.div_ceil(c.LEB128_GROUP_SIZE) * 8).div_ceil(32),
    );
    let untrusted_validators_padded = (0..c.N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_validator_pub_keys = (0..c.N_VALIDATORS)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_validator_vps = (0..c.N_VALIDATORS)
        .map(|_| builder.add_virtual_biguint_target(c.VP_BITS.div_ceil(32)))
        .collect::<Vec<BigUintTarget>>();
    let untrusted_header_padded = add_virtual_header_padded_target(builder);

    let trusted_hash = builder.add_virtual_hash256_target();
    let trusted_height = builder.add_virtual_biguint_target(c.HEIGHT_BITS.div_ceil(32));
    let trusted_timestamp = builder.add_virtual_biguint_target(
        (c.TIMESTAMP_BITS.div_ceil(c.LEB128_GROUP_SIZE) * 8).div_ceil(32),
    );
    let trusted_next_validators_padded = (0..c.N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_next_validator_pub_keys = (0..c.N_VALIDATORS)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_next_validator_vps = (0..c.N_VALIDATORS)
        .map(|_| builder.add_virtual_biguint_target(c.VP_BITS.div_ceil(32)))
        .collect::<Vec<BigUintTarget>>();
    let trusted_header_padded = add_virtual_header_padded_target(builder);

    let signature_indices = (0..c.N_SIGNATURE_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let untrusted_intersect_indices = (0..c.N_INTERSECTION_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let trusted_next_intersect_indices = (0..c.N_INTERSECTION_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();

    // *** sub circuits ***
    let untrusted_validators_hash = get_formatted_hash_256_bools(&merkle_1_block_leaf_root(
        builder,
        &untrusted_validators_padded.clone(),
    ));
    let trusted_next_validators_hash = get_formatted_hash_256_bools(&merkle_1_block_leaf_root(
        builder,
        &trusted_next_validators_padded.clone(),
    ));
    constrain_trusted_quorum(
        builder,
        &untrusted_validator_pub_keys,
        &trusted_next_validator_pub_keys,
        &trusted_next_validator_vps,
        &signature_indices,
        &untrusted_intersect_indices,
        &trusted_next_intersect_indices,
        c,
    );
    constrain_untrusted_quorum(builder, &untrusted_validator_vps, &signature_indices, c);
    constrain_update_validity(
        builder,
        &untrusted_height,
        &trusted_height,
        &untrusted_timestamp,
        &trusted_timestamp,
        &untrusted_header_padded.version,
        &untrusted_header_padded.chain_id,
        c,
    );
    constrain_timestamp(
        builder,
        &untrusted_header_padded.time,
        &untrusted_timestamp,
        c,
    );
    constrain_timestamp(builder, &trusted_header_padded.time, &trusted_timestamp, c);
    constrain_pub_keys_vps(
        builder,
        &untrusted_validator_pub_keys,
        &untrusted_validators_padded,
        &untrusted_validator_vps,
        c,
    );
    constrain_pub_keys_vps(
        builder,
        &trusted_next_validator_pub_keys,
        &trusted_next_validators_padded,
        &trusted_next_validator_vps,
        c,
    );

    let untrusted_header_merkle_root_bool_targets =
        header_merkle_root(builder, untrusted_header_padded.clone().into_iter());
    let trusted_header_merkle_root_bool_targets =
        header_merkle_root(builder, trusted_header_padded.clone().into_iter());

    let untrusted_hash_bool_targets = &hash256_to_bool_targets(builder, &untrusted_hash);
    let untrusted_hash_bool_targets_formatted =
        get_formatted_hash_256_bools(untrusted_hash_bool_targets);

    constrain_sign_message(
        builder,
        &sign_messages_padded,
        &signatures,
        &untrusted_validator_pub_keys,
        &untrusted_hash_bool_targets_formatted,
        &untrusted_height,
        &signature_indices,
        c,
    );

    // connect `untrusted_validators_hash` and `untrusted_validators_hash_padded`
    (0..256).for_each(|i| {
        builder.connect(
            untrusted_validators_hash[i].target,
            untrusted_header_padded.validators_hash[24 + i].target,
        )
    });

    // connect `trusted_next_validators_hash` and `trusted_next_validators_hash_padded`
    (0..256).for_each(|i| {
        builder.connect(
            trusted_next_validators_hash[i].target,
            trusted_header_padded.next_validators_hash[24 + i].target,
        )
    });

    //  connect `untrusted_header_merkle_root_bool_targets` with `untrusted_hash_bool_targets`
    (0..256).for_each(|i| {
        builder.connect(
            untrusted_header_merkle_root_bool_targets[i].target,
            untrusted_hash_bool_targets[i].target,
        )
    });

    //  connect `trusted_header_merkle_root_bool_targets` with `trusted_hash_bool_targets`
    let trusted_hash_bool_targets = &hash256_to_bool_targets(builder, &trusted_hash);
    (0..256).for_each(|i| {
        builder.connect(
            trusted_header_merkle_root_bool_targets[i].target,
            trusted_hash_bool_targets[i].target,
        )
    });

    ProofTarget {
        sign_messages_padded,
        signatures,

        untrusted_hash,
        untrusted_height,
        untrusted_timestamp,
        untrusted_validators_padded,
        untrusted_validator_pub_keys,
        untrusted_validator_vps,
        untrusted_header_padded,

        trusted_hash,
        trusted_height,
        trusted_timestamp,
        trusted_next_validators_padded,
        trusted_next_validator_pub_keys,
        trusted_next_validator_vps,
        trusted_header_padded,

        signature_indices,
        untrusted_intersect_indices,
        trusted_next_intersect_indices,
    }
}

// sets all padded header fields as sha256 block
// last_block_id is 2 sha blocks, rest of the fields are 1 sha block
pub fn set_header_padded_target<F: RichField, W: Witness<F>>(
    witness: &mut W,
    header_padded: &HeaderPadded,
    target: &HeaderPaddedTarget,
) {
    (0..SHA_BLOCK_BITS)
        .for_each(|i| witness.set_bool_target(target.version[i], header_padded.version[i]));
    (0..SHA_BLOCK_BITS)
        .for_each(|i| witness.set_bool_target(target.chain_id[i], header_padded.chain_id[i]));
    (0..SHA_BLOCK_BITS)
        .for_each(|i| witness.set_bool_target(target.height[i], header_padded.height[i]));
    (0..SHA_BLOCK_BITS)
        .for_each(|i| witness.set_bool_target(target.time[i], header_padded.time[i]));
    (0..SHA_BLOCK_BITS * 2).for_each(|i| {
        witness.set_bool_target(target.last_block_id[i], header_padded.last_block_id[i])
    });
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.last_commit_hash[i],
            header_padded.last_commit_hash[i],
        )
    });
    (0..SHA_BLOCK_BITS)
        .for_each(|i| witness.set_bool_target(target.data_hash[i], header_padded.data_hash[i]));
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(target.validators_hash[i], header_padded.validators_hash[i])
    });
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.next_validators_hash[i],
            header_padded.next_validators_hash[i],
        )
    });
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(target.consensus_hash[i], header_padded.consensus_hash[i])
    });
    (0..SHA_BLOCK_BITS)
        .for_each(|i| witness.set_bool_target(target.app_hash[i], header_padded.app_hash[i]));
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.last_results_hash[i],
            header_padded.last_results_hash[i],
        )
    });
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(target.evidence_hash[i], header_padded.evidence_hash[i])
    });
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.proposer_address[i],
            header_padded.proposer_address[i],
        )
    });
}

pub fn set_proof_target<F: RichField, W: Witness<F>>(
    witness: &mut W,
    sign_messages_padded: &Vec<Vec<bool>>,
    signatures: &Vec<Vec<bool>>,

    untrusted_hash: &Vec<u8>,
    untrusted_height: u64,
    untrusted_timestamp: u64,
    untrusted_validators_padded: &Vec<Vec<bool>>,
    untrusted_validator_pub_keys: &Vec<Vec<bool>>,
    untrusted_validator_vps: &Vec<u64>,
    untrusted_header_padded: &HeaderPadded,

    trusted_hash: &Vec<u8>,
    trusted_height: u64,
    trusted_timestamp: u64,
    trusted_next_validators_padded: &Vec<Vec<bool>>,
    trusted_next_validator_pub_keys: &Vec<Vec<bool>>,
    trusted_next_validator_vps: &Vec<u64>,
    trusted_header_padded: &HeaderPadded,

    signature_indices: &Vec<u8>,
    untrusted_intersect_indices: &Vec<u8>,
    trusted_next_intersect_indices: &Vec<u8>,

    target: &ProofTarget,
    c: &Config,
) {
    // Set N_SIGNATURE_INDICES signed messages (each message is already padded as sha512 - 2 block)
    (0..c.N_SIGNATURE_INDICES).for_each(|i| {
        (0..SHA_BLOCK_BITS * 4).for_each(|j| {
            witness.set_bool_target(
                target.sign_messages_padded[i][j],
                sign_messages_padded[i][j],
            )
        });
    });
    // Set N_SIGNATURE_INDICES signatures
    (0..c.N_SIGNATURE_INDICES).for_each(|i| {
        (0..c.SIGNATURE_BITS)
            .for_each(|j| witness.set_bool_target(target.signatures[i][j], signatures[i][j]))
    });

    // Set new block hash target (new block hash is sha256 digest)
    let mut untrusted_hash_slice = [0u8; 32];
    untrusted_hash_slice.copy_from_slice(untrusted_hash.as_slice());
    witness.set_hash256_target(&target.untrusted_hash, &untrusted_hash_slice);

    // Untrusted Height as biguint target (u64)
    witness.set_biguint_target(
        &target.untrusted_height,
        &BigUint::from_u64(untrusted_height).unwrap(),
    );

    // Untrusted time stamp as BigUintTarget
    witness.set_biguint_target(
        &target.untrusted_timestamp,
        &BigUint::from_u64(untrusted_timestamp).unwrap(),
    );

    // We take already padded N_VALIDATORS untrusted validator and then connect untrusted_validator_vps
    // and untrusted_validator_pub_keys
    (0..c.N_VALIDATORS).for_each(|i| {
        (0..SHA_BLOCK_BITS).for_each(|j| {
            witness.set_bool_target(
                target.untrusted_validators_padded[i][j],
                untrusted_validators_padded[i][j],
            )
        })
    });

    // Set N_VALIDATORS (total vals of block) pub keys as target to reconstruct untrusted_validators_hash
    (0..c.N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.untrusted_validator_pub_keys[i][j],
                untrusted_validator_pub_keys[i][j],
            )
        })
    });
    // Set N_VALIDATORS (total vals of block) voting powers as target to reconstruct untrusted_validators_hash
    // To verify 2/3rd majority
    (0..c.N_VALIDATORS).for_each(|i| {
        witness.set_biguint_target(
            &target.untrusted_validator_vps[i],
            &BigUint::from_u64(untrusted_validator_vps[i]).unwrap(),
        )
    });
    // set untrusted header fields
    set_header_padded_target(
        witness,
        untrusted_header_padded,
        &target.untrusted_header_padded,
    );

    // Set trusted header root
    let mut trusted_hash_slice = [0u8; 32];
    trusted_hash_slice.copy_from_slice(trusted_hash.as_slice());
    witness.set_hash256_target(&target.trusted_hash, &trusted_hash_slice);

    // Set trusted height
    witness.set_biguint_target(
        &target.trusted_height,
        &BigUint::from_u64(trusted_height).unwrap(),
    );

    // Set trusted timestamp
    witness.set_biguint_target(
        &target.trusted_timestamp,
        &BigUint::from_u64(trusted_timestamp).unwrap(),
    );

    (0..c.N_VALIDATORS).for_each(|i| {
        (0..SHA_BLOCK_BITS).for_each(|j| {
            witness.set_bool_target(
                target.trusted_next_validators_padded[i][j],
                trusted_next_validators_padded[i][j],
            )
        })
    });

    (0..c.N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.trusted_next_validator_pub_keys[i][j],
                trusted_next_validator_pub_keys[i][j],
            )
        })
    });

    (0..c.N_VALIDATORS).for_each(|i| {
        witness.set_biguint_target(
            &target.trusted_next_validator_vps[i],
            &BigUint::from_u64(trusted_next_validator_vps[i]).unwrap(),
        )
    });
    // set trusted header fields
    set_header_padded_target(
        witness,
        trusted_header_padded,
        &target.trusted_header_padded,
    );

    (0..c.N_SIGNATURE_INDICES).for_each(|i| {
        witness.set_target(
            target.signature_indices[i],
            F::from_canonical_u8(signature_indices[i]),
        )
    });
    (0..c.N_INTERSECTION_INDICES).for_each(|i| {
        witness.set_target(
            target.untrusted_intersect_indices[i],
            F::from_canonical_u8(untrusted_intersect_indices[i]),
        )
    });
    (0..c.N_INTERSECTION_INDICES).for_each(|i| {
        witness.set_target(
            target.trusted_next_intersect_indices[i],
            F::from_canonical_u8(trusted_next_intersect_indices[i]),
        )
    });
}
