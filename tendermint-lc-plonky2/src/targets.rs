use super::merkle_targets::{
    biguint_hash_to_bool_targets, get_256_bool_target, get_512_bool_target,
    get_formatted_hash_256_bools, get_sha_512_2_block_target, get_sha_block_target,
    hash256_to_bool_targets, merkle_1_block_leaf_root, sha256_1_block_hash_target,
    sha256_2_block_two_to_one_hash_target, SHA_BLOCK_BITS,
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
use plonky2_crypto::biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint};
use plonky2_crypto::hash::{CircuitBuilderHash, Hash256Target, WitnessHash};
use plonky2_crypto::u32::arithmetic_u32::CircuitBuilderU32;
use plonky2_ed25519::gadgets::eddsa::{make_verify_circuits, verify_using_preprocessed_sha_block};

use crate::config_data::*;
// TODO: remove all merkle proofs against header and add header merkle tree instead
// TODO: construct and connect merkle tree of old state

pub struct VerifySignatures {
    pub signatures: Vec<Vec<BoolTarget>>,
    pub messaged_padded: Vec<Vec<BoolTarget>>,
    pub pub_keys: Vec<Vec<BoolTarget>>,
}

pub struct TrustedValidatorsQuorumTarget {
    pub untrusted_validator_pub_keys: Vec<Vec<BoolTarget>>,
    pub trusted_next_validator_pub_keys: Vec<Vec<BoolTarget>>,
    pub trusted_next_validator_vp: Vec<BigUintTarget>,
    pub signature_indices: Vec<Target>,
    pub untrusted_intersect_indices: Vec<Target>,
    pub trusted_next_intersect_indices: Vec<Target>,
}

pub struct UntrustedValidatorsQuorumTarget {
    pub untrusted_validator_vp: Vec<BigUintTarget>,
    pub signature_indices: Vec<Target>,
}

pub struct MerkleProofTarget {
    pub leaf_padded: Vec<BoolTarget>, // shaBlock(0x00 || leaf)
    pub proof: Vec<Vec<BoolTarget>>,
    pub root: Hash256Target,
}

pub struct UpdateValidityTarget {
    pub untrusted_height: BigUintTarget,
    pub trusted_height: BigUintTarget,
    pub untrusted_timestamp: BigUintTarget,
    pub trusted_timestamp: BigUintTarget,
    pub untrusted_version_padded: Vec<BoolTarget>,
    pub untrusted_chain_id_padded: Vec<BoolTarget>,
}

// TODO: use BlockIDFlag: https://pkg.go.dev/github.com/tendermint/tendermint@v0.35.9/types#BlockIDFlag

pub struct ConnectSignMessageTarget {
    pub messages_padded: Vec<Vec<BoolTarget>>,
    pub header_hash: Vec<BoolTarget>,
    pub height: BigUintTarget,
    pub signatures: Vec<Vec<BoolTarget>>,
    pub signature_indexes: Vec<Target>, // we will extract public keys using these signature indexes
    pub untrusted_pub_keys: Vec<Vec<BoolTarget>>,
}

pub struct ConnectTimestampTarget {
    pub header_time_padded: Vec<BoolTarget>,
    pub header_timestamp: BigUintTarget,
}

pub struct ConnectPubKeysVPsTarget {
    pub validators_padded: Vec<Vec<BoolTarget>>,
    pub vps: Vec<BigUintTarget>,
    pub pub_keys: Vec<Vec<BoolTarget>>,
}

/* indices */
/* `signature_indices` */
// - first 45 indices of non-null signatures, where 63 >= index >=0, for each index
// - unlike intersect indices, no reserved index here (assuming there will always be atleast 45 non-null signatures)

/* `untrusted_intersect_indices` and `trusted_next_intersect_indices `*/
// - contains indices for common public keys in untrusted_validators and trusted_mext_validators
// - For instance, an index pair (i, j) suggests ith pub key in untrusted vals == jth pub key in trusted next_vals
// - arrays of length 45, where 62 >= index >=0, for each index
// - index `63` is reserved to represent null
// - `untrusted_intersect_indices` must be a subset of `signature_indices`, except for index `63`

// TODO: need multiple arrays in case 1 array fails to accomodate for sufficient common vals?

pub struct ProofTarget {
    pub sign_messages_padded: Vec<Vec<BoolTarget>>,
    pub signatures: Vec<Vec<BoolTarget>>,
    pub untrusted_hash: Hash256Target,
    pub untrusted_version_padded: Vec<BoolTarget>,
    pub untrusted_chain_id_padded: Vec<BoolTarget>,
    pub untrusted_height: BigUintTarget,
    pub untrusted_time_padded: Vec<BoolTarget>,
    pub untrusted_timestamp: BigUintTarget, // Unix timestamps in seconds
    pub untrusted_validators_hash_padded: Vec<BoolTarget>,
    pub untrusted_validators_padded: Vec<Vec<BoolTarget>>,
    pub untrusted_validator_pub_keys: Vec<Vec<BoolTarget>>,
    pub untrusted_validator_vp: Vec<BigUintTarget>,
    pub untrusted_version_proof: Vec<Vec<BoolTarget>>,
    pub untrusted_chain_id_proof: Vec<Vec<BoolTarget>>,
    pub untrusted_time_proof: Vec<Vec<BoolTarget>>,
    pub untrusted_validators_hash_proof: Vec<Vec<BoolTarget>>,
    pub trusted_hash: Hash256Target,
    pub trusted_height: BigUintTarget,
    pub trusted_time_padded: Vec<BoolTarget>,
    pub trusted_timestamp: BigUintTarget, // Unix timestamps in seconds
    pub trusted_next_validators_hash_padded: Vec<BoolTarget>,
    pub trusted_next_validators_padded: Vec<Vec<BoolTarget>>,
    pub trusted_next_validator_pub_keys: Vec<Vec<BoolTarget>>,
    pub trusted_next_validator_vp: Vec<BigUintTarget>,
    pub trusted_time_proof: Vec<Vec<BoolTarget>>,
    pub trusted_next_validators_hash_proof: Vec<Vec<BoolTarget>>,
    pub trusted_version_proof: Vec<Vec<BoolTarget>>,
    pub trusted_version_padded: Vec<BoolTarget>,
    pub trusted_chain_id_proof: Vec<Vec<BoolTarget>>,
    pub trusted_chain_id_padded: Vec<BoolTarget>,
    pub signature_indices: Vec<Target>,
    pub untrusted_intersect_indices: Vec<Target>,
    pub trusted_next_intersect_indices: Vec<Target>,
}

// Checks trustLevel ([1/3, 1]) of trustedHeaderVals (or trustedHeaderNextVals) signed correctly
pub fn add_virtual_trusted_quorum_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> TrustedValidatorsQuorumTarget {
    let untrusted_validator_pub_keys = (0..*TOP_N_SIGNATURES)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_next_validator_pub_keys = (0..*TOP_N_SIGNATURES)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_next_validator_vp = (0..*N_VALIDATORS)
        .map(|_| builder.add_virtual_biguint_target(VP_BITS.div_ceil(32)))
        .collect::<Vec<BigUintTarget>>();
    let signature_indices = (0..*N_SIGNATURE_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let untrusted_intersect_indices = (0..*N_INTERSECTION_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let trusted_next_intersect_indices = (0..*N_INTERSECTION_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();

    let zero_bool_target = builder._false();
    let three_big_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap());
    let sixty_three = builder.constant(F::from_canonical_u16(63));

    let mut total_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut intersection_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());

    // `untrusted_intersect_indices` must be a subset of `signature_indices`, except for index `63`
    untrusted_intersect_indices
        .iter()
        .for_each(|&untrusted_idx| {
            let is_reserved_index = builder.is_equal(untrusted_idx, sixty_three);
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
    (0..*N_VALIDATORS)
        .for_each(|i| total_vp = builder.add_biguint(&total_vp, &trusted_next_validator_vp[i]));

    // prepares voting power columns
    // because random_access_index wont work on BigUintTarget so need to split it into limbs
    let trusted_validator_vp_columns = vec![
        trusted_next_validator_vp[..*TOP_N_VALIDATORS_FOR_INTERSECTION]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        trusted_next_validator_vp[..*TOP_N_VALIDATORS_FOR_INTERSECTION]
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
        (0..*TOP_N_SIGNATURES).for_each(|j| {
            untrusted_pub_key_column.push(untrusted_validator_pub_keys[j][i].target);
            trusted_pub_key_column.push(trusted_next_validator_pub_keys[j][i].target);
        });
        untrusted_pub_keys_columns.push(untrusted_pub_key_column);
        trusted_pub_keys_columns.push(trusted_pub_key_column);
    });

    (0..*N_INTERSECTION_INDICES).for_each(|i| {
        let random_access_index = trusted_next_intersect_indices[i];
        let is_reserved_index = builder.is_equal(random_access_index, sixty_three);
        // constrain only if its a non-reserved index
        let enable_constraint = builder.not(is_reserved_index);

        // compute intersection voting power in trusted
        let mut vp = builder.add_virtual_biguint_target(VP_BITS.div_ceil(32));
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

    TrustedValidatorsQuorumTarget {
        untrusted_validator_pub_keys,
        trusted_next_validator_pub_keys,
        trusted_next_validator_vp,
        signature_indices,
        untrusted_intersect_indices,
        trusted_next_intersect_indices,
    }
}

// Ensure that +2/3 of new validators signed correctly.
pub fn add_virtual_untrusted_quorum_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> UntrustedValidatorsQuorumTarget {
    let untrusted_validator_vp = (0..*N_VALIDATORS)
        .map(|_| builder.add_virtual_biguint_target(VP_BITS.div_ceil(32)))
        .collect::<Vec<BigUintTarget>>();
    let signature_indices = (0..*N_SIGNATURE_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();

    let mut total_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut quorum_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let three_big_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap());
    let two_big_target = builder.constant_biguint(&BigUint::from_u64(2).unwrap());
    let zero_bool_target = builder._false();

    // compute total voting power
    (0..*N_VALIDATORS)
        .for_each(|i| total_vp = builder.add_biguint(&total_vp, &untrusted_validator_vp[i]));

    // prepares voting power columns
    let untrusted_validator_vp_columns = vec![
        untrusted_validator_vp[..*TOP_N_SIGNATURES]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        untrusted_validator_vp[..*TOP_N_SIGNATURES]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];

    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        let random_access_index = signature_indices[i];

        // compute intersection voting power in trusted
        let mut vp = builder.add_virtual_biguint_target(VP_BITS.div_ceil(32));
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

    UntrustedValidatorsQuorumTarget {
        untrusted_validator_vp,
        signature_indices,
    }
}

// returns pub_keys corresponding to top 45 signatures in constrained manner (to be used for signature verification)
pub fn get_random_access_pub_keys<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pub_keys: &Vec<Vec<BoolTarget>>,
    signature_indices: &Vec<Target>,
) -> Vec<Vec<BoolTarget>> {
    // prepares pub_keys columns
    let mut pub_keys_columns: Vec<Vec<Target>> = vec![];
    (0..256).for_each(|i| {
        let mut pub_keys_column: Vec<Target> = vec![];
        (0..*TOP_N_SIGNATURES).for_each(|j| {
            pub_keys_column.push(pub_keys[j][i].target);
        });
        pub_keys_columns.push(pub_keys_column);
    });

    let mut random_access_pub_keys: Vec<Vec<BoolTarget>> = Vec::with_capacity(*TOP_N_SIGNATURES);

    (0..*N_SIGNATURE_INDICES).for_each(|i| {
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
//     let signatures = (0..*N_VALIDATORS)
//         .map(|_| {
//             (0..SIGNATURE_BITS)
//                 .map(|_| builder.add_virtual_bool_target_unsafe())
//                 .collect()
//         })
//         .collect::<Vec<Vec<BoolTarget>>>();
//     let verify = (0..*N_VALIDATORS)
//         .map(|_| builder.add_virtual_bool_target_unsafe())
//         .collect::<Vec<BoolTarget>>();

//     VerifySignatures { signatures, verify }
// }

pub fn add_virtual_validators_hash_merkle_proof_target<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleProofTarget {
    let root = builder.add_virtual_hash256_target();
    let proof = (0..*HEADER_VALIDATORS_HASH_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let leaf_padded = get_sha_block_target(builder);

    let mut hash = sha256_1_block_hash_target(builder, &leaf_padded);

    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &get_formatted_hash_256_bools(&proof[0]),
        &hash,
    );
    hash = biguint_hash_to_bool_targets(builder, &hash_biguint);
    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &get_formatted_hash_256_bools(&proof[1]),
        &hash,
    );
    hash = biguint_hash_to_bool_targets(builder, &hash_biguint);
    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &get_formatted_hash_256_bools(&proof[2]),
        &hash,
    );
    hash = biguint_hash_to_bool_targets(builder, &hash_biguint);
    let computed_root = sha256_2_block_two_to_one_hash_target(
        builder,
        &hash,
        &get_formatted_hash_256_bools(&proof[3]),
    );

    (0..computed_root.num_limbs())
        .for_each(|i| builder.connect_u32(computed_root.get_limb(i), root[i]));

    MerkleProofTarget {
        leaf_padded,
        proof,
        root,
    }
}

pub fn add_virtual_next_validators_hash_merkle_proof_target<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleProofTarget {
    let root = builder.add_virtual_hash256_target();
    let proof = (0..*HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let leaf_padded = get_sha_block_target(builder);

    let mut hash = sha256_1_block_hash_target(builder, &leaf_padded);

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

    MerkleProofTarget {
        leaf_padded,
        proof,
        root,
    }
}

pub fn add_virtual_header_time_merkle_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleProofTarget {
    let root = builder.add_virtual_hash256_target();
    let proof = (0..*HEADER_TIME_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let leaf_padded = get_sha_block_target(builder);

    let mut hash = sha256_1_block_hash_target(builder, &leaf_padded);

    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &get_formatted_hash_256_bools(&proof[0]),
        &hash,
    );
    hash = biguint_hash_to_bool_targets(builder, &hash_biguint);
    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &get_formatted_hash_256_bools(&proof[1]),
        &hash,
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
        &hash,
        &get_formatted_hash_256_bools(&proof[3]),
    );

    (0..computed_root.num_limbs())
        .for_each(|i| builder.connect_u32(computed_root.get_limb(i), root[i]));

    MerkleProofTarget {
        leaf_padded,
        proof,
        root,
    }
}

pub fn add_virtual_header_chain_id_merkle_proof_target<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleProofTarget {
    let root = builder.add_virtual_hash256_target();
    let proof = (0..*HEADER_CHAIN_ID_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let leaf_padded = get_sha_block_target(builder);

    let mut hash = sha256_1_block_hash_target(builder, &leaf_padded);

    let hash_biguint = sha256_2_block_two_to_one_hash_target(
        builder,
        &get_formatted_hash_256_bools(&proof[0]),
        &hash,
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
        &hash,
        &get_formatted_hash_256_bools(&proof[3]),
    );

    (0..computed_root.num_limbs())
        .for_each(|i| builder.connect_u32(computed_root.get_limb(i), root[i]));

    MerkleProofTarget {
        leaf_padded,
        proof,
        root,
    }
}

pub fn add_virtual_header_version_merkle_proof_target<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleProofTarget {
    let root = builder.add_virtual_hash256_target();
    let proof = (0..*HEADER_VERSION_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let leaf_padded = get_sha_block_target(builder);

    let mut hash = sha256_1_block_hash_target(builder, &leaf_padded);

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
        &hash,
        &get_formatted_hash_256_bools(&proof[3]),
    );

    (0..computed_root.num_limbs())
        .for_each(|i| builder.connect_u32(computed_root.get_limb(i), root[i]));

    MerkleProofTarget {
        leaf_padded,
        proof,
        root,
    }
}

pub fn add_virtual_update_validity_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> UpdateValidityTarget {
    let untrusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS.div_ceil(32));
    let trusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS.div_ceil(32));
    let untrusted_timestamp = builder
        .add_virtual_biguint_target((TIMESTAMP_BITS.div_ceil(*LEB128_GROUP_SIZE) * 8).div_ceil(32));
    let trusted_timestamp = builder
        .add_virtual_biguint_target((TIMESTAMP_BITS.div_ceil(*LEB128_GROUP_SIZE) * 8).div_ceil(32));
    let untrusted_version_padded = get_sha_block_target(builder);
    let untrusted_chain_id_padded = get_sha_block_target(builder);

    let two_big_target = builder.constant_biguint(&BigUint::from_i8(2).unwrap());
    let one_bool_target = builder._true();

    // ensures untrusted height >= trusted height + 2
    let trusted_height_plus_two = builder.add_biguint(&trusted_height, &two_big_target);
    let result = builder.cmp_biguint(&trusted_height_plus_two, &untrusted_height);
    builder.connect(result.target, one_bool_target.target);

    // ensures trusted height + trusting period >= untrusted height
    let trusting_period_seconds =
        builder.constant_biguint(&BigUint::from_usize(*TRUSTING_PERIOD).unwrap());
    let untrusted_max_allowed_timestamp =
        builder.add_biguint(&trusted_timestamp, &trusting_period_seconds);
    let result = builder.cmp_biguint(&untrusted_timestamp, &untrusted_max_allowed_timestamp);
    builder.connect(result.target, one_bool_target.target);

    // ensure correct version block
    let version_block = VERSION_BLOCK
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
    let chain_id = CHAIN_ID
        .iter()
        .map(|&elm| builder.constant_bool(elm))
        .collect::<Vec<BoolTarget>>();
    (0..chain_id.len()).for_each(|i| {
        builder.connect(untrusted_chain_id_padded[24 + i].target, chain_id[i].target)
    });

    UpdateValidityTarget {
        untrusted_height,
        trusted_height,
        untrusted_timestamp,
        trusted_timestamp,
        untrusted_version_padded,
        untrusted_chain_id_padded,
    }
}

pub fn add_virtual_connect_sign_message_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ConnectSignMessageTarget {
    let messages_padded = (0..*N_SIGNATURE_INDICES)
        .map(|_| get_sha_512_2_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let header_hash = get_256_bool_target(builder);
    let signatures = (0..*N_SIGNATURE_INDICES)
        .map(|_| get_512_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let signature_indexes = (0..*N_SIGNATURE_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let height = builder.add_virtual_biguint_target(HEIGHT_BITS.div_ceil(32));
    let untrusted_pub_keys = (0..*N_VALIDATORS)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();

    let pub_keys = get_random_access_pub_keys(builder, &untrusted_pub_keys, &signature_indexes);

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

    ConnectSignMessageTarget {
        messages_padded,
        header_hash,
        height,
        signatures,
        signature_indexes,
        untrusted_pub_keys,
    }
}

pub fn add_virtual_connect_timestamp_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ConnectTimestampTarget {
    let header_time_padded = get_sha_block_target(builder);
    let header_timestamp = builder
        .add_virtual_biguint_target((TIMESTAMP_BITS.div_ceil(*LEB128_GROUP_SIZE) * 8).div_ceil(32));

    let mut header_timestamp_bits = builder.split_le_base::<2>(header_timestamp.get_limb(0).0, 32);
    let next_bits = builder.split_le_base::<2>(header_timestamp.get_limb(1).0, 32);
    (0..32).for_each(|i| header_timestamp_bits.push(next_bits[i]));

    // 7 bits from each of 5 consecutive bytes in `header_time_padded` starting from the 3rd byte makes up the `header_timestamp_bits`
    // `header_time_padded` contains timestamp in LEB128 format
    let offset = 16;
    (0..TIMESTAMP_BITS.div_ceil(*LEB128_GROUP_SIZE)).for_each(|j| {
        (0..7).for_each(|k| {
            builder.connect(
                header_time_padded[offset + j * 8 + k + 1].target,
                header_timestamp_bits[j * 7 + 7 - 1 - k],
            );
        })
    });

    ConnectTimestampTarget {
        header_time_padded,
        header_timestamp,
    }
}

pub fn add_virtual_connect_pub_keys_vps_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ConnectPubKeysVPsTarget {
    let pub_keys = (0..*N_VALIDATORS)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let vps = (0..*N_VALIDATORS)
        .map(|_| {
            builder
                .add_virtual_biguint_target((VP_BITS.div_ceil(*LEB128_GROUP_SIZE) * 8).div_ceil(32))
        })
        .collect::<Vec<BigUintTarget>>();
    let validators_padded = (0..*N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();

    // 7 bits from each of 10 consecutive bytes in `validators_padded[i]` starting from the 39th byte makes up the `vp_bits`
    // `validators_padded[i]` contains voting power in LEB128 format
    (0..*N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(validators_padded[i][40 + j].target, pub_keys[i][j].target)
        });

        let mut vp_bits = builder.split_le_base::<2>(vps[i].get_limb(0).0, 32);
        let mut next_bits = builder.split_le_base::<2>(vps[i].get_limb(1).0, 32);
        (0..32).for_each(|i| vp_bits.push(next_bits[i]));
        next_bits = builder.split_le_base::<2>(vps[i].get_limb(2).0, 32);
        (0..32).for_each(|i| vp_bits.push(next_bits[i]));

        let offset = (37 + 1) * 8; // add 1 for 0 byte prefix
        (0..VP_BITS.div_ceil(*LEB128_GROUP_SIZE)).for_each(|j| {
            (0..7).for_each(|k| {
                builder.connect(
                    validators_padded[i][offset + j * 8 + k + 1].target,
                    vp_bits[j * 7 + 7 - 1 - k],
                );
            })
        });
    });

    ConnectPubKeysVPsTarget {
        validators_padded,
        pub_keys,
        vps,
    }
}

pub fn add_virtual_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ProofTarget {
    let sign_messages_padded = (0..*N_SIGNATURE_INDICES)
        .map(|_| get_sha_512_2_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let signatures = (0..*N_VALIDATORS)
        .map(|_| {
            (0..*SIGNATURE_BITS)
                .map(|_| builder.add_virtual_bool_target_unsafe())
                .collect()
        })
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_hash = builder.add_virtual_hash256_target();
    let untrusted_version_padded = get_sha_block_target(builder);
    let untrusted_chain_id_padded = get_sha_block_target(builder);
    let untrusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS.div_ceil(32));
    let untrusted_time_padded = get_sha_block_target(builder);
    let untrusted_timestamp = builder
        .add_virtual_biguint_target((TIMESTAMP_BITS.div_ceil(*LEB128_GROUP_SIZE) * 8).div_ceil(32));
    let untrusted_validators_hash_padded = get_sha_block_target(builder);
    let untrusted_validator_pub_keys = (0..*N_VALIDATORS)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_validator_vp = (0..*N_VALIDATORS)
        .map(|_| builder.add_virtual_biguint_target(VP_BITS.div_ceil(32)))
        .collect::<Vec<BigUintTarget>>();
    let untrusted_validators_padded = (0..*N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_version_proof = (0..*HEADER_VERSION_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_chain_id_proof = (0..*HEADER_CHAIN_ID_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_time_proof = (0..*HEADER_TIME_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_validators_hash_proof = (0..*HEADER_VALIDATORS_HASH_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();

    let trusted_hash = builder.add_virtual_hash256_target();
    let trusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS.div_ceil(32));
    let trusted_time_padded = get_sha_block_target(builder);
    let trusted_timestamp = builder
        .add_virtual_biguint_target((TIMESTAMP_BITS.div_ceil(*LEB128_GROUP_SIZE) * 8).div_ceil(32));
    let trusted_next_validators_hash_padded = get_sha_block_target(builder);
    let trusted_next_validator_pub_keys = (0..*N_VALIDATORS)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_next_validator_vp = (0..*N_VALIDATORS)
        .map(|_| builder.add_virtual_biguint_target(VP_BITS.div_ceil(32)))
        .collect::<Vec<BigUintTarget>>();
    let trusted_next_validators_padded = (0..*N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_time_proof = (0..*HEADER_TIME_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_next_validators_hash_proof = (0..*HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_version_proof = (0..*HEADER_VERSION_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_chain_id_proof = (0..*HEADER_CHAIN_ID_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_version_padded = get_sha_block_target(builder);
    let trusted_chain_id_padded = get_sha_block_target(builder);
    let signature_indices = (0..*N_SIGNATURE_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let untrusted_intersect_indices = (0..*N_INTERSECTION_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let trusted_next_intersect_indices = (0..*N_INTERSECTION_INDICES)
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
    let trusted_quorum_target = add_virtual_trusted_quorum_target(builder);
    let untrusted_quorum_target = add_virtual_untrusted_quorum_target(builder);
    // TODO: Later on than checking so many merkle proofs we can just reconstruct the whole header root
    let untrusted_version_merkle_proof_target =
        add_virtual_header_version_merkle_proof_target(builder);
    let untrusted_chain_id_merkle_proof_target =
        add_virtual_header_chain_id_merkle_proof_target(builder);
    let untrusted_time_merkle_proof_target = add_virtual_header_time_merkle_proof_target(builder);
    let untrusted_validators_hash_merkle_proof_target =
        add_virtual_validators_hash_merkle_proof_target(builder);
    let trusted_time_merkle_proof_target = add_virtual_header_time_merkle_proof_target(builder);
    let trusted_next_validators_hash_merkle_proof_target =
        add_virtual_next_validators_hash_merkle_proof_target(builder);
    let trusted_version_merkle_proof_target =
        add_virtual_header_version_merkle_proof_target(builder);
    let trusted_chain_id_merkle_proof_target =
        add_virtual_header_chain_id_merkle_proof_target(builder);
    let update_validity_target = add_virtual_update_validity_target(builder);
    let connect_message_target = add_virtual_connect_sign_message_target(builder);
    let connect_untrusted_timestamp_target = add_virtual_connect_timestamp_target(builder);
    let connect_trusted_timestamp_target = add_virtual_connect_timestamp_target(builder);
    let connect_untrusted_pub_keys_vps_target = add_virtual_connect_pub_keys_vps_target(builder);
    let connect_trusted_next_pub_keys_vps_target = add_virtual_connect_pub_keys_vps_target(builder);
    // TODO: connect approval message height to header root leaf and verify the merkle proof

    // *** TrustedValidatorsQuorumTarget ***
    (0..*TOP_N_VALIDATORS_FOR_INTERSECTION).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                trusted_quorum_target.untrusted_validator_pub_keys[i][j].target,
                untrusted_validator_pub_keys[i][j].target,
            )
        })
    });
    (0..*TOP_N_VALIDATORS_FOR_INTERSECTION).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                trusted_quorum_target.trusted_next_validator_pub_keys[i][j].target,
                trusted_next_validator_pub_keys[i][j].target,
            )
        })
    });
    (0..*N_VALIDATORS).for_each(|i| {
        builder.connect_biguint(
            &trusted_quorum_target.trusted_next_validator_vp[i],
            &trusted_next_validator_vp[i],
        )
    });
    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        builder.connect(
            trusted_quorum_target.signature_indices[i],
            signature_indices[i],
        )
    });
    (0..*N_INTERSECTION_INDICES).for_each(|i| {
        builder.connect(
            trusted_quorum_target.untrusted_intersect_indices[i],
            untrusted_intersect_indices[i],
        )
    });
    (0..*N_INTERSECTION_INDICES).for_each(|i| {
        builder.connect(
            trusted_quorum_target.trusted_next_intersect_indices[i],
            trusted_next_intersect_indices[i],
        )
    });

    // *** UntrustedValidatorsQuorumTarget ***
    (0..*N_VALIDATORS).for_each(|i| {
        builder.connect_biguint(
            &untrusted_quorum_target.untrusted_validator_vp[i],
            &untrusted_validator_vp[i],
        )
    });
    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        builder.connect(
            untrusted_quorum_target.signature_indices[i],
            signature_indices[i],
        )
    });

    // *** MerkleProofTarget - untrusted_version ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            untrusted_version_merkle_proof_target.leaf_padded[i].target,
            untrusted_version_padded[i].target,
        )
    });
    (0..*HEADER_VERSION_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                untrusted_version_merkle_proof_target.proof[i][j].target,
                untrusted_version_proof[i][j].target,
            )
        })
    });
    builder.connect_hash256(untrusted_version_merkle_proof_target.root, untrusted_hash);

    // *** MerkleProofTarget - chain id ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            untrusted_chain_id_merkle_proof_target.leaf_padded[i].target,
            untrusted_chain_id_padded[i].target,
        )
    });
    (0..*HEADER_CHAIN_ID_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                untrusted_chain_id_merkle_proof_target.proof[i][j].target,
                untrusted_chain_id_proof[i][j].target,
            )
        })
    });
    builder.connect_hash256(untrusted_chain_id_merkle_proof_target.root, untrusted_hash);

    // *** MerkleProofTarget - untrusted time ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            untrusted_time_merkle_proof_target.leaf_padded[i].target,
            untrusted_time_padded[i].target,
        )
    });
    (0..*HEADER_TIME_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                untrusted_time_merkle_proof_target.proof[i][j].target,
                untrusted_time_proof[i][j].target,
            )
        })
    });
    builder.connect_hash256(untrusted_time_merkle_proof_target.root, untrusted_hash);

    // *** MerkleProofTarget - untrusted_validators_hash ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            untrusted_validators_hash_merkle_proof_target.leaf_padded[i].target,
            untrusted_validators_hash_padded[i].target,
        )
    });
    (0..*HEADER_VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                untrusted_validators_hash_merkle_proof_target.proof[i][j].target,
                untrusted_validators_hash_proof[i][j].target,
            )
        })
    });
    builder.connect_hash256(
        untrusted_validators_hash_merkle_proof_target.root,
        untrusted_hash,
    );

    // *** MerkleProofTarget - trusted time ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            trusted_time_merkle_proof_target.leaf_padded[i].target,
            trusted_time_padded[i].target,
        )
    });
    (0..*HEADER_TIME_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                trusted_time_merkle_proof_target.proof[i][j].target,
                trusted_time_proof[i][j].target,
            )
        })
    });
    builder.connect_hash256(trusted_time_merkle_proof_target.root, trusted_hash);

    // *** MerkleProofTarget - trusted_next_validators_hash ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            trusted_next_validators_hash_merkle_proof_target.leaf_padded[i].target,
            trusted_next_validators_hash_padded[i].target,
        )
    });
    (0..*HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                trusted_next_validators_hash_merkle_proof_target.proof[i][j].target,
                trusted_next_validators_hash_proof[i][j].target,
            )
        })
    });
    builder.connect_hash256(
        trusted_next_validators_hash_merkle_proof_target.root,
        trusted_hash,
    );

    // *** MerkleProofTarget - trusted_version ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            trusted_version_merkle_proof_target.leaf_padded[i].target,
            trusted_version_padded[i].target,
        )
    });
    (0..*HEADER_VERSION_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                trusted_version_merkle_proof_target.proof[i][j].target,
                trusted_version_proof[i][j].target,
            )
        })
    });
    builder.connect_hash256(trusted_version_merkle_proof_target.root, trusted_hash);

    // *** MerkleProofTarget - trusted chain id ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            trusted_chain_id_merkle_proof_target.leaf_padded[i].target,
            trusted_chain_id_padded[i].target,
        )
    });
    (0..*HEADER_CHAIN_ID_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                trusted_chain_id_merkle_proof_target.proof[i][j].target,
                trusted_chain_id_proof[i][j].target,
            )
        })
    });
    builder.connect_hash256(trusted_chain_id_merkle_proof_target.root, trusted_hash);

    // *** UpdateValidityTarget ***
    builder.connect_biguint(&update_validity_target.untrusted_height, &untrusted_height);
    builder.connect_biguint(&update_validity_target.trusted_height, &trusted_height);
    builder.connect_biguint(
        &update_validity_target.untrusted_timestamp,
        &untrusted_timestamp,
    );
    builder.connect_biguint(
        &update_validity_target.trusted_timestamp,
        &trusted_timestamp,
    );
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            update_validity_target.untrusted_version_padded[i].target,
            untrusted_version_padded[i].target,
        )
    });
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            update_validity_target.untrusted_chain_id_padded[i].target,
            untrusted_chain_id_padded[i].target,
        )
    });

    // *** ConnectSignMessageTarget ***
    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        (0..SHA_BLOCK_BITS * 4).for_each(|j| {
            builder.connect(
                connect_message_target.messages_padded[i][j].target,
                sign_messages_padded[i][j].target,
            )
        });
    });
    // connect header hash
    let untrusted_hash_bool_targets =
        get_formatted_hash_256_bools(&hash256_to_bool_targets(builder, &untrusted_hash));
    (0..256).for_each(|i| {
        builder.connect(
            connect_message_target.header_hash[i].target,
            untrusted_hash_bool_targets[i].target,
        )
    });
    // connect height
    builder.connect_biguint(&connect_message_target.height, &untrusted_height);
    // connect signatures
    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        (0..512).for_each(|j| {
            builder.connect(
                connect_message_target.signatures[i][j].target,
                signatures[i][j].target,
            )
        })
    });
    // connect signature indexes
    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        builder.connect(
            connect_message_target.signature_indexes[i],
            signature_indices[i],
        )
    });
    // connect untrusted_pub_key
    (0..*N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                connect_message_target.untrusted_pub_keys[i][j].target,
                untrusted_validator_pub_keys[i][j].target,
            )
        })
    });

    // *** ConnectTimestampTarget - untrusted ***
    builder.connect_biguint(
        &connect_untrusted_timestamp_target.header_timestamp,
        &untrusted_timestamp,
    );
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            connect_untrusted_timestamp_target.header_time_padded[i].target,
            untrusted_time_padded[i].target,
        )
    });

    // *** ConnectTimestampTarget - trusted ***
    builder.connect_biguint(
        &connect_trusted_timestamp_target.header_timestamp,
        &trusted_timestamp,
    );
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            connect_trusted_timestamp_target.header_time_padded[i].target,
            trusted_time_padded[i].target,
        )
    });

    // connect `untrusted_validators_hash` and `untrusted_validators_hash_padded`
    (0..256).for_each(|i| {
        builder.connect(
            untrusted_validators_hash[i].target,
            untrusted_validators_hash_padded[24 + i].target,
        )
    });

    // connect `trusted_next_validators_hash` and `trusted_next_validators_hash_padded`
    (0..256).for_each(|i| {
        builder.connect(
            trusted_next_validators_hash[i].target,
            trusted_next_validators_hash_padded[24 + i].target,
        )
    });

    // *** ConnectPubKeysVPsTarget - untrusted ***
    (0..*N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                connect_untrusted_pub_keys_vps_target.pub_keys[i][j].target,
                untrusted_validator_pub_keys[i][j].target,
            )
        })
    });
    (0..*N_VALIDATORS).for_each(|i| {
        builder.connect_biguint(
            &connect_untrusted_pub_keys_vps_target.vps[i],
            &untrusted_validator_vp[i],
        )
    });
    (0..*N_VALIDATORS).for_each(|i| {
        (0..SHA_BLOCK_BITS).for_each(|j| {
            builder.connect(
                connect_untrusted_pub_keys_vps_target.validators_padded[i][j].target,
                untrusted_validators_padded[i][j].target,
            )
        })
    });

    // *** ConnectPubKeysVPsTarget - trusted ***
    (0..*N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                connect_trusted_next_pub_keys_vps_target.pub_keys[i][j].target,
                trusted_next_validator_pub_keys[i][j].target,
            )
        })
    });
    (0..*N_VALIDATORS).for_each(|i| {
        builder.connect_biguint(
            &connect_trusted_next_pub_keys_vps_target.vps[i],
            &trusted_next_validator_vp[i],
        )
    });
    (0..*N_VALIDATORS).for_each(|i| {
        (0..SHA_BLOCK_BITS).for_each(|j| {
            builder.connect(
                connect_trusted_next_pub_keys_vps_target.validators_padded[i][j].target,
                trusted_next_validators_padded[i][j].target,
            )
        })
    });

    ProofTarget {
        sign_messages_padded,
        signatures,
        untrusted_hash,
        untrusted_version_padded,
        untrusted_chain_id_padded,
        untrusted_height,
        untrusted_time_padded,
        untrusted_timestamp,
        untrusted_validators_hash_padded,
        untrusted_validators_padded,
        untrusted_validator_pub_keys,
        untrusted_validator_vp,
        untrusted_version_proof,
        untrusted_chain_id_proof,
        untrusted_time_proof,
        untrusted_validators_hash_proof,
        trusted_hash,
        trusted_height,
        trusted_time_padded,
        trusted_timestamp,
        trusted_next_validators_hash_padded,
        trusted_next_validators_padded,
        trusted_next_validator_pub_keys,
        trusted_next_validator_vp,
        trusted_time_proof,
        trusted_next_validators_hash_proof,
        trusted_version_proof,
        trusted_version_padded,
        trusted_chain_id_proof,
        trusted_chain_id_padded,
        signature_indices,
        untrusted_intersect_indices,
        trusted_next_intersect_indices,
    }
}

pub fn set_proof_target<F: RichField, W: Witness<F>>(
    witness: &mut W,
    sign_messages_padded: &Vec<Vec<bool>>,
    signatures: &Vec<Vec<bool>>,
    untrusted_hash: &Vec<u8>,
    untrusted_version_padded: &Vec<bool>,
    untrusted_chain_id_padded: &Vec<bool>,
    untrusted_height: u64,
    untrusted_time_padded: &Vec<bool>,
    untrusted_timestamp: u64,
    untrusted_validators_hash_padded: &Vec<bool>,
    untrusted_validators_padded: &Vec<Vec<bool>>,
    untrusted_validator_pub_keys: &Vec<Vec<bool>>,
    untrusted_validator_vp: &Vec<u64>,
    untrusted_version_proof: &Vec<Vec<bool>>,
    untrusted_chain_id_proof: &Vec<Vec<bool>>,
    untrusted_time_proof: &Vec<Vec<bool>>,
    untrusted_validators_hash_proof: &Vec<Vec<bool>>,
    trusted_hash: &Vec<u8>,
    trusted_height: u64,
    trusted_time_padded: &Vec<bool>,
    trusted_timestamp: u64,
    trusted_next_validators_hash_padded: &Vec<bool>,
    trusted_next_validators_padded: &Vec<Vec<bool>>,
    trusted_next_validator_pub_keys: &Vec<Vec<bool>>,
    trusted_next_validator_vp: &Vec<u64>,
    trusted_time_proof: &Vec<Vec<bool>>,
    trusted_next_validators_hash_proof: &Vec<Vec<bool>>,
    trusted_chain_id_proof: &Vec<Vec<bool>>,
    trusted_version_proof: &Vec<Vec<bool>>,
    signature_indices: &Vec<u8>,
    untrusted_intersect_indices: &Vec<u8>,
    trusted_next_intersect_indices: &Vec<u8>,
    trusted_chain_id_padded: &Vec<bool>,
    trusted_version_padded: &Vec<bool>,
    target: &ProofTarget,
) {
    // Set *N_SIGNATURE_INDICES signed messages (each message is already padded as sha512 - 2 block)
    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        (0..SHA_BLOCK_BITS * 4).for_each(|j| {
            witness.set_bool_target(
                target.sign_messages_padded[i][j],
                sign_messages_padded[i][j],
            )
        });
    });
    // Set *N_SIGNATURE_INDICES signatures
    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        (0..*SIGNATURE_BITS)
            .for_each(|j| witness.set_bool_target(target.signatures[i][j], signatures[i][j]))
    });

    // Set new block hash target (new block hash is sha256 digest)
    let mut untrusted_hash_slice = [0u8; 32];
    untrusted_hash_slice.copy_from_slice(untrusted_hash.as_slice());
    witness.set_hash256_target(&target.untrusted_hash, &untrusted_hash_slice);

    // Untrusted header version as padded sha256 - 1 block
    // We take in padded input as it is a leaf in block header
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.untrusted_version_padded[i],
            untrusted_version_padded[i],
        )
    });

    // Untrusted chain id as padded sha256 - 1 block
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.untrusted_chain_id_padded[i],
            untrusted_chain_id_padded[i],
        )
    });

    // Untrusted Height as biguint target (u64)
    witness.set_biguint_target(
        &target.untrusted_height,
        &BigUint::from_u64(untrusted_height).unwrap(),
    );

    // untrusted_time_padded is constrained with untrusted_timestamp inside the ckt
    // Untrusted time padded as padded sha256 - 1 block
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(target.untrusted_time_padded[i], untrusted_time_padded[i])
    });

    // Untrusted time stamp as BigUintTarget
    witness.set_biguint_target(
        &target.untrusted_timestamp,
        &BigUint::from_u64(untrusted_timestamp).unwrap(),
    );

    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.untrusted_validators_hash_padded[i],
            untrusted_validators_hash_padded[i],
        )
    });

    // Set *N_VALIDATORS (total vals of block) pub keys as target to reconstruct untrusted_validators_hash
    // TODO: will break with *N_VALIDATORS != 150
    (0..*N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.untrusted_validator_pub_keys[i][j],
                untrusted_validator_pub_keys[i][j],
            )
        })
    });
    // Set *N_VALIDATORS (total vals of block) voting powers as target to reconstruct untrusted_validators_hash
    // To verify 2/3rd majority
    (0..*N_VALIDATORS).for_each(|i| {
        witness.set_biguint_target(
            &target.untrusted_validator_vp[i],
            &BigUint::from_u64(untrusted_validator_vp[i]).unwrap(),
        )
    });

    // We take already padded *N_VALIDATORS untrusted validator and then connect untrusted_validator_vp
    // and untrusted_validator_pub_keys
    (0..*N_VALIDATORS).for_each(|i| {
        (0..SHA_BLOCK_BITS).for_each(|j| {
            witness.set_bool_target(
                target.untrusted_validators_padded[i][j],
                untrusted_validators_padded[i][j],
            )
        })
    });

    // HEADER_VERSION_PROOF_SIZE != 4 will break
    // merkle inclusion proof of header version in header root
    (0..*HEADER_VERSION_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.untrusted_version_proof[i][j],
                untrusted_version_proof[i][j],
            )
        })
    });

    // HEADER_CHAIN_ID_PROOF_SIZE != 4 will break
    // merkle inclusion proof of header chain id in header root
    (0..*HEADER_CHAIN_ID_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.untrusted_chain_id_proof[i][j],
                untrusted_chain_id_proof[i][j],
            )
        })
    });

    // HEADER_TIME_PROOF_SIZE != 4 will break
    // merkle inclusion proof of time in header root
    (0..*HEADER_TIME_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.untrusted_time_proof[i][j],
                untrusted_time_proof[i][j],
            )
        })
    });

    // HEADER_TIME_PROOF_SIZE != 4 will break
    // merkle inclusion proof of validators hash in header root
    (0..*HEADER_VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.untrusted_validators_hash_proof[i][j],
                untrusted_validators_hash_proof[i][j],
            )
        })
    });

    // Set trusted header root
    let mut trusted_hash_slice = [0u8; 32];
    trusted_hash_slice.copy_from_slice(trusted_hash.as_slice());
    witness.set_hash256_target(&target.trusted_hash, &trusted_hash_slice);

    // Set trusted height
    witness.set_biguint_target(
        &target.trusted_height,
        &BigUint::from_u64(trusted_height).unwrap(),
    );

    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(target.trusted_version_padded[i], trusted_version_padded[i])
    });

    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.trusted_chain_id_padded[i],
            trusted_chain_id_padded[i],
        )
    });

    // Set trusted time padded
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(target.trusted_time_padded[i], trusted_time_padded[i])
    });

    // Set trusted timestamp
    witness.set_biguint_target(
        &target.trusted_timestamp,
        &BigUint::from_u64(trusted_timestamp).unwrap(),
    );

    // We take trusted next validators hash padded
    (0..SHA_BLOCK_BITS).for_each(|i| {
        witness.set_bool_target(
            target.trusted_next_validators_hash_padded[i],
            trusted_next_validators_hash_padded[i],
        )
    });

    (0..*N_VALIDATORS).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.trusted_next_validator_pub_keys[i][j],
                trusted_next_validator_pub_keys[i][j],
            )
        })
    });

    (0..*N_VALIDATORS).for_each(|i| {
        witness.set_biguint_target(
            &target.trusted_next_validator_vp[i],
            &BigUint::from_u64(trusted_next_validator_vp[i]).unwrap(),
        )
    });
    (0..*N_VALIDATORS).for_each(|i| {
        (0..SHA_BLOCK_BITS).for_each(|j| {
            witness.set_bool_target(
                target.trusted_next_validators_padded[i][j],
                trusted_next_validators_padded[i][j],
            )
        })
    });
    (0..*HEADER_TIME_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(target.trusted_time_proof[i][j], trusted_time_proof[i][j])
        })
    });
    (0..*HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.trusted_next_validators_hash_proof[i][j],
                trusted_next_validators_hash_proof[i][j],
            )
        })
    });
    (0..*HEADER_VERSION_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.trusted_version_proof[i][j],
                trusted_version_proof[i][j],
            )
        })
    });
    (0..*HEADER_CHAIN_ID_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.trusted_chain_id_proof[i][j],
                trusted_chain_id_proof[i][j],
            )
        })
    });
    (0..*N_SIGNATURE_INDICES).for_each(|i| {
        witness.set_target(
            target.signature_indices[i],
            F::from_canonical_u8(signature_indices[i]),
        )
    });
    (0..*N_INTERSECTION_INDICES).for_each(|i| {
        witness.set_target(
            target.untrusted_intersect_indices[i],
            F::from_canonical_u8(untrusted_intersect_indices[i]),
        )
    });
    (0..*N_INTERSECTION_INDICES).for_each(|i| {
        witness.set_target(
            target.trusted_next_intersect_indices[i],
            F::from_canonical_u8(trusted_next_intersect_indices[i]),
        )
    });
}
