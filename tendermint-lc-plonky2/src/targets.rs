use super::merkle_tree_gadget::{
    add_virtual_merkle_tree_1_block_leaf_target, get_256_bool_target, get_sha_block_target,
    sha256_1_block, sha256_2_block, two_to_one_pad_target, SHA_BLOCK_BITS,
};
use num::{BigUint, FromPrimitive};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::biguint::{BigUintTarget, CircuitBuilderBiguint};

pub struct VerifySignatures {
    pub signatures: Vec<Vec<BoolTarget>>,
    pub verify: Vec<BoolTarget>,
}

pub struct TrustedValidatorsQuorumTarget {
    pub untrusted_validator_pub_keys: Vec<Vec<BoolTarget>>,
    pub trusted_validator_pub_keys: Vec<Vec<BoolTarget>>,
    pub trusted_validator_votes: Vec<BigUintTarget>,
    pub is_not_null_signature: Vec<BoolTarget>,
    pub untrusted_intersect_indices: Vec<Target>,
    pub trusted_intersect_indices: Vec<Target>,
}

pub struct MerkleProofTarget {
    pub leaf_padded: Vec<BoolTarget>, // shaBlock(0x00 || leaf)
    pub proof: Vec<Vec<BoolTarget>>,
    pub root: Vec<BoolTarget>,
}

pub struct UpdateValidityTarget {
    pub untrusted_height: BigUintTarget,
    pub trusted_height: BigUintTarget,
    pub untrusted_timestamp: BigUintTarget,
    pub trusted_timestamp: BigUintTarget,
}

pub struct ConnectSignMessageTarget {
    pub message: Vec<BoolTarget>,
    pub header_hash: Vec<BoolTarget>,
    pub height: BigUintTarget,
}

pub struct ConnectTimestampTarget {
    pub header_time_padded: Vec<BoolTarget>,
    pub header_timestamp: BigUintTarget,
}

/* indices */
// ensure each corresponding signature is not null
// 0 indices are reserved to indicate null values, that is, no intersection
// index must not exceed `N_VALIDATORS_FOR_INTERSECTION`

// all padded leaves are of the form: shaBlock(0x00 || leaf)
pub struct ProofTarget {
    pub sign_message: Vec<BoolTarget>,
    pub untrusted_hash: Vec<BoolTarget>,
    pub untrusted_height: BigUintTarget,
    pub untrusted_time_padded: Vec<BoolTarget>,
    pub untrusted_time_proof: Vec<Vec<BoolTarget>>,
    pub untrusted_timestamp: BigUintTarget, // Unix timestamps in seconds
    pub untrusted_validators_hash_padded: Vec<BoolTarget>,
    pub untrusted_validators_padded: Vec<Vec<BoolTarget>>,
    pub untrusted_validators_hash_proof: Vec<Vec<BoolTarget>>,
    pub trusted_hash: Vec<BoolTarget>,
    pub trusted_height: BigUintTarget,
    pub trusted_time_padded: Vec<BoolTarget>,
    pub trusted_time_proof: Vec<Vec<BoolTarget>>,
    pub trusted_timestamp: BigUintTarget, // Unix timestamps in seconds
    pub trusted_next_validators_padded: Vec<Vec<BoolTarget>>,
}

pub const N_VALIDATORS: usize = 150;
pub const VALIDATORS_HASH_PROOF_SIZE: usize = 4;
pub const HEADER_TIME_PROOF_SIZE: usize = 4;
pub const SIGN_MESSAGE_BITS: usize = 110 * 8;
pub const HEIGHT_BITS: usize = 64;
pub const TIMESTAMP_BITS: usize = 35; // will be able to accomodate for new blocks till the year 3058
pub const TRUSTING_PERIOD: usize = 1209600; // 2 weeks in seconds
pub const N_INTERSECTION_INDICES: usize = 50;
// TODO: make it 128 - error
pub const N_VALIDATORS_FOR_INTERSECTION: usize = 64; // must be a power of two

pub fn add_virtual_trusted_quorum_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> TrustedValidatorsQuorumTarget {
    let untrusted_validator_pub_keys = (0..N_VALIDATORS)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_validator_pub_keys = (0..N_VALIDATORS)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_validator_votes = (0..N_VALIDATORS)
        .map(|_| builder.add_virtual_biguint_target(2))
        .collect::<Vec<BigUintTarget>>();
    let is_not_null_signature = (0..N_VALIDATORS)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect::<Vec<BoolTarget>>();
    let untrusted_intersect_indices = (0..N_INTERSECTION_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let trusted_intersect_indices = (0..N_INTERSECTION_INDICES)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();

    let zero_bool_target = builder._false();
    let one_bool_target = builder._true();
    let three_big_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap());
    let mut total_votes = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut intersection_votes = builder.constant_biguint(&BigUint::from_usize(0).unwrap());

    // compute total votes
    (0..N_VALIDATORS)
        .for_each(|i| total_votes = builder.add_biguint(&total_votes, &trusted_validator_votes[i]));

    // prepare votes columns
    let trusted_validator_votes_columns = vec![
        trusted_validator_votes[..N_VALIDATORS_FOR_INTERSECTION]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        trusted_validator_votes[..N_VALIDATORS_FOR_INTERSECTION]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];

    // prepare pub keys columns
    let mut untrusted_pub_keys_columns: Vec<Vec<Target>> = vec![];
    let mut trusted_pub_keys_columns: Vec<Vec<Target>> = vec![];
    (0..256).for_each(|i| {
        let mut untrusted_pub_key_column: Vec<Target> = vec![];
        let mut trusted_pub_key_column: Vec<Target> = vec![];
        (0..N_VALIDATORS_FOR_INTERSECTION).for_each(|j| {
            untrusted_pub_key_column.push(untrusted_validator_pub_keys[j][i].target);
            trusted_pub_key_column.push(trusted_validator_pub_keys[j][i].target);
        });
        untrusted_pub_keys_columns.push(untrusted_pub_key_column);
        trusted_pub_keys_columns.push(trusted_pub_key_column);
    });

    // get is_not_null in `Target` from `BoolTarget``
    let is_not_null_signature_targets = is_not_null_signature[..N_VALIDATORS_FOR_INTERSECTION]
        .iter()
        .map(|&elm| elm.target)
        .collect::<Vec<Target>>();

    (0..N_INTERSECTION_INDICES).for_each(|i| {
        let random_access_index = trusted_intersect_indices[i];
        let is_zero_index = builder.is_equal(random_access_index, zero_bool_target.target);
        let enable_constraint = builder.not(is_zero_index); // constrain only if index is non-zero; 0 is reserved for no intersection (null)

        let is_not_null =
            builder.random_access(random_access_index, is_not_null_signature_targets.clone());
        let mut a = builder.mul(is_not_null, enable_constraint.target);
        let mut b = builder.mul(one_bool_target.target, enable_constraint.target);
        builder.connect(a, b);

        // compute intersection votes in trusted
        let mut vote = builder.add_virtual_biguint_target(2);
        let vote_c0 = builder.random_access(
            random_access_index,
            trusted_validator_votes_columns[0].clone(),
        );
        let vote_c1 = builder.random_access(
            random_access_index,
            trusted_validator_votes_columns[1].clone(),
        );
        builder.connect(vote.get_limb(0).0, vote_c0);
        builder.connect(vote.get_limb(1).0, vote_c1);
        vote = builder.mul_biguint_by_bool(&vote, enable_constraint);
        intersection_votes = builder.add_biguint(&intersection_votes, &vote);

        // ensure intersection pub keys
        (0..256).for_each(|j| {
            let untrusted_key = builder.random_access(
                untrusted_intersect_indices[i],
                untrusted_pub_keys_columns[j].clone(),
            );
            let trusted_key = builder.random_access(
                trusted_intersect_indices[i],
                trusted_pub_keys_columns[j].clone(),
            );
            a = builder.mul(untrusted_key, enable_constraint.target);
            b = builder.mul(trusted_key, enable_constraint.target);
            builder.connect(a, b);
        });
    });

    // ensures 3 * intersection votes > total_votes
    let three_times_intersection_votes =
        builder.mul_biguint(&intersection_votes, &three_big_target);
    let comparison = builder.cmp_biguint(&three_times_intersection_votes, &total_votes);
    builder.connect(comparison.target, zero_bool_target.target);

    TrustedValidatorsQuorumTarget {
        untrusted_validator_pub_keys,
        trusted_validator_pub_keys,
        trusted_validator_votes,
        is_not_null_signature,
        untrusted_intersect_indices,
        trusted_intersect_indices,
    }
}

pub fn add_virtual_verify_signatures_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> VerifySignatures {
    let signatures = (0..N_VALIDATORS)
        .map(|_| {
            (0..64 * 8)
                .map(|_| builder.add_virtual_bool_target_safe())
                .collect()
        })
        .collect::<Vec<Vec<BoolTarget>>>();
    let verify = (0..N_VALIDATORS)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect::<Vec<BoolTarget>>();

    VerifySignatures { signatures, verify }
}

pub fn is_not_null_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signatures: Vec<Vec<BoolTarget>>,
) -> Vec<BoolTarget> {
    let mut is_null_signature = (0..signatures.len())
        .map(|_| builder._false())
        .collect::<Vec<BoolTarget>>();
    for i in 0..signatures.len() {
        for j in 0..signatures[i].len() {
            is_null_signature[i] = builder.or(is_null_signature[i], signatures[i][j]);
        }
    }
    is_null_signature
}

// TODO: starky
pub fn verify_signatures<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signatures: Vec<Vec<BoolTarget>>,
) -> Vec<BoolTarget> {
    let verify = (0..signatures.len())
        .map(|_| builder._true())
        .collect::<Vec<BoolTarget>>();
    verify
}

pub fn add_virtual_validators_hash_merkle_proof_target<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleProofTarget {
    let root = get_256_bool_target(builder);
    let proof = (0..VALIDATORS_HASH_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let leaf_padded = get_sha_block_target(builder);

    let mut hash = sha256_1_block(builder, &leaf_padded);

    let mut pad_result = two_to_one_pad_target(builder, &proof[0], &hash);
    hash = sha256_2_block(builder, &pad_result);

    pad_result = two_to_one_pad_target(builder, &proof[1], &hash);
    hash = sha256_2_block(builder, &pad_result);

    pad_result = two_to_one_pad_target(builder, &proof[2], &hash);
    hash = sha256_2_block(builder, &pad_result);

    pad_result = two_to_one_pad_target(builder, &hash, &proof[3]);
    hash = sha256_2_block(builder, &pad_result);

    (0..256).for_each(|i| builder.connect(hash[i].target, root[i].target));

    MerkleProofTarget {
        leaf_padded,
        proof,
        root,
    }
}

pub fn add_virtual_header_time_merkle_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleProofTarget {
    let root = get_256_bool_target(builder);
    let proof = (0..HEADER_TIME_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let leaf_padded = get_sha_block_target(builder);

    let mut hash = sha256_1_block(builder, &leaf_padded);

    let mut pad_result = two_to_one_pad_target(builder, &proof[0], &hash);
    hash = sha256_2_block(builder, &pad_result);

    pad_result = two_to_one_pad_target(builder, &proof[1], &hash);
    hash = sha256_2_block(builder, &pad_result);

    pad_result = two_to_one_pad_target(builder, &hash, &proof[2]);
    hash = sha256_2_block(builder, &pad_result);

    pad_result = two_to_one_pad_target(builder, &hash, &proof[3]);
    hash = sha256_2_block(builder, &pad_result);

    (0..256).for_each(|i| builder.connect(hash[i].target, root[i].target));

    MerkleProofTarget {
        leaf_padded,
        proof,
        root,
    }
}

pub fn validators_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaves_padded: Vec<Vec<BoolTarget>>,
) -> Vec<BoolTarget> {
    let hash = get_256_bool_target(builder);

    let merkle_tree = add_virtual_merkle_tree_1_block_leaf_target(builder, N_VALIDATORS);

    (0..N_VALIDATORS).for_each(|i| {
        (0..SHA_BLOCK_BITS).for_each(|j| {
            builder.connect(
                merkle_tree.leaves_padded[i][j].target,
                leaves_padded[i][j].target,
            )
        })
    });
    (0..256).for_each(|i| builder.connect(merkle_tree.root[i].target, hash[i].target));

    hash
}

pub fn add_virtual_update_validity_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> UpdateValidityTarget {
    let untrusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);
    let trusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);
    let untrusted_timestamp = builder.add_virtual_biguint_target(TIMESTAMP_BITS.div_ceil(32));
    let trusted_timestamp = builder.add_virtual_biguint_target(TIMESTAMP_BITS.div_ceil(32));

    let two_big_target = builder.constant_biguint(&BigUint::from_i8(2).unwrap());
    let one_bool_target = builder._true();

    // ensures untrusted height >= trusted height + 2
    let trusted_height_plus_two = builder.add_biguint(&trusted_height, &two_big_target);
    let result = builder.cmp_biguint(&trusted_height_plus_two, &untrusted_height);
    builder.connect(result.target, one_bool_target.target);

    // ensures trusted height + trusting period >= untrusted height
    // TODO: verify trusting period once
    let trusting_period_seconds =
        builder.constant_biguint(&BigUint::from_usize(TRUSTING_PERIOD).unwrap());
    let untrusted_max_allowed_timestamp =
        builder.add_biguint(&trusted_timestamp, &trusting_period_seconds);
    let result = builder.cmp_biguint(&untrusted_timestamp, &untrusted_max_allowed_timestamp);
    builder.connect(result.target, one_bool_target.target);

    UpdateValidityTarget {
        untrusted_height,
        trusted_height,
        untrusted_timestamp,
        trusted_timestamp,
    }
}

pub fn add_virtual_connect_sign_message_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ConnectSignMessageTarget {
    let message = (0..SIGN_MESSAGE_BITS)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect::<Vec<BoolTarget>>();
    let header_hash = get_256_bool_target(builder);
    let height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);

    // connect header hash in message
    // header hash takes the position at [128, 128+256)
    (0..256).for_each(|i| builder.connect(message[128 + i].target, header_hash[i].target));

    // connect header height in message
    // header height takes the position at [32, 32+64)
    let offset = 32;
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

    ConnectSignMessageTarget {
        message,
        header_hash,
        height,
    }
}

pub fn add_virtual_connect_timestamp_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ConnectTimestampTarget {
    let header_time_padded = get_sha_block_target(builder);
    let header_timestamp = builder.add_virtual_biguint_target(TIMESTAMP_BITS.div_ceil(32));

    let mut header_timestamp_bits = builder.split_le_base::<2>(header_timestamp.get_limb(0).0, 32);
    let next_bits = builder.split_le_base::<2>(header_timestamp.get_limb(1).0, 32);
    (0..8).for_each(|i| header_timestamp_bits.push(next_bits[i]));

    // 7 bits from each of 5 consecutive bytes in `header_time_padded` starting from 3rd bytes makes up the `header_timestamp_bits`
    // `header_time_padded` contains timestamp in LEB128 format
    let offset = 16;
    (0..TIMESTAMP_BITS.div_ceil(7)).for_each(|j| {
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

pub fn add_virtual_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ProofTarget {
    let sign_message = (0..SIGN_MESSAGE_BITS)
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect::<Vec<BoolTarget>>();
    let untrusted_hash = get_256_bool_target(builder);
    let untrusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);
    let untrusted_time_padded = get_sha_block_target(builder);
    let untrusted_time_proof = (0..HEADER_TIME_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_timestamp = builder.add_virtual_biguint_target(TIMESTAMP_BITS.div_ceil(32));
    let untrusted_validators_hash_padded = get_sha_block_target(builder);
    let untrusted_validators_padded = (0..N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_validators_hash_proof = (0..VALIDATORS_HASH_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_hash = get_256_bool_target(builder);
    let trusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);
    let trusted_time_padded = get_sha_block_target(builder);
    let trusted_timestamp = builder.add_virtual_biguint_target(TIMESTAMP_BITS.div_ceil(32));
    let trusted_time_proof = (0..HEADER_TIME_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_next_validators_padded = (0..N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();

    let untrusted_validators_hash =
        validators_hash_target(builder, untrusted_validators_padded.clone());
    let trusted_next_validators_hash =
        validators_hash_target(builder, trusted_next_validators_padded.clone());
    let untrusted_validators_hash_merkle_proof_target =
        add_virtual_validators_hash_merkle_proof_target(builder);
    let untrusted_time_merkle_proof_target = add_virtual_header_time_merkle_proof_target(builder);
    let trusted_time_merkle_proof_target = add_virtual_header_time_merkle_proof_target(builder);
    let update_validity_target = add_virtual_update_validity_target(builder);
    let connect_message_target = add_virtual_connect_sign_message_target(builder);
    let connect_untrusted_timestamp_target = add_virtual_connect_timestamp_target(builder);
    let connect_trusted_timestamp_target = add_virtual_connect_timestamp_target(builder);

    // *** MerkleProofTarget - untrusted_validators_hash ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            untrusted_validators_hash_merkle_proof_target.leaf_padded[i].target,
            untrusted_validators_hash_padded[i].target,
        )
    });
    (0..VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                untrusted_validators_hash_merkle_proof_target.proof[i][j].target,
                untrusted_validators_hash_proof[i][j].target,
            )
        })
    });
    (0..256).for_each(|i| {
        builder.connect(
            untrusted_validators_hash_merkle_proof_target.root[i].target,
            untrusted_hash[i].target,
        )
    });

    // *** MerkleProofTarget - untrusted time ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            untrusted_time_merkle_proof_target.leaf_padded[i].target,
            untrusted_time_padded[i].target,
        )
    });
    (0..HEADER_TIME_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                untrusted_time_merkle_proof_target.proof[i][j].target,
                untrusted_time_proof[i][j].target,
            )
        })
    });
    (0..256).for_each(|i| {
        builder.connect(
            untrusted_time_merkle_proof_target.root[i].target,
            untrusted_hash[i].target,
        )
    });

    // *** MerkleProofTarget - trusted time ***
    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            trusted_time_merkle_proof_target.leaf_padded[i].target,
            trusted_time_padded[i].target,
        )
    });
    (0..HEADER_TIME_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            builder.connect(
                trusted_time_merkle_proof_target.proof[i][j].target,
                trusted_time_proof[i][j].target,
            )
        })
    });
    (0..256).for_each(|i| {
        builder.connect(
            trusted_time_merkle_proof_target.root[i].target,
            trusted_hash[i].target,
        )
    });

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

    // *** ConnectSignMessageTarget ***
    (0..SIGN_MESSAGE_BITS).for_each(|i| {
        builder.connect(
            connect_message_target.message[i].target,
            sign_message[i].target,
        )
    });
    (0..256).for_each(|i| {
        builder.connect(
            connect_message_target.header_hash[i].target,
            untrusted_hash[i].target,
        )
    });
    builder.connect_biguint(&connect_message_target.height, &untrusted_height);

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
            untrusted_validators_hash_padded[8 + i].target,
        )
    });

    ProofTarget {
        sign_message,
        untrusted_hash,
        untrusted_height,
        untrusted_time_padded,
        untrusted_time_proof,
        untrusted_timestamp,
        untrusted_validators_hash_padded,
        untrusted_validators_padded,
        untrusted_validators_hash_proof,
        trusted_hash,
        trusted_height,
        trusted_time_padded,
        trusted_timestamp,
        trusted_time_proof,
        trusted_next_validators_padded,
    }
}
