use super::merkle_targets::{
    get_256_bool_target, get_formatted_hash_256_bools, get_sha_2_block_target,
    get_sha_512_2_block_target, get_sha_block_target, hash256_to_bool_targets, header_merkle_root,
    merkle_1_block_leaf_root, verify_next_validators_hash_merkle_proof, SHA_BLOCK_BITS,
};
use crate::circuits::checks::check_update_validity;
use crate::circuits::connect::{connect_pub_keys_and_vps, connect_timestamp};
use crate::circuits::indices::constrain_indices;
use crate::circuits::sign_messages::verify_signatures;
use crate::circuits::validators_quorum::{constrain_trusted_quorum, constrain_untrusted_quorum};
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
use std::array::IntoIter;

use crate::config_data::*;
use crate::input_types::HeaderPadded;

// TODO: use BlockIDFlag: https://pkg.go.dev/github.com/tendermint/tendermint@v0.35.9/types#BlockIDFlag

pub struct VerifySignatures {
    pub signatures: Vec<Vec<BoolTarget>>,
    pub messaged_padded: Vec<Vec<BoolTarget>>,
    pub pub_keys: Vec<Vec<BoolTarget>>,
}

// each field is prefixed with a 0-byte, then padded as a sha blocks
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

pub struct ProofTarget {
    pub sign_messages_padded_set_1: Vec<Vec<BoolTarget>>,
    pub sign_messages_padded_set_2: Vec<Vec<BoolTarget>>,

    pub signatures_set_1: Vec<Vec<BoolTarget>>,
    pub signatures_set_2: Vec<Vec<BoolTarget>>,

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

    pub trusted_next_validators_hash_proof: Vec<Vec<BoolTarget>>,

    pub signature_indices_set_1: Vec<Target>,
    pub signature_indices_set_2: Vec<Target>,

    pub untrusted_intersect_indices_set_1: Vec<Target>,
    pub untrusted_intersect_indices_set_2: Vec<Target>,
    pub trusted_next_intersect_indices_set_1: Vec<Target>,
    pub trusted_next_intersect_indices_set_2: Vec<Target>,
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
    let sign_messages_padded_set_1 = (0..c.N_SIGNATURE_INDICES_SET_1)
        .map(|_| get_sha_512_2_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let sign_messages_padded_set_2 = (0..c.N_SIGNATURE_INDICES_SET_2)
        .map(|_| get_sha_512_2_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let signatures_set_1 = (0..c.N_SIGNATURE_INDICES_SET_1)
        .map(|_| {
            (0..c.SIGNATURE_BITS)
                .map(|_| builder.add_virtual_bool_target_unsafe())
                .collect()
        })
        .collect::<Vec<Vec<BoolTarget>>>();
    let signatures_set_2 = (0..c.N_SIGNATURE_INDICES_SET_2)
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

    let trusted_next_validators_hash_proof = (0..c.HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();

    let signature_indices_set_1 = (0..c.N_SIGNATURE_INDICES_SET_1)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let signature_indices_set_2 = (0..c.N_SIGNATURE_INDICES_SET_2)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let untrusted_intersect_indices_set_1 = (0..c.N_INTERSECTION_INDICES_SET_1)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let untrusted_intersect_indices_set_2 = (0..c.N_INTERSECTION_INDICES_SET_2)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let trusted_next_intersect_indices_set_1 = (0..c.N_INTERSECTION_INDICES_SET_1)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<Target>>();
    let trusted_next_intersect_indices_set_2 = (0..c.N_INTERSECTION_INDICES_SET_2)
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
        &untrusted_intersect_indices_set_1,
        &untrusted_intersect_indices_set_2,
        &trusted_next_intersect_indices_set_1,
        &trusted_next_intersect_indices_set_2,
        c,
    );
    constrain_untrusted_quorum(builder, &untrusted_validator_vps, &signature_indices_set_1, &signature_indices_set_2,c);
    check_update_validity(
        builder,
        &untrusted_height,
        &trusted_height,
        &untrusted_timestamp,
        &trusted_timestamp,
        &untrusted_header_padded.version,
        &untrusted_header_padded.chain_id,
        c,
    );
    connect_timestamp(
        builder,
        &untrusted_header_padded.time,
        &untrusted_timestamp,
        c,
    );
    connect_timestamp(builder, &trusted_header_padded.time, &trusted_timestamp, c);
    connect_pub_keys_and_vps(
        builder,
        &untrusted_validator_pub_keys,
        &untrusted_validators_padded,
        &untrusted_validator_vps,
        c,
    );
    connect_pub_keys_and_vps(
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
    verify_signatures(
        builder,
        &sign_messages_padded_set_1,
        &sign_messages_padded_set_2,

        &signatures_set_1,
        &signatures_set_2,

        &untrusted_validator_pub_keys,
        &untrusted_hash_bool_targets_formatted,
        &untrusted_height,
        &signature_indices_set_1,
        &signature_indices_set_2,
        c,
    );
    verify_next_validators_hash_merkle_proof(
        builder,
        &trusted_header_padded.next_validators_hash,
        &trusted_next_validators_hash_proof,
        &trusted_hash,
    );
    constrain_indices(builder, &signature_indices_set_1, &signature_indices_set_2, &untrusted_intersect_indices_set_1, &untrusted_intersect_indices_set_2, &c);

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
        sign_messages_padded_set_1,
        sign_messages_padded_set_2,

        signatures_set_1,
        signatures_set_2,


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

        trusted_next_validators_hash_proof,

        signature_indices_set_1,
        signature_indices_set_2,
        untrusted_intersect_indices_set_1,
        untrusted_intersect_indices_set_2,
        trusted_next_intersect_indices_set_1,
        trusted_next_intersect_indices_set_2,
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
    sign_messages_padded_set_1: &Vec<Vec<bool>>,
    sign_messages_padded_set_2: &Vec<Vec<bool>>,

    signatures_set_1: &Vec<Vec<bool>>,
    signatures_set_2: &Vec<Vec<bool>>,

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

    trusted_next_validators_hash_proof: &Vec<Vec<bool>>,

    signature_indices_set_1: &Vec<u8>,
    signature_indices_set_2: &Vec<u8>,

    untrusted_intersect_indices_set_1: &Vec<u8>,
    untrusted_intersect_indices_set_2: &Vec<u8>,
    trusted_next_intersect_indices_set_1: &Vec<u8>,
    trusted_next_intersect_indices_set_2: &Vec<u8>,

    target: &ProofTarget,
    c: &Config,
) {
    // Set N_SIGNATURE_INDICES signed messages (each message is already padded as sha512 - 2 block)
    (0..c.N_SIGNATURE_INDICES_SET_1).for_each(|i| {
        (0..SHA_BLOCK_BITS * 4).for_each(|j| {
            witness.set_bool_target(
                target.sign_messages_padded_set_1[i][j],
                sign_messages_padded_set_1[i][j],
            )
        });
    });

    (0..c.N_SIGNATURE_INDICES_SET_2).for_each(|i| {
        (0..SHA_BLOCK_BITS * 4).for_each(|j| {
            witness.set_bool_target(
                target.sign_messages_padded_set_2[i][j],
                sign_messages_padded_set_2[i][j],
            )
        });
    });

    
    // Set N_SIGNATURE_INDICES signatures
    (0..c.N_SIGNATURE_INDICES_SET_1).for_each(|i| {
        (0..c.SIGNATURE_BITS)
            .for_each(|j| witness.set_bool_target(target.signatures_set_1[i][j], signatures_set_1[i][j]))
    });
    (0..c.N_SIGNATURE_INDICES_SET_2).for_each(|i| {
        (0..c.SIGNATURE_BITS)
            .for_each(|j| witness.set_bool_target(target.signatures_set_2[i][j], signatures_set_2[i][j]))
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

    (0..c.HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
        (0..256).for_each(|j| {
            witness.set_bool_target(
                target.trusted_next_validators_hash_proof[i][j],
                trusted_next_validators_hash_proof[i][j],
            )
        })
    });

    (0..c.N_SIGNATURE_INDICES_SET_1).for_each(|i| {
        witness.set_target(
            target.signature_indices_set_1[i],
            F::from_canonical_u8(signature_indices_set_1[i]),
        )
    });
    (0..c.N_SIGNATURE_INDICES_SET_2).for_each(|i| {
        witness.set_target(
            target.signature_indices_set_2[i],
            F::from_canonical_u8(signature_indices_set_2[i]),
        )
    });
    (0..c.N_INTERSECTION_INDICES_SET_1).for_each(|i| {
        witness.set_target(
            target.untrusted_intersect_indices_set_1[i],
            F::from_canonical_u8(untrusted_intersect_indices_set_1[i]),
        )
    });
    (0..c.N_INTERSECTION_INDICES_SET_2).for_each(|i| {
        witness.set_target(
            target.untrusted_intersect_indices_set_2[i],
            F::from_canonical_u8(untrusted_intersect_indices_set_2[i]),
        )
    });
    (0..c.N_INTERSECTION_INDICES_SET_1).for_each(|i| {
        witness.set_target(
            target.trusted_next_intersect_indices_set_1[i],
            F::from_canonical_u8(trusted_next_intersect_indices_set_1[i]),
        )
    });
    (0..c.N_INTERSECTION_INDICES_SET_2).for_each(|i| {
        witness.set_target(
            target.trusted_next_intersect_indices_set_2[i],
            F::from_canonical_u8(trusted_next_intersect_indices_set_2[i]),
        )
    });
}
