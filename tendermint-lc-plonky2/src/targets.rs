use super::merkle_tree_gadget::{
    add_virtual_merkle_tree_1_block_leaf_target, get_256_bool_target, get_sha_block_target,
    sha256_1_block, sha256_2_block, two_to_one_pad_target, SHA_BLOCK_BITS,
};
use num::{BigUint, Integer, Zero, FromPrimitive};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint},
    hash::{
        sha256::{CircuitBuilderHashSha2, WitnessHashSha2},
        CircuitBuilderHash, Hash256Target, HashInputTarget, WitnessHash,
    },
    u32::arithmetic_u32::CircuitBuilderU32,
};

use crate::utils::{add_virtual_cmp_vec_bool_target,add_virtual_dummy_verify_signature_target};

pub struct MerkleProofTarget {
    pub leaf_padded: Vec<BoolTarget>, // shaBlock(0x00 || leaf)
    pub proof: Vec<Vec<BoolTarget>>,
    pub root: Vec<BoolTarget>,
}

pub struct UpdateValidityTarget {
    pub untrusted_height: BigUintTarget,
    pub trusted_height: BigUintTarget,
}

// all padded leaves are of the form: shaBlock(0x00 || leaf)
pub struct ProofTarget {
    untrusted_headers_hash: Vec<BoolTarget>,
    untrusted_validators_hash_padded: Vec<BoolTarget>,
    untrusted_validators_leaves_padded: Vec<Vec<BoolTarget>>,
    trusted_next_validators_leaves_padded: Vec<Vec<BoolTarget>>,
    untrusted_validators_hash_proof: Vec<Vec<BoolTarget>>,
}
pub struct UntrustedValidatorsQuorum{ 
    pub untrusted_validators_pub_keys: Vec<Vec<BoolTarget>>,
    pub untrusted_validators_votes: Vec<BigUintTarget>,
    pub untrusted_signatures: Vec<Vec<BoolTarget>>, 
}

pub struct TrustedValidatorsQuorum{
    pub untrusted_validators_pub_keys: Vec<Vec<BoolTarget>>,
    pub untrusted_validators_votes: Vec<BigUintTarget>,
    pub trusted_validators_pub_keys: Vec<Vec<BoolTarget>>,
    pub trusted_validators_votes: Vec<BigUintTarget>,
}

pub const N_VALIDATORS: usize = 150;
pub const UNTRUSTED_VALIDATORS_HASH_PROOF_SIZE: usize = 4;

pub fn add_virtual_trusted_quorum_target <
    F: RichField + Extendable<D>,
    const D: usize
> (
    builder: &mut CircuitBuilder<F,D>
) -> TrustedValidatorsQuorum {
    let untrusted_validators_pub_keys = (0..N_VALIDATORS).map(|_|{
        (0..32*8).map(|_|{
            builder.add_virtual_bool_target_safe()
        }).collect()
    }).collect::<Vec<Vec<BoolTarget>>>();


    let untrusted_validators_votes = (0..N_VALIDATORS).map(|_|{
        builder.add_virtual_biguint_target(8)
    }).collect::<Vec<BigUintTarget>>();

    let trusted_validators_pub_keys = (0..N_VALIDATORS).map(|_|{
        (0..32*8).map(|_|{
            builder.add_virtual_bool_target_safe()
        }).collect()
    }).collect::<Vec<Vec<BoolTarget>>>();


    let trusted_validators_votes = (0..N_VALIDATORS).map(|_|{
        builder.add_virtual_biguint_target(8)
    }).collect::<Vec<BigUintTarget>>();

    let mut total_voting_power = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut trusted_validator_voting_power = builder.constant_biguint(&BigUint::from_usize(0).unwrap());

    for i in 0..N_VALIDATORS{
        let result = add_virtual_cmp_vec_bool_target(builder, trusted_validators_pub_keys[i].clone(), untrusted_validators_pub_keys[i].clone());
        let intermediate = builder.mul_biguint_by_bool(&trusted_validators_votes[i], result);
        trusted_validator_voting_power = builder.add_biguint(&trusted_validator_voting_power, &intermediate);

        total_voting_power = builder.add_biguint(&total_voting_power, &untrusted_validators_votes[i]);
    }

    // 3 trusted_signature_voting_power > total_voting_power(untrusted)
    let one_target = builder.one();
    let three_biguint_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap()); 
    let three_trusted_validators_voting_power = builder.mul_biguint(&trusted_validator_voting_power, &three_biguint_target);
    let comparison = builder.cmp_biguint(&total_voting_power, &three_trusted_validators_voting_power);          
    builder.connect(comparison.target, one_target);

    return TrustedValidatorsQuorum {
        untrusted_validators_pub_keys: untrusted_validators_pub_keys,
        untrusted_validators_votes: untrusted_validators_votes,
        trusted_validators_pub_keys: trusted_validators_pub_keys,
        trusted_validators_votes: trusted_validators_votes
    }
}


pub fn add_virtual_untrusted_consensus_target<
    F: RichField + Extendable<D>,
    const D: usize
>(
    builder: &mut CircuitBuilder<F,D>
) -> UntrustedValidatorsQuorum{

    let untrusted_validators_pub_keys = (0..N_VALIDATORS).map(|_|{
        (0..32*8).map(|_|{
            builder.add_virtual_bool_target_safe()
        }).collect()
    }).collect::<Vec<Vec<BoolTarget>>>();


    let untrusted_validators_votes = (0..N_VALIDATORS).map(|_|{
        builder.add_virtual_biguint_target(8)
    }).collect::<Vec<BigUintTarget>>();

    let untrusted_signatures = (0..N_VALIDATORS).map(|_|{
        (0..64*8).map(|_|{
            builder.add_virtual_bool_target_safe()
        }).collect()
    }).collect::<Vec<Vec<BoolTarget>>>();

    let zero_biguint_target = builder.zero_biguint(); 

    let mut total_voting_power = builder.add_virtual_biguint_target(8);
    builder.connect_biguint(&total_voting_power, &zero_biguint_target);

    let mut signature_voting_power = builder.add_virtual_biguint_target(8);
    builder.connect_biguint(&signature_voting_power, &zero_biguint_target);


    for i in 0..untrusted_validators_pub_keys.len(){
        let result = add_virtual_dummy_verify_signature_target(builder, untrusted_signatures[i].clone());
        let signature_voting_power_intermediate = builder.mul_biguint_by_bool(&untrusted_validators_votes[i].clone(), result);
        signature_voting_power = builder.add_biguint(&signature_voting_power, &signature_voting_power_intermediate);
        total_voting_power = builder.add_biguint(&total_voting_power,&untrusted_validators_votes[i]);
    }

    let two_biguint_target = builder.constant_biguint(&BigUint::from_u64(2).unwrap());
    let three_biguint_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap()); 
    let two_total_voting_power = builder.mul_biguint(&two_biguint_target, &total_voting_power);
    let three_signature_voting_power = builder.mul_biguint(&three_biguint_target, &signature_voting_power);
    let result = builder.cmp_biguint(&two_total_voting_power,&three_signature_voting_power);
    let one_target = builder.one();
    builder.connect(result.target,one_target);

    return UntrustedValidatorsQuorum{
        untrusted_validators_pub_keys: untrusted_validators_pub_keys,
        untrusted_validators_votes: untrusted_validators_votes,
        untrusted_signatures: untrusted_signatures
    };

}

pub fn add_virtual_validators_hash_merkle_proof_target<
    F: RichField + Extendable<D>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> MerkleProofTarget {
    let root = get_256_bool_target(builder);
    let proof = (0..UNTRUSTED_VALIDATORS_HASH_PROOF_SIZE)
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
    let untrusted_height = builder.add_virtual_biguint_target(2); // 64 bytes
    let trusted_height = builder.add_virtual_biguint_target(2); // 64 bytes

    let two_big_target = builder.constant_biguint(&BigUint::from_i8(2).unwrap());
    let one_bool_target = builder._true();
    let trusted_height_plus_two = builder.add_biguint(&trusted_height, &two_big_target);

    // ensures untrusted height >= trusted height + 2
    let result = builder.cmp_biguint(&trusted_height_plus_two, &untrusted_height);
    builder.connect(result.target, one_bool_target.target);

    // TODO: add more here
    // - untrusted height  < trusted height + trusting period

    UpdateValidityTarget{
        untrusted_height,
        trusted_height
    }

}

pub fn add_virtual_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ProofTarget {
    let untrusted_headers_hash = get_256_bool_target(builder);
    let untrusted_validators_hash_padded = get_sha_block_target(builder);
    let untrusted_validators_leaves_padded = (0..N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let trusted_next_validators_leaves_padded = (0..N_VALIDATORS)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();
    let untrusted_validators_hash_proof = (0..UNTRUSTED_VALIDATORS_HASH_PROOF_SIZE)
        .map(|_| get_256_bool_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();

    let untrusted_validators_hash =
        validators_hash_target(builder, untrusted_validators_leaves_padded.clone());
    let trusted_next_validators_hash =
        validators_hash_target(builder, trusted_next_validators_leaves_padded.clone());
    let untrusted_validators_hash_merkle_proof_target =
        add_virtual_validators_hash_merkle_proof_target(builder);

    (0..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(
            untrusted_validators_hash_merkle_proof_target.leaf_padded[i].target,
            untrusted_validators_hash_padded[i].target,
        )
    });
    (0..UNTRUSTED_VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
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
            untrusted_headers_hash[i].target,
        )
    });

    (0..256).for_each(|i| {
        builder.connect(
            untrusted_validators_hash[i].target,
            untrusted_validators_hash_padded[8 + i].target,
        )
    });

    ProofTarget {
        untrusted_headers_hash,
        untrusted_validators_hash_padded,
        untrusted_validators_leaves_padded,
        trusted_next_validators_leaves_padded,
        untrusted_validators_hash_proof,
    }
}
