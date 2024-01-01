use super::merkle_tree_gadget::{
    add_virtual_merkle_tree_1_block_leaf_target, get_256_bool_target, get_sha_block_target,
    sha256_1_block, sha256_2_block, two_to_one_pad_target, SHA_BLOCK_BITS,
};
use num::{BigUint, FromPrimitive, Integer, Zero};
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

pub struct ConnectSignMessageTarget {
    pub message: Vec<BoolTarget>,
    pub header_hash: Vec<BoolTarget>,
    pub height: BigUintTarget,
}

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
    sign_message: Vec<BoolTarget>,
    untrusted_header_hash: Vec<BoolTarget>,
    untrusted_header_height: BigUintTarget,
    trusted_header_height: BigUintTarget,
    untrusted_validators_hash_padded: Vec<BoolTarget>,
    untrusted_validators_leaves_padded: Vec<Vec<BoolTarget>>,
    trusted_next_validators_leaves_padded: Vec<Vec<BoolTarget>>,
    untrusted_validators_hash_proof: Vec<Vec<BoolTarget>>,
}

pub const N_VALIDATORS: usize = 150;
pub const UNTRUSTED_VALIDATORS_HASH_PROOF_SIZE: usize = 4;
pub const SIGN_MESSAGE_BITS: usize = 110 * 8;
pub const HEIGHT_BITS: usize = 64;

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
    (0..2).for_each(|i| {
        let height_bits = builder.split_le_base::<2>(height.get_limb(i).0, 32);
        (0..4).for_each(|j| {
            (0..8).for_each(|k| {
                builder.connect(
                    message[32 + i * 32 + j * 8 + k].target,
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
    let untrusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);
    let trusted_height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);

    let two_big_target = builder.constant_biguint(&BigUint::from_i8(2).unwrap());
    let one_bool_target = builder._true();
    let trusted_height_plus_two = builder.add_biguint(&trusted_height, &two_big_target);

    // ensures untrusted height >= trusted height + 2
    let result = builder.cmp_biguint(&trusted_height_plus_two, &untrusted_height);
    builder.connect(result.target, one_bool_target.target);

    // TODO: add more here
    // - untrusted height  < trusted height + trusting period

    UpdateValidityTarget {
        untrusted_height,
        trusted_height,
    }
}

pub fn add_virtual_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ProofTarget {
    let sign_message = (0..SIGN_MESSAGE_BITS)
        .map(|i| builder.add_virtual_bool_target_safe())
        .collect::<Vec<BoolTarget>>();
    let untrusted_header_hash = get_256_bool_target(builder);
    let untrusted_header_height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);
    let trusted_header_height = builder.add_virtual_biguint_target(HEIGHT_BITS / 32);
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

    let connect_message_target = add_virtual_connect_sign_message_target(builder);
    let untrusted_validators_hash =
        validators_hash_target(builder, untrusted_validators_leaves_padded.clone());
    let trusted_next_validators_hash =
        validators_hash_target(builder, trusted_next_validators_leaves_padded.clone());
    let untrusted_validators_hash_merkle_proof_target =
        add_virtual_validators_hash_merkle_proof_target(builder);


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
            untrusted_header_hash[i].target,
        )
    });
    builder.connect_biguint(&connect_message_target.height, &untrusted_header_height);


    // *** MerkleProofTarget-untrusted_validators_hash ***
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
            untrusted_header_hash[i].target,
        )
    });


    // *** UpdateValidityTarget ***
    let update_validity_target = add_virtual_update_validity_target(builder);
    builder.connect_biguint(
        &update_validity_target.untrusted_height,
        &untrusted_header_height,
    );
    builder.connect_biguint(
        &update_validity_target.trusted_height,
        &trusted_header_height,
    );


    // connect `untrusted_validators_hash` and `untrusted_validators_hash_padded`
    (0..256).for_each(|i| {
        builder.connect(
            untrusted_validators_hash[i].target,
            untrusted_validators_hash_padded[8 + i].target,
        )
    });

    ProofTarget {
        sign_message,
        untrusted_header_hash,
        untrusted_header_height,
        trusted_header_height,
        untrusted_validators_hash_padded,
        untrusted_validators_leaves_padded,
        trusted_next_validators_leaves_padded,
        untrusted_validators_hash_proof,
    }
}
