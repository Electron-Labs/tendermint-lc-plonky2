use super::merkle_tree_gadget::{
    add_virtual_merkle_tree_1_block_leaf_target, get_256_bool_target, get_sha_block_target,
    sha256_1_block, sha256_2_block, two_to_one_pad_target, SHA_BLOCK_BITS,
};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

pub struct MerkleProofTarget {
    pub leaf_padded: Vec<BoolTarget>, // shaBlock(0x00 || leaf)
    pub proof: Vec<Vec<BoolTarget>>,
    pub root: Vec<BoolTarget>,
}

// all padded leaves are of the form: shaBlock(0x00 || leaf)
pub struct ProofTarget {
    untrusted_headers_hash: Vec<BoolTarget>,
    untrusted_validators_hash_padded: Vec<BoolTarget>,
    untrusted_validators_leaves_padded: Vec<Vec<BoolTarget>>,
    trusted_next_validators_leaves_padded: Vec<Vec<BoolTarget>>,
    untrusted_validators_hash_proof: Vec<Vec<BoolTarget>>,
}

pub const N_VALIDATORS: usize = 150;
pub const UNTRUSTED_VALIDATORS_HASH_PROOF_SIZE: usize = 4;

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
