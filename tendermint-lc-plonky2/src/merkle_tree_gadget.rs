use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};

pub struct Sha256_1Block {
    pub input: Vec<BoolTarget>,
    pub result: Vec<BoolTarget>,
}

pub struct Sha256_2Block {
    pub input: Vec<Vec<BoolTarget>>,
    pub result: Vec<BoolTarget>,
}

pub struct MerkleTree1BlockLeaf {
    pub leaves_padded: Vec<Vec<BoolTarget>>,  // shaBlock(0x00 || leaf)
    pub root: Vec<BoolTarget>,
}

pub const SHA_BLOCK_BITS: usize = 512;

pub fn get_256_bool_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..256)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect::<Vec<BoolTarget>>()
}

pub fn get_sha_block_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..SHA_BLOCK_BITS)
        .map(|_| builder.add_virtual_bool_target_unsafe())
        .collect::<Vec<BoolTarget>>()
}

// TODO: use starky
pub fn sha256_1_block<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &Vec<BoolTarget>,
) -> Vec<BoolTarget> {
    let result = get_256_bool_target(builder);
    let one_bool_target = builder._true();
    (0..256).for_each(|i| builder.connect(result[i].target, one_bool_target.target));
    result
}

// TODO: use starky
pub fn sha256_2_block<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    input: &Vec<Vec<BoolTarget>>,
) -> Vec<BoolTarget> {
    let result = get_256_bool_target(builder);
    let one_bool_target = builder._true();
    (0..256).for_each(|i| builder.connect(result[i].target, one_bool_target.target));
    result
}

// follows RFC-6962
// left - 256bits
// right - 256bits
// result - padded(0x01 || left || right)
pub fn two_to_one_pad_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: &Vec<BoolTarget>,
    right: &Vec<BoolTarget>,
) -> Vec<Vec<BoolTarget>> {
    let result = (0..2)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();

    // prefix '0x01'
    let one_bool_target = builder._true();
    let zero_bool_target = builder._false();
    (0..7).for_each(|i| builder.connect(result[0][i].target, zero_bool_target.target));
    builder.connect(result[0][7].target, one_bool_target.target);

    // append `left`
    (8..8 + 256).for_each(|i| {
        builder.connect(result[0][i].target, left[i - 8].target);
    });

    // append `right`
    (256 + 8..SHA_BLOCK_BITS).for_each(|i| {
        builder.connect(result[0][i].target, right[i - 256 - 8].target);
    });
    (0..8).for_each(|i| {
        builder.connect(result[1][i].target, right[256 - 8 + i].target);
    });

    // append 1 bit
    builder.connect(result[1][8].target, one_bool_target.target);

    // append zeros
    (9..SHA_BLOCK_BITS - 64).for_each(|i| {
        builder.connect(result[1][i].target, zero_bool_target.target);
    });

    // append big-endian u64 bit len
    // message len = 1 + 256 + 256 = 513 bits
    // bytearray = [0, 0, 0, 0, 0, 0, 2, 1]
    //
    // append [0, 0, 0, 0, 0, 0]
    (SHA_BLOCK_BITS - 64..SHA_BLOCK_BITS - 16).for_each(|i| {
        builder.connect(result[1][i].target, zero_bool_target.target);
    });

    // append [2]
    (SHA_BLOCK_BITS - 16..SHA_BLOCK_BITS - 16 + 6).for_each(|i| {
        builder.connect(result[1][i].target, zero_bool_target.target);
    });
    builder.connect(
        result[1][SHA_BLOCK_BITS - 16 + 6].target,
        one_bool_target.target,
    );
    builder.connect(
        result[1][SHA_BLOCK_BITS - 16 + 7].target,
        zero_bool_target.target,
    );

    // append [1]
    (SHA_BLOCK_BITS - 8..SHA_BLOCK_BITS - 8 + 7).for_each(|i| {
        builder.connect(result[1][i].target, zero_bool_target.target);
    });
    builder.connect(
        result[1][SHA_BLOCK_BITS - 8 + 7].target,
        one_bool_target.target,
    );

    result
}

// follows RFC-6962
pub fn add_virtual_merkle_tree_1_block_leaf_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    n_leaves: usize,
) -> MerkleTree1BlockLeaf {
    assert!(n_leaves > 0, "number of leaves provided must be > 0");

    let leaves_padded = (0..n_leaves)
        .map(|_| get_sha_block_target(builder))
        .collect::<Vec<Vec<BoolTarget>>>();

    let mut size = n_leaves;
    let mut prev_items = leaves_padded
        .iter()
        .map(|elm| sha256_1_block(builder, elm))
        .collect::<Vec<Vec<BoolTarget>>>();

    while size != 1 {
        let mut items: Vec<Vec<BoolTarget>> = vec![];
        let mut rp = 0; // read position
        let mut wp = 0; // write position
        while rp < size {
            if rp + 1 < size {
                let pad_result =
                    two_to_one_pad_target(builder, &prev_items[rp], &prev_items[rp + 1]);
                let hash = sha256_2_block(builder, &pad_result);
                items.push(hash);
                rp += 2;
            } else {
                items.push(prev_items[rp].clone());
                rp += 1;
            }
            wp += 1;
        }
        size = wp;
        prev_items = items;
    }

    MerkleTree1BlockLeaf {
        leaves_padded,
        root: prev_items[0].clone(),
    }
}
