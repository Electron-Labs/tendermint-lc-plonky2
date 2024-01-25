use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    iop::witness::Witness, plonk::circuit_builder::CircuitBuilder,
};
use sha2::{Digest};

pub struct Sha256_1Block {
    pub input: Vec<BoolTarget>,
    pub result: Vec<BoolTarget>,
}

pub struct Sha256_2Block {
    pub input: Vec<Vec<BoolTarget>>,
    pub result: Vec<BoolTarget>,
}

pub struct MerkleTree1BlockLeaf {
    pub leaves_padded: Vec<Vec<BoolTarget>>, // shaBlock(0x00 || leaf)
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

pub fn get_sha_2block_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Vec<BoolTarget> {
    (0..SHA_BLOCK_BITS * 2)
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
    input: &Vec<BoolTarget>,
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
) -> Vec<BoolTarget> {
    let result = get_sha_2block_target(builder);
    let one_bool_target = builder._true();
    let zero_bool_target = builder._false();

    // prefix '0x01'
    (0..7).for_each(|i| builder.connect(result[i].target, zero_bool_target.target));
    builder.connect(result[7].target, one_bool_target.target);

    let mut idx = 8;

    // append `left`
    (0..256).for_each(|i| {
        builder.connect(result[idx].target, left[i].target);
        idx += 1;
    });

    // append `right`
    (0..256).for_each(|i| {
        builder.connect(result[idx].target, right[i].target);
        idx += 1;
    });

    // append 1 bit
    builder.connect(result[idx].target, one_bool_target.target);
    idx += 1;

    // append zeros
    (idx..SHA_BLOCK_BITS * 2 - 64).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
        idx += 1;
    });

    // append big-endian u64 bit len
    // message len = 8 + 256 + 256 = 520 bits
    // bytearray = [0, 0, 0, 0, 0, 0, 2, 8]
    //
    // append [0, 0, 0, 0, 0, 0]
    (idx..SHA_BLOCK_BITS * 2 - 16).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
        idx += 1;
    });

    // append [2] - byte
    (idx..idx + 6).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
        idx += 1;
    });
    builder.connect(result[idx].target, one_bool_target.target);
    idx += 1;
    builder.connect(result[idx].target, zero_bool_target.target);
    idx += 1;

    // append [8] - byte
    (idx..idx + 4).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
        idx += 1;
    });
    builder.connect(result[idx].target, one_bool_target.target);
    idx += 1;
    (idx..idx + 3).for_each(|i| {
        builder.connect(result[i].target, zero_bool_target.target);
        idx += 1;
    });

    result
}

pub fn sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);
    hash_bytes.to_vec()
}

pub fn leaf_hash(input: Vec<u8>) -> Vec<u8> {
    let mut padded = (0..input.len() + 1).map(|_| 0u8).collect::<Vec<u8>>();
    (0..input.len()).for_each(|i| padded[1 + i] = input[i]);
    sha256(&padded)
}

pub fn inner_hash(leaf1: Vec<u8>, leaf2: Vec<u8>) -> Vec<u8> {
    let mut padded = (0..leaf1.len() + leaf2.len() + 1)
        .map(|_| 1u8)
        .collect::<Vec<u8>>();
    (0..leaf1.len()).for_each(|i| padded[1 + i] = leaf1[i]);
    (0..leaf2.len()).for_each(|i| padded[1 + leaf1.len() + i] = leaf2[i]);
    sha256(&padded)
}

// assuming input is a multiple of 8
pub fn bool_to_bytes(bool_arr: Vec<bool>) -> Vec<u8> {
    let mut b = (0..bool_arr.len() / 8).map(|_| 0u8).collect::<Vec<u8>>();
    for (idx, bit) in bool_arr.into_iter().enumerate() {
        let byte = idx / 8;
        let shift = 7 - idx % 8;
        b[byte] |= (bit as u8) << shift;
    }
    b
}

pub fn bytes_to_bool(bytes_arr: Vec<u8>) -> Vec<bool> {
    let mut bool_vec: Vec<bool> = Vec::new();
    for byte in bytes_arr {
        for i in 0..8 {
            let res = if (byte >> (7 - i) & 1) == 1 {
                true
            } else {
                false
            };
            bool_vec.push(res);
        }
    }
    return bool_vec;
}

// follows RFC-6962
pub fn merkle_1_block_leaf_root<F: RichField + Extendable<D>, W: Witness<F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    witness: &mut W,
    leaves_padded_target: Vec<Vec<BoolTarget>>,
    leaves: Vec<Vec<u8>>,
) -> Vec<BoolTarget> {
    let mut items = leaves
        .iter()
        .map(|elm| leaf_hash(elm.clone()))
        .collect::<Vec<Vec<u8>>>();
    let mut items_target: Vec<Vec<BoolTarget>> = vec![];
    (0..items.len()).for_each(|i| {
        let target = get_256_bool_target(builder);
        let values = bytes_to_bool(items[i].clone());
        (0..256).for_each(|j| witness.set_bool_target(target[j], values[j]));
        items_target.push(target);
    });

    // TODO: 1-block-sha256 between leaves_padded_target and items_target here

    let mut size = items.len();

    while size != 1 {
        let mut rp = 0; // read position
        let mut wp = 0; // write position
        while rp < size {
            if rp + 1 < size {
                items[wp] = inner_hash(items[rp].clone(), items[rp + 1].clone());
                let two_to_one_padded =
                    two_to_one_pad_target(builder, &items_target[rp], &items_target[rp + 1]);
                let hash_bool = bytes_to_bool(items[wp].clone());
                let hash_target = get_256_bool_target(builder);
                (0..256).for_each(|i| witness.set_bool_target(hash_target[i], hash_bool[i]));
                items_target[wp] = hash_target;
                // TODO: 2-block-sha256 between two_to_one_padded and hash_target here
                rp += 2;
            } else {
                items[wp] = items[rp].clone();
                items_target[wp] = items_target[rp].clone();
                rp += 1;
            }
            wp += 1;
        }
        size = wp;
    }

    items_target[0].clone()
}

#[cfg(test)]
mod tests {
    use super::{
        get_256_bool_target, get_sha_2block_target, two_to_one_pad_target, SHA_BLOCK_BITS,
    };
    use plonky2::{
        iop::{witness::PartialWitness, witness::WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonBn254GoldilocksConfig},
        },
    };

    const D: usize = 2;
    type C = PoseidonBn254GoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // TODO: load all test data only once

    pub fn prove_and_verify(data: CircuitData<F, C, D>, witness: PartialWitness<F>) {
        let start_time = std::time::Instant::now();
        let proof = data.prove(witness).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_two_to_one_pad_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let leaf1 = [
            false, false, true, true, false, true, false, false, false, true, true, true, false,
            false, true, true, false, false, false, true, true, false, true, true, true, false,
            false, false, false, false, true, true, true, false, true, false, false, true, false,
            true, true, false, false, true, false, false, false, true, false, false, false, true,
            false, true, true, true, true, false, false, false, false, false, true, false, true,
            false, true, true, true, false, false, false, false, true, false, true, false, true,
            true, false, true, false, false, false, true, true, false, false, false, true, true,
            false, false, false, true, true, true, false, true, false, false, true, false, true,
            true, false, true, false, true, false, false, false, false, true, true, true, false,
            false, true, false, true, true, false, true, true, false, true, false, true, true,
            true, false, false, true, true, true, true, true, true, false, false, false, true,
            true, false, false, false, false, false, true, false, true, true, true, true, true,
            true, false, false, false, false, false, true, true, false, true, false, true, false,
            true, true, false, false, false, true, true, false, true, true, true, true, false,
            false, false, false, false, false, true, false, true, false, false, true, true, false,
            true, true, false, false, false, false, true, true, true, false, true, true, true,
            true, false, true, false, false, false, false, true, false, true, false, true, true,
            false, true, false, false, true, false, true, true, true, true, true, true, false,
            true, false, true, false, false, false, false, true, false, false, false, true, true,
            true, true, true, false, false, true, true, true, true,
        ];
        let leaf2 = [
            true, false, true, false, true, true, true, false, true, true, true, false, false,
            false, false, false, false, true, true, true, true, false, false, false, false, false,
            false, true, true, true, true, true, false, false, true, false, false, false, true,
            false, false, false, true, false, true, false, true, true, false, false, false, true,
            true, true, false, true, false, false, true, true, false, false, true, true, true,
            false, true, false, false, true, false, true, false, true, true, true, false, false,
            true, false, true, true, false, false, false, true, false, true, false, false, true,
            false, true, false, false, true, false, false, false, false, false, false, false,
            false, true, true, true, true, true, true, false, false, true, false, true, true,
            false, false, true, true, false, false, false, false, true, false, false, false, false,
            false, true, false, false, false, true, true, true, false, true, true, false, false,
            false, true, false, false, true, false, true, true, false, false, false, false, true,
            false, true, true, false, true, false, false, true, true, true, false, true, false,
            false, true, false, false, true, true, true, true, true, false, false, true, false,
            false, true, true, false, false, false, true, true, true, false, true, false, true,
            true, true, true, false, true, true, false, false, false, false, false, false, true,
            true, true, false, false, true, true, false, true, true, true, true, false, false,
            false, false, true, true, true, false, false, false, true, false, false, false, true,
            true, true, true, false, true, true, false, true, false, true, true, true, false, true,
            false, true, true, true, true, false, true, false, false,
        ];
        let padded = [
            false, false, false, false, false, false, false, true, false, false, true, true, false,
            true, false, false, false, true, true, true, false, false, true, true, false, false,
            false, true, true, false, true, true, true, false, false, false, false, false, true,
            true, true, false, true, false, false, true, false, true, true, false, false, true,
            false, false, false, true, false, false, false, true, false, true, true, true, true,
            false, false, false, false, false, true, false, true, false, true, true, true, false,
            false, false, false, true, false, true, false, true, true, false, true, false, false,
            false, true, true, false, false, false, true, true, false, false, false, true, true,
            true, false, true, false, false, true, false, true, true, false, true, false, true,
            false, false, false, false, true, true, true, false, false, true, false, true, true,
            false, true, true, false, true, false, true, true, true, false, false, true, true,
            true, true, true, true, false, false, false, true, true, false, false, false, false,
            false, true, false, true, true, true, true, true, true, false, false, false, false,
            false, true, true, false, true, false, true, false, true, true, false, false, false,
            true, true, false, true, true, true, true, false, false, false, false, false, false,
            true, false, true, false, false, true, true, false, true, true, false, false, false,
            false, true, true, true, false, true, true, true, true, false, true, false, false,
            false, false, true, false, true, false, true, true, false, true, false, false, true,
            false, true, true, true, true, true, true, false, true, false, true, false, false,
            false, false, true, false, false, false, true, true, true, true, true, false, false,
            true, true, true, true, true, false, true, false, true, true, true, false, true, true,
            true, false, false, false, false, false, false, true, true, true, true, false, false,
            false, false, false, false, true, true, true, true, true, false, false, true, false,
            false, false, true, false, false, false, true, false, true, false, true, true, false,
            false, false, true, true, true, false, true, false, false, true, true, false, false,
            true, true, true, false, true, false, false, true, false, true, false, true, true,
            true, false, false, true, false, true, true, false, false, false, true, false, true,
            false, false, true, false, true, false, false, true, false, false, false, false, false,
            false, false, false, true, true, true, true, true, true, false, false, true, false,
            true, true, false, false, true, true, false, false, false, false, true, false, false,
            false, false, false, true, false, false, false, true, true, true, false, true, true,
            false, false, false, true, false, false, true, false, true, true, false, false, false,
            false, true, false, true, true, false, true, false, false, true, true, true, false,
            true, false, false, true, false, false, true, true, true, true, true, false, false,
            true, false, false, true, true, false, false, false, true, true, true, false, true,
            false, true, true, true, true, false, true, true, false, false, false, false, false,
            false, true, true, true, false, false, true, true, false, true, true, true, true,
            false, false, false, false, true, true, true, false, false, false, true, false, false,
            false, true, true, true, true, false, true, true, false, true, false, true, true, true,
            false, true, false, true, true, true, true, false, true, false, false, true, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false, false, false, false, false,
            true, false, false, false, false, false, true, false, false, false,
        ];

        let leaf1_target = get_256_bool_target(&mut builder);
        let leaf2_target = get_256_bool_target(&mut builder);
        let padded_target = get_sha_2block_target(&mut builder);

        (0..256).for_each(|i| witness.set_bool_target(leaf1_target[i], leaf1[i]));
        (0..256).for_each(|i| witness.set_bool_target(leaf2_target[i], leaf2[i]));
        (0..SHA_BLOCK_BITS * 2).for_each(|i| witness.set_bool_target(padded_target[i], padded[i]));

        let computed = two_to_one_pad_target(&mut builder, &leaf1_target, &leaf2_target);

        (0..SHA_BLOCK_BITS * 2)
            .for_each(|i| builder.connect(computed[i].target, padded_target[i].target));

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
