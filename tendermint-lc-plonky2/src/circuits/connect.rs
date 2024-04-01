use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::biguint::{BigUintTarget, CircuitBuilderBiguint};

use crate::config_data::*;

pub fn connect_timestamp<F: RichField + Extendable<D>, const D: usize>(
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

pub fn connect_pub_keys_and_vps<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pub_keys: &Vec<Vec<BoolTarget>>,
    validators_padded: &Vec<Vec<BoolTarget>>,
    vps: &Vec<BigUintTarget>,
    c: &Config,
) {
    let _vps = (0..c.MAX_N_VALIDATORS)
        .map(|_| {
            builder.add_virtual_biguint_target(
                (c.VP_BITS.div_ceil(c.LEB128_GROUP_SIZE) * 8).div_ceil(32),
            )
        })
        .collect::<Vec<BigUintTarget>>();

    (0..c.MAX_N_VALIDATORS).for_each(|i| builder.connect_biguint(&_vps[i], &vps[i]));

    // 7 bits from each of 10 consecutive bytes in `validators_padded[i]` starting from the 39th byte makes up the `vp_bits`
    // `validators_padded[i]` contains voting power in LEB128 format
    (0..c.MAX_N_VALIDATORS).for_each(|i| {
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
