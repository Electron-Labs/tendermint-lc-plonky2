use num::{BigUint, FromPrimitive};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::biguint::{BigUintTarget, CircuitBuilderBiguint};

use crate::config_data::*;
pub fn check_update_validity<F: RichField + Extendable<D>, const D: usize>(
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
