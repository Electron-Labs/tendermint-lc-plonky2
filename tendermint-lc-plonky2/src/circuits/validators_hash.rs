use crate::circuits::merkle_targets::get_validators_hash_range;
use num::{BigUint, Float, FromPrimitive};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    u32::arithmetic_u32::CircuitBuilderU32,
};
use std::cmp::min;

use crate::config_data::*;

pub fn compute_validators_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    n_validators: &Target,
    max_validators_leaves_padded: &Vec<Vec<BoolTarget>>,
    c: &Config,
) -> Vec<BoolTarget> {
    let mut validators_hash_range = get_validators_hash_range(
        builder,
        &max_validators_leaves_padded,
        c.MIN_N_VALIDATORS,
        c.MAX_N_VALIDATORS,
    );

    let range_n_validators = c.MAX_N_VALIDATORS - c.MIN_N_VALIDATORS + 1;
    let domain_size = (range_n_validators as f32).log2().ceil().exp2() as u8;
    assert!(domain_size as usize <= 64, "Invalid domain_size");

    // extend 0 hashes till domain_size
    let zero_hash = (0..256)
        .map(|_| builder._false())
        .collect::<Vec<BoolTarget>>();
    (validators_hash_range.len()..domain_size as usize).for_each(|_| {
        validators_hash_range.push(zero_hash.clone());
    });

    // prepare validators hashes columns
    let mut validators_hashes_columns: Vec<Vec<Target>> = vec![];
    (0..256).for_each(|i| {
        let mut validators_hashes_column: Vec<Target> = vec![];
        (0..domain_size).for_each(|j| {
            validators_hashes_column.push(validators_hash_range[j as usize][i].target);
        });
        validators_hashes_columns.push(validators_hashes_column);
    });

    let min_n_validators_target = builder.constant(F::from_canonical_usize(c.MIN_N_VALIDATORS));
    let validator_hash_index = builder.sub(n_validators.clone(), min_n_validators_target);
    let mut validators_hash: Vec<BoolTarget> = Vec::with_capacity(256);
    (0..256).for_each(|j| {
        let value =
            builder.random_access(validator_hash_index, validators_hashes_columns[j].clone());
        let bool_value = builder.add_virtual_bool_target_unsafe();
        builder.connect(bool_value.target, value);
        validators_hash.push(bool_value);
    });

    validators_hash
}
