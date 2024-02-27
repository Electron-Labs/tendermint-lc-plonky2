use num::{BigUint, FromPrimitive};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
  u32::multiple_comparison::list_le_u32_circuit,
    biguint::{BigUintTarget, CircuitBuilderBiguint},
    u32::arithmetic_u32::CircuitBuilderU32,
};

use crate::config_data::*;

// TODO: constrain non-repetition of indices
pub fn constrain_indices<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signature_indices: &Vec<Target>,
    untrusted_intersect_indices: &Vec<Target>,
    trusted_next_intersect_indices: &Vec<Target>,
    c: &Config,
) {
  // builder.
}
