use crate::config_data::*;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::gadgets::multiple_comparison::list_le_circuit;

// TODO: constrain non-repetition of indices
pub fn constrain_indices<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signature_indices: &Vec<Target>,
    untrusted_intersect_indices: &Vec<Target>,
    c: &Config,
) {
    let zero_target = builder.zero();

    // ensuring signature indices are strictly greater than their previous indices
    for i in 1..signature_indices.len() {
        let curr = vec![signature_indices[i]];
        let prev = vec![signature_indices[i - 1]];
        let result = list_le_circuit(builder, curr, prev, 6); // returns true if curr <= prev
        builder.connect(result.target, zero_target);
    }

    let null_idx = builder.constant(F::from_canonical_u16(
        (c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u16,
    ));

    // ensuring untrusted indices are strictly greater than previous indices or equal to null_index
    for i in 1..untrusted_intersect_indices.len() {
        let res1 = builder.is_equal(untrusted_intersect_indices[i], null_idx.clone());
        let res2 = builder.is_equal(untrusted_intersect_indices[i - 1], null_idx.clone());

        let mul_result = builder.mul(res1.target, res2.target);

        let curr = vec![untrusted_intersect_indices[i]];
        let prev = vec![untrusted_intersect_indices[i - 1]];
        let result = list_le_circuit(builder, curr, prev, 6); // returns true if curr <= prev
        builder.connect(result.target, mul_result);
    }
}
