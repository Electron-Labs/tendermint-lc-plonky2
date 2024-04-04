use crate::config_data::*;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::gadgets::multiple_comparison::list_le_circuit;

pub fn constrain_indices<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signature_indices: &Vec<Target>,
    untrusted_intersect_indices: &Vec<Target>,
    trusted_next_intersect_indices: &Vec<Target>,
    n_untrusted_validators: &Target,
    n_trusted_next_validators: &Target,
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

    // `untrusted_intersect_indices` must be a subset of `signature_indices`, except for reserved index
    untrusted_intersect_indices
        .iter()
        .for_each(|&untrusted_idx| {
            let is_reserved_index = builder.is_equal(untrusted_idx, null_idx);
            // constrain only if its a non-reserved index
            let enable_constraint = builder.not(is_reserved_index);

            let mut is_untrusted_in_signature = builder._false();
            signature_indices.iter().for_each(|&signature_idx| {
                let is_equal = builder.is_equal(untrusted_idx, signature_idx);
                is_untrusted_in_signature = builder.or(is_untrusted_in_signature, is_equal);
            });
            let a = builder.mul(is_untrusted_in_signature.target, enable_constraint.target);
            builder.connect(a, enable_constraint.target);
        });

    // ensure signature_indices are less than n_untrusted_validators
    for i in 0..signature_indices.len() {
        let result = list_le_circuit(
            builder,
            vec![n_untrusted_validators.clone()],
            vec![signature_indices[i]],
            8,
        ); // returns true if n_untrusted_validators <= signature_indices[i]
        builder.connect(result.target, zero_target);
    }

    // ensure trusted_next_intersection_indices are less than n_untrusted_validators
    trusted_next_intersect_indices.iter().for_each(|&idx| {
        let is_reserved_index = builder.is_equal(idx, null_idx);
        // constrain only if its a non-reserved index
        let enable_constraint = builder.not(is_reserved_index);
        let result = list_le_circuit(
            builder,
            vec![n_trusted_next_validators.clone()],
            vec![idx],
            8,
        ); // returns true if n_untrusted_validators <= signature_indices[i]
        let not_result = builder.not(result);
        let a = builder.mul(not_result.target, enable_constraint.target);
        builder.connect(a, enable_constraint.target);
    });
}
