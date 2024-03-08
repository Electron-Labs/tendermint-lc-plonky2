use crate::config_data::*;
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::u32::gadgets::multiple_comparison::list_le_circuit;

pub fn constrain_indices<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signature_indices_set_1: &Vec<Target>,
    signature_indices_set_2: &Vec<Target>,
    untrusted_intersect_indices_set_1: &Vec<Target>,
    untrusted_intersect_indices_set_2: &Vec<Target>,
    c: &Config,
) {
    let zero_target = builder.zero();

    // ensuring signature indices are strictly greater than their previous indices
    for i in 1..signature_indices_set_1.len() {
        let curr = vec![signature_indices_set_1[i]];
        let prev = vec![signature_indices_set_1[i - 1]];
        let result = list_le_circuit(builder, curr, prev, 6); // returns true if curr <= prev
        builder.connect(result.target, zero_target);
    }

    for i in 1..signature_indices_set_2.len() {
        let curr = vec![signature_indices_set_2[i]];
        let prev = vec![signature_indices_set_2[i - 1]];
        let result = list_le_circuit(builder, curr, prev, 6); // returns true if curr <= prev
        builder.connect(result.target, zero_target);
    }


    let null_idx = builder.constant(F::from_canonical_u16(
        (c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u16,
    ));

    // ensuring untrusted indices are strictly greater than previous indices or equal to null_index
    for i in 1..untrusted_intersect_indices_set_1.len() {
        let res1 = builder.is_equal(untrusted_intersect_indices_set_1[i], null_idx.clone());
        let res2 = builder.is_equal(untrusted_intersect_indices_set_1[i - 1], null_idx.clone());

        let mul_result = builder.mul(res1.target, res2.target);

        let curr = vec![untrusted_intersect_indices_set_1[i]];
        let prev = vec![untrusted_intersect_indices_set_1[i - 1]];
        let result = list_le_circuit(builder, curr, prev, 6); // returns true if curr <= prev
        builder.connect(result.target, mul_result);
    }

    // ensuring untrusted indices are strictly greater than previous indices or equal to null_index
    for i in 1..untrusted_intersect_indices_set_2.len() {
        let res1 = builder.is_equal(untrusted_intersect_indices_set_2[i], null_idx.clone());
        let res2 = builder.is_equal(untrusted_intersect_indices_set_2[i - 1], null_idx.clone());

        let mul_result = builder.mul(res1.target, res2.target);

        let curr = vec![untrusted_intersect_indices_set_2[i]];
        let prev = vec![untrusted_intersect_indices_set_2[i - 1]];
        let result = list_le_circuit(builder, curr, prev, 6); // returns true if curr <= prev
        builder.connect(result.target, mul_result);
    }

    // `untrusted_intersect_indices` must be a subset of `signature_indices`, except for reserved index
    untrusted_intersect_indices_set_1
        .iter()
        .for_each(|&untrusted_idx| {
            let is_reserved_index = builder.is_equal(untrusted_idx, null_idx);
            // constrain only if its a non-reserved index
            let enable_constraint = builder.not(is_reserved_index);

            let mut is_untrusted_in_signature = builder._false();
            // NOTE: subset condition not needed to check in set 2 as the domain size of intersect indices is atmax 64 and always <= the domain size of signature_indices_set_1
            signature_indices_set_1.iter().for_each(|&signature_idx| {
                let is_equal = builder.is_equal(untrusted_idx, signature_idx);
                is_untrusted_in_signature = builder.or(is_untrusted_in_signature, is_equal);
            });
            let a = builder.mul(is_untrusted_in_signature.target, enable_constraint.target);
            builder.connect(a, enable_constraint.target);
        });

        untrusted_intersect_indices_set_2
        .iter()
        .for_each(|&untrusted_idx| {
            let is_reserved_index = builder.is_equal(untrusted_idx, null_idx);
            // constrain only if its a non-reserved index
            let enable_constraint = builder.not(is_reserved_index);

            let mut is_untrusted_in_signature = builder._false();
            // NOTE: subset condition not needed to check in set 2 as the domain size of intersect indices is atmax 64 and always <= the domain size of signature_indices_set_1
            signature_indices_set_2.iter().for_each(|&signature_idx| {
                let is_equal = builder.is_equal(untrusted_idx, signature_idx);
                is_untrusted_in_signature = builder.or(is_untrusted_in_signature, is_equal);
            });
            let a = builder.mul(is_untrusted_in_signature.target, enable_constraint.target);
            builder.connect(a, enable_constraint.target);
        });
}
