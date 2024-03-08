use num::{BigUint, FromPrimitive};
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

// Checks trustLevel ([1/3, 1]) of trustedHeaderVals (or trustedHeaderNextVals) signed correctly
pub fn constrain_trusted_quorum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    untrusted_validator_pub_keys: &Vec<Vec<BoolTarget>>,
    trusted_next_validator_pub_keys: &Vec<Vec<BoolTarget>>,
    trusted_next_validator_vps: &Vec<BigUintTarget>,
    untrusted_intersect_indices: &Vec<Target>,
    trusted_next_intersect_indices: &Vec<Target>,
    c: &Config,
) {
    let zero_pub_key = (0..256)
        .map(|_| builder._false())
        .collect::<Vec<BoolTarget>>();

    let mut zero_vp = builder.constant_biguint(&BigUint::from_u64(0).unwrap());
    // making zero_vp equivalent 64 bit target
    zero_vp.limbs.push(builder.constant_u32(0));
    zero_vp.limbs.push(builder.constant_u32(0));

    let mut untrusted_validator_pub_keys = untrusted_validator_pub_keys
        [0..min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)]
        .to_vec();
    (min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)..c.INTERSECTION_INDICES_DOMAIN_SIZE)
        .for_each(|_| {
            untrusted_validator_pub_keys.push(zero_pub_key.clone());
        });

    let mut trusted_next_validator_pub_keys = trusted_next_validator_pub_keys
        [0..min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)]
        .to_vec();
    (min(c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)..c.INTERSECTION_INDICES_DOMAIN_SIZE)
        .for_each(|_| {
            trusted_next_validator_pub_keys.push(zero_pub_key.clone());
        });

    let mut trusted_next_validator_vps = trusted_next_validator_vps[0..c.N_VALIDATORS].to_vec();

    (c.N_VALIDATORS..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|_| {
        trusted_next_validator_vps.push(zero_vp.clone());
    });

    let untrusted_intersect_indices =
        untrusted_intersect_indices[0..c.N_INTERSECTION_INDICES].to_vec();
    let trusted_next_intersect_indices =
        trusted_next_intersect_indices[0..c.N_INTERSECTION_INDICES].to_vec();

    let zero_bool_target = builder._false();
    let three_big_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap());
    let null_idx = builder.constant(F::from_canonical_u16(
        (c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u16,
    ));

    let mut total_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut intersection_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());

    // compute total voting power
    (0..c.N_VALIDATORS)
        .for_each(|i| total_vp = builder.add_biguint(&total_vp, &trusted_next_validator_vps[i]));

    // prepares voting power columns
    // because random_access_index wont work on BigUintTarget so need to split it into limbs
    let trusted_validator_vp_columns = vec![
        trusted_next_validator_vps[..c.INTERSECTION_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        trusted_next_validator_vps[..c.INTERSECTION_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];
    // split pub keys columns to use random_access_index
    let mut untrusted_pub_keys_columns: Vec<Vec<Target>> = vec![];
    let mut trusted_pub_keys_columns: Vec<Vec<Target>> = vec![];
    (0..256).for_each(|i| {
        let mut untrusted_pub_key_column: Vec<Target> = vec![];
        let mut trusted_pub_key_column: Vec<Target> = vec![];
        (0..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|j| {
            untrusted_pub_key_column.push(untrusted_validator_pub_keys[j][i].target);
            trusted_pub_key_column.push(trusted_next_validator_pub_keys[j][i].target);
        });
        untrusted_pub_keys_columns.push(untrusted_pub_key_column);
        trusted_pub_keys_columns.push(trusted_pub_key_column);
    });

    (0..c.N_INTERSECTION_INDICES).for_each(|i| {
        let random_access_index = trusted_next_intersect_indices[i];
        let is_reserved_index = builder.is_equal(random_access_index, null_idx);
        // constrain only if its a non-reserved index
        let enable_constraint = builder.not(is_reserved_index);

        // compute intersection voting power in trusted
        let mut vp = builder.add_virtual_biguint_target(c.VP_BITS.div_ceil(32));
        let vp_c0 =
            builder.random_access(random_access_index, trusted_validator_vp_columns[0].clone());
        let vp_c1 =
            builder.random_access(random_access_index, trusted_validator_vp_columns[1].clone());
        builder.connect(vp.get_limb(0).0, vp_c0);
        builder.connect(vp.get_limb(1).0, vp_c1);
        vp = builder.mul_biguint_by_bool(&vp, enable_constraint);
        intersection_vp = builder.add_biguint(&intersection_vp, &vp);

        // ensure intersection pub keys
        (0..256).for_each(|j| {
            let untrusted_key = builder.random_access(
                untrusted_intersect_indices[i],
                untrusted_pub_keys_columns[j].clone(),
            );
            let trusted_key = builder.random_access(
                trusted_next_intersect_indices[i],
                trusted_pub_keys_columns[j].clone(),
            );
            let a = builder.mul(untrusted_key, enable_constraint.target);
            let b = builder.mul(trusted_key, enable_constraint.target);
            builder.connect(a, b);
        });
    });

    // ensures 3 * intersection_vp > total_vp
    let three_times_intersection_vp = builder.mul_biguint(&intersection_vp, &three_big_target);
    let comparison = builder.cmp_biguint(&three_times_intersection_vp, &total_vp);
    builder.connect(comparison.target, zero_bool_target.target);
}

// Ensure that +2/3 of new validators signed correctly.
pub fn constrain_untrusted_quorum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    untrusted_validator_vps: &Vec<BigUintTarget>,
    signature_indices: &Vec<Target>,
    c: &Config,
) {
    let mut zero_vp = builder.constant_biguint(&BigUint::from_u64(0).unwrap());
    // making zero_vp equivalent 64 bit target
    zero_vp.limbs.push(builder.constant_u32(0));
    zero_vp.limbs.push(builder.constant_u32(0));

    let mut untrusted_validator_vps = untrusted_validator_vps[0..c.N_VALIDATORS].to_vec();

    // TODO: replace c.INTERSECTION_INDICES_DOMAIN_SIZE with c.SIGNATURE_INDICES_DOMAIN_SIZE
    (c.N_VALIDATORS..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|_| {
        untrusted_validator_vps.push(zero_vp.clone());
    });
    let signature_indices = signature_indices[0..c.N_SIGNATURE_INDICES].to_vec();

    let mut total_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut quorum_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let three_big_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap());
    let two_big_target = builder.constant_biguint(&BigUint::from_u64(2).unwrap());
    let zero_bool_target = builder._false();

    // compute total voting power
    (0..c.N_VALIDATORS)
        .for_each(|i| total_vp = builder.add_biguint(&total_vp, &untrusted_validator_vps[i]));

    // prepares voting power columns
    let untrusted_validator_vp_columns = vec![
        untrusted_validator_vps[..c.SIGNATURE_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        untrusted_validator_vps[..c.SIGNATURE_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];

    (0..c.N_SIGNATURE_INDICES).for_each(|i| {
        let random_access_index = signature_indices[i];

        // compute intersection voting power in trusted
        let vp = builder.add_virtual_biguint_target(c.VP_BITS.div_ceil(32));
        let vp_c0 = builder.random_access(
            random_access_index,
            untrusted_validator_vp_columns[0].clone(),
        );
        let vp_c1 = builder.random_access(
            random_access_index,
            untrusted_validator_vp_columns[1].clone(),
        );
        builder.connect(vp.get_limb(0).0, vp_c0);
        builder.connect(vp.get_limb(1).0, vp_c1);
        quorum_vp = builder.add_biguint(&quorum_vp, &vp);
    });

    // ensures 3 * quorum vp > 2 * total_vp
    let three_times_quorum_vp = builder.mul_biguint(&quorum_vp, &three_big_target);
    let two_times_total_vp = builder.mul_biguint(&total_vp, &two_big_target);
    let comparison = builder.cmp_biguint(&three_times_quorum_vp, &two_times_total_vp);
    builder.connect(comparison.target, zero_bool_target.target);
}
