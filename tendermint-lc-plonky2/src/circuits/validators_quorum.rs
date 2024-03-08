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
    untrusted_intersect_indices_set_1: &Vec<Target>,
    untrusted_intersect_indices_set_2: &Vec<Target>,
    trusted_next_intersect_indices_set_1: &Vec<Target>,
    trusted_next_intersect_indices_set_2: &Vec<Target>,
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
        [0..min(2*c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)]
        .to_vec();
    (min(2*c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)..(2*c.INTERSECTION_INDICES_DOMAIN_SIZE))
        .for_each(|_| {
            untrusted_validator_pub_keys.push(zero_pub_key.clone());
        });

    let mut trusted_next_validator_pub_keys = trusted_next_validator_pub_keys
        [0..min(2*c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)]
        .to_vec();
    (min(2*c.INTERSECTION_INDICES_DOMAIN_SIZE, c.N_VALIDATORS)..(2*c.INTERSECTION_INDICES_DOMAIN_SIZE))
        .for_each(|_| {
            trusted_next_validator_pub_keys.push(zero_pub_key.clone());
        });

    let mut trusted_next_validator_vps = trusted_next_validator_vps[0..c.N_VALIDATORS].to_vec();

    (c.N_VALIDATORS..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|_| {
        trusted_next_validator_vps.push(zero_vp.clone());
    });

    let untrusted_intersect_indices_set_1 =
        untrusted_intersect_indices_set_1[0..c.N_INTERSECTION_INDICES_SET_1].to_vec();
    let untrusted_intersect_indices_set_2 =
        untrusted_intersect_indices_set_2[0..c.N_INTERSECTION_INDICES_SET_2].to_vec();
    
    let trusted_next_intersect_indices_set_1 =
        trusted_next_intersect_indices_set_1[0..c.N_INTERSECTION_INDICES_SET_1].to_vec();
    let trusted_next_intersect_indices_set_2 =
        trusted_next_intersect_indices_set_2[0..c.N_INTERSECTION_INDICES_SET_2].to_vec();

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
    let trusted_validator_set_1_vp_columns = vec![
        trusted_next_validator_vps[..c.INTERSECTION_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        trusted_next_validator_vps[..c.INTERSECTION_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];

    let trusted_validator_set_2_vp_columns = vec![
        trusted_next_validator_vps[c.INTERSECTION_INDICES_DOMAIN_SIZE..(2*c.INTERSECTION_INDICES_DOMAIN_SIZE) ]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        trusted_next_validator_vps[c.INTERSECTION_INDICES_DOMAIN_SIZE..(2*c.INTERSECTION_INDICES_DOMAIN_SIZE)]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];
    // split pub keys columns to use random_access_index
    let mut untrusted_pub_keys_columns_set_1: Vec<Vec<Target>> = vec![];
    let mut untrusted_pub_keys_columns_set_2: Vec<Vec<Target>> = vec![];
    let mut trusted_pub_keys_columns_set_1: Vec<Vec<Target>> = vec![];
    let mut trusted_pub_keys_columns_set_2: Vec<Vec<Target>> = vec![];
    (0..256).for_each(|i| {
        let mut untrusted_pub_key_column: Vec<Target> = vec![];
        let mut trusted_pub_key_column: Vec<Target> = vec![];
        (0..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|j| {
            untrusted_pub_key_column.push(untrusted_validator_pub_keys[j][i].target);
            trusted_pub_key_column.push(trusted_next_validator_pub_keys[j][i].target);
        });
        untrusted_pub_keys_columns_set_1.push(untrusted_pub_key_column);
        trusted_pub_keys_columns_set_1.push(trusted_pub_key_column);
    });

    (0..256).for_each(|i| {
        let mut untrusted_pub_key_column: Vec<Target> = vec![];
        let mut trusted_pub_key_column: Vec<Target> = vec![];
        (0..c.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|j| {
            untrusted_pub_key_column.push(untrusted_validator_pub_keys[j+c.INTERSECTION_INDICES_DOMAIN_SIZE][i].target);
            trusted_pub_key_column.push(trusted_next_validator_pub_keys[j+c.INTERSECTION_INDICES_DOMAIN_SIZE][i].target);
        });
        untrusted_pub_keys_columns_set_2.push(untrusted_pub_key_column);
        trusted_pub_keys_columns_set_2.push(trusted_pub_key_column);
    });

    (0..c.N_INTERSECTION_INDICES_SET_1).for_each(|i| {
        intersection_vp = calculate_intersection_vp_and_add_equal_key_constraints::<F,D>(builder, &trusted_next_intersect_indices_set_1, 
            &untrusted_intersect_indices_set_1, i, c,&mut intersection_vp,
             &trusted_validator_set_1_vp_columns, &untrusted_pub_keys_columns_set_1, 
             &trusted_pub_keys_columns_set_1, null_idx);
    });
    (0..c.N_INTERSECTION_INDICES_SET_2).for_each(|i| {
        intersection_vp = calculate_intersection_vp_and_add_equal_key_constraints::<F,D>(builder, &trusted_next_intersect_indices_set_2, 
            &untrusted_intersect_indices_set_2, i, c,&mut intersection_vp,
             &trusted_validator_set_2_vp_columns, &untrusted_pub_keys_columns_set_2, 
             &trusted_pub_keys_columns_set_2, null_idx);
    });

    // ensures 3 * intersection_vp > total_vp
    let three_times_intersection_vp = builder.mul_biguint(&intersection_vp, &three_big_target);
    let comparison = builder.cmp_biguint(&three_times_intersection_vp, &total_vp);
    builder.connect(comparison.target, zero_bool_target.target);
}

fn calculate_intersection_vp_and_add_equal_key_constraints<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    trusted_next_intersect_indices: &Vec<Target>,
    untrusted_intersect_indices: &Vec<Target>,
    index: usize,
    c: &Config,
    intersection_vp:&BigUintTarget,
    trusted_validator_vp_columns: &Vec<Vec<Target>>,
    untrusted_pub_keys_columns: &Vec<Vec<Target>>,  
    trusted_pub_keys_columns: &Vec<Vec<Target>>,
    null_idx: Target
) -> BigUintTarget {

    let random_access_index = trusted_next_intersect_indices[index];
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
    
    let new_intersection_vp = builder.add_biguint(intersection_vp, &vp);

    // ensure intersection pub keys
    (0..256).for_each(|j| {
        let untrusted_key = builder.random_access(
            untrusted_intersect_indices[index],
            untrusted_pub_keys_columns[j].clone(),
        );
        let trusted_key = builder.random_access(
            trusted_next_intersect_indices[index],
            trusted_pub_keys_columns[j].clone(),
        );
        let a = builder.mul(untrusted_key, enable_constraint.target);
        let b = builder.mul(trusted_key, enable_constraint.target);
        builder.connect(a, b);
    });

    new_intersection_vp
}

// Ensure that +2/3 of new validators signed correctly.
pub fn constrain_untrusted_quorum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    untrusted_validator_vps: &Vec<BigUintTarget>,
    signature_indices_set_1: &Vec<Target>,
    signature_indices_set_2: &Vec<Target>,
    c: &Config,
) {
    let mut zero_vp = builder.constant_biguint(&BigUint::from_u64(0).unwrap());
    // making zero_vp equivalent 64 bit target
    zero_vp.limbs.push(builder.constant_u32(0));
    zero_vp.limbs.push(builder.constant_u32(0));

    let mut untrusted_validator_vps = untrusted_validator_vps[0..c.N_VALIDATORS].to_vec();

    (c.N_VALIDATORS..c.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|_| {
        untrusted_validator_vps.push(zero_vp.clone());
    });
    let signature_indices_set_1 = signature_indices_set_1[0..c.N_SIGNATURE_INDICES_SET_1].to_vec();
    let signature_indices_set_2 = signature_indices_set_2[0..c.N_SIGNATURE_INDICES_SET_2].to_vec();

    let mut total_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let mut quorum_vp = builder.constant_biguint(&BigUint::from_usize(0).unwrap());
    let three_big_target = builder.constant_biguint(&BigUint::from_u64(3).unwrap());
    let two_big_target = builder.constant_biguint(&BigUint::from_u64(2).unwrap());
    let zero_bool_target = builder._false();

    // compute total voting power
    (0..c.N_VALIDATORS)
        .for_each(|i| total_vp = builder.add_biguint(&total_vp, &untrusted_validator_vps[i]));

    let signature_indices_domain_size = c.SIGNATURE_INDICES_DOMAIN_SIZE;
    // prepares voting power columns
    let untrusted_validator_set_1_vp_columns = vec![
        untrusted_validator_vps[..c.SIGNATURE_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        untrusted_validator_vps[..c.SIGNATURE_INDICES_DOMAIN_SIZE]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];

    let untrusted_validator_set_2_vp_columns = vec![
        untrusted_validator_vps[signature_indices_domain_size..(signature_indices_domain_size + signature_indices_domain_size)]
            .iter()
            .map(|x| x.get_limb(0).0)
            .collect::<Vec<Target>>(),
        untrusted_validator_vps[signature_indices_domain_size..(signature_indices_domain_size + signature_indices_domain_size)]
            .iter()
            .map(|x| x.get_limb(1).0)
            .collect::<Vec<Target>>(),
    ];

    (0..c.N_SIGNATURE_INDICES_SET_1).for_each(|i| {
        let random_access_index = signature_indices_set_1[i];

        // compute intersection voting power in trusted
        let vp = builder.add_virtual_biguint_target(c.VP_BITS.div_ceil(32));
        let vp_c0 = builder.random_access(
            random_access_index,
            untrusted_validator_set_1_vp_columns[0].clone(),
        );
        let vp_c1 = builder.random_access(
            random_access_index,
            untrusted_validator_set_1_vp_columns[1].clone(),
        );
        builder.connect(vp.get_limb(0).0, vp_c0);
        builder.connect(vp.get_limb(1).0, vp_c1);
        quorum_vp = builder.add_biguint(&quorum_vp, &vp);
    });

    (0..c.N_SIGNATURE_INDICES_SET_2).for_each(|i| {
        let random_access_index = signature_indices_set_2[i];

        // compute intersection voting power in trusted
        let vp = builder.add_virtual_biguint_target(c.VP_BITS.div_ceil(32));
        let vp_c0 = builder.random_access(
            random_access_index,
            untrusted_validator_set_2_vp_columns[0].clone(),
        );
        let vp_c1 = builder.random_access(
            random_access_index,
            untrusted_validator_set_2_vp_columns[1].clone(),
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
