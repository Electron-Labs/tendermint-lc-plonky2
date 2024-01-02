#[cfg(test)]
mod tests {
    use crate::merkle_tree_gadget::{get_256_bool_target, SHA_BLOCK_BITS};
    use crate::targets::{
        add_virtual_connect_sign_message_target, add_virtual_connect_timestamp_target,
        add_virtual_trusted_quorum_target, add_virtual_update_validity_target,
        is_not_null_signature, UpdateValidityTarget, N_INTERSECTION_INDICES, N_VALIDATORS,
        SIGN_MESSAGE_BITS, TRUSTING_PERIOD,
    };
    use crate::test_utils::get_test_data;
    use num::BigUint;
    use num::FromPrimitive;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::{
        field::types::Field, hash::hash_types::RichField, iop::target::BoolTarget,
        plonk::circuit_builder::CircuitBuilder,
    };
    use plonky2_crypto::{biguint::WitnessBigUint, hash::sha256::WitnessHashSha2};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // TODO: load all test data only once

    pub fn prove_and_verify(data: CircuitData<F, C, D>, witness: PartialWitness<F>) {
        let start_time = std::time::Instant::now();
        let proof = data.prove(witness).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    fn set_validity_target<F: RichField, W: WitnessHashSha2<F>>(
        witness: &mut W,
        untrusted_height: u64,
        trusted_height: u64,
        untrusted_timestamp: u64,
        trusted_timestamp: u64,
        target: &UpdateValidityTarget,
    ) {
        witness.set_biguint_target(
            &target.untrusted_height,
            &BigUint::from_u64(untrusted_height).unwrap(),
        );
        witness.set_biguint_target(
            &target.trusted_height,
            &BigUint::from_u64(trusted_height).unwrap(),
        );
        witness.set_biguint_target(
            &target.untrusted_timestamp,
            &BigUint::from_u64(untrusted_timestamp).unwrap(),
        );
        witness.set_biguint_target(
            &target.trusted_timestamp,
            &BigUint::from_u64(trusted_timestamp).unwrap(),
        );
    }

    #[test]
    fn test_update_validity_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        set_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            &target,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_target_invalid_height_1() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();
        set_validity_target(
            &mut witness,
            12975357,
            12975356,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            &target,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_target_invalid_height_2() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();
        set_validity_target(
            &mut witness,
            12975357,
            12975357,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            &target,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_target_invalid_timestamp() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let untrusted_timestamp = data.trusted_timestamp + TRUSTING_PERIOD as u64 + 1;

        set_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            untrusted_timestamp,
            data.trusted_timestamp,
            &target,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_sign_message() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_sign_message_target(&mut builder);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..SIGN_MESSAGE_BITS)
            .for_each(|i| witness.set_bool_target(target.message[i], data.sign_message[i]));
        (0..256)
            .for_each(|i| witness.set_bool_target(target.header_hash[i], data.untrusted_hash[i]));
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_sign_message_wrong_hash() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_sign_message_target(&mut builder);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..SIGN_MESSAGE_BITS)
            .for_each(|i| witness.set_bool_target(target.message[i], data.sign_message[i]));
        let mut hash = data.untrusted_hash;
        hash[0] = true;

        (0..256).for_each(|i| witness.set_bool_target(target.header_hash[i], hash[i]));
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_sign_message_wrong_height() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_sign_message_target(&mut builder);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..SIGN_MESSAGE_BITS)
            .for_each(|i| witness.set_bool_target(target.message[i], data.sign_message[i]));
        let mut height = data.untrusted_height;
        height += 1;

        (0..256)
            .for_each(|i| witness.set_bool_target(target.header_hash[i], data.untrusted_hash[i]));
        witness.set_biguint_target(&target.height, &BigUint::from_u64(height).unwrap());

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_timestamp() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_timestamp_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(target.header_time_padded[i], data.untrusted_time_padded[i])
        });
        witness.set_biguint_target(
            &target.header_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_timestamp_incorrect() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_timestamp_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(target.header_time_padded[i], data.untrusted_time_padded[i])
        });
        witness.set_biguint_target(
            &target.header_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp + 1).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_is_not_null_signature() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let mut signatures_target = vec![(0..64 * 8)
            .map(|_| builder._false())
            .collect::<Vec<BoolTarget>>()];
        let mut temp = vec![builder._true()];
        (0..64 * 8 - 1).for_each(|_| temp.push(builder._false()));
        signatures_target.push(temp);

        let is_not_null_signature = is_not_null_signature(&mut builder, signatures_target);
        let one = builder._true();
        let zero = builder._false();
        builder.connect(is_not_null_signature[0].target, zero.target);
        builder.connect(is_not_null_signature[1].target, one.target);

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    // TODO: add negative tests
    #[test]
    fn test_sufficient_trusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let mut target = add_virtual_trusted_quorum_target(&mut builder);

        let data = get_test_data();

        (0..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.trusted_validator_pub_keys[i][j],
                    data.trusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_validator_votes[i],
                &BigUint::from_u64(data.trusted_validator_votes[i]).unwrap(),
            )
        });

        let signatures_target = (0..N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        (0..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(signatures_target[i][j], data.untrusted_signatures[i][j]);
            })
        });
        let is_not_null_signature = is_not_null_signature(&mut builder, signatures_target);
        (0..N_VALIDATORS).for_each(|i| {
            builder.connect(
                target.is_not_null_signature[i].target,
                is_not_null_signature[i].target,
            )
        });

        // TODO: what about 0 indices?
        (0..N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.untrusted_intersect_indices[i],
                F::from_canonical_u8(data.untrusted_intersect_indices[i]),
            )
        });
        (0..N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.trusted_intersect_indices[i],
                F::from_canonical_u8(data.trusted_intersect_indices[i]),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
