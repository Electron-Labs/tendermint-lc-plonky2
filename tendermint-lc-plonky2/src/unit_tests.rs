#[cfg(test)]
mod tests {
    use crate::targets::{
        add_virtual_connect_sign_message_target, add_virtual_update_validity_target, HEIGHT_BITS,
        SIGN_MESSAGE_BITS,
    };
    use crate::test_utils::get_test_data;
    use num::BigUint;
    use num::FromPrimitive;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
    use plonky2_crypto::{biguint::WitnessBigUint, hash::WitnessHash};

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    pub fn prove_and_verify(data: CircuitData<F, C, D>, witness: PartialWitness<F>) {
        let start_time = std::time::Instant::now();
        let proof = data.prove(witness).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_update_validity_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        witness.set_biguint_target(
            &target.untrusted_height,
            &BigUint::from_i32(12975357).unwrap(),
        );
        witness.set_biguint_target(
            &target.trusted_height,
            &BigUint::from_i32(12975355).unwrap(),
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

        witness.set_biguint_target(
            &target.untrusted_height,
            &BigUint::from_i32(12975357).unwrap(),
        );
        witness.set_biguint_target(
            &target.trusted_height,
            &BigUint::from_i32(12975356).unwrap(),
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

        witness.set_biguint_target(
            &target.untrusted_height,
            &BigUint::from_i32(12975357).unwrap(),
        );
        witness.set_biguint_target(
            &target.trusted_height,
            &BigUint::from_i32(12975357).unwrap(),
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
            .for_each(|i| witness.set_bool_target(target.message[i], data.message[i]));
        (0..256).for_each(|i| {
            witness.set_bool_target(target.header_hash[i], data.untrusted_header_hash[i])
        });
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_bytes_le(&data.untrusted_header_height),
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
            .for_each(|i| witness.set_bool_target(target.message[i], data.message[i]));
        let mut hash = data.untrusted_header_hash;
        hash[0] = true;

        (0..256).for_each(|i| {
            witness.set_bool_target(target.header_hash[i], hash[i])
        });
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_bytes_le(&data.untrusted_header_height),
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
            .for_each(|i| witness.set_bool_target(target.message[i], data.message[i]));
        let mut height = data.untrusted_header_height;
        height[0] = 10;

        (0..256).for_each(|i| {
            witness.set_bool_target(target.header_hash[i], data.untrusted_header_hash[i])
        });
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_bytes_le(&height),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
