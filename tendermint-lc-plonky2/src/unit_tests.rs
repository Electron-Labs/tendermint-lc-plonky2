#[cfg(test)]
mod tests {
    use crate::targets::add_virtual_update_validity_target;
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

        witness.set_biguint_target(&target.untrusted_height, &BigUint::from_i32(12975357).unwrap());
        witness.set_biguint_target(&target.trusted_height, &BigUint::from_i32(12975355).unwrap());

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

        witness.set_biguint_target(&target.untrusted_height, &BigUint::from_i32(12975357).unwrap());
        witness.set_biguint_target(&target.trusted_height, &BigUint::from_i32(12975356).unwrap());

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

        witness.set_biguint_target(&target.untrusted_height, &BigUint::from_i32(12975357).unwrap());
        witness.set_biguint_target(&target.trusted_height, &BigUint::from_i32(12975357).unwrap());

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
