#[cfg(test)]
mod tests {

    extern crate rustc_serialize;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use rustc_serialize::json::Json;
    use std::fs::File;
    use std::io::Read;
    use crate::targets::{
        add_virtual_update_validity_target,
        add_virtual_untrusted_quorum_target, N_VALIDATORS,
        add_virtual_trusted_quorum_target, is_verified_signature,
    };
    use crate::test_utils::get_test_data;
    use num::BigUint;
    use num::FromPrimitive;
    use plonky2::iop::target::BoolTarget;
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

    #[test]
    fn test_sufficient_untrusted_quorum(){

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut witness = PartialWitness::new();
        let start_time = std::time::Instant::now();


        let untrusted_quorum = add_virtual_untrusted_quorum_target(&mut builder);
        let is_verified_signature = is_verified_signature(&mut builder, untrusted_quorum.untrusted_signatures.clone());
        println!("built target in {}ms",start_time.elapsed().as_millis());

        
        let test_data = get_test_data();
        let untrusted_validators_pub_key = test_data.untrusted_validators_pub_key;
        let untrusted_voting_power = test_data.untrusted_voting_power;
        let untrusted_signatures = test_data.untrusted_signatures;
        

        for i in 0..N_VALIDATORS{
            for j in 0..32*8{
                witness.set_bool_target(untrusted_quorum.untrusted_validators_pub_keys[i][j], untrusted_validators_pub_key[i][j]);
            }
            for j in 0..64*8 {
                witness.set_bool_target(untrusted_quorum.untrusted_signatures[i][j], untrusted_signatures[i][j]);
            }
            witness.set_biguint_target(&untrusted_quorum.untrusted_validators_votes[i], &BigUint::from_u64(untrusted_voting_power[i]).unwrap());
        }
        for i in 0..is_verified_signature.len(){
            builder.connect(is_verified_signature[i].target, untrusted_quorum.is_verified_signature[i].target);
        }
        let data = builder.build::<C>();
        let proof = data.prove(witness).unwrap();
        println!("proved in {}ms",start_time.elapsed().as_millis());
        assert!(data.verify(proof).is_ok());    
        
    }
    #[test]
    #[should_panic]
    fn test_insufficient_untrusted_quorum(){

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut witness = PartialWitness::new();
        let start_time = std::time::Instant::now();

        let untrusted_quorum = add_virtual_untrusted_quorum_target(&mut builder);
        let is_verified_signature = is_verified_signature(&mut builder, untrusted_quorum.untrusted_signatures.clone());
        println!("built target in {}ms",start_time.elapsed().as_millis());

        

        let mut file1 = File::open("src/test_data/dummy_data.json").unwrap();
        let mut data1 = String::new();
        file1.read_to_string(&mut data1).unwrap();
        let json1 = Json::from_str(&data1).unwrap();


        let test_data = get_test_data();
        let untrusted_validators_pub_key = test_data.untrusted_validators_pub_key;
        let untrusted_voting_power = test_data.untrusted_voting_power;
        let untrusted_signatures = json1.find_path(&["neg_untrusted_signatures"]).unwrap();
        

        for i in 0..N_VALIDATORS{
            for j in 0..32*8{
                witness.set_bool_target(untrusted_quorum.untrusted_validators_pub_keys[i][j], untrusted_validators_pub_key[i][j]);
            }
            for j in 0..64*8{
                witness.set_bool_target(untrusted_quorum.untrusted_signatures[i][j], untrusted_signatures[i][j].as_boolean().unwrap());
            }
            witness.set_biguint_target(&untrusted_quorum.untrusted_validators_votes[i], &BigUint::from_u64(untrusted_voting_power[i]).unwrap());
        }

        for i in 0..is_verified_signature.len(){
            builder.connect(is_verified_signature[i].target, untrusted_quorum.is_verified_signature[i].target);
        }
        
        let data = builder.build::<C>();
        let proof = data.prove(witness).unwrap();
        println!("proved in {}ms",start_time.elapsed().as_millis());
        assert!(data.verify(proof).is_ok());    
        
    }
    #[test]
    fn test_sufficient_trusted_quorum(){
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut witness = PartialWitness::new();
        let start_time = std::time::Instant::now();

        let trusted_quorum = add_virtual_trusted_quorum_target(&mut builder);
        let is_verified_signature = is_verified_signature(&mut builder, trusted_quorum.untrusted_signatures.clone());
        println!("built target in {}ms",start_time.elapsed().as_millis());


        let test_data = get_test_data();
        let untrusted_validators_pub_key = test_data.untrusted_validators_pub_key;
        let untrusted_signatures = test_data.untrusted_signatures;
        let untrusted_voting_power = test_data.untrusted_voting_power;
        let trusted_validators_pub_key = test_data.trusted_validators_pub_key;
        let trusted_voting_power = test_data.trusted_voting_power;


        for i in 0..N_VALIDATORS {
            for j in 0..32*8 {
                witness.set_bool_target(trusted_quorum.trusted_validators_pub_keys[i][j], trusted_validators_pub_key[i][j]);
                witness.set_bool_target(trusted_quorum.untrusted_validators_pub_keys[i][j], untrusted_validators_pub_key[i][j]);
            }
            for j in 0..64*8 {
                witness.set_bool_target(trusted_quorum.untrusted_signatures[i][j],untrusted_signatures[i][j]);
            }
            witness.set_biguint_target(&trusted_quorum.trusted_validators_votes[i], &BigUint::from_u64(trusted_voting_power[i]).unwrap());
            witness.set_biguint_target(&trusted_quorum.untrusted_validators_votes[i], &BigUint::from_u64(untrusted_voting_power[i]).unwrap());
        }
        for i in 0..is_verified_signature.len(){
            builder.connect(is_verified_signature[i].target, trusted_quorum.is_verified_signature[i].target);
        }
        
        let data = builder.build::<C>();
        let proof = data.prove(witness).unwrap();
        println!("proved in {}ms",start_time.elapsed().as_millis());
        assert!(data.verify(proof).is_ok());

    }

    #[test]
    #[should_panic]
    fn test_insufficient_trusted_quorum(){
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut witness = PartialWitness::new();
        let start_time = std::time::Instant::now();

        let trusted_quorum = add_virtual_trusted_quorum_target(&mut builder);
        let is_verified_signature = is_verified_signature(&mut builder, trusted_quorum.untrusted_signatures.clone());
        println!("built target in {}ms",start_time.elapsed().as_millis());

        let mut file1 = File::open("src/test_data/dummy_data.json").unwrap();
        let mut data1 = String::new();
        file1.read_to_string(&mut data1).unwrap();
        let json1 = Json::from_str(&data1).unwrap();
        
        let test_data = get_test_data();
        let untrusted_validators_pub_key = test_data.untrusted_validators_pub_key;
        let untrusted_voting_power = test_data.untrusted_voting_power;
        let trusted_voting_power = test_data.trusted_voting_power;

        let trusted_validators_pub_key = json1.find_path(&["neg_trusted_validators_pub_key"]).unwrap();
        let untrusted_signatures = json1.find_path(&["neg_untrusted_signatures"]).unwrap();


        for i in 0..N_VALIDATORS {
            for j in 0..32*8 {
                witness.set_bool_target(trusted_quorum.trusted_validators_pub_keys[i][j], trusted_validators_pub_key[i][j].as_boolean().unwrap());
                witness.set_bool_target(trusted_quorum.untrusted_validators_pub_keys[i][j], untrusted_validators_pub_key[i][j]);
            }
            for j in 0..64*8 {
                witness.set_bool_target(trusted_quorum.untrusted_signatures[i][j],untrusted_signatures[i][j].as_boolean().unwrap());
            }
            witness.set_biguint_target(&trusted_quorum.trusted_validators_votes[i], &BigUint::from_u64(trusted_voting_power[i]).unwrap());
            witness.set_biguint_target(&trusted_quorum.untrusted_validators_votes[i], &BigUint::from_u64(untrusted_voting_power[i]).unwrap());
        }
        for i in 0..is_verified_signature.len(){
            builder.connect(is_verified_signature[i].target, trusted_quorum.is_verified_signature[i].target);
        }
        let data = builder.build::<C>();
        let proof = data.prove(witness).unwrap();
        println!("proved in {}ms",start_time.elapsed().as_millis());
        assert!(data.verify(proof).is_ok());
    }
}
