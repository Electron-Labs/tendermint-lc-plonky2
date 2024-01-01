#[cfg(test)]
mod tests {

    extern crate rustc_serialize;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use rustc_serialize::json::Json;
    use std::fs::File;
    use std::io::Read;
    use crate::targets::{
        add_virtual_update_validity_target,
        add_virtual_untrusted_consensus_target, N_VALIDATORS,
        add_virtual_trusted_quorum_target,
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
        let mut pw = PartialWitness::new();
        let start_time = std::time::Instant::now();

        let untrusted_consensus = add_virtual_untrusted_consensus_target(&mut builder);
        println!("built target in {}ms",start_time.elapsed().as_millis());

        //getting data from json
        let mut file = File::open("src/test_data/12946557_12975357.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let json = Json::from_str(&data).unwrap();
        
        let untrusted_validators_pub_key = json.find_path(&["untrusted_validators_pub_key"]).unwrap();
        let untrusted_voting_power = json.find_path(&["untrusted_voting_power"]).unwrap();
        let untrusted_signatures = json.find_path(&["untrusted_signatures"]).unwrap();
        

        for i in 0..N_VALIDATORS{
            for j in 0..32*8{
                pw.set_bool_target(untrusted_consensus.untrusted_validators_pub_keys[i][j], untrusted_validators_pub_key[i][j].as_boolean().unwrap());
            }
            for j in 0..64*8 {
                pw.set_bool_target(untrusted_consensus.untrusted_signatures[i][j], untrusted_signatures[i][j].as_boolean().unwrap());
            }
            pw.set_biguint_target(&untrusted_consensus.untrusted_validators_votes[i], &BigUint::from_u64(untrusted_voting_power[i].as_u64().unwrap()).unwrap());
        }
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        println!("proved in {}ms",start_time.elapsed().as_millis());
        assert!(data.verify(proof).is_ok());    
        
    }
    #[test]
    #[should_panic]
    fn test_insufficient_untrusted_quorum(){

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();
        let start_time = std::time::Instant::now();

        let untrusted_consensus = add_virtual_untrusted_consensus_target(&mut builder);
        println!("built target in {}ms",start_time.elapsed().as_millis());

        //getting data from json
        let mut file = File::open("src/test_data/12946557_12975357.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let json = Json::from_str(&data).unwrap();

        let mut file1 = File::open("src/test_data/dummy_data.json").unwrap();
        let mut data1 = String::new();
        file1.read_to_string(&mut data1).unwrap();
        let json1 = Json::from_str(&data1).unwrap();


        let untrusted_validators_pub_key = json.find_path(&["untrusted_validators_pub_key"]).unwrap();
        let untrusted_voting_power = json.find_path(&["untrusted_voting_power"]).unwrap();
        let untrusted_signatures = json1.find_path(&["neg_untrusted_signatures"]).unwrap();
        

        for i in 0..N_VALIDATORS{
            for j in 0..32*8{
                pw.set_bool_target(untrusted_consensus.untrusted_validators_pub_keys[i][j], untrusted_validators_pub_key[i][j].as_boolean().unwrap());
            }
            for j in 0..64*8{
                pw.set_bool_target(untrusted_consensus.untrusted_signatures[i][j], untrusted_signatures[i][j].as_boolean().unwrap());
            }
            pw.set_biguint_target(&untrusted_consensus.untrusted_validators_votes[i], &BigUint::from_u64(untrusted_voting_power[i].as_u64().unwrap()).unwrap());
        }
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        println!("proved in {}ms",start_time.elapsed().as_millis());
        assert!(data.verify(proof).is_ok());    
        
    }
    #[test]
    fn test_sufficient_trusted_quorum(){
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();
        let start_time = std::time::Instant::now();

        let trusted_quorum = add_virtual_trusted_quorum_target(&mut builder);
        println!("built target in {}ms",start_time.elapsed().as_millis());


        //getting data from json
        let mut file = File::open("src/test_data/12946557_12975357.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let json = Json::from_str(&data).unwrap();
        
        let untrusted_validators_pub_key = json.find_path(&["untrusted_validators_pub_key"]).unwrap();
        let untrusted_voting_power = json.find_path(&["untrusted_voting_power"]).unwrap();
        let trusted_validators_pub_key = json.find_path(&["trusted_validators_pub_key"]).unwrap();
        let trusted_voting_power = json.find_path(&["trusted_voting_power"]).unwrap();


        for i in 0..N_VALIDATORS {
            for j in 0..32*8 {
                pw.set_bool_target(trusted_quorum.trusted_validators_pub_keys[i][j], trusted_validators_pub_key[i][j].as_boolean().unwrap());
                pw.set_bool_target(trusted_quorum.untrusted_validators_pub_keys[i][j], untrusted_validators_pub_key[i][j].as_boolean().unwrap());
            }
            pw.set_biguint_target(&trusted_quorum.trusted_validators_votes[i], &BigUint::from_u64(trusted_voting_power[i].as_u64().unwrap()).unwrap());
            pw.set_biguint_target(&trusted_quorum.untrusted_validators_votes[i], &BigUint::from_u64(untrusted_voting_power[i].as_u64().unwrap()).unwrap());
        }
        
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        println!("proved in {}ms",start_time.elapsed().as_millis());
        assert!(data.verify(proof).is_ok());


    }

    #[test]
    #[should_panic]
    fn test_insufficient_trusted_quorum(){
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let mut pw = PartialWitness::new();
        let start_time = std::time::Instant::now();

        let trusted_quorum = add_virtual_trusted_quorum_target(&mut builder);
        println!("built target in {}ms",start_time.elapsed().as_millis());


        //getting data from json
        let mut file = File::open("src/test_data/12946557_12975357.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let json = Json::from_str(&data).unwrap();

        let mut file1 = File::open("src/test_data/dummy_data.json").unwrap();
        let mut data1 = String::new();
        file1.read_to_string(&mut data1).unwrap();
        let json1 = Json::from_str(&data1).unwrap();
        
        let untrusted_validators_pub_key = json.find_path(&["untrusted_validators_pub_key"]).unwrap();
        let untrusted_voting_power = json.find_path(&["untrusted_voting_power"]).unwrap();
        let trusted_validators_pub_key = json1.find_path(&["neg_trusted_validators_pub_key"]).unwrap();
        let trusted_voting_power = json.find_path(&["trusted_voting_power"]).unwrap();


        for i in 0..N_VALIDATORS {
            for j in 0..32*8 {
                pw.set_bool_target(trusted_quorum.trusted_validators_pub_keys[i][j], trusted_validators_pub_key[i][j].as_boolean().unwrap());
                pw.set_bool_target(trusted_quorum.untrusted_validators_pub_keys[i][j], untrusted_validators_pub_key[i][j].as_boolean().unwrap());
            }
            pw.set_biguint_target(&trusted_quorum.trusted_validators_votes[i], &BigUint::from_u64(trusted_voting_power[i].as_u64().unwrap()).unwrap());
            pw.set_biguint_target(&trusted_quorum.untrusted_validators_votes[i], &BigUint::from_u64(untrusted_voting_power[i].as_u64().unwrap()).unwrap());
        }
        
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        println!("proved in {}ms",start_time.elapsed().as_millis());
        assert!(data.verify(proof).is_ok());
    }

}
