use num::{BigUint, Integer, Zero, FromPrimitive};
use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget,
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_crypto::{
    biguint::{BigUintTarget, CircuitBuilderBiguint, WitnessBigUint},
    hash::{
        sha256::{CircuitBuilderHashSha2, WitnessHashSha2},
        CircuitBuilderHash, Hash256Target, HashInputTarget, WitnessHash,
    },
    u32::arithmetic_u32::CircuitBuilderU32,
};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};


pub fn add_virtual_cmp_vec_bool_target <F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F,D>,
    vec_bool_target_1: Vec<BoolTarget>,
    vec_bool_target_2: Vec<BoolTarget>
) -> BoolTarget{
    let mut result = builder._true();
    for i in 0..vec_bool_target_1.len(){
        let cmp = builder.is_equal(vec_bool_target_1[i].target, vec_bool_target_2[i].target);
        result = builder.and(result,cmp);
    }
    return result;
}

pub fn add_virtual_dummy_verify_signature_target<F: RichField + Extendable<D>, const D:usize>(
    builder: &mut CircuitBuilder<F,D>,
    validator_signature: Vec<BoolTarget>
) -> BoolTarget {
    let mut result = builder._false();
    for i in 0..validator_signature.len(){
        result = builder.or(result,validator_signature[i]);
    }
    return result;
}


#[cfg(test)]

 #[test]
    fn test_cmp_vec_bool_target(){
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut pw = PartialWitness::new();

        let b1 = (0..32).map(|_| {
            builder.add_virtual_bool_target_safe()
        }).collect::<Vec<BoolTarget>>();
        let b2 =  (0..32).map(|_| {
            builder.add_virtual_bool_target_safe()
        }).collect::<Vec<BoolTarget>>();

        let result = add_virtual_cmp_vec_bool_target(&mut builder,b1.clone(),b2.clone());

        for i in 0..b1.len() {
            if i%2 == 0{
                pw.set_bool_target(b1[i], false);
                pw.set_bool_target(b2[i], false);
            }
            else {
                pw.set_bool_target(b1[i], true);
                pw.set_bool_target(b2[i], true);
            }
            
        }
        let true_target = builder._true();
        builder.connect(result.target, true_target.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok())
    }

    #[test]
    #[should_panic]
    fn test_neg_cmp_vec_bool_target(){
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut pw = PartialWitness::new();

        let b1 = (0..32).map(|_| {
            builder.add_virtual_bool_target_safe()
        }).collect::<Vec<BoolTarget>>();
        let b2 =  (0..32).map(|_| {
            builder.add_virtual_bool_target_safe()
        }).collect::<Vec<BoolTarget>>();

        let result = add_virtual_cmp_vec_bool_target(&mut builder,b1.clone(),b2.clone());

        for i in 0..b1.len() {
            pw.set_bool_target(b1[i], true);
            pw.set_bool_target(b2[i], false);
        }
        let true_target = builder._true();
        builder.connect(result.target, true_target.target);
        
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok())
    }
    
    #[test]
    fn test_dummy_verify_signature_target(){
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut pw = PartialWitness::new();
        let b1 = (0..64*8).map(|_| {
            builder.add_virtual_bool_target_safe()
        }).collect::<Vec<BoolTarget>>();

        let result = add_virtual_dummy_verify_signature_target(&mut builder, b1.clone());

        for i in 0..b1.len() {
            pw.set_bool_target(b1[i], true);
        }
        let true_target = builder._true();
        builder.connect(result.target, true_target.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    #[should_panic] 
    fn test_neg_dummy_verify_signature_target(){
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut pw = PartialWitness::new();
        
        let b1 = (0..64*8).map(|_| {
            builder.add_virtual_bool_target_safe()
        }).collect::<Vec<BoolTarget>>();

        let result = add_virtual_dummy_verify_signature_target(&mut builder, b1.clone());
        for i in 0..b1.len() {
            pw.set_bool_target(b1[i], false);
        }
        let true_target = builder._true();
        builder.connect(result.target, true_target.target);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        assert!(data.verify(proof).is_ok());
    }

