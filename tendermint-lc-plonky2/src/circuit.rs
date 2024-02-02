use std::fs::File;
use std::io::{BufWriter, Write};
use std::marker::PhantomData;
use std::time::Instant;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, ProverOnlyCircuitData, VerifierCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig, Hasher};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::plonk::prover::prove;
use serde::Serialize;
use crate::input_types::Inputs;
use crate::serializer::{CustomGateSerializer, CustomGeneratorSerializer};
use crate::targets::{add_virtual_proof_target, ProofTarget, set_proof_target};
use crate::test_utils::get_test_data;
use crate::utils::{dump_bytes_to_json, dump_circuit_data, load_circuit_dat_from_dir, read_bytes_from_json};

pub fn save_proof_data<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + Serialize, const D: usize>(data: CircuitData<F, C, D>, proof: ProofWithPublicInputs<F, C, D>) {
    let common_data = data.common;
    let verifier_only_data = data.verifier_only;
    let pub_inputs = proof.public_inputs.clone();

    let file = File::create("tendermint-lc-plonky2/src/proof_data/common_data.json").unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &common_data).unwrap();
    writer.flush().unwrap();

    let file = File::create("tendermint-lc-plonky2/src/proof_data/proof_with_pis.json").unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &proof.proof).unwrap();
    writer.flush().unwrap();

    let file = File::create("tendermint-lc-plonky2/src/proof_data/verifier_only.json").unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &verifier_only_data).unwrap();
    writer.flush().unwrap();

    let file = File::create("tendermint-lc-plonky2/src/proof_data/pub_inputs.json").unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &pub_inputs).unwrap();
    writer.flush().unwrap();
}

pub fn generate_circuit<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> ProofTarget {
    let target = add_virtual_proof_target(builder);
    // register public inputs - {untrusted_hash, trusted_hash, untrusted_height, trusted_height}
    (0..target.untrusted_hash.len())
        .for_each(|i| builder.register_public_input(target.untrusted_hash[i].target));
    (0..target.trusted_hash.len())
        .for_each(|i| builder.register_public_input(target.trusted_hash[i].target));
    (0..target.untrusted_height.num_limbs())
        .for_each(|i| builder.register_public_input(target.untrusted_height.get_limb(i).0));
    (0..target.untrusted_height.num_limbs())
        .for_each(|i| builder.register_public_input(target.trusted_height.get_limb(i).0));
    target
}

pub struct RecursionTargets<const D: usize> {
    pt: ProofWithPublicInputsTarget<D>,
    inner_data: VerifierCircuitTarget
}

pub fn make_recursion_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
> (
    builder: &mut CircuitBuilder<F, D>,
    inner_common_data: &CommonCircuitData<F, D>,
) -> RecursionTargets<D> 
where
    InnerC::Hasher: AlgebraicHasher<F> 
{
    let pt = builder.add_virtual_proof_with_pis(inner_common_data);
    let inner_data = builder.add_virtual_verifier_data(inner_common_data.config.fri_config.cap_height);
    builder.register_public_inputs(&pt.public_inputs);
    builder.verify_proof::<InnerC>(&pt, &inner_data, inner_common_data);
    RecursionTargets::<D> {
        pt,
        inner_data,
    }
}


pub fn set_proof_targets<F: RichField + Extendable<D>, const D: usize, W: Witness<F>>(pw: &mut W, inputs: Inputs, proof_target: &ProofTarget) {
    set_proof_target::<F, W>(
        pw,
        &inputs.sign_messages_padded,
        &inputs.signatures,
        &inputs.untrusted_hash,
        &inputs.untrusted_version_padded,
        &inputs.untrusted_chain_id_padded,
        inputs.untrusted_height,
        &inputs.untrusted_time_padded,
        inputs.untrusted_timestamp,
        &inputs.untrusted_validators_hash_padded,
        &inputs.untrusted_validators_padded,
        &inputs.untrusted_validator_pub_keys,
        &inputs.untrusted_validator_vp,
        &inputs.untrusted_version_proof,
        &inputs.untrusted_chain_id_proof,
        &inputs.untrusted_time_proof,
        &inputs.untrusted_validators_hash_proof,
        &inputs.trusted_hash,
        inputs.trusted_height,
        &inputs.trusted_time_padded,
        inputs.trusted_timestamp,
        &inputs.trusted_next_validators_hash_padded,
        &inputs.trusted_next_validators_padded,
        &inputs.trusted_next_validator_pub_keys,
        &inputs.trusted_next_validator_vp,
        &inputs.trusted_time_proof,
        &inputs.trusted_next_validators_hash_proof,
        &inputs.trusted_chain_id_proof,
        &inputs.trusted_version_proof,
        &inputs.signature_indices,
        &inputs.untrusted_intersect_indices,
        &inputs.trusted_next_intersect_indices,
        &inputs.trusted_chain_id_padded,
        &inputs.trusted_version_padded,
        proof_target,
    );
}

// build and dump circuit data for tendermint lc circuit
pub fn build_tendermint_lc_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + 'static, const D: usize>(
    storage_dir: &str
)
where
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    println!("Building Tendermint lc circuit");
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let _target = generate_circuit::<F, D>(&mut builder);
    println!("Building circuit with {:?} gates", builder.num_gates());
    let t = Instant::now();
    let data = builder.build::<C>();
    println!("Time taken to build the circuit : {:?}", t.elapsed());
    dump_circuit_data::<F, C, D>(&data, storage_dir);
}

// build and dump circuit data for recursion circuit
pub fn build_recursion_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
> (
    inner_common_data_path: &str,
    storage_dir: &str
)
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
 {
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    println!("Reconstructing inner common data");
    let inner_cd_bytes = read_bytes_from_json(inner_common_data_path);
    let inner_common_data = CommonCircuitData::<F, D>::from_bytes(inner_cd_bytes, &CustomGateSerializer).unwrap();
    make_recursion_circuit::<F, C, InnerC, D>(&mut builder, &inner_common_data);
    println!("Building recursive circuit with {:?} gates", builder.num_gates());

    let data = builder.build::<C>();
    println!("Recursive circuit build complete");
    dump_circuit_data::<F, C, D>(&data, storage_dir);
}


pub fn generate_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + 'static, const D: usize>(
    lc_storage_dir: &str,
    recursive_storage_dir: &str,
    inputs: Inputs
) 
where
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{   
    println!("--- Light Client circuit ---");
    let data = load_circuit_dat_from_dir::<F, C, D>(lc_storage_dir);
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let target = generate_circuit::<F, D>(&mut builder);
    println!("Starting lc proof generation");
    let t_pg = Instant::now();
    let mut pw = PartialWitness::new();
    set_proof_targets::<F, D, PartialWitness<F>>(&mut pw, inputs, &target);
    let proof_with_pis = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut Default::default()).unwrap();
    println!("Proof generated in {:?}", t_pg.elapsed());
    let proof_with_pis_bytes = proof_with_pis.to_bytes();
    dump_bytes_to_json(proof_with_pis_bytes, format!("{lc_storage_dir}/proofs/proof_with_pis.json").as_str());

    data.verify(proof_with_pis.clone()).expect("verify error");

    println!("--- Recursion Circuit ---");
    // Add one more recursion proof generation layer 
    let recursive_data = load_circuit_dat_from_dir::<F, C, D>(recursive_storage_dir);
    let mut recursive_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    // Config for both outer and inner circuit are same for now
    let recursion_targets = make_recursion_circuit::<F, C, C, D>(&mut recursive_builder, &data.common);
    println!("Starting to generate recursive proof");
    let t_pg_rec = Instant::now();
    let mut pw_rec = PartialWitness::new();
    pw_rec.set_proof_with_pis_target(&recursion_targets.pt, &proof_with_pis);
    pw_rec.set_verifier_data_target(&recursion_targets.inner_data, &data.verifier_only);
    let rec_proof_with_pis = prove::<F, C, D>(&recursive_data.prover_only, &recursive_data.common, pw_rec, &mut Default::default()).unwrap();
    let proof_with_pis_bytes = proof_with_pis.to_bytes();
    dump_bytes_to_json(proof_with_pis_bytes, format!("{recursive_storage_dir}/proofs/proof_with_pis.json").as_str());
    println!("recursive proof gen done in {:?}", t_pg_rec.elapsed());
    recursive_data.verify(rec_proof_with_pis).expect("verify error");

}

pub fn run_circuit() {
    //TODO: move this stuff to yaml
    let light_client_path = "/home/ubuntu/tendermint-lc-plonky2/data_store/lc_circuit";
    let recursion_path = "/home/ubuntu/tendermint-lc-plonky2/data_store/recursion_circuit";

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let t: Inputs = get_test_data();

    // TODO pick this x up from cmd env
    let x: usize = 3;

    // Build tendermint light client circuit
    if x == 1{
        build_tendermint_lc_circuit::<F, C, D>(light_client_path);
    }
    // Build recursive circuit 
    if x == 2{
        build_recursion_circuit::<F, C, C, D>(format!("{light_client_path}/circuit_data/common_data.json").as_str(), recursion_path);
    }
    // Generate proof for lc and recursion both
    if x == 3 {
        generate_proof::<F, C, D>(light_client_path, recursion_path, t);
    }
}