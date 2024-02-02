use std::fs::File;
use std::io::{BufWriter, Write};
use std::marker::PhantomData;
use std::time::Instant;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, ProverOnlyCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use serde::Serialize;
use crate::input_types::Inputs;
use crate::serializer::{CustomGateSerializer, CustomGeneratorSerializer};
use crate::targets::{add_virtual_proof_target, ProofTarget, set_proof_target};
use crate::test_utils::get_test_data;
use crate::utils::{dump_bytes_to_json, read_bytes_from_json};

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

pub fn build_tendermint_lc_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + 'static, const D: usize>(
    storage_dir: &str
)
where
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    println!("Building Tendermint lc circuit");
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let target = generate_circuit::<F, D>(&mut builder);
    println!("Building circuit with {:?} gates", builder.num_gates());
    let t = Instant::now();
    let data = builder.build::<C>();
    println!("Time taken to build the circuit : {:?}", t.elapsed());
    let cd_bytes = data.common.clone().to_bytes(&CustomGateSerializer).unwrap();
    dump_bytes_to_json(cd_bytes, format!("{storage_dir}/common_data.json").as_str());
    let prover_only_bytes = data.prover_only.to_bytes(&CustomGeneratorSerializer::<C, D> {_phantom: PhantomData::<C>}, &data.common).unwrap();
    dump_bytes_to_json(prover_only_bytes, format!("{storage_dir}/prover_only.json").as_str());
    let verifier_only_bytes = data.verifier_only.to_bytes().unwrap();
    dump_bytes_to_json(verifier_only_bytes, format!("{storage_dir}/verifier_only.json").as_str());
}

pub fn generate_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + 'static, const D: usize>(
    storage_dir: &str,
    inputs: Inputs
) 
where
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    println!("Reconstructing common data");
    let t_cd = Instant::now();
    let cd_bytes = read_bytes_from_json(format!("{storage_dir}/common_data.json").as_str());
    let common_data = CommonCircuitData::<F, D>::from_bytes(cd_bytes, &CustomGateSerializer).unwrap();
    println!("Common data reconstructed in {:?}", t_cd.elapsed());

    println!("Reconstructing prover only data");
    let t_po = Instant::now();
    let prover_only_bytes = read_bytes_from_json(format!("{storage_dir}/prover_only.json").as_str());
    let prover_only = ProverOnlyCircuitData::<F, C, D>::from_bytes(
        prover_only_bytes.as_slice(),
        &CustomGeneratorSerializer::<C, D> {_phantom: PhantomData::<C>},
        &common_data
    ).unwrap();
    println!("Prover only data reconstructed in {:?}", t_po.elapsed());    

    println!("Reconstructing verifier only data");
    let t_vo = Instant::now();
    let verifier_only_bytes = read_bytes_from_json(format!("{storage_dir}/verifier_only.json").as_str());
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes).unwrap();
    println!("Verifier only data reconstructed in {:?}", t_vo.elapsed());

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let target = generate_circuit::<F, D>(&mut builder);
    println!("Starting proof generation");
    let t_pg = Instant::now();
    let mut pw = PartialWitness::new();
    set_proof_targets::<F, D, PartialWitness<F>>(&mut pw, inputs, &target);
    let proof_with_pis = prove::<F, C, D>(&prover_only, &common_data, pw, &mut Default::default()).unwrap();
    println!("Proof generated in {:?}", t_pg.elapsed());
    let proof_with_pis_bytes = proof_with_pis.to_bytes();
    dump_bytes_to_json(proof_with_pis_bytes, format!("{storage_dir}/proof_with_pis.json").as_str());

    let data = CircuitData::<F, C, D> {
        prover_only,
        verifier_only,
        common: common_data,
    };
    data.verify(proof_with_pis).expect("verify error");
}

pub fn run_circuit() {
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_ecc_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut witness = PartialWitness::new();

    let target = generate_circuit::<F, D>(&mut builder);

    let t: Inputs = get_test_data();

    set_proof_targets::<F, D, PartialWitness<F>>(&mut witness, t, &target);

    println!("Starting to build the circuit");
    let data = builder.build::<C>();
    println!("Circuit build done");
    println!("Proof gen started");
    let start_time = std::time::Instant::now();
    let proof = data.prove(witness).unwrap();
    let duration_ms = start_time.elapsed().as_millis();
    println!("proved in {}ms", duration_ms);
    assert!(data.verify(proof.clone()).is_ok());

    // save_proof_data::<F, C, D>(data, proof);
}