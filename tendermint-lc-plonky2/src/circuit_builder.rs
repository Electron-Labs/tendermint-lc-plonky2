use crate::circuits::tendermint::{add_virtual_proof_target, set_proof_target, ProofTarget};
use crate::config_data::{get_chain_config, Config};
use crate::input_types::{get_inputs_for_height, Inputs};
use crate::tests::test_heights::*;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::plonk::prover::prove;
use plonky2_circuit_serializer::serializer::CustomGateSerializer;
use plonky2_circuit_serializer::utils::{
    dump_bytes_to_json, dump_circuit_data, load_circuit_data_from_dir, read_bytes_from_json,
};
use std::time::Instant;
use tokio::time::{sleep, Duration};
use tracing::{info,error};

pub fn get_lc_storage_dir(chain_name: &str, storage_dir: &str) -> String {
    format!("{storage_dir}/{chain_name}/lc_circuit")
}

pub fn get_recursive_storage_dir(chain_name: &str, storage_dir: &str) -> String {
    format!("{storage_dir}/{chain_name}/recursion_circuit")
}

pub fn generate_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    config: &Config,
) -> ProofTarget {
    let target = add_virtual_proof_target(builder, config);
    // register public inputs - {trusted_hash, trusted_height, untrusted_hash, untrusted_height}
    (0..target.trusted_hash.len())
        .for_each(|i| builder.register_public_input(target.trusted_hash[i].0));
    (0..target.untrusted_height.num_limbs())
        .for_each(|i| builder.register_public_input(target.trusted_height.get_limb(i).0));
    (0..target.untrusted_hash.len())
        .for_each(|i| builder.register_public_input(target.untrusted_hash[i].0));
    (0..target.untrusted_height.num_limbs())
        .for_each(|i| builder.register_public_input(target.untrusted_height.get_limb(i).0));
    target
}

pub struct RecursionTargets<const D: usize> {
    pt: ProofWithPublicInputsTarget<D>,
    inner_data: VerifierCircuitTarget,
}

pub struct GeneratedProofInfo {
    pub proof_with_pis: Vec<u8>,
    pub proof_generate_time_duration: Duration,
    pub recursive_proof_generation_time_duration: Duration,
}

pub fn make_recursion_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
    inner_common_data: &CommonCircuitData<F, D>,
) -> RecursionTargets<D>
where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let pt = builder.add_virtual_proof_with_pis(inner_common_data);
    let inner_data =
        builder.add_virtual_verifier_data(inner_common_data.config.fri_config.cap_height);
    builder.register_public_inputs(&pt.public_inputs);
    builder.verify_proof::<InnerC>(&pt, &inner_data, inner_common_data);
    RecursionTargets::<D> { pt, inner_data }
}

pub fn set_proof_targets<F: RichField + Extendable<D>, const D: usize, W: Witness<F>>(
    pw: &mut W,
    inputs: Inputs,
    proof_target: &ProofTarget,
    config: &Config,
) {
    set_proof_target::<F, W>(
        pw,
        &inputs.sign_messages_padded_set_1,
        &inputs.sign_messages_padded_set_2,
        &inputs.signatures_set_1,
        &inputs.signatures_set_2,
        &inputs.untrusted_hash,
        inputs.untrusted_height,
        inputs.untrusted_timestamp,
        &inputs.untrusted_validators_padded,
        &inputs.untrusted_validator_pub_keys,
        &inputs.untrusted_validator_vps,
        &inputs.untrusted_header_padded,
        &inputs.trusted_hash,
        inputs.trusted_height,
        inputs.trusted_timestamp,
        &inputs.trusted_next_validators_padded,
        &inputs.trusted_next_validator_pub_keys,
        &inputs.trusted_next_validator_vps,
        &inputs.trusted_header_padded,
        &inputs.trusted_next_validators_hash_proof,
        &inputs.signature_indices_set_1,
        &inputs.signature_indices_set_2,
        &inputs.untrusted_intersect_indices,
        &inputs.trusted_next_intersect_indices,
        proof_target,
        config,
    );
}

// build and dump circuit data for tendermint lc circuit
pub fn build_tendermint_lc_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    chain_name: &str,
    chains_config_path: &str,
    storage_dir: &str,
) where
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let config = get_chain_config(chains_config_path, chain_name);

    let lc_storage_dir = &get_lc_storage_dir(chain_name, storage_dir);

    info!("Building Tendermint lc circuit");
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let _target = generate_circuit::<F, D>(&mut builder, &config);
    info!("Building circuit with {:?} gates", builder.num_gates());
    let t = Instant::now();
    let data = builder.build::<C>();
    info!("Time taken to build the circuit : {:?}", t.elapsed());
    dump_circuit_data::<F, C, D>(&data, &format!("{lc_storage_dir}/circuit_data/"));
}

// build and dump circuit data for recursion circuit
pub fn build_recursion_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    chain_name: &str,
    storage_dir: &str,
) where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let lc_storage_dir = get_lc_storage_dir(chain_name, storage_dir);
    let inner_common_data_path = &format!("{lc_storage_dir}/circuit_data/common_data.json");
    let recursive_storage_dir = &get_recursive_storage_dir(chain_name, storage_dir);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    info!("Reconstructing inner common data");
    let inner_cd_bytes = read_bytes_from_json(inner_common_data_path);
    let inner_common_data =
        CommonCircuitData::<F, D>::from_bytes(inner_cd_bytes, &CustomGateSerializer).unwrap();
    make_recursion_circuit::<F, C, InnerC, D>(&mut builder, &inner_common_data);
    info!(
        "Building recursive circuit with {:?} gates",
        builder.num_gates()
    );

    let data = builder.build::<C>();
    info!("Recursive circuit build complete");
    dump_circuit_data::<F, C, D>(&data, &format!("{recursive_storage_dir}/circuit_data/"));
}

pub fn generate_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
>(
    chains_config_path: &str,
    chain_name: &str,
    storage_dir: &str,
    inputs: Inputs,
    tag: &str,
) -> GeneratedProofInfo
where
    [(); C::Hasher::HASH_SIZE]:,
    <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
{
    let config = get_chain_config(chains_config_path, chain_name);
    let lc_storage_dir = &get_lc_storage_dir(chain_name, storage_dir);
    let recursive_storage_dir = &get_recursive_storage_dir(chain_name, storage_dir);

    info!("--- Light Client circuit ---");
    let data = load_circuit_data_from_dir::<F, C, D>(&format!("{lc_storage_dir}/circuit_data"));
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
    let target = generate_circuit::<F, D>(&mut builder, &config);
    info!("Starting lc proof generation");
    let t_pg = Instant::now();
    let mut pw = PartialWitness::new();
    set_proof_targets::<F, D, PartialWitness<F>>(&mut pw, inputs, &target, &config);
    let proof_with_pis =
        prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut Default::default()).unwrap();
    info!("Proof generated in {:?}", t_pg.elapsed());
    let proof_with_pis_bytes = proof_with_pis.to_bytes();
    dump_bytes_to_json(
        proof_with_pis_bytes,
        format!("{lc_storage_dir}/proof_data/proof_with_pis.json").as_str(),
    );

    data.verify(proof_with_pis.clone()).expect("verify error");

    info!("--- Recursion Circuit ---");
    // Add one more recursion proof generation layer
    let recursive_data =
        load_circuit_data_from_dir::<F, C, D>(&format!("{recursive_storage_dir}/circuit_data"));
    let mut recursive_builder =
        CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    // Config for both outer and inner circuit are same for now
    let recursion_targets =
        make_recursion_circuit::<F, C, C, D>(&mut recursive_builder, &data.common);
    info!("Starting to generate recursive proof");
    let t_pg_rec = Instant::now();
    let mut pw_rec = PartialWitness::new();
    pw_rec.set_proof_with_pis_target(&recursion_targets.pt, &proof_with_pis);
    pw_rec.set_verifier_data_target(&recursion_targets.inner_data, &data.verifier_only);
    let rec_proof_with_pis = prove::<F, C, D>(
        &recursive_data.prover_only,
        &recursive_data.common,
        pw_rec,
        &mut Default::default(),
    )
    .unwrap();
    let rec_proof_with_pis_bytes = rec_proof_with_pis.to_bytes();
    dump_bytes_to_json(
        rec_proof_with_pis_bytes.clone(),
        format!("{recursive_storage_dir}/proof_data/proof_with_pis_{tag}.json").as_str(),
    );
    info!("recursive proof gen done in {:?}", t_pg_rec.elapsed());
    recursive_data
        .verify(rec_proof_with_pis)
        .expect("verify error");

    GeneratedProofInfo {
        proof_with_pis: rec_proof_with_pis_bytes,
        proof_generate_time_duration: t_pg.elapsed(),
        recursive_proof_generation_time_duration: t_pg_rec.elapsed(),
    }
}

pub async fn run_circuit() {
    let chain_name = "OSMOSIS";
    let untrusted_height = OSMOSIS_UNTRUSTED_HEIGHT;
    let trusted_height = OSMOSIS_TRUSTED_HEIGHT;
    let storage_dir = "./storage";
    let chains_config_path = "tendermint-lc-plonky2/src/chain_config";

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = get_chain_config(chains_config_path, chain_name);

    let x = std::env::var("X").expect("`X` env variable must be set");

    // Build tendermint light client circuit
    if x == "1" {
        build_tendermint_lc_circuit::<F, C, D>(chain_name, chains_config_path, storage_dir);
    }
    // Build recursive circuit
    if x == "2" {
        build_recursion_circuit::<F, C, C, D>(chain_name, storage_dir);
    }
    // Generate proof for lc and recursion both
    if x == "3" {
        let t: Inputs;
        loop {
            match get_inputs_for_height(untrusted_height, trusted_height, &config).await {
                Ok(_inputs) => {
                    t = _inputs;
                    break;
                }
                Err(e) => {
                    error!("Error in get_inputs_for_height::{:?}, {:?}", e.to_string(), "Trying again...");
                    sleep(Duration::from_secs_f32(2 as f32)).await; // 2 seconds
                }
            };
        }
        generate_proof::<F, C, D>(chains_config_path, chain_name, storage_dir, t, "xyz");
    }
}
