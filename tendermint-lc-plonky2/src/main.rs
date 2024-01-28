pub mod constants;
pub mod input_types;
pub mod merkle_targets;
pub mod targets;
pub mod test_utils;

use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    circuit_data::{CircuitConfig, CircuitData},
    config::{GenericConfig, PoseidonGoldilocksConfig},
    proof::ProofWithPublicInputs,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use targets::{add_virtual_proof_target, set_proof_target};
use test_utils::get_test_data;

const D: usize = 2;
// type C = PoseidonBn254GoldilocksConfig;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub fn save_proof_data(data: CircuitData<F, C, D>, proof: ProofWithPublicInputs<F, C, D>) {
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

fn main() {
    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut witness = PartialWitness::new();

    let target = add_virtual_proof_target(&mut builder);

    // register public inputs - {untrusted_hash, trusted_hash, untrusted_height, trusted_height}
    (0..target.untrusted_hash.len())
        .for_each(|i| builder.register_public_input(target.untrusted_hash[i].target));
    (0..target.trusted_hash.len())
        .for_each(|i| builder.register_public_input(target.trusted_hash[i].target));
    (0..target.untrusted_height.num_limbs())
        .for_each(|i| builder.register_public_input(target.untrusted_height.get_limb(i).0));
    (0..target.untrusted_height.num_limbs())
        .for_each(|i| builder.register_public_input(target.trusted_height.get_limb(i).0));

    let t = get_test_data();

    set_proof_target(
        &mut witness,
        &t.sign_messages_padded,
        &t.signatures,
        &t.untrusted_hash,
        &t.untrusted_version_padded,
        &t.untrusted_chain_id_padded,
        t.untrusted_height,
        &t.untrusted_time_padded,
        t.untrusted_timestamp,
        &t.untrusted_validators_hash_padded,
        &t.untrusted_validators_padded,
        &t.untrusted_validator_pub_keys,
        &t.untrusted_validator_vp,
        &t.untrusted_version_proof,
        &t.untrusted_chain_id_proof,
        &t.untrusted_time_proof,
        &t.untrusted_validators_hash_proof,
        &t.trusted_hash,
        t.trusted_height,
        &t.trusted_time_padded,
        t.trusted_timestamp,
        &t.trusted_next_validators_hash_padded,
        &t.trusted_next_validators_padded,
        &t.trusted_next_validator_pub_keys,
        &t.trusted_next_validator_vp,
        &t.trusted_time_proof,
        &t.trusted_next_validators_hash_proof,
        &t.signature_indices,
        &t.untrusted_intersect_indices,
        &t.trusted_next_intersect_indices,
        &target,
    );

    let data = builder.build::<C>();

    let start_time = std::time::Instant::now();
    let proof = data.prove(witness).unwrap();
    let duration_ms = start_time.elapsed().as_millis();
    println!("proved in {}ms", duration_ms);
    assert!(data.verify(proof.clone()).is_ok());

    save_proof_data(data, proof);
}
