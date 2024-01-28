pub mod constants;
pub mod input_types;
pub mod merkle_targets;
pub mod targets;
pub mod test_utils;

use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    circuit_data::{CircuitConfig, CircuitData},
    config::{GenericConfig, PoseidonGoldilocksConfig},
    proof::ProofWithPublicInputs,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use targets::{add_virtual_proof_target, set_proof_target};
use test_utils::get_test_data;
use crate::input_types::Inputs;
use crate::targets::ProofTarget;

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

fn main() {
    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut witness = PartialWitness::new();

    let target = generate_circuit::<F, D>(&mut builder);

    let t = get_test_data();

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

    save_proof_data(data, proof);
}
