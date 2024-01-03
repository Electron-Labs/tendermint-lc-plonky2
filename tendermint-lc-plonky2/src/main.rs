pub mod constants;
pub mod input_types;
pub mod merkle_tree_gadget;
pub mod targets;
pub mod test_utils;

use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::{
    circuit_builder::CircuitBuilder,
    circuit_data::CircuitConfig,
    config::{GenericConfig, PoseidonGoldilocksConfig},
};
use targets::{add_virtual_proof_target, set_proof_target};
use test_utils::get_test_data;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

fn main() {
    let config = CircuitConfig::standard_recursion_config();

    let mut builder = CircuitBuilder::<F, D>::new(config);

    let mut witness = PartialWitness::new();

    let target = add_virtual_proof_target(&mut builder);

    let t = get_test_data();

    set_proof_target(
        &mut witness,
        &t.signatures,
        &t.untrusted_version_block_padded,
        &t.untrusted_chain_id_padded,
        t.untrusted_height,
        t.untrusted_timestamp,
        &t.untrusted_validator_pub_keys,
        &t.untrusted_validator_votes,
        t.trusted_height,
        t.trusted_timestamp,
        &t.trusted_next_validator_pub_keys,
        &t.trusted_next_validator_votes,
        &t.untrusted_intersect_indices,
        &t.trusted_next_intersect_indices,
        &target,
    );

    let data = builder.build::<C>();

    let start_time = std::time::Instant::now();
    let proof = data.prove(witness).unwrap();
    let duration_ms = start_time.elapsed().as_millis();
    println!("proved in {}ms", duration_ms);
    assert!(data.verify(proof).is_ok());
}
