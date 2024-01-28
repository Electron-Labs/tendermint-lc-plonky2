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
use tendermint_lc_plonky2::circuit::{generate_circuit, run_circuit, set_proof_targets};
use input_types::Inputs;
use test_utils::get_test_data;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;



fn main() {
    run_circuit();
}
