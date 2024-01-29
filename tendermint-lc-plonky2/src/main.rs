pub mod constants;
pub mod input_types;
pub mod merkle_targets;
pub mod targets;
pub mod test_utils;

use plonky2::iop::witness::Witness;
use plonky2::plonk::{
    config::{GenericConfig},
};
use std::io::Write;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use tendermint_lc_plonky2::circuit::run_circuit;

fn main() {
    run_circuit();
}
