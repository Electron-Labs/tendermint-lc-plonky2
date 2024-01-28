use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::Witness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::input_types::Inputs;
use crate::targets::{add_virtual_proof_target, ProofTarget, set_proof_target};

pub mod merkle_targets;
pub mod input_types;
pub mod test_utils;
pub mod targets;
pub mod unit_tests;
pub mod constants;
pub mod circuit;