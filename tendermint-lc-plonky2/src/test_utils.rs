use crate::input_types::*;
use bitvec::prelude::*;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

pub fn get_test_data() -> Inputs {
    let cur_dir = env::current_dir().unwrap();
    let is_test = cur_dir.ends_with("tendermint-lc-plonky2/tendermint-lc-plonky2");
    let file = match is_test {
        true => PathBuf::from("src/test_data/12960957_12975357.json"),
        false => PathBuf::from("tendermint-lc-plonky2/src/test_data/12960957_12975357.json"),
    };
    let file_path = cur_dir.join(file);
    let data_str = std::fs::read_to_string(file_path.as_path()).unwrap();
    let data: Inputs = serde_json::from_str(&data_str).unwrap();
    // println!("data {:?}", data);
    data
}

// prefix with a 0 byte, then proceed towards sha512 padding, outputing 1 sha block
pub fn get_sha_block_for_leaf(input: Vec<bool>) -> Vec<bool> {
    let mut block = [false; 512];
    let mut input_len = input.len() + 8; // prefix `0x00`

    (0..8).for_each(|i| block[i] = false);

    let mut idx = 8;
    for x in input {
        block[idx] = x;
        idx += 1;
    }

    block[idx] = true;
    idx += 1;

    (idx..512 - 64).for_each(|i| {
        block[i] = false;
        idx += 1;
    });

    let input_len_bits = input_len.view_bits_mut::<Msb0>();
    input_len_bits.iter().for_each(|elm| {
        block[idx] = *elm;
        idx += 1;
    });
    // println!("idx {:?}", idx);
    // println!("block {:?}", block);
    block.to_vec()
}

// prefix with a 1 byte, then proceed towards sha512 padding, outputting 2 blocks
pub fn get_sha_block_for_inner(leaf1: Vec<bool>, leaf2: Vec<bool>) -> Vec<bool> {
    let mut block = [false; 512*2];
    let mut input_len = 8 + leaf1.len() + leaf2.len(); // prefix `0x01`

    (0..7).for_each(|i| block[i] = false);
    block[7] = true;

    let mut idx = 8;
    for x in leaf1 {
        block[idx] = x;
        idx += 1;
    }
    for x in leaf2 {
        block[idx] = x;
        idx += 1;
    }

    block[idx] = true;
    idx += 1;

    (idx..(512*2) - 64).for_each(|i| {
        block[i] = false;
        idx += 1;
    });

    let input_len_bits = input_len.view_bits_mut::<Msb0>();
    input_len_bits.iter().for_each(|elm| {
        block[idx] = *elm;
        idx += 1;
    });
    // println!("idx {:?}", idx);
    // println!("block {:?}", block);
    block.to_vec()
}

// TODO:
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Validators {
    pub leaves: Vec<Vec<bool>>,
}
