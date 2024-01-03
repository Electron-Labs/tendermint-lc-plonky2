use crate::input_types::*;
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
