use crate::input_types::*;

pub fn get_test_data() -> Inputs {
  let data_str = std::fs::read_to_string(format!("tendermint-lc-plonky2/src/test_data/12975357.json")).unwrap();
  let data: Inputs = serde_json::from_str(&data_str).unwrap();
  // println!("data {:?}", data);
  data
}