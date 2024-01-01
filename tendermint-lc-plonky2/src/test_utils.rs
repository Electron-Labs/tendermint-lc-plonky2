use crate::input_types::*;

pub fn get_test_data() -> Inputs {
  let data_str = std::fs::read_to_string(format!("src/test_data/12946557_12975357.json")).unwrap();
  let data: Inputs = serde_json::from_str(&data_str).unwrap();
  // println!("data {:?}", data);
  data
}