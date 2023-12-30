use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inputs {
  pub untrusted_header_hash: Vec<bool>,
  pub untrusted_validators_hash_proof: Vec<Vec<bool>>,
  pub untusted_validators_hash_padded: Vec<bool>,
}