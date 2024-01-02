use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inputs {
  pub untrusted_header_hash: Vec<bool>,
  pub untrusted_validators_hash_proof: Vec<Vec<bool>>,
  pub untusted_validators_hash_padded: Vec<bool>,
  pub untrusted_signatures: Vec<Vec<bool>>,
  pub untrusted_validators_pub_key: Vec<Vec<bool>>,
  pub untrusted_voting_power: Vec<u64>,
  pub trusted_validators_pub_key: Vec<Vec<bool>>,
  pub trusted_voting_power: Vec<u64>,
}