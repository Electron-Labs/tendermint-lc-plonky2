use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inputs {
    pub message: Vec<bool>,
    pub untrusted_hash: Vec<bool>,
    pub untrusted_height: u64,
    pub untrusted_time_padded: Vec<bool>,
    pub untrusted_timestamp: u64,
    pub untrusted_validators_hash_proof: Vec<Vec<bool>>,
    pub untusted_validators_hash_padded: Vec<bool>,
    pub trusted_height: u64,
    pub trusted_timestamp: u64,
}
