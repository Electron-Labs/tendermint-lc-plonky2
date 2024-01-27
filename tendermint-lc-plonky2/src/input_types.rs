use serde::{Deserialize, Serialize};

// TODO: don't keep any padded input in the json, pad it separetely

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inputs {
    // TODO: change to sign_messages, pad it after reading it
    pub sign_messages_padded: Vec<Vec<bool>>,
    // TODO: remove
    pub sign_message: Vec<bool>,
    pub signatures: Vec<Vec<bool>>,
    pub untrusted_hash: Vec<bool>,
    pub untrusted_height: u64,
    pub untrusted_time_padded: Vec<bool>,
    pub untrusted_time_proof: Vec<Vec<bool>>,
    pub untrusted_timestamp: u64,
    pub untrusted_validators_hash_padded: Vec<bool>,
    pub untrusted_validators_padded: Vec<Vec<bool>>,
    pub untrusted_chain_id_padded: Vec<bool>,
    pub untrusted_version_block_padded: Vec<bool>,
    pub untrusted_validators_hash_proof: Vec<Vec<bool>>,
    pub untrusted_validator_pub_keys: Vec<Vec<bool>>,
    pub untrusted_validator_votes: Vec<u64>,
    // TODO: change to untrusted_validators_leaves
    pub trusted_hash: Vec<bool>,
    pub trusted_height: u64,
    pub trusted_time_padded: Vec<bool>,
    pub trusted_time_proof: Vec<Vec<bool>>,
    pub trusted_timestamp: u64,
    pub trusted_next_validators_hash_padded: Vec<bool>,
    pub trusted_next_validators_padded: Vec<Vec<bool>>,
    pub trusted_next_validator_pub_keys: Vec<Vec<bool>>,
    pub trusted_next_validator_votes: Vec<u64>,
    // TODO: change to trusted_validators_leaves
    pub untrusted_intersect_indices: Vec<u8>,
    pub trusted_next_intersect_indices: Vec<u8>,
}
