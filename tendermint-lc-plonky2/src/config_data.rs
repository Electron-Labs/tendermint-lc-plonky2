use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
pub struct Config {
    pub RPC_ENDPOINT: Vec<String>,
    pub VP_BITS: usize,
    pub SIGNATURE_BITS: usize,
    pub MAX_N_VALIDATORS: usize,
    pub MIN_N_VALIDATORS: usize,
    pub HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE: usize,
    pub HEIGHT_BITS: usize,
    pub TIMESTAMP_BITS: usize,
    pub TRUSTING_PERIOD: usize,
    pub N_SIGNATURE_INDICES: usize,
    pub N_INTERSECTION_INDICES: usize,
    pub INTERSECTION_INDICES_DOMAIN_SIZE: usize,
    pub SIGNATURE_INDICES_DOMAIN_SIZE: usize,
    pub LEB128_GROUP_SIZE: usize,
    // TODO: remove this
    pub N_VALIDATORS_LEAVES: usize,
    pub CHAIN_ID: Vec<bool>,
    pub VERSION_BLOCK: Vec<bool>,
}

pub fn get_chain_config(chains_config_path: &str, chain_name: &str) -> Config {
    let file_content = std::fs::read_to_string(format! {"{chains_config_path}/{chain_name}.yaml"})
        .expect(&format!("Unable to read config yaml file for {chain_name}"));
    serde_yaml::from_str(file_content.as_str()).unwrap()
}
