use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    pub RPC_ENDPOINT: String,
    pub VP_BITS: usize,
    pub SIGNATURE_BITS: usize,
    pub N_VALIDATORS: usize,
    pub HEADER_VALIDATORS_HASH_PROOF_SIZE: usize,
    pub HEADER_TIME_PROOF_SIZE: usize,
    pub HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE: usize,
    pub HEADER_CHAIN_ID_PROOF_SIZE: usize,
    pub HEADER_VERSION_PROOF_SIZE: usize,
    pub HEIGHT_BITS: usize,
    pub TIMESTAMP_BITS: usize,
    pub TRUSTING_PERIOD: usize,
    pub N_SIGNATURE_INDICES: usize,
    pub N_INTERSECTION_INDICES: usize,
    pub TOP_N_VALIDATORS_FOR_INTERSECTION: usize,
    pub TOP_N_SIGNATURES: usize,
    pub LEB128_GROUP_SIZE: usize,
    pub N_VALIDATORS_LEAVES: usize,
    pub CHAIN_ID: Vec<bool>,
    pub VERSION_BLOCK: Vec<bool>,
}

lazy_static! {
    static ref CONFIG_STRUCT: Config = {
        // Read the config file and deserialize it into a Config struct
        let file_content =
            std::fs::read_to_string("tendermint-lc-plonky2/src/chain_config/dydx.yaml").expect("Unable to read config yaml file");
        serde_yaml::from_str(file_content.as_str()).unwrap()
    };

    pub static ref RPC_ENDPOINT: String = CONFIG_STRUCT.RPC_ENDPOINT.clone();
    pub static ref VP_BITS: usize = CONFIG_STRUCT.VP_BITS;
    pub static ref SIGNATURE_BITS: usize = CONFIG_STRUCT.SIGNATURE_BITS;
    pub static ref N_VALIDATORS: usize = CONFIG_STRUCT.N_VALIDATORS;
    pub static ref HEADER_VALIDATORS_HASH_PROOF_SIZE: usize = CONFIG_STRUCT.HEADER_VALIDATORS_HASH_PROOF_SIZE;
    pub static ref HEADER_TIME_PROOF_SIZE: usize = CONFIG_STRUCT.HEADER_TIME_PROOF_SIZE;
    pub static ref HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE:usize = CONFIG_STRUCT.HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE;
    pub static ref HEADER_CHAIN_ID_PROOF_SIZE: usize = CONFIG_STRUCT.HEADER_CHAIN_ID_PROOF_SIZE;
    pub static ref HEADER_VERSION_PROOF_SIZE: usize = CONFIG_STRUCT.HEADER_VERSION_PROOF_SIZE;
    pub static ref HEIGHT_BITS: usize = CONFIG_STRUCT.HEIGHT_BITS;
    pub static ref TIMESTAMP_BITS: usize = CONFIG_STRUCT.TIMESTAMP_BITS;
    pub static ref TRUSTING_PERIOD: usize = CONFIG_STRUCT.TRUSTING_PERIOD;
    pub static ref N_SIGNATURE_INDICES: usize = CONFIG_STRUCT.N_SIGNATURE_INDICES;
    pub static ref N_INTERSECTION_INDICES: usize = CONFIG_STRUCT.N_INTERSECTION_INDICES;
    pub static ref TOP_N_VALIDATORS_FOR_INTERSECTION: usize = CONFIG_STRUCT.TOP_N_VALIDATORS_FOR_INTERSECTION;
    pub static ref TOP_N_SIGNATURES: usize = CONFIG_STRUCT.TOP_N_SIGNATURES;
    pub static ref LEB128_GROUP_SIZE: usize = CONFIG_STRUCT.LEB128_GROUP_SIZE;
    pub static ref N_VALIDATORS_LEAVES: usize = CONFIG_STRUCT.N_VALIDATORS_LEAVES;
    pub static ref CHAIN_ID: Vec<bool> = CONFIG_STRUCT.CHAIN_ID.clone();
    pub static ref VERSION_BLOCK: Vec<bool> = CONFIG_STRUCT.VERSION_BLOCK.clone();

}
