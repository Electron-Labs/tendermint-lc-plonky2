use std::fs;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Data {
    bytes: Vec<u8>
}

pub fn dump_bytes_to_json(bytes: Vec<u8>, json_path: &str) {
    // Serialize Vec<u8> to json
    let serialized_data = serde_json::to_string(&Data { bytes: bytes.clone() })
        .expect("Failed to serialize data");
    // Write json to file
    fs::write(json_path, serialized_data).expect("Failed to write to file");
}

pub fn read_bytes_from_json(json_path: &str) -> Vec<u8> {
    // Read json data
    let json_data = fs::read_to_string(json_path).expect("Failed to read from file");
    // Deserialize json back to Vec<u8>
    let deserialized_data: Data = serde_json::from_str(&json_data).expect("Failed to deserialize data");
    deserialized_data.bytes
}