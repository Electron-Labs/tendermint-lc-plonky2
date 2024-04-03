use crate::circuits::merkle_targets::{bool_to_bytes, bytes_to_bool};
use crate::config_data::*;
use crate::rpc::*;
use crate::tests::test_utils::{get_n_sha_blocks_for_leaf, get_sha512_preprocessed_input};
use ct_merkle::inclusion::InclusionProof;
use ct_merkle::CtMerkleTree;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::error::Error;
use tendermint::block::{CommitSig, Header, Height};
use tendermint::vote::{CanonicalVote, Type, ValidatorIndex, Vote};
use tendermint::Signature;
use tendermint_proto::Protobuf;

// each field is prefixed with a 0-byte, then padded as a sha blocks
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HeaderPadded {
    pub version: Vec<bool>,
    pub chain_id: Vec<bool>,
    pub height: Vec<bool>,
    pub time: Vec<bool>,
    pub last_block_id: Vec<bool>,
    pub last_commit_hash: Vec<bool>,
    pub data_hash: Vec<bool>,
    pub validators_hash: Vec<bool>,
    pub next_validators_hash: Vec<bool>,
    pub consensus_hash: Vec<bool>,
    pub app_hash: Vec<bool>,
    pub last_results_hash: Vec<bool>,
    pub evidence_hash: Vec<bool>,
    pub proposer_address: Vec<bool>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Inputs {
    pub sign_messages_padded: Vec<Vec<bool>>,
    pub signatures: Vec<Vec<bool>>,

    pub untrusted_hash: Vec<u8>,
    pub untrusted_height: u64,
    pub untrusted_timestamp: u64,
    pub untrusted_validators_padded: Vec<Vec<bool>>,
    pub untrusted_validator_pub_keys: Vec<Vec<bool>>,
    pub untrusted_validator_vps: Vec<u64>,
    pub untrusted_header_padded: HeaderPadded,

    pub trusted_hash: Vec<u8>,
    pub trusted_height: u64,
    pub trusted_timestamp: u64,
    pub trusted_next_validators_padded: Vec<Vec<bool>>,
    pub trusted_next_validator_pub_keys: Vec<Vec<bool>>,
    pub trusted_next_validator_vps: Vec<u64>,
    pub trusted_header_padded: HeaderPadded,

    pub trusted_next_validators_hash_proof: Vec<Vec<bool>>,

    pub signature_indices: Vec<u8>,
    pub untrusted_intersect_indices: Vec<u8>,
    pub trusted_next_intersect_indices: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TestInputsNative {
    pub validators: Vec<Vec<u8>>,
    pub validators_hash: Vec<u8>,
}

pub fn get_block_header_merkle_tree(header: Header) -> CtMerkleTree<Sha256, Vec<u8>> {
    let mut mt = CtMerkleTree::<Sha256, Vec<u8>>::new();

    mt.push(Protobuf::<tendermint_proto::version::Consensus>::encode_vec(header.version));
    mt.push(header.chain_id.encode_vec());
    mt.push(header.height.encode_vec());
    mt.push(header.time.encode_vec());
    mt.push(Protobuf::<tendermint_proto::types::BlockId>::encode_vec(
        header.last_block_id.unwrap_or_default(),
    ));
    mt.push(header.last_commit_hash.unwrap().encode_vec());
    mt.push(header.data_hash.unwrap().encode_vec());
    mt.push(header.validators_hash.encode_vec());
    mt.push(header.next_validators_hash.encode_vec());
    mt.push(header.consensus_hash.encode_vec());
    mt.push(header.app_hash.encode_vec());
    mt.push(header.last_results_hash.unwrap().encode_vec());
    mt.push(header.evidence_hash.unwrap().encode_vec());
    mt.push(header.proposer_address.encode_vec());

    mt
}

pub fn get_merkle_proof_byte_vec(inclusion_proof: &InclusionProof<Sha256>) -> Vec<Vec<bool>> {
    let proof_array = inclusion_proof.as_bytes();
    let proof_elms = vec![
        bytes_to_bool(proof_array[..32].to_vec()),
        bytes_to_bool(proof_array[32..64].to_vec()),
        bytes_to_bool(proof_array[64..96].to_vec()),
        bytes_to_bool(proof_array[96..].to_vec()),
    ];
    proof_elms
}

pub async fn get_some_latest_inputs(c: &Config) -> Result<Inputs, Box<dyn Error + Send + Sync>> {
    let latest_commit = get_latest_commit(&c).await?;
    let untrusted_height = latest_commit.height.value() - 100;
    let trusted_height = untrusted_height - 2000;
    get_inputs_for_height(untrusted_height, trusted_height, c).await
}

pub async fn get_inputs_for_height(
    untrusted_height: u64,
    trusted_height: u64,
    c: &Config,
) -> Result<Inputs, Box<dyn Error + Send + Sync>> {
    let u_height = Height::from(untrusted_height as u32);
    let t_height = Height::from(trusted_height as u32);
    let untrusted_commit = get_commit(&c, u_height).await?;
    let untrusted_block = get_block(&c, u_height).await?;
    let untrusted_validators = get_validators_all(&c, u_height).await?;

    let trusted_commit = get_commit(&c, t_height).await?;
    let trusted_block = get_block(&c, t_height).await?;
    let trusted_next_validators =
        get_validators_all(&c, Height::from((t_height.value() + 1) as u32)).await?;

    let mut signatures_for_indices: Vec<Vec<bool>> = vec![];
    let mut signatures_indices: Vec<u8> = vec![];

    let signatures = untrusted_commit.clone().signatures;
    for i in 0..signatures.len() {
        if signatures_indices.len() == c.N_SIGNATURE_INDICES {
            break;
        }
        let sig = match signatures[i].clone() {
            CommitSig::BlockIdFlagCommit { signature, .. } => Some(signature),
            CommitSig::BlockIdFlagNil { signature, .. } => None,
            _ => None,
        };

        if !sig.is_none() && i < c.SIGNATURE_INDICES_DOMAIN_SIZE {
            signatures_for_indices.push(bytes_to_bool(sig.unwrap().unwrap().into_bytes()));
            signatures_indices.push(i as u8);
        }
    }

    assert!(
        signatures_indices.len() == c.N_SIGNATURE_INDICES,
        "couln't find required number of non-null signature indices"
    );

    let untrusted_hash = untrusted_commit.clone().block_id.hash.as_bytes().to_vec();
    let untrusted_time = untrusted_block.header.time;
    let mut untrusted_validator_pub_keys: Vec<Vec<bool>> = Vec::new();
    let mut untrusted_validators_padded: Vec<Vec<bool>> = Vec::new();
    for i in 0..untrusted_validators.len() {
        untrusted_validator_pub_keys
            .push(bytes_to_bool(untrusted_validators[i].pub_key.to_bytes()));
    }
    for i in 0..untrusted_validators.len() {
        untrusted_validators_padded.push(get_n_sha_blocks_for_leaf(
            bytes_to_bool(untrusted_validators[i].hash_bytes()),
            1,
        ))
    }
    let mut untrusted_validator_vps: Vec<u64> = Vec::new();
    for i in 0..untrusted_validators.len() {
        untrusted_validator_vps.push(untrusted_validators[i].power.value());
    }

    let trusted_hash = trusted_commit.block_id.hash.as_bytes().to_vec();
    let trusted_time = trusted_block.header.time;
    let mut trusted_next_validator_pub_keys: Vec<Vec<bool>> = Vec::new();
    for i in 0..trusted_next_validators.len() {
        trusted_next_validator_pub_keys
            .push(bytes_to_bool(trusted_next_validators[i].pub_key.to_bytes()));
    }
    let mut trusted_next_validators_padded: Vec<Vec<bool>> = Vec::new();
    for i in 0..trusted_next_validators.len() {
        trusted_next_validators_padded.push(get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_next_validators[i].hash_bytes()),
            1,
        ))
    }
    let mut trusted_next_validator_vps: Vec<u64> = Vec::new();
    for i in 0..trusted_next_validators.len() {
        trusted_next_validator_vps.push(trusted_next_validators[i].power.value());
    }

    let untrusted_header_padded = HeaderPadded {
        version: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                Protobuf::<tendermint_proto::version::Consensus>::encode_vec(
                    untrusted_block.clone().header.version,
                ),
            ),
            1,
        ),
        chain_id: get_n_sha_blocks_for_leaf(
            bytes_to_bool(untrusted_block.clone().header.chain_id.encode_vec()),
            1,
        ),
        height: get_n_sha_blocks_for_leaf(
            bytes_to_bool(untrusted_block.clone().header.height.encode_vec()),
            1,
        ),
        time: get_n_sha_blocks_for_leaf(bytes_to_bool(untrusted_time.encode_vec()), 1),
        last_block_id: get_n_sha_blocks_for_leaf(
            bytes_to_bool(Protobuf::<tendermint_proto::types::BlockId>::encode_vec(
                untrusted_block.clone().header.last_block_id.unwrap(),
            )),
            2,
        ),
        last_commit_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                untrusted_block
                    .clone()
                    .header
                    .last_commit_hash
                    .unwrap()
                    .encode_vec(),
            ),
            1,
        ),
        data_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                untrusted_block
                    .clone()
                    .header
                    .data_hash
                    .unwrap()
                    .encode_vec(),
            ),
            1,
        ),
        validators_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(untrusted_block.header.validators_hash.encode_vec()),
            1,
        ),
        next_validators_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                untrusted_block
                    .clone()
                    .header
                    .next_validators_hash
                    .encode_vec(),
            ),
            1,
        ),
        consensus_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(untrusted_block.clone().header.consensus_hash.encode_vec()),
            1,
        ),
        app_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(untrusted_block.clone().header.app_hash.encode_vec()),
            1,
        ),
        last_results_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                untrusted_block
                    .clone()
                    .header
                    .last_results_hash
                    .unwrap()
                    .encode_vec(),
            ),
            1,
        ),
        evidence_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                untrusted_block
                    .clone()
                    .header
                    .evidence_hash
                    .unwrap()
                    .encode_vec(),
            ),
            1,
        ),
        proposer_address: get_n_sha_blocks_for_leaf(
            bytes_to_bool(untrusted_block.clone().header.proposer_address.encode_vec()),
            1,
        ),
    };
    let trusted_header_padded = HeaderPadded {
        version: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                Protobuf::<tendermint_proto::version::Consensus>::encode_vec(
                    trusted_block.header.version,
                ),
            ),
            1,
        ),
        chain_id: get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_block.clone().header.chain_id.encode_vec()),
            1,
        ),
        height: get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_block.clone().header.height.encode_vec()),
            1,
        ),
        time: get_n_sha_blocks_for_leaf(bytes_to_bool(trusted_time.encode_vec()), 1),
        last_block_id: get_n_sha_blocks_for_leaf(
            bytes_to_bool(Protobuf::<tendermint_proto::types::BlockId>::encode_vec(
                trusted_block.clone().header.last_block_id.unwrap(),
            )),
            2,
        ),

        last_commit_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                trusted_block
                    .clone()
                    .header
                    .last_commit_hash
                    .unwrap()
                    .encode_vec(),
            ),
            1,
        ),
        data_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_block.clone().header.data_hash.unwrap().encode_vec()),
            1,
        ),
        validators_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_block.clone().header.validators_hash.encode_vec()),
            1,
        ),
        next_validators_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_block.header.next_validators_hash.encode_vec()),
            1,
        ),
        consensus_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_block.clone().header.consensus_hash.encode_vec()),
            1,
        ),
        app_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_block.clone().header.app_hash.encode_vec()),
            1,
        ),
        last_results_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                trusted_block
                    .clone()
                    .header
                    .last_results_hash
                    .unwrap()
                    .encode_vec(),
            ),
            1,
        ),
        evidence_hash: get_n_sha_blocks_for_leaf(
            bytes_to_bool(
                trusted_block
                    .clone()
                    .header
                    .evidence_hash
                    .unwrap()
                    .encode_vec(),
            ),
            1,
        ),
        proposer_address: get_n_sha_blocks_for_leaf(
            bytes_to_bool(trusted_block.clone().header.proposer_address.encode_vec()),
            1,
        ),
    };

    let mt_trusted = get_block_header_merkle_tree(trusted_block.clone().header);
    let trusted_next_validators_hash_proof = mt_trusted.prove_inclusion(8);

    let mut untrusted_intersect_indices: Vec<u8> = Vec::new();
    let mut trusted_next_intersect_indices: Vec<u8> = Vec::new();

    // Since RandomAccess index cant go >= `null_index_for_intersection`, and we need one index reserved for Null so `null_index_for_intersection` index
    // is reserved
    for i in 0..untrusted_validators.len() {
        let untrusted_sig = untrusted_commit.signatures.clone()[i].clone();
        let sig_check = match untrusted_sig {
            CommitSig::BlockIdFlagCommit { signature, .. } => Some(signature),
            CommitSig::BlockIdFlagNil { signature, .. } => None,
            _ => None,
        };
        for j in 0..trusted_next_validators.len() {
            if (untrusted_validator_pub_keys[i] == trusted_next_validator_pub_keys[j])
                && i < c.INTERSECTION_INDICES_DOMAIN_SIZE - 1
                && j < c.INTERSECTION_INDICES_DOMAIN_SIZE - 1
                && signatures_indices.contains(&(i as u8))
            {
                untrusted_intersect_indices.push(i as u8);
                trusted_next_intersect_indices.push(j as u8);
            }
            if untrusted_intersect_indices.len() == c.N_INTERSECTION_INDICES {
                break;
            }
        }
        if untrusted_intersect_indices.len() == c.N_INTERSECTION_INDICES {
            break;
        }
    }
    while untrusted_intersect_indices.len() != c.N_INTERSECTION_INDICES {
        untrusted_intersect_indices.push((c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u8);
        trusted_next_intersect_indices.push((c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u8);
    }

    let mut sign_messages_padded: Vec<Vec<bool>> = Vec::with_capacity(signatures.len());

    for idx in 0..signatures_indices.len() {
        let i = signatures_indices[idx] as usize;

        let timestamp_x = match signatures[i].clone() {
            CommitSig::BlockIdFlagCommit { timestamp, .. } => Some(timestamp),
            CommitSig::BlockIdFlagNil { timestamp, .. } => None,
            _ => None,
        };

        if timestamp_x.is_none() {
            continue;
        }

        let val_x = match signatures[i].clone() {
            CommitSig::BlockIdFlagCommit {
                validator_address, ..
            } => Some(validator_address),
            CommitSig::BlockIdFlagNil {
                validator_address, ..
            } => None,
            _ => None,
        };

        if val_x.is_none() {
            continue;
        }

        let v = Vote {
            vote_type: Type::Precommit,
            height: untrusted_commit.height,
            round: untrusted_commit.round,
            block_id: Some(untrusted_commit.block_id),
            timestamp: timestamp_x,
            validator_address: val_x.unwrap(),
            validator_index: ValidatorIndex::try_from(i).unwrap(),
            signature: Some(
                Signature::try_from(bool_to_bytes(signatures_for_indices[idx].to_vec())).unwrap(),
            ),
            extension: vec![0u8; 8],
            extension_signature: None,
        };

        let cv = CanonicalVote::new(v, untrusted_block.header.chain_id.clone());

        let msg = Protobuf::<tendermint_proto::types::CanonicalVote>::encode_vec(cv);

        let sign_message: Vec<u8> = [vec![msg.len() as u8], msg.clone()].concat();

        // To create sign messages padded we would need sha512 preprocessed with [sig[0..256] + pub_key[0..256] + bytes_to_bool(sign_message)
        let sig_r = &signatures_for_indices[idx][0..256];
        let pub_key = untrusted_validator_pub_keys[i].clone();
        let msg_bits = bytes_to_bool(sign_message.clone());
        let signed_message = [sig_r, pub_key.as_slice(), msg_bits.as_slice()].concat();
        // get_sha512_preprocessed_input(signed_message.clone());
        // if idx == 0 {
        // println!("== {:?} ==", i);
        // println!("msg {:?}", bool_to_bytes(msg_bits.clone()));
        // println!("sig {:?}", bool_to_bytes(signatures_for_indices[idx].clone()));
        // println!("pub key {:?}", bool_to_bytes(pub_key.clone()));
        // println!("signed_msg {:?}", bool_to_bytes(get_sha512_preprocessed_input(signed_message.clone())));
        // }
        // println!("{:?}", )
        sign_messages_padded.push(get_sha512_preprocessed_input(signed_message.clone()));
    }

    let inputs = Inputs {
        sign_messages_padded,
        signatures: signatures_for_indices,

        untrusted_hash,
        untrusted_height,
        untrusted_validators_padded,
        untrusted_timestamp: untrusted_time.unix_timestamp() as u64,
        untrusted_validator_pub_keys,
        untrusted_validator_vps,
        untrusted_header_padded,

        trusted_hash,
        trusted_height,
        trusted_timestamp: trusted_time.unix_timestamp() as u64,
        trusted_next_validators_padded,
        trusted_next_validator_pub_keys,
        trusted_next_validator_vps,
        trusted_header_padded,

        trusted_next_validators_hash_proof: get_merkle_proof_byte_vec(
            &trusted_next_validators_hash_proof,
        ),

        signature_indices: signatures_indices,
        untrusted_intersect_indices,
        trusted_next_intersect_indices,
    };

    // TODO: remove
    // dump inputs
    use std::fs;
    use std::fs::File;
    use std::io::BufWriter;
    fs::create_dir_all("./dump_inputs")?;
    let file = File::create(format!("./dump_inputs/last_inputs.json"))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &inputs)?; //.unwrap();

    Ok(inputs)
}

pub async fn get_test_inputs_native_for_height(
    height: u64,
    c: &Config,
) -> Result<TestInputsNative, Box<dyn Error + Send + Sync>> {
    let height = Height::from(height as u32);
    let block = get_block(&c, height).await?;
    let validators_info = get_validators_all(&c, height).await?;

    let mut validators: Vec<Vec<u8>> = Vec::new();
    for i in 0..validators_info.len() {
        validators.push(validators_info[i].hash_bytes());
    }

    let validators_hash = block.header.validators_hash.as_bytes().to_vec();

    let inputs = TestInputsNative {
        validators,
        validators_hash,
    };

    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use crate::config_data::get_chain_config;
    use crate::input_types::{get_inputs_for_height, get_test_inputs_native_for_height};
    use crate::tests::test_heights::*;
    use std::fs::File;
    use std::io::{BufWriter, Write};

    #[tokio::test]
    #[ignore]
    pub async fn test() {
        pub const UNTRUSTED_HEIGHT: u64 = OSMOSIS_UNTRUSTED_HEIGHT;
        pub const TRUSTED_HEIGHT: u64 = OSMOSIS_TRUSTED_HEIGHT;

        let chain_name = "OSMOSIS";
        // TODO: read from env
        let chains_config_path = "src/chain_config";
        let config = get_chain_config(chains_config_path, chain_name);
        let file = File::create(format!(
            "./src/tests/test_data/{TRUSTED_HEIGHT}_{UNTRUSTED_HEIGHT}.json"
        ))
        .unwrap();
        let input = get_inputs_for_height(UNTRUSTED_HEIGHT, TRUSTED_HEIGHT, &config)
            .await
            .unwrap();
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &input).unwrap();
        writer.flush().unwrap();
    }

    #[tokio::test]
    #[ignore]
    pub async fn save_test_inputs_native_for_height() {
        pub const HEIGHT: u64 = 14627326;
        let chain_name = "OSMOSIS";

        let chains_config_path = "src/chain_config";
        let config = get_chain_config(chains_config_path, chain_name);
        let input = get_test_inputs_native_for_height(HEIGHT, &config)
            .await
            .unwrap();
        let file = File::create(format!(
            "./src/tests/test_data/test_inputs_data_{HEIGHT}.json"
        ))
        .unwrap();
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &input).unwrap();
        writer.flush().unwrap();
    }
}
