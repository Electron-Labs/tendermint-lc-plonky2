use crate::config_data::*;
use crate::circuits::merkle_targets::{bool_to_bytes, bytes_to_bool};
use crate::tests::test_utils::{get_n_sha_blocks_for_leaf, get_sha512_preprocessed_input};
use ct_merkle::inclusion::InclusionProof;
use ct_merkle::CtMerkleTree;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tendermint::block::{Commit, CommitSig, Header, Height};
use tendermint::vote::{CanonicalVote, Type, ValidatorIndex, Vote};
use tendermint::{Block, Signature};
use tendermint_proto::Protobuf;
use tendermint_rpc::{Client, HttpClient, Paging};
use std::error::Error;

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
    pub sign_messages_padded_set_1: Vec<Vec<bool>>,
    pub sign_messages_padded_set_2: Vec<Vec<bool>>,

    pub signatures_set_1: Vec<Vec<bool>>,
    pub signatures_set_2: Vec<Vec<bool>>,

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

    pub signature_indices_set_1: Vec<u8>,
    pub signature_indices_set_2: Vec<u8>,
    pub untrusted_intersect_indices_set_1: Vec<u8>,
    pub untrusted_intersect_indices_set_2: Vec<u8>,
    pub trusted_next_intersect_indices_set_1: Vec<u8>,
    pub trusted_next_intersect_indices_set_2: Vec<u8>,
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

pub async fn get_inputs_for_height(
    untrusted_height: u64,
    trusted_height: u64,
    c: &Config,
) -> Result<Inputs, Box<dyn Error + Send + Sync>> {
    let client = HttpClient::new(c.RPC_ENDPOINT.as_str())?;
    let u_height = Height::from(untrusted_height as u32);
    let t_height = Height::from(trusted_height as u32);
    let untrusted_commit = client.commit(u_height).await?.signed_header.commit;
    let untrusted_block = client.block(u_height).await?.block;
    let untrusted_validators = client.validators(u_height, Paging::All).await?.validators;

    let trusted_commit = client.commit(t_height).await?.signed_header.commit;
    let trusted_block = client.block(t_height).await?.block;
    let trusted_next_validators = client
        .validators(Height::from((t_height.value() + 1) as u32), Paging::All)
        .await?
        .validators;

    // let untrusted_commit = match untrusted_commit_response {
    //     Ok(commit_response) => commit_response.signed_header.commit,
    //     Err(_) => {
    //         panic!("Couldnt fetch untrusted commit")
    //     }
    // };

    // let trusted_commit = match trusted_commit_response {
    //     Ok(commit_response) => commit_response.signed_header.commit,
    //     Err(_) => {
    //         panic!("Couldnt fetch trusted commit")
    //     }
    // };

    // let untrusted_block = match untrusted_block_response {
    //     Ok(block_response) => block_response.block,
    //     Err(_) => {
    //         panic!("Couldnt fetch untrusted_block")
    //     }
    // };

    // let trusted_block = match trusted_block_response {
    //     Ok(block_response) => block_response.block,
    //     Err(_) => {
    //         panic!("Couldnt fetch untrusted_block")
    //     }
    // };

    // let untrusted_validators = match untrusted_validators_response {
    //     Ok(validators_response) => validators_response.validators,
    //     Err(_) => {
    //         panic!("Couldnt fetch untrusted_validators")
    //     }
    // };

    // let trusted_next_validators = match trusted_next_validators_response {
    //     Ok(validators_response) => validators_response.validators,
    //     Err(_) => {
    //         panic!("Couldnt fetch trusted_next_validators")
    //     }
    // };

    let mut signatures_for_indices_set_1: Vec<Vec<bool>> = vec![];
    let mut signatures_for_indices_set_2: Vec<Vec<bool>> = vec![];
    let mut signatures_indices_set_1: Vec<u8> = vec![];
    let mut signatures_indices_set_2: Vec<u8> = vec![];
    
    let signature_indices_domain_size = c.SIGNATURE_INDICES_DOMAIN_SIZE;

    let signatures = untrusted_commit.clone().signatures;
    for i in 0..signature_indices_domain_size {
        if signatures_indices_set_1.len() == c.N_SIGNATURE_INDICES_SET_1 {
            break;
        }
        let sig = match signatures[i].clone() {
            CommitSig::BlockIdFlagCommit { signature, .. } => Some(signature),
            CommitSig::BlockIdFlagNil { signature, .. } => None,
            _ => None,
        };

        if !sig.is_none() && i < c.SIGNATURE_INDICES_DOMAIN_SIZE {
            signatures_for_indices_set_1.push(bytes_to_bool(sig.unwrap().unwrap().into_bytes()));
            signatures_indices_set_1.push(i as u8);
        }
    }
    assert!(signatures_indices_set_1.len() == c.N_SIGNATURE_INDICES_SET_1, "couldn't find require number of non-null sinature indices");

    for i in signature_indices_domain_size..(signature_indices_domain_size+signature_indices_domain_size) {
        if signatures_indices_set_2.len() == c.N_SIGNATURE_INDICES_SET_2 {
            break;
        }
        let sig = match signatures[i].clone() {
            CommitSig::BlockIdFlagCommit { signature, .. } => Some(signature),
            CommitSig::BlockIdFlagNil { signature, .. } => None,
            _ => None,
        };

        if !sig.is_none() && (i - signature_indices_domain_size < signature_indices_domain_size) {
            signatures_for_indices_set_2.push(bytes_to_bool(sig.unwrap().unwrap().into_bytes()));
            signatures_indices_set_2.push((i - signature_indices_domain_size) as u8);
        }
    }
    assert!(signatures_indices_set_2.len() == c.N_SIGNATURE_INDICES_SET_2, "couldn't find require number of non-null sinature indices");

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

    let mut untrusted_intersect_indices_set_1: Vec<u8> = Vec::new();
    let mut untrusted_intersect_indices_set_2: Vec<u8> = Vec::new();
    let mut trusted_next_intersect_indices_set_1: Vec<u8> = Vec::new();
    let mut trusted_next_intersect_indices_set_2: Vec<u8> = Vec::new();


    assert!(c.INTERSECTION_INDICES_DOMAIN_SIZE == c.SIGNATURE_INDICES_DOMAIN_SIZE, "They must be equal");
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
            if untrusted_validator_pub_keys[i] == trusted_next_validator_pub_keys[j]
                && i < c.INTERSECTION_INDICES_DOMAIN_SIZE - 1
                && j < c.INTERSECTION_INDICES_DOMAIN_SIZE - 1
                && signatures_indices_set_1.contains(&(i as u8))
                && untrusted_intersect_indices_set_1.len() < c.N_INTERSECTION_INDICES_SET_1
            
            {
                untrusted_intersect_indices_set_1.push(i as u8);
                trusted_next_intersect_indices_set_1.push(j as u8);
            }

            if untrusted_validator_pub_keys[i] == trusted_next_validator_pub_keys[j]
                && i >= c.INTERSECTION_INDICES_DOMAIN_SIZE 
                && i < 2*c.INTERSECTION_INDICES_DOMAIN_SIZE - 1 
                && j >= c.INTERSECTION_INDICES_DOMAIN_SIZE 
                && j < c.INTERSECTION_INDICES_DOMAIN_SIZE - 1 
                && signatures_indices_set_2.contains(&((i-c.INTERSECTION_INDICES_DOMAIN_SIZE) as u8))
                && untrusted_intersect_indices_set_2.len() < c.N_INTERSECTION_INDICES_SET_2
            
            {
                untrusted_intersect_indices_set_2.push((i - c.INTERSECTION_INDICES_DOMAIN_SIZE) as u8);
                trusted_next_intersect_indices_set_2.push((j - c.INTERSECTION_INDICES_DOMAIN_SIZE) as u8);
            }


            if untrusted_intersect_indices_set_1.len() == c.N_INTERSECTION_INDICES_SET_1 && 
                untrusted_intersect_indices_set_2.len() == c.N_INTERSECTION_INDICES_SET_2  
            {
                break;
            }
        }
        if untrusted_intersect_indices_set_1.len() == c.N_INTERSECTION_INDICES_SET_1 && 
                untrusted_intersect_indices_set_2.len() == c.N_INTERSECTION_INDICES_SET_2  
            {
                break;
            }
    }
    while untrusted_intersect_indices_set_1.len() != c.N_INTERSECTION_INDICES_SET_1 {
        untrusted_intersect_indices_set_1.push((c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u8);
        trusted_next_intersect_indices_set_1.push((c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u8);
    }
    while untrusted_intersect_indices_set_2.len() != c.N_INTERSECTION_INDICES_SET_2 {
        untrusted_intersect_indices_set_2.push((c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u8);
        trusted_next_intersect_indices_set_2.push((c.INTERSECTION_INDICES_DOMAIN_SIZE - 1) as u8);
    }

    let mut sign_messages_padded_set_1: Vec<Vec<bool>> = Vec::with_capacity(signatures.len());
    let mut sign_messages_padded_set_2: Vec<Vec<bool>> = Vec::with_capacity(signatures.len());

    for idx in 0..signatures_indices_set_1.len() {
        get_signned_message_padded(&signatures_indices_set_1, idx, &signatures, &untrusted_commit, 
            &signatures_for_indices_set_1, &untrusted_block, &mut sign_messages_padded_set_1, 
            &untrusted_validator_pub_keys, 0);
    }

    for idx in 0..signatures_indices_set_2.len() {
        get_signned_message_padded(&signatures_indices_set_2, idx, &signatures, &untrusted_commit, 
            &signatures_for_indices_set_2, &untrusted_block, &mut sign_messages_padded_set_2, 
            &untrusted_validator_pub_keys, signature_indices_domain_size);
    }


    let inputs = Inputs {
        sign_messages_padded_set_1,
        sign_messages_padded_set_2,
        signatures_set_1: signatures_for_indices_set_1,
        signatures_set_2: signatures_for_indices_set_2,

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

        signature_indices_set_1: signatures_indices_set_1,
        signature_indices_set_2: signatures_indices_set_2,
        untrusted_intersect_indices_set_1,
        untrusted_intersect_indices_set_2,
        trusted_next_intersect_indices_set_1,
        trusted_next_intersect_indices_set_2,
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


fn get_signned_message_padded(
    signatures_indices:  &Vec<u8>, 
    idx: usize, 
    signatures: &Vec<CommitSig>, 
    untrusted_commit: &Commit, 
    signatures_for_indices: &Vec<Vec<bool>>,
    untrusted_block: &Block,
    sign_messages_padded: &mut Vec<Vec<bool>>,
    untrusted_validator_pub_keys: &Vec<Vec<bool>>,
    offset: usize
) {
    let i = signatures_indices[idx] as usize;

        let timestamp_x = match signatures[i].clone() {
            CommitSig::BlockIdFlagCommit { timestamp, .. } => Some(timestamp),
            CommitSig::BlockIdFlagNil { timestamp, .. } => None,
            _ => None,
        };

        if timestamp_x.is_none() {
            return
        }

        let val_x = match signatures[i+offset].clone() {
            CommitSig::BlockIdFlagCommit {
                validator_address, ..
            } => Some(validator_address),
            CommitSig::BlockIdFlagNil {
                validator_address, ..
            } => None,
            _ => None,
        };

        if val_x.is_none() {
            return
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
        let pub_key = untrusted_validator_pub_keys[i+offset].clone();
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

#[cfg(test)]
mod tests {
    use crate::config_data::get_chain_config;
    use crate::input_types::get_inputs_for_height;
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
        let input = get_inputs_for_height(UNTRUSTED_HEIGHT, TRUSTED_HEIGHT, &config).await.unwrap();
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &input).unwrap();
        writer.flush().unwrap();
    }
}
