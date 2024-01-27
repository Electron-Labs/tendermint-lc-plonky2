use std::io::Error;
use serde::{Deserialize, Serialize};
use tendermint::block::{CommitSig, Height, Header};
use tendermint::vote::{CanonicalVote, SignedVote, Type, ValidatorIndex, Vote};
use crate::merkle_targets::{bool_to_bytes, bytes_to_bool};
use tendermint_rpc::{Client, HttpClient, Paging};
use tendermint_proto::Protobuf;
use ct_merkle::CtMerkleTree;
use crate::constants::N_INTERSECTION_INDICES;
use crate::test_utils::{get_sha512_preprocessed_input, get_sha_block_for_leaf, get_test_data};
use sha2::Sha256;

pub const RPC_ENDPOINT: &str = "https://osmosis-rpc.quickapi.com";
pub const CURRENT_HEIGHT: u64 =  12975357;
pub const TRUSTED_HEIGHT: u64 = 12960957;

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
    // pub signature_indices: Vec<u8> TODO
}

pub fn get_block_header_merkle_tree(header: Header) -> CtMerkleTree<Sha256, Vec<u8>> {
    let mut mt = CtMerkleTree::<Sha256, Vec<u8>>::new();

    mt.push(Protobuf::<tendermint_proto::version::Consensus>::encode_vec(header.version));
    mt.push(header.chain_id.encode_vec());
    mt.push(header.height.encode_vec());
    mt.push(header.time.encode_vec());
    mt.push(Protobuf::<tendermint_proto::types::BlockId>::encode_vec(header.last_block_id.unwrap_or_default()));
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


pub async fn get_inputs_for_height(untrusted_height: u64, trusted_height: u64)  -> Inputs {
    let client = HttpClient::new(RPC_ENDPOINT).unwrap();
    let u_height = Height::from(untrusted_height as u32);
    let t_height = Height::from(trusted_height as u32);
    let untrusted_commit_response = client.commit(u_height).await;
    let untrusted_block_response = client.block(u_height).await;
    let untrusted_validators_response = client.validators(u_height, Paging::All).await;

    let trusted_commit_response = client.commit(t_height).await;
    let trusted_block_response = client.block(t_height).await;
    let trusted_next_validators_response = client.validators(Height::from((t_height.value()+1) as u32), Paging::All).await;

    let untrusted_commit = match untrusted_commit_response {
        Ok(commit_response) => {
            commit_response.signed_header.commit
        }
        Err(_) => {
            panic!("Couldnt fetch untrusted commit")
        }
    };

    let trusted_commit = match trusted_commit_response {
        Ok(commit_response) => {
            commit_response.signed_header.commit
        }
        Err(_) => {
            panic!("Couldnt fetch trusted commit")
        }
    };

    let untrusted_block = match untrusted_block_response {
        Ok(block_response) => {
            block_response.block
        }
        Err(_) => {
            panic!("Couldnt fetch untrusted_block")
        }
    };

    let trusted_block = match trusted_block_response {
        Ok(block_response) => {
            block_response.block
        }
        Err(_) => {
            panic!("Couldnt fetch untrusted_block")
        }
    };

    let untrusted_validators = match untrusted_validators_response {
        Ok(validators_response) => {
            validators_response.validators
        }
        Err(_) => {
            panic!("Couldnt fetch untrusted_validators")
        }
    };

    let trusted_next_validators = match trusted_next_validators_response {
        Ok(validators_response) => {
            validators_response.validators
        }
        Err(_) => {
            panic!("Couldnt fetch trusted_next_validators")
        }
    };


    let mut signatures_45: Vec<Vec<bool>> = vec![];
    let mut signatures_45_indices: Vec<u8> = vec![];

    let signatures = untrusted_commit.clone().signatures;
    for i in 0..signatures.len() {
        if signatures_45_indices.len() == 45 {
            break;
        }
        let sig  = match signatures[i].clone() {
                CommitSig::BlockIdFlagCommit {
                    signature, ..
                } => Some(signature),
                CommitSig::BlockIdFlagNil {
                    signature, ..
                } => None,
                _ => None,
            };

        if !sig.is_none() {
            signatures_45.push(bytes_to_bool(sig.unwrap().unwrap().into_bytes()));
            signatures_45_indices.push(i as u8);
        }
    }

    let untrusted_hash = bytes_to_bool(untrusted_commit.clone().block_id.hash.as_bytes().to_vec());
    let trusted_hash = bytes_to_bool(trusted_commit.block_id.hash.as_bytes().to_vec());

    let untrusted_time = untrusted_block.header.time;
    let untrusted_time_padded = get_sha_block_for_leaf(bytes_to_bool(untrusted_time.encode_vec()));

    let trusted_time = trusted_block.header.time;
    let trusted_time_padded = get_sha_block_for_leaf(bytes_to_bool(trusted_time.encode_vec()));

    let untrusted_validators_hash_padded = get_sha_block_for_leaf(bytes_to_bool(untrusted_block.header.validators_hash.encode_vec()));
    let trusted_next_validators_hash_padded = get_sha_block_for_leaf(bytes_to_bool(trusted_block.header.next_validators_hash.encode_vec()));

    let mut untrusted_validators_padded: Vec<Vec<bool>> = Vec::new();
    for i in 0..untrusted_validators.len() {
        untrusted_validators_padded.push(get_sha_block_for_leaf(bytes_to_bool(untrusted_validators[i].hash_bytes())))
    }

    let mut trusted_next_validators_padded: Vec<Vec<bool>> = Vec::new();
    for i in 0..trusted_next_validators.len() {
        trusted_next_validators_padded.push(get_sha_block_for_leaf(bytes_to_bool(trusted_next_validators[i].hash_bytes())))
    }

    let untrusted_chain_id_padded = get_sha_block_for_leaf(bytes_to_bool(untrusted_block.clone().header.chain_id.encode_vec()));
    let untrusted_version_block_padded = get_sha_block_for_leaf(bytes_to_bool(Protobuf::<tendermint_proto::version::Consensus>::encode_vec(untrusted_block.clone().header.version)));

    let mut untrusted_validator_pub_keys: Vec<Vec<bool>> = Vec::new();
    for i in 0..untrusted_validators.len() {
        untrusted_validator_pub_keys.push(bytes_to_bool(untrusted_validators[i].pub_key.to_bytes()));
    }

    let mut trusted_next_validator_pub_keys: Vec<Vec<bool>> = Vec::new();
    for i in 0..trusted_next_validators.len() {
        trusted_next_validator_pub_keys.push(bytes_to_bool(trusted_next_validators[i].pub_key.to_bytes()));
    }


    let mut untrusted_validator_votes: Vec<u64> = Vec::new();
    for i in 0..untrusted_validators.len() {
        untrusted_validator_votes.push(untrusted_validators[i].power.value());
    }

    let mut trusted_next_validator_votes: Vec<u64> = Vec::new();
    for i in 0..trusted_next_validators.len() {
        trusted_next_validator_votes.push(trusted_next_validators[i].power.value());
    }

    let mut untrusted_intersect_indices: Vec<u8> = Vec::new();
    let mut trusted_next_intersect_indices: Vec<u8> = Vec::new();

    // Since RandomAccess cant go >= 64,and we need one index reserved for Null so 63rd index
    // is reserved
    for i in 0..untrusted_validators.len() {
        let untrusted_sig  = untrusted_commit.signatures.clone()[i].clone();
        let sig_check  = match untrusted_sig {
            CommitSig::BlockIdFlagCommit {
                signature, ..
            } => Some(signature),
            CommitSig::BlockIdFlagNil {
                signature, ..
            } => None,
            _ => None,
        };
        for j in 0..trusted_next_validators.len() {
            if (untrusted_validator_pub_keys[i] == trusted_next_validator_pub_keys[j])
                && i<63
                && j<63
                && !sig_check.is_none()
            {
                untrusted_intersect_indices.push(i as u8);
                trusted_next_intersect_indices.push(j as u8);
            }
            if untrusted_intersect_indices.len() == N_INTERSECTION_INDICES {
                break;
            }
        }
        if untrusted_intersect_indices.len() == N_INTERSECTION_INDICES {
            break;
        }
    }
    while untrusted_intersect_indices.len() != N_INTERSECTION_INDICES {
        untrusted_intersect_indices.push(63u8);
        trusted_next_intersect_indices.push(63u8);
    }

    let mut sign_messages_padded: Vec<Vec<bool>> = Vec::with_capacity(signatures.len());

    for idx in 0..signatures_45_indices.len() {
        let i = signatures_45_indices[idx] as usize;

        let timestamp_x = match signatures[i].clone() {
            CommitSig::BlockIdFlagCommit {
                timestamp, ..
            } => Some(timestamp),
            CommitSig::BlockIdFlagNil {
                timestamp, ..
            } => None,
            _ => None,
        };

        if timestamp_x.is_none() {
            continue
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
            continue
        }

        let v = Vote {
            vote_type: Type::Precommit,
            height: untrusted_commit.height,
            round: untrusted_commit.round,
            block_id: Some(untrusted_commit.block_id),
            timestamp: timestamp_x,
            validator_address: val_x.unwrap(),
            validator_index: ValidatorIndex::try_from(0u32).unwrap(),
            signature: None,
            extension: vec![0u8; 8],
            extension_signature: None,
        };

        let cv = CanonicalVote::new(v, untrusted_block.header.chain_id.clone());

        let msg = Protobuf::<tendermint_proto::types::CanonicalVote>::encode_vec(cv);

        let sign_message: Vec<u8> = [vec![msg.len() as u8], msg.clone()].concat();
        sign_messages_padded.push(get_sha512_preprocessed_input(bytes_to_bool(sign_message)));
    }

    let mt_untrusted = get_block_header_merkle_tree(untrusted_block.header);
    let mt_trusted = get_block_header_merkle_tree(trusted_block.header);

    let untrusted_time_mt_proof = mt_trusted.prove_inclusion(3);

    let td = get_test_data();

    Inputs {
        sign_messages_padded, // 45 messages
        sign_message: vec![], // TODO to remove
        signatures: signatures_45,
        untrusted_hash,
        untrusted_height,
        untrusted_time_padded,
        untrusted_time_proof: vec![],
        untrusted_timestamp: untrusted_time.unix_timestamp() as u64,
        untrusted_validators_hash_padded,
        untrusted_validators_padded,
        untrusted_chain_id_padded,
        untrusted_version_block_padded, // rename to untrusted_version_padded
        untrusted_validators_hash_proof: vec![],
        untrusted_validator_pub_keys,
        untrusted_validator_votes, // TODO: rename to voting power (VP)
        trusted_hash,
        trusted_height,
        trusted_time_padded,
        trusted_time_proof: vec![],
        trusted_timestamp: trusted_time.unix_timestamp() as u64,
        trusted_next_validators_hash_padded,
        trusted_next_validators_padded,
        trusted_next_validator_pub_keys,
        trusted_next_validator_votes,
        untrusted_intersect_indices,
        trusted_next_intersect_indices,
        // signature_indices: signatures_45_indices, // TODO
    }
}


#[cfg(test)]
mod tests {
    use tendermint::block::Height;
    use tendermint_rpc::{Client, HttpClient};
    use tendermint_lc_plonky2::input_types::CURRENT_HEIGHT;
    use crate::input_types::{get_inputs_for_height, RPC_ENDPOINT, TRUSTED_HEIGHT};

    #[tokio::test]
    pub async fn test() {
        get_inputs_for_height(CURRENT_HEIGHT, TRUSTED_HEIGHT).await;
    }

}