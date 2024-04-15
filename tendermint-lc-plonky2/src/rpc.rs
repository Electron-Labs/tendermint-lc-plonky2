use crate::config_data::*;
use std::error::Error;
use std::fmt;
use tendermint::block::{Block, Commit, Height};
use tendermint::validator::Info;
use tendermint_rpc::{Client, HttpClient, Paging, Response};
use tokio::time::timeout;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

#[derive(Debug)]
struct Empty;

impl Error for Empty {}

impl fmt::Display for Empty {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Empty")
    }
}

pub async fn get_latest_commit(c: &Config) -> Result<Commit, Box<dyn Error + Send + Sync>> {
    let mut result: Result<Commit, Box<dyn Error + Send + Sync>> = Err(Box::new(Empty));
    for endpoint in &c.RPC_ENDPOINT {
        let client = HttpClient::new(endpoint.as_str())?;
        match timeout(Duration::from_millis(5000), client.latest_commit()).await {
            Err(e) => {
                info!(
                    "unresponsive RPC->{:?}, {:?}. {:?}",
                    endpoint,
                    e.to_string(),
                    "Trying with another RPC..."
                );
                result = Err(Box::new(e))
            }
            Ok(reponse) => match reponse {
                Ok(s) => {
                    result = Ok(s.signed_header.commit);
                    break;
                }
                Err(e) => {
                    info!(
                        "Error in get_latest_commit::RPC->{:?}, {:?}, {:?}",
                        endpoint,
                        e.to_string(),
                        "Trying with another RPC..."
                    );
                    result = Err(Box::new(e));
                }
            },
        }
    }

    result
}

pub async fn get_commit(
    c: &Config,
    height: Height,
) -> Result<Commit, Box<dyn Error + Send + Sync>> {
    let mut result: Result<Commit, Box<dyn Error + Send + Sync>> = Err(Box::new(Empty));
    for endpoint in &c.RPC_ENDPOINT {
        let client = HttpClient::new(endpoint.as_str())?;
        match timeout(Duration::from_millis(5000), client.commit(height)).await {
            Err(e) => {
                info!(
                    "unresponsive RPC->{:?}, {:?}. {:?}",
                    endpoint,
                    e.to_string(),
                    "Trying with another RPC..."
                );
                result = Err(Box::new(e))
            }
            Ok(reponse) => match reponse {
                Ok(s) => {
                    result = Ok(s.signed_header.commit);
                    break;
                }
                Err(e) => {
                    info!(
                        "Error in get_commit::RPC->{:?}, {:?}, {:?}",
                        endpoint,
                        e.to_string(),
                        "Trying with another RPC..."
                    );
                    result = Err(Box::new(e));
                }
            },
        }
    }

    result
}

pub async fn get_block(c: &Config, height: Height) -> Result<Block, Box<dyn Error + Send + Sync>> {
    let mut result: Result<Block, Box<dyn Error + Send + Sync>> = Err(Box::new(Empty));
    for endpoint in &c.RPC_ENDPOINT {
        let client = HttpClient::new(endpoint.as_str())?;

        match timeout(Duration::from_millis(5000), client.block(height)).await {
            Err(e) => {
                info!(
                    "unresponsive RPC->{:?}, {:?}. {:?}",
                    endpoint,
                    e.to_string(),
                    "Trying with another RPC..."
                );
                result = Err(Box::new(e))
            }
            Ok(reponse) => match reponse {
                Ok(s) => {
                    result = Ok(s.block);
                    break;
                }
                Err(e) => {
                    info!(
                        "Error in get_block::RPC->{:?}, {:?}, {:?}",
                        endpoint,
                        e.to_string(),
                        "Trying with another RPC..."
                    );
                    result = Err(Box::new(e));
                }
            },
        }
    }

    result
}

pub async fn get_validators_all(
    c: &Config,
    height: Height,
) -> Result<Vec<Info>, Box<dyn Error + Send + Sync>> {
    let mut result: Result<Vec<Info>, Box<dyn Error + Send + Sync>> = Err(Box::new(Empty));
    for endpoint in &c.RPC_ENDPOINT {
        let client = HttpClient::new(endpoint.as_str())?;
        match timeout(
            Duration::from_millis(5000),
            client.validators(height, Paging::All),
        )
        .await
        {
            Err(e) => {
                info!(
                    "unresponsive RPC->{:?}, {:?}. {:?}",
                    endpoint,
                    e.to_string(),
                    "Trying with another RPC..."
                );
                result = Err(Box::new(e))
            }
            Ok(reponse) => match reponse {
                Ok(s) => {
                    result = Ok(s.validators);
                    break;
                }
                Err(e) => {
                    info!(
                        "Error in get_validators_all::RPC->{:?}, {:?}, {:?}",
                        endpoint,
                        e.to_string(),
                        "Trying with another RPC..."
                    );
                    result = Err(Box::new(e));
                }
            },
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_data::get_chain_config;

    #[tokio::test]
    pub async fn test() {
        let chain_name = "OSMOSIS";
        let chains_config_path = "src/chain_config";
        let config = get_chain_config(chains_config_path, chain_name);
        let commit = get_latest_commit(&config).await.unwrap();
        get_block(&config, commit.height).await.unwrap();
        get_commit(&config, commit.height).await.unwrap();
        get_validators_all(&config, commit.height).await.unwrap();
    }
}
