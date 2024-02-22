pub mod config_data;
pub mod input_types;
pub mod merkle_targets;
pub mod targets;
pub mod test_data;
pub mod test_utils;
pub mod test_heights;

use dotenv::dotenv;

use tendermint_lc_plonky2::circuit::run_circuit;

#[tokio::main]

async fn main() {
    dotenv().ok();
    run_circuit().await;
}
