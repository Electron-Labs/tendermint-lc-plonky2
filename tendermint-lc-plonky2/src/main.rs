use dotenv::dotenv;

use tendermint_lc_plonky2::{circuit_builder::run_circuit, logger::initialize_logger};

#[tokio::main]

async fn main() {
    dotenv().ok();
    let _guard = initialize_logger();
    run_circuit().await;
}
