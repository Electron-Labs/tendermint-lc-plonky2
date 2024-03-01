use dotenv::dotenv;

use tendermint_lc_plonky2::{circuit_builder::run_circuit, logger::initialize_logger};

#[tokio::main]

async fn main() {
    dotenv().ok();
    run_circuit().await;
    let _guard = initialize_logger();
}
