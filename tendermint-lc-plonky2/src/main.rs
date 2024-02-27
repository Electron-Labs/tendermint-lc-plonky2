use dotenv::dotenv;

use tendermint_lc_plonky2::circuit_builder::run_circuit;

#[tokio::main]

async fn main() {
    dotenv().ok();
    run_circuit().await;
}
