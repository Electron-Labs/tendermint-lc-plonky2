# LightClient for Tendermint consensus based chains in Plonky2

## Introduction
- This repository contains plonky2 circuits aiming to create a single proof for the transition from some trusted block height and block hash to some future height and hash.
- The proof can be created for any tendermint based chain providing a config file for it. See `tendermint-lc-plonky2/src/chain_config/*` for example config files different chains.

## Tendermint Circuit
- The circuit code is splitted into various "sub-circuits" in multiple files located here `tendermint-lc-plonky2/src/circuits`.
- The entry point of the circuit is the `tendermint.rs` file.

## Recursion Circuit
- We create a recursive proof on top of the tendermint circuit. The recursion circuit does the proof verifiation in plonky2.
- This facilitates us to aggregate multiple chains into a single proof.

## Run
- First, set the following fields in the *circuit_builder.rs*:
  - chain_name, untrusted_height, trusted_height
- Build the tendermint circuit:
`X=1 cargo run --release`
- Next, build its recursion circuit
`X=2 cargo run --release`
- Finally, generate both the proofs:
`X=3 cargo run --release`
- The generate build and proof files can be found in the `storage` directory.


## Developer chat
In case you wish to contribute or collaborate, you can join our ZK builder chat at - https://t.me/+leHcoDWYoaFiZDM1
