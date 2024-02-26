#[cfg(test)]
mod tests {
    use crate::config_data::*;
    use crate::merkle_targets::{
        bytes_to_bool, get_256_bool_target, get_formatted_hash_256_bools, get_sha_2_block_target,
        get_sha_512_2_block_target, get_sha_block_target, hash256_to_bool_targets,
        header_merkle_root, merkle_1_block_leaf_root, sha256_n_block_hash_target, SHA_BLOCK_BITS,
    };
    use crate::targets::{
        add_virtual_header_padded_target, constrain_pub_keys_vps, constrain_sign_message,
        constrain_timestamp, constrain_trusted_quorum, constrain_untrusted_quorum,
        constrain_update_validity, set_header_padded_target,
    };
    use crate::test_utils::*;
    use lazy_static::lazy_static;
    use num::BigUint;
    use num::FromPrimitive;
    use plonky2::iop::target::Target;
    use plonky2::{
        field::types::Field,
        hash::hash_types::RichField,
        iop::target::BoolTarget,
        iop::{witness::PartialWitness, witness::Witness, witness::WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::biguint::{BigUintTarget, CircuitBuilderBiguint};
    use plonky2_crypto::{
        biguint::WitnessBigUint,
        hash::{CircuitBuilderHash, WitnessHash},
        u32::binary_u32::CircuitBuilderBU32,
    };
    use std::cmp::min;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // TODO: load all test data only once

    // for osmosis
    pub fn load_chain_config() -> &'static Config {
        lazy_static! {
            static ref CONFIG: Config = {
                // Read the config file and deserialize it into a Config struct
                let file_content =
                    std::fs::read_to_string("./src/chain_config/osmosis.yaml").expect("Unable to read config yaml file");
                serde_yaml::from_str(file_content.as_str()).unwrap()
            };
        }

        &CONFIG
    }

    pub fn prove_and_verify(data: CircuitData<F, C, D>, witness: PartialWitness<F>) {
        let start_time = std::time::Instant::now();
        let proof = data.prove(witness).unwrap();
        let duration_ms = start_time.elapsed().as_millis();
        println!("proved in {}ms", duration_ms);
        assert!(data.verify(proof).is_ok());
    }

    #[test]
    fn test_update_validity_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let trusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let untrusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let trusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let untrusted_header_padded = add_virtual_header_padded_target(&mut builder);

        constrain_update_validity(
            &mut builder,
            &untrusted_height,
            &trusted_height,
            &untrusted_timestamp,
            &trusted_timestamp,
            &untrusted_header_padded.version,
            &untrusted_header_padded.chain_id,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        witness.set_biguint_target(
            &trusted_timestamp,
            &BigUint::from_u64(data.trusted_timestamp).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp).unwrap(),
        );

        witness.set_biguint_target(
            &trusted_height,
            &BigUint::from_u64(data.trusted_height).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        set_header_padded_target(
            &mut witness,
            &data.untrusted_header_padded,
            &untrusted_header_padded,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_target_invalid_height_1() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let trusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let untrusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let trusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let untrusted_header_padded = add_virtual_header_padded_target(&mut builder);

        constrain_update_validity(
            &mut builder,
            &untrusted_height,
            &trusted_height,
            &untrusted_timestamp,
            &trusted_timestamp,
            &untrusted_header_padded.version,
            &untrusted_header_padded.chain_id,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        witness.set_biguint_target(
            &trusted_timestamp,
            &BigUint::from_u64(data.trusted_timestamp).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp).unwrap(),
        );

        witness.set_biguint_target(&trusted_height, &BigUint::from_u64(12975356).unwrap());
        witness.set_biguint_target(&untrusted_height, &BigUint::from_u64(12975357).unwrap());

        set_header_padded_target(
            &mut witness,
            &data.untrusted_header_padded,
            &untrusted_header_padded,
        );
        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_target_invalid_height_2() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let trusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let untrusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let trusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let untrusted_header_padded = add_virtual_header_padded_target(&mut builder);

        constrain_update_validity(
            &mut builder,
            &untrusted_height,
            &trusted_height,
            &untrusted_timestamp,
            &trusted_timestamp,
            &untrusted_header_padded.version,
            &untrusted_header_padded.chain_id,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        witness.set_biguint_target(
            &trusted_timestamp,
            &BigUint::from_u64(data.trusted_timestamp).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp).unwrap(),
        );

        witness.set_biguint_target(&trusted_height, &BigUint::from_u64(12975357).unwrap());
        witness.set_biguint_target(&untrusted_height, &BigUint::from_u64(12975357).unwrap());

        set_header_padded_target(
            &mut witness,
            &data.untrusted_header_padded,
            &untrusted_header_padded,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_target_invalid_timestamp() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let trusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let untrusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let trusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let untrusted_header_padded = add_virtual_header_padded_target(&mut builder);

        constrain_update_validity(
            &mut builder,
            &untrusted_height,
            &trusted_height,
            &untrusted_timestamp,
            &trusted_timestamp,
            &untrusted_header_padded.version,
            &untrusted_header_padded.chain_id,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        witness.set_biguint_target(
            &trusted_timestamp,
            &BigUint::from_u64(data.trusted_timestamp).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_timestamp,
            &BigUint::from_u64(data.trusted_timestamp + cc.TRUSTING_PERIOD as u64 + 1).unwrap(),
        );

        witness.set_biguint_target(
            &trusted_height,
            &BigUint::from_u64(data.trusted_height).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );
        set_header_padded_target(
            &mut witness,
            &data.untrusted_header_padded,
            &untrusted_header_padded,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_target_invalid_chain_id() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let trusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let untrusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let trusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let untrusted_header_padded = add_virtual_header_padded_target(&mut builder);

        constrain_update_validity(
            &mut builder,
            &untrusted_height,
            &trusted_height,
            &untrusted_timestamp,
            &trusted_timestamp,
            &untrusted_header_padded.version,
            &untrusted_header_padded.chain_id,
            cc,
        );

        let mut witness = PartialWitness::new();
        let mut data = get_test_data();

        data.untrusted_header_padded.chain_id[25] = false;

        witness.set_biguint_target(
            &trusted_timestamp,
            &BigUint::from_u64(data.trusted_timestamp).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp).unwrap(),
        );

        witness.set_biguint_target(
            &trusted_height,
            &BigUint::from_u64(data.trusted_height).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        set_header_padded_target(
            &mut witness,
            &data.untrusted_header_padded,
            &untrusted_header_padded,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_update_validity_target_invalid_version_block() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let trusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let untrusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let trusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        let untrusted_header_padded = add_virtual_header_padded_target(&mut builder);

        constrain_update_validity(
            &mut builder,
            &untrusted_height,
            &trusted_height,
            &untrusted_timestamp,
            &trusted_timestamp,
            &untrusted_header_padded.version,
            &untrusted_header_padded.chain_id,
            cc,
        );

        let mut witness = PartialWitness::new();
        let mut data = get_test_data();

        data.untrusted_header_padded.version[18] = true;

        witness.set_biguint_target(
            &trusted_timestamp,
            &BigUint::from_u64(data.trusted_timestamp).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp).unwrap(),
        );

        witness.set_biguint_target(
            &trusted_height,
            &BigUint::from_u64(data.trusted_height).unwrap(),
        );
        witness.set_biguint_target(
            &untrusted_height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        set_header_padded_target(
            &mut witness,
            &data.untrusted_header_padded,
            &untrusted_header_padded,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_sign_message() {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let messages_padded = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| get_sha_512_2_block_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let signatures = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| {
                (0..cc.SIGNATURE_BITS)
                    .map(|_| builder.add_virtual_bool_target_unsafe())
                    .collect()
            })
            .collect::<Vec<Vec<BoolTarget>>>();

        let untrusted_pub_keys = (0..cc.N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let untrusted_hash = builder.add_virtual_hash256_target();
        let untrusted_hash_bool_targets = &hash256_to_bool_targets(&mut builder, &untrusted_hash);
        let untrusted_hash_bool_targets_formatted =
            get_formatted_hash_256_bools(untrusted_hash_bool_targets);
        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let signature_indices = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        constrain_sign_message(
            &mut builder,
            &messages_padded,
            &signatures,
            &untrusted_pub_keys,
            &untrusted_hash_bool_targets_formatted,
            &untrusted_height,
            &signature_indices,
            cc,
        );
        println!("num_gates {:?}", builder.num_gates());
        let data = get_test_data();

        let mut witness = PartialWitness::<F>::new();

        // connect padded message
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..SHA_BLOCK_BITS * 4).for_each(|j| {
                witness.set_bool_target(messages_padded[i][j], data.sign_messages_padded[i][j])
            })
        });
        // connect signatures
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..cc.SIGNATURE_BITS)
                .for_each(|j| witness.set_bool_target(signatures[i][j], data.signatures[i][j]))
        });
        // connect untrusted_pub_key
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                );
            });
        });
        // in case when the indices domain size is greator than n validators
        (cc.N_VALIDATORS..cc.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                (0..256).for_each(|j| witness.set_bool_target(untrusted_pub_keys[i][j], false));
            });
        });

        // connect untrusted hash
        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(data.untrusted_hash.as_slice());
        witness.set_hash256_target(&untrusted_hash, &untrusted_hash_slice);

        witness.set_biguint_target(
            &untrusted_height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_sign_message_wrong_hash() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let messages_padded = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| get_sha_512_2_block_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let signatures = (0..cc.N_VALIDATORS)
            .map(|_| {
                (0..cc.SIGNATURE_BITS)
                    .map(|_| builder.add_virtual_bool_target_unsafe())
                    .collect()
            })
            .collect::<Vec<Vec<BoolTarget>>>();

        let untrusted_pub_keys = (0..cc.N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();

        let untrusted_hash = builder.add_virtual_hash256_target();
        let untrusted_hash_bool_targets = &hash256_to_bool_targets(&mut builder, &untrusted_hash);
        let untrusted_hash_bool_targets_formatted =
            get_formatted_hash_256_bools(untrusted_hash_bool_targets);
        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let signature_indices = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        constrain_sign_message(
            &mut builder,
            &messages_padded,
            &signatures,
            &untrusted_pub_keys,
            &untrusted_hash_bool_targets_formatted,
            &untrusted_height,
            &signature_indices,
            cc,
        );

        let data = get_test_data();
        let mut witness = PartialWitness::new();

        // connect padded message
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..SHA_BLOCK_BITS * 4).for_each(|j| {
                witness.set_bool_target(messages_padded[i][j], data.sign_messages_padded[i][j])
            })
        });
        // connect signatures
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..cc.SIGNATURE_BITS)
                .for_each(|j| witness.set_bool_target(signatures[i][j], data.signatures[i][j]))
        });
        // connect untrusted_pub_key
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                );
            });
        });

        // in case when the indices domain size is greator than n validators
        (cc.N_VALIDATORS..cc.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                (0..256).for_each(|j| witness.set_bool_target(untrusted_pub_keys[i][j], false));
            });
        });

        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(data.untrusted_hash.as_slice());
        untrusted_hash_slice[0] = 10;
        witness.set_hash256_target(&untrusted_hash, &untrusted_hash_slice);

        witness.set_biguint_target(
            &untrusted_height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_sign_message_wrong_height() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let messages_padded = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| get_sha_512_2_block_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let signatures = (0..cc.N_VALIDATORS)
            .map(|_| {
                (0..cc.SIGNATURE_BITS)
                    .map(|_| builder.add_virtual_bool_target_unsafe())
                    .collect()
            })
            .collect::<Vec<Vec<BoolTarget>>>();

        let untrusted_pub_keys = (0..cc.N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();

        let untrusted_hash = builder.add_virtual_hash256_target();
        let untrusted_hash_bool_targets = &hash256_to_bool_targets(&mut builder, &untrusted_hash);
        let untrusted_hash_bool_targets_formatted =
            get_formatted_hash_256_bools(untrusted_hash_bool_targets);
        let untrusted_height = builder.add_virtual_biguint_target(cc.HEIGHT_BITS.div_ceil(32));
        let signature_indices = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        constrain_sign_message(
            &mut builder,
            &messages_padded,
            &signatures,
            &untrusted_pub_keys,
            &untrusted_hash_bool_targets_formatted,
            &untrusted_height,
            &signature_indices,
            cc,
        );

        let data = get_test_data();

        let mut witness = PartialWitness::new();
        // connect padded message
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..SHA_BLOCK_BITS * 4).for_each(|j| {
                witness.set_bool_target(messages_padded[i][j], data.sign_messages_padded[i][j])
            })
        });
        // connect signatures
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..cc.SIGNATURE_BITS)
                .for_each(|j| witness.set_bool_target(signatures[i][j], data.signatures[i][j]))
        });
        // connect untrusted_pub_key
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                );
            });
        });
        // in case when the indices domain size is greator than n validators
        (cc.N_VALIDATORS..cc.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                (0..256).for_each(|j| witness.set_bool_target(untrusted_pub_keys[i][j], false));
            });
        });
        let mut height = data.untrusted_height;
        height += 1;

        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(data.untrusted_hash.as_slice());
        witness.set_hash256_target(&untrusted_hash, &untrusted_hash_slice);

        witness.set_biguint_target(
            &untrusted_height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_timestamp() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_time_padded = get_sha_block_target(&mut builder);
        let untrusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        constrain_timestamp(
            &mut builder,
            &untrusted_time_padded,
            &untrusted_timestamp,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                untrusted_time_padded[i],
                data.untrusted_header_padded.time[i],
            )
        });
        witness.set_biguint_target(
            &untrusted_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_timestamp_incorrect() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_time_padded = get_sha_block_target(&mut builder);
        let untrusted_timestamp = builder.add_virtual_biguint_target(
            (cc.TIMESTAMP_BITS.div_ceil(cc.LEB128_GROUP_SIZE) * 8).div_ceil(32),
        );
        constrain_timestamp(
            &mut builder,
            &untrusted_time_padded,
            &untrusted_timestamp,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                untrusted_time_padded[i],
                data.untrusted_header_padded.time[i],
            )
        });
        witness.set_biguint_target(
            &untrusted_timestamp,
            &BigUint::from_u64(data.untrusted_timestamp + 1).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_pub_keys_vps() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_validator_pub_keys = (0..cc.N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let untrusted_validators_padded = (0..cc.N_VALIDATORS)
            .map(|_| get_sha_block_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let untrusted_validator_vps = (0..cc.N_VALIDATORS)
            .map(|_| builder.add_virtual_biguint_target(cc.VP_BITS.div_ceil(32)))
            .collect::<Vec<BigUintTarget>>();

        constrain_pub_keys_vps(
            &mut builder,
            &untrusted_validator_pub_keys,
            &untrusted_validators_padded,
            &untrusted_validator_vps,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..SHA_BLOCK_BITS).for_each(|j| {
                witness.set_bool_target(
                    untrusted_validators_padded[i][j],
                    data.untrusted_validators_padded[i][j],
                )
            })
        });

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &untrusted_validator_vps[i],
                &BigUint::from_u64(data.untrusted_validator_vps[i]).unwrap(),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_pub_keys_vps_invalid_pubkey() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_validator_pub_key = (0..cc.N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let untrusted_validators_padded = (0..cc.N_VALIDATORS)
            .map(|_| get_sha_block_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let untrusted_validator_vps = (0..cc.N_VALIDATORS)
            .map(|_| builder.add_virtual_biguint_target(cc.VP_BITS.div_ceil(32)))
            .collect::<Vec<BigUintTarget>>();

        let target = constrain_pub_keys_vps(
            &mut builder,
            &untrusted_validator_pub_key,
            &untrusted_validators_padded,
            &untrusted_validator_vps,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_validator_pub_keys = data.untrusted_validator_pub_keys;
        untrusted_validator_pub_keys[3][3] = false;

        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    untrusted_validator_pub_key[i][j],
                    untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..SHA_BLOCK_BITS).for_each(|j| {
                witness.set_bool_target(
                    untrusted_validators_padded[i][j],
                    data.untrusted_validators_padded[i][j],
                )
            })
        });

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &untrusted_validator_vps[i],
                &BigUint::from_u64(data.untrusted_validator_vps[i]).unwrap(),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_pub_keys_vps_invalid_vp() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let untrusted_validator_pub_keys = (0..cc.N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let untrusted_validator_vps = (0..cc.N_VALIDATORS)
            .map(|_| builder.add_virtual_biguint_target(cc.VP_BITS.div_ceil(32)))
            .collect::<Vec<BigUintTarget>>();
        let untrusted_validators_padded = (0..cc.N_VALIDATORS)
            .map(|_| get_sha_block_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        let untrusted_validator_vps = (0..cc.N_VALIDATORS)
            .map(|_| builder.add_virtual_biguint_target(cc.VP_BITS.div_ceil(32)))
            .collect::<Vec<BigUintTarget>>();

        constrain_pub_keys_vps(
            &mut builder,
            &untrusted_validator_pub_keys,
            &untrusted_validators_padded,
            &untrusted_validator_vps,
            cc,
        );

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_validator_vp = data.untrusted_validator_vps;
        untrusted_validator_vp[3] = 14141431 + 1;

        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..SHA_BLOCK_BITS).for_each(|j| {
                witness.set_bool_target(
                    untrusted_validators_padded[i][j],
                    data.untrusted_validators_padded[i][j],
                )
            })
        });

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &untrusted_validator_vps[i],
                &BigUint::from_u64(untrusted_validator_vp[i]).unwrap(),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    // TODO: add negative tests and cover more cases
    #[test]
    fn test_sufficient_trusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let untrusted_validator_pub_keys = (0..cc.N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();

        let untrusted_intersect_indices = (0..cc.N_INTERSECTION_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        let trusted_next_validator_pub_keys = (0..cc.N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();

        let trusted_next_validator_vp = (0..cc.N_VALIDATORS)
            .map(|_| builder.add_virtual_biguint_target(cc.VP_BITS.div_ceil(32)))
            .collect::<Vec<BigUintTarget>>();
        let trusted_next_intersect_indices = (0..cc.N_INTERSECTION_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        let signature_indices = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        constrain_trusted_quorum(
            &mut builder,
            &untrusted_validator_pub_keys,
            &trusted_next_validator_pub_keys,
            &trusted_next_validator_vp,
            &signature_indices,
            &untrusted_intersect_indices,
            &trusted_next_intersect_indices,
            cc,
        );

        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });

        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    trusted_next_validator_pub_keys[i][j],
                    data.trusted_next_validator_pub_keys[i][j],
                )
            })
        });

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &trusted_next_validator_vp[i],
                &BigUint::from_u64(data.trusted_next_validator_vps[i]).unwrap(),
            )
        });

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                untrusted_intersect_indices[i],
                F::from_canonical_u8(data.untrusted_intersect_indices[i]),
            )
        });
        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                trusted_next_intersect_indices[i],
                F::from_canonical_u8(data.trusted_next_intersect_indices[i]),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_sufficient_untrusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let mut witness = PartialWitness::new();

        let untrusted_validator_vp = (0..cc.N_VALIDATORS)
            .map(|_| builder.add_virtual_biguint_target(cc.VP_BITS.div_ceil(32)))
            .collect::<Vec<BigUintTarget>>();

        let signature_indices = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        constrain_untrusted_quorum(
            &mut builder,
            &untrusted_validator_vp,
            &signature_indices,
            cc,
        );

        let data = get_test_data();

        // in case if the indices domain size is gretor than n validators
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &untrusted_validator_vp[i],
                &BigUint::from_u64(data.untrusted_validator_vps[i]).unwrap(),
            )
        });

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    // only for osmosis
    #[test]
    fn test_sufficient_untrusted_quorum_target_border() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let mut witness = PartialWitness::new();

        let untrusted_validator_vp = (0..cc.N_VALIDATORS)
            .map(|_| builder.add_virtual_biguint_target(cc.VP_BITS.div_ceil(32)))
            .collect::<Vec<BigUintTarget>>();

        let signature_indices = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        constrain_untrusted_quorum(
            &mut builder,
            &untrusted_validator_vp,
            &signature_indices,
            cc,
        );

        let data = get_test_data();

        // just > 2/3
        let mut vp = [2; 45].to_vec();
        vp[0] += 1;
        vp.extend([0; 150 - 45 - 1].to_vec());
        vp.extend([45; 1].to_vec());
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &untrusted_validator_vp[i],
                &BigUint::from_u64(vp[i]).unwrap(),
            )
        });
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    // only for osmosis
    #[test]
    #[should_panic]
    fn test_insufficient_untrusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let mut witness = PartialWitness::new();

        let untrusted_validator_vp = (0..cc.N_VALIDATORS)
            .map(|_| builder.add_virtual_biguint_target(cc.VP_BITS.div_ceil(32)))
            .collect::<Vec<BigUintTarget>>();

        let signature_indices = (0..cc.N_SIGNATURE_INDICES)
            .map(|_| builder.add_virtual_target())
            .collect::<Vec<Target>>();

        constrain_untrusted_quorum(
            &mut builder,
            &untrusted_validator_vp,
            &signature_indices,
            cc,
        );

        let data = get_test_data();

        // less than 2/3
        let mut vp = [2; 45].to_vec();
        vp.extend([0; 150 - 45 - 1].to_vec());
        vp.extend([45; 1].to_vec());
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &untrusted_validator_vp[i],
                &BigUint::from_u64(vp[i]).unwrap(),
            )
        });
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_validators_hash() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let t = get_test_data();

        let mut witness = PartialWitness::new();

        let validator_leaves_padded_target = (0..cc.N_VALIDATORS)
            .map(|_| get_sha_block_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();

        (0..cc.N_VALIDATORS_LEAVES).for_each(|i| {
            (0..SHA_BLOCK_BITS).for_each(|j| {
                witness.set_bool_target(
                    validator_leaves_padded_target[i][j],
                    t.untrusted_validators_padded[i][j],
                )
            })
        });

        let computed = merkle_1_block_leaf_root(&mut builder, &validator_leaves_padded_target);

        let expected_hash = [
            232, 89, 230, 77, 86, 114, 76, 122, 224, 97, 170, 76, 43, 119, 30, 183, 92, 152, 183,
            190, 44, 225, 8, 7, 237, 32, 132, 245, 7, 108, 141, 252,
        ];
        println!(
            "{:?}",
            bytes_to_bool(
                [
                    214, 242, 229, 96, 1, 143, 18, 196, 185, 125, 195, 27, 82, 2, 127, 24, 4, 144,
                    31, 39, 56, 236, 16, 77, 86, 13, 22, 83, 212, 156, 85, 242
                ]
                .to_vec()
            )
        );
        let expected_hash_target = builder.add_virtual_hash256_target();
        witness.set_hash256_target(&expected_hash_target, &expected_hash);

        expected_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bin32_target = builder.convert_u32_bin32(u32_elm);
                (0..32).for_each(|j| {
                    builder.connect(computed[i * 32 + j].target, bin32_target.bits[j].target)
                });
            });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_header_merkle_root() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let t = get_test_data();

        let mut witness = PartialWitness::new();

        let untrusted_header_padded = add_virtual_header_padded_target(&mut builder);
        set_header_padded_target(
            &mut witness,
            &t.untrusted_header_padded,
            &untrusted_header_padded,
        );

        let computed = header_merkle_root(&mut builder, untrusted_header_padded.into_iter());
        let expected_hash = [
            122, 142, 192, 235, 60, 200, 129, 138, 195, 28, 210, 246, 239, 120, 205, 133, 142, 55,
            139, 49, 122, 88, 39, 159, 168, 141, 149, 188, 97, 173, 187, 96,
        ];

        let expected_hash_target = builder.add_virtual_hash256_target();
        witness.set_hash256_target(&expected_hash_target, &expected_hash);

        expected_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bin32_target = builder.convert_u32_bin32(u32_elm);
                (0..32).for_each(|j| {
                    builder.connect(computed[i * 32 + j].target, bin32_target.bits[j].target)
                });
            });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_sha256_2_block_hash_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let t = get_test_data();

        let mut witness = PartialWitness::new();
        let last_block_id_target = get_sha_2_block_target(&mut builder);
        (0..SHA_BLOCK_BITS * 2).for_each(|i| {
            witness.set_bool_target(
                last_block_id_target[i],
                t.untrusted_header_padded.last_block_id[i],
            )
        });

        let computed = sha256_n_block_hash_target(&mut builder, &last_block_id_target, 2);

        let expected_hash = [
            74, 80, 141, 164, 102, 195, 37, 198, 28, 154, 188, 145, 132, 242, 240, 115, 132, 85,
            238, 254, 108, 86, 33, 242, 76, 246, 104, 198, 46, 45, 61, 247,
        ];
        let expected_hash_target = builder.add_virtual_hash256_target();
        witness.set_hash256_target(&expected_hash_target, &expected_hash);

        expected_hash_target
            .iter()
            .enumerate()
            .for_each(|(i, &u32_elm)| {
                let bin32_target = builder.convert_u32_bin32(u32_elm);
                (0..32).for_each(|j| {
                    builder.connect(computed[i * 32 + j].target, bin32_target.bits[j].target)
                });
            });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
