#[cfg(test)]
mod tests {
    use crate::config_data::*;
    use crate::merkle_targets::{
        bytes_to_bool, get_formatted_hash_256_bools, get_sha_2_block_target, get_sha_block_target,
        hash256_to_bool_targets, header_hash_merkle_root, merkle_1_block_leaf_root,
        sha256_1_block_hash_target, sha256_2_block_hash_target, SHA_BLOCK_BITS,
    };
    use crate::targets::{
        add_virtual_connect_pub_keys_vps_target, add_virtual_connect_sign_message_target,
        add_virtual_connect_timestamp_target, add_virtual_header_chain_id_merkle_proof_target,
        add_virtual_header_time_merkle_proof_target,
        add_virtual_header_version_merkle_proof_target,
        add_virtual_next_validators_hash_merkle_proof_target, add_virtual_trusted_quorum_target,
        add_virtual_untrusted_quorum_target, add_virtual_update_validity_target,
        add_virtual_validators_hash_merkle_proof_target, UpdateValidityTarget,
    };
    use crate::test_utils::*;
    use lazy_static::lazy_static;
    use num::BigUint;
    use num::FromPrimitive;
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
    use plonky2_crypto::{
        biguint::WitnessBigUint,
        hash::{CircuitBuilderHash, HashInputTarget, WitnessHash},
        u32::binary_u32::{Bin32Target, CircuitBuilderBU32},
    };
    use sha2::digest::FixedOutput;
    use std::cmp::min;

    use sha2::{Digest, Sha256};

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

    fn set_update_validity_target<F: RichField, W: Witness<F>>(
        witness: &mut W,
        untrusted_height: u64,
        trusted_height: u64,
        untrusted_timestamp: u64,
        trusted_timestamp: u64,
        untrusted_version_padded: Vec<bool>,
        untrusted_chain_id_padded: Vec<bool>,
        target: &UpdateValidityTarget,
    ) {
        witness.set_biguint_target(
            &target.untrusted_height,
            &BigUint::from_u64(untrusted_height).unwrap(),
        );
        witness.set_biguint_target(
            &target.trusted_height,
            &BigUint::from_u64(trusted_height).unwrap(),
        );
        witness.set_biguint_target(
            &target.untrusted_timestamp,
            &BigUint::from_u64(untrusted_timestamp).unwrap(),
        );
        witness.set_biguint_target(
            &target.trusted_timestamp,
            &BigUint::from_u64(trusted_timestamp).unwrap(),
        );
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                target.untrusted_version_padded[i],
                untrusted_version_padded[i],
            )
        });
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                target.untrusted_chain_id_padded[i],
                untrusted_chain_id_padded[i],
            )
        });
    }

    #[test]
    fn test_update_validity_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let target = add_virtual_update_validity_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        set_update_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_padded,
            data.untrusted_chain_id_padded,
            &target,
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

        let target = add_virtual_update_validity_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();
        set_update_validity_target(
            &mut witness,
            12975357,
            12975356,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_padded,
            data.untrusted_chain_id_padded,
            &target,
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

        let target = add_virtual_update_validity_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();
        set_update_validity_target(
            &mut witness,
            12975357,
            12975357,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_padded,
            data.untrusted_chain_id_padded,
            &target,
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

        let target = add_virtual_update_validity_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let untrusted_timestamp = data.trusted_timestamp + cc.TRUSTING_PERIOD as u64 + 1;

        set_update_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_padded,
            data.untrusted_chain_id_padded,
            &target,
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

        let target = add_virtual_update_validity_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_chain_id_padded = data.untrusted_chain_id_padded;
        untrusted_chain_id_padded[25] = false;

        set_update_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_padded,
            untrusted_chain_id_padded,
            &target,
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

        let target = add_virtual_update_validity_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_version_padded = data.untrusted_version_padded;
        untrusted_version_padded[18] = true;

        set_update_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            untrusted_version_padded,
            data.untrusted_chain_id_padded,
            &target,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_sign_message() {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let target = add_virtual_connect_sign_message_target(&mut builder, cc);
        println!("num_gates {:?}", builder.num_gates());
        let data = get_test_data();

        let mut witness = PartialWitness::<F>::new();

        // connect padded message
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..SHA_BLOCK_BITS * 4).for_each(|j| {
                witness.set_bool_target(
                    target.messages_padded[i][j],
                    data.sign_messages_padded[i][j],
                )
            })
        });
        // connect untrusted hash
        let header_hash = builder.add_virtual_hash256_target();
        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(data.untrusted_hash.as_slice());
        witness.set_hash256_target(&header_hash, &untrusted_hash_slice);
        let header_hash_bool_targets =
            get_formatted_hash_256_bools(&hash256_to_bool_targets(&mut builder, &header_hash));
        (0..256).for_each(|i| {
            builder.connect(
                target.header_hash[i].target,
                header_hash_bool_targets[i].target,
            )
        });
        // connect untrusted height
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );
        // connect signatures
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..512).for_each(|j| {
                witness.set_bool_target(target.signatures[i][j], data.signatures[i][j])
            })
        });
        // connect signature indices
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indexes[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        // connect untrusted_pub_key
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                );
            });
        });
        // in case when the indices domain size is greator than n validators
        (cc.N_VALIDATORS..cc.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                (0..256)
                    .for_each(|j| witness.set_bool_target(target.untrusted_pub_keys[i][j], false));
            });
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

        let target = add_virtual_connect_sign_message_target(&mut builder, cc);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..SHA_BLOCK_BITS * 4).for_each(|j| {
                witness.set_bool_target(
                    target.messages_padded[i][j],
                    data.sign_messages_padded[i][j],
                )
            })
        });

        let header_hash = builder.add_virtual_hash256_target();
        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(data.untrusted_hash.as_slice());
        untrusted_hash_slice[0] = 10;
        witness.set_hash256_target(&header_hash, &untrusted_hash_slice);
        let header_hash_bool_targets =
            get_formatted_hash_256_bools(&hash256_to_bool_targets(&mut builder, &header_hash));
        (0..256).for_each(|i| {
            builder.connect(
                target.header_hash[i].target,
                header_hash_bool_targets[i].target,
            )
        });

        witness.set_biguint_target(
            &target.height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );
        // connect signatures
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..512).for_each(|j| {
                witness.set_bool_target(target.signatures[i][j], data.signatures[i][j])
            })
        });
        // connect signature indexes
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indexes[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        // connect untrusted_pub_key
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                );
            });
        });
        // in case when the indices domain size is greator than n validators
        (cc.N_VALIDATORS..cc.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                (0..256)
                    .for_each(|j| witness.set_bool_target(target.untrusted_pub_keys[i][j], false));
            });
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

        let target = add_virtual_connect_sign_message_target(&mut builder, cc);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..SHA_BLOCK_BITS * 4).for_each(|j| {
                witness.set_bool_target(
                    target.messages_padded[i][j],
                    data.sign_messages_padded[i][j],
                )
            })
        });
        let mut height = data.untrusted_height;
        height += 1;

        let header_hash = builder.add_virtual_hash256_target();
        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(data.untrusted_hash.as_slice());
        witness.set_hash256_target(&header_hash, &untrusted_hash_slice);
        let header_hash_bool_targets =
            get_formatted_hash_256_bools(&hash256_to_bool_targets(&mut builder, &header_hash));
        (0..256).for_each(|i| {
            builder.connect(
                target.header_hash[i].target,
                header_hash_bool_targets[i].target,
            )
        });
        witness.set_biguint_target(&target.height, &BigUint::from_u64(height).unwrap());
        // connect signatures
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            (0..512).for_each(|j| {
                witness.set_bool_target(target.signatures[i][j], data.signatures[i][j])
            })
        });
        // connect signature indexes
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indexes[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        // connect untrusted_pub_key
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                );
            });
        });
        // in case when the indices domain size is greator than n validators
        (cc.N_VALIDATORS..cc.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                (0..256)
                    .for_each(|j| witness.set_bool_target(target.untrusted_pub_keys[i][j], false));
            });
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_timestamp() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let target = add_virtual_connect_timestamp_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(target.header_time_padded[i], data.untrusted_time_padded[i])
        });
        witness.set_biguint_target(
            &target.header_timestamp,
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

        let target = add_virtual_connect_timestamp_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(target.header_time_padded[i], data.untrusted_time_padded[i])
        });
        witness.set_biguint_target(
            &target.header_timestamp,
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

        let target = add_virtual_connect_pub_keys_vps_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.vps[i],
                &BigUint::from_u64(data.untrusted_validator_vp[i]).unwrap(),
            )
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..SHA_BLOCK_BITS).for_each(|j| {
                witness.set_bool_target(
                    target.validators_padded[i][j],
                    data.untrusted_validators_padded[i][j],
                )
            })
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

        let target = add_virtual_connect_pub_keys_vps_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_validator_pub_keys = data.untrusted_validator_pub_keys;
        untrusted_validator_pub_keys[3][3] = false;

        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(target.pub_keys[i][j], untrusted_validator_pub_keys[i][j])
            })
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.vps[i],
                &BigUint::from_u64(data.untrusted_validator_vp[i]).unwrap(),
            )
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..SHA_BLOCK_BITS).for_each(|j| {
                witness.set_bool_target(
                    target.validators_padded[i][j],
                    data.untrusted_validators_padded[i][j],
                )
            })
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

        let target = add_virtual_connect_pub_keys_vps_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_validator_vp = data.untrusted_validator_vp;
        untrusted_validator_vp[3] = 14141431 + 1;

        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.vps[i],
                &BigUint::from_u64(untrusted_validator_vp[i]).unwrap(),
            )
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..SHA_BLOCK_BITS).for_each(|j| {
                witness.set_bool_target(
                    target.validators_padded[i][j],
                    data.untrusted_validators_padded[i][j],
                )
            })
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

        let target = add_virtual_trusted_quorum_target(&mut builder, cc);

        let data = get_test_data();

        (0..min(cc.INTERSECTION_INDICES_DOMAIN_SIZE, cc.N_VALIDATORS)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        // in case if n_validators are less than the indices domain size
        (min(cc.INTERSECTION_INDICES_DOMAIN_SIZE, cc.N_VALIDATORS)
            ..cc.INTERSECTION_INDICES_DOMAIN_SIZE)
            .for_each(|i| {
                (0..256).for_each(|j| {
                    witness.set_bool_target(target.untrusted_validator_pub_keys[i][j], false)
                })
            });

        (0..min(cc.INTERSECTION_INDICES_DOMAIN_SIZE, cc.N_VALIDATORS)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.trusted_next_validator_pub_keys[i][j],
                    data.trusted_next_validator_pub_keys[i][j],
                )
            })
        });
        // in case if n_validators are less than the indices domain size
        (min(cc.INTERSECTION_INDICES_DOMAIN_SIZE, cc.N_VALIDATORS)
            ..cc.INTERSECTION_INDICES_DOMAIN_SIZE)
            .for_each(|i| {
                (0..256).for_each(|j| {
                    witness.set_bool_target(target.trusted_next_validator_pub_keys[i][j], false)
                })
            });

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_next_validator_vp[i],
                &BigUint::from_u64(data.trusted_next_validator_vp[i]).unwrap(),
            )
        });
        (cc.N_VALIDATORS..cc.INTERSECTION_INDICES_DOMAIN_SIZE).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_next_validator_vp[i],
                &BigUint::from_u64(0).unwrap(),
            )
        });

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.untrusted_intersect_indices[i],
                F::from_canonical_u8(data.untrusted_intersect_indices[i]),
            )
        });
        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.trusted_next_intersect_indices[i],
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

        let target = add_virtual_untrusted_quorum_target(&mut builder, cc);

        let data = get_test_data();

        // in case if the indices domain size is gretor than n validators
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.untrusted_validator_vp[i],
                &BigUint::from_u64(data.untrusted_validator_vp[i]).unwrap(),
            )
        });

        (cc.N_VALIDATORS..cc.SIGNATURE_INDICES_DOMAIN_SIZE).for_each(|i| {
            witness.set_biguint_target(
                &target.untrusted_validator_vp[i],
                &BigUint::from_u64(0).unwrap(),
            )
        });

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indices[i],
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

        let target = add_virtual_untrusted_quorum_target(&mut builder, cc);

        let data = get_test_data();

        // just > 2/3
        let mut vp = [2; 45].to_vec();
        vp[0] += 1;
        vp.extend([0; 150 - 45 - 1].to_vec());
        vp.extend([45; 1].to_vec());
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.untrusted_validator_vp[i],
                &BigUint::from_u64(vp[i]).unwrap(),
            )
        });
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indices[i],
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

        let target = add_virtual_untrusted_quorum_target(&mut builder, cc);

        let data = get_test_data();

        // less than 2/3
        let mut vp = [2; 45].to_vec();
        vp.extend([0; 150 - 45 - 1].to_vec());
        vp.extend([45; 1].to_vec());
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.untrusted_validator_vp[i],
                &BigUint::from_u64(vp[i]).unwrap(),
            )
        });
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indices[i],
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
    fn test_header_hash() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let t = get_test_data();

        let mut witness = PartialWitness::new();

        let header_leaves_padded_target = (0..14)
            .map(|i| {
                if i == 4 {
                    return get_sha_2_block_target(&mut builder);
                } else {
                    return get_sha_block_target(&mut builder);
                }
            })
            .collect::<Vec<Vec<BoolTarget>>>();
        // set header version
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[0][i],
                t.untrusted_version_padded[i],
            )
        });

        // set chain id
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[1][i],
                t.untrusted_chain_id_padded[i],
            )
        });

        // set height
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[2][i],
                t.untrusted_height_padded[i],
            )
        });

        // set time
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[3][i],
                t.untrusted_time_padded[i],
            )
        });

        // set last_block_id
        (0..SHA_BLOCK_BITS * 2).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[4][i],
                t.untrusted_last_block_id_padded[i],
            )
        });

        // set last_commit_hash
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[5][i],
                t.untrusted_last_commit_hash_padded[i],
            )
        });

        // set data_hash
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[6][i],
                t.untrusted_data_hash_padded[i],
            )
        });

        // set validators_hash
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[7][i],
                t.untrusted_validators_hash_padded[i],
            )
        });

        // set next_validators_hash
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[8][i],
                t.untrusted_next_validators_hash_padded[i],
            )
        });

        // set consensus hash
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[9][i],
                t.untrusted_consensus_hash_padded[i],
            )
        });

        // set app_hash
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[10][i],
                t.untrusted_app_hash_padded[i],
            )
        });

        // set last_results_hash
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[11][i],
                t.untrusted_last_results_hash_padded[i],
            )
        });

        // set evidence_hash
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[12][i],
                t.untrusted_evidence_hash_padded[i],
            )
        });

        // set proposer_address
        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                header_leaves_padded_target[13][i],
                t.untrusted_proposer_address_padded[i],
            )
        });

        let computed = header_hash_merkle_root(&mut builder, &header_leaves_padded_target);
        let expected_hash = [
            122, 142, 192, 235, 60, 200, 129, 138, 195, 28, 210, 246, 239, 120, 205, 133, 142, 55,
            139, 49, 122, 88, 39, 159, 168, 141, 149, 188, 97, 173, 187, 96,
        ];

        // // checking if first element hash is done correctly -> Error is coming

        // let computed = header_hash_merkle_root(&mut builder, &header_leaves_padded_target);
        // let expected_hash = [17, 108, 61, 227, 1, 152, 64, 6, 137, 249, 81, 191, 188, 103, 200, 53, 120, 86, 12, 150, 217, 90, 236, 12, 100, 206, 199, 113, 45, 38, 127, 78];

        println!("Expected hash: {:?}", expected_hash);

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
        let cc = load_chain_config();

        let t = get_test_data();

        let mut witness = PartialWitness::new();
        let last_block_id_target = get_sha_2_block_target(&mut builder);
        (0..SHA_BLOCK_BITS * 2).for_each(|i| {
            witness.set_bool_target(last_block_id_target[i], t.untrusted_last_block_id_padded[i])
        });

        let computed = sha256_2_block_hash_target(&mut builder, &last_block_id_target);

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
    #[test]
    fn test_header_time_merkle_proof_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let t = get_test_data();

        let target = add_virtual_header_time_merkle_proof_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(target.leaf_padded[i], t.untrusted_time_padded[i])
        });
        (0..cc.HEADER_TIME_PROOF_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(target.proof[i][j], t.untrusted_time_proof[i][j])
            })
        });
        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(t.untrusted_hash.as_slice());
        witness.set_hash256_target(&target.root, &untrusted_hash_slice);

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_validators_hash_merkle_proof_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let t = get_test_data();

        let target = add_virtual_validators_hash_merkle_proof_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(target.leaf_padded[i], t.untrusted_validators_hash_padded[i])
        });
        (0..cc.HEADER_VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(target.proof[i][j], t.untrusted_validators_hash_proof[i][j])
            })
        });
        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(t.untrusted_hash.as_slice());
        witness.set_hash256_target(&target.root, &untrusted_hash_slice);

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_next_validators_hash_merkle_proof_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let t = get_test_data();

        let target = add_virtual_next_validators_hash_merkle_proof_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(
                target.leaf_padded[i],
                t.trusted_next_validators_hash_padded[i],
            )
        });
        (0..cc.HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.proof[i][j],
                    t.trusted_next_validators_hash_proof[i][j],
                )
            })
        });
        let mut trusted_hash_slice = [0u8; 32];
        trusted_hash_slice.copy_from_slice(t.trusted_hash.as_slice());
        witness.set_hash256_target(&target.root, &trusted_hash_slice);

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_chain_id_merkle_proof_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let t = get_test_data();

        let target = add_virtual_header_chain_id_merkle_proof_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(target.leaf_padded[i], t.untrusted_chain_id_padded[i])
        });
        (0..cc.HEADER_CHAIN_ID_PROOF_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(target.proof[i][j], t.untrusted_chain_id_proof[i][j])
            })
        });
        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(t.untrusted_hash.as_slice());
        witness.set_hash256_target(&target.root, &untrusted_hash_slice);

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_version_merkle_proof_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let t = get_test_data();

        let target = add_virtual_header_version_merkle_proof_target(&mut builder, cc);

        let mut witness = PartialWitness::new();

        (0..SHA_BLOCK_BITS).for_each(|i| {
            witness.set_bool_target(target.leaf_padded[i], t.untrusted_version_padded[i])
        });
        (0..cc.HEADER_VERSION_PROOF_SIZE).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(target.proof[i][j], t.untrusted_version_proof[i][j])
            })
        });
        let mut untrusted_hash_slice = [0u8; 32];
        untrusted_hash_slice.copy_from_slice(t.untrusted_hash.as_slice());
        witness.set_hash256_target(&target.root, &untrusted_hash_slice);

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
