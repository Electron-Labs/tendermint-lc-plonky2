#[cfg(test)]
mod tests {
    use crate::config_data::*;
    use crate::merkle_targets::{
        bytes_to_bool, get_formatted_hash_256_bools, get_sha_block_target, hash256_to_bool_targets,
        merkle_1_block_leaf_root, SHA_BLOCK_BITS,
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

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    use crate::config_data::*;
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
        // connect signature indexes
        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indexes[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        // connect untrusted validators
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
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
        // connect untrusted validators
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
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
        // connect untrusted validators
        (0..cc.N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
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

        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.trusted_next_validator_pub_keys[i][j],
                    data.trusted_next_validator_pub_keys[i][j],
                )
            })
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_next_validator_vp[i],
                &BigUint::from_u64(data.trusted_next_validator_vp[i]).unwrap(),
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
    }

    #[test]
    fn test_sufficient_border_trusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let mut witness = PartialWitness::new();

        let target = add_virtual_trusted_quorum_target(&mut builder, cc);

        let mut data = get_test_data();

        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.trusted_next_validator_pub_keys[i][j],
                    data.trusted_next_validator_pub_keys[i][j],
                )
            })
        });

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_next_validator_vp[i],
                &BigUint::from_u64(data.trusted_next_validator_vp[i]).unwrap(),
            )
        });

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        // first find the index where 3 * one_third > total in
        // trusted_next_intersect_indices

        let mut total = 0;
        for i in data.trusted_next_validator_vp.clone() {
            total += i;
        }

        let mut one_third = 0;
        let mut idx = 0;

        for i in 0..data.trusted_next_intersect_indices.clone().len() {
            one_third += data.trusted_next_validator_vp.clone()
                [data.trusted_next_intersect_indices.clone()[i] as usize];
            if 3 * one_third > total {
                idx = i;
                break;
            }
        }

        // so at idx the condition should be statisfied
        // meaning if we give correct indices till idx
        // the condition should still pass

        let mut trusted_next_intersect_indices = data.trusted_next_intersect_indices.clone();
        let mut untrusted_intersect_indices = data.untrusted_intersect_indices.clone();

        (idx + 1..cc.N_INTERSECTION_INDICES).for_each(|i| {
            trusted_next_intersect_indices[i] = 63;
            untrusted_intersect_indices[i] = 63;
        });

        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.untrusted_intersect_indices[i],
                F::from_canonical_u8(untrusted_intersect_indices[i]),
            )
        });
        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.trusted_next_intersect_indices[i],
                F::from_canonical_u8(trusted_next_intersect_indices[i]),
            )
        });
        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_insufficient_trusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let mut witness = PartialWitness::new();

        let target = add_virtual_trusted_quorum_target(&mut builder, cc);

        let mut data = get_test_data();

        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.trusted_next_validator_pub_keys[i][j],
                    data.trusted_next_validator_pub_keys[i][j],
                )
            })
        });

        // Voting power of intersection is less than 1/3rd of total voting power
        // in trusted_next_validators

        let mut trusted_vp = data.trusted_next_validator_vp.clone();
        (1..45).for_each(|i| {
            trusted_vp[i] = 0;
        });

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_next_validator_vp[i],
                &BigUint::from_u64(trusted_vp[i]).unwrap(),
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
    #[should_panic]
    fn test_null_count_indices_votes_trusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let mut witness = PartialWitness::new();

        let target = add_virtual_trusted_quorum_target(&mut builder, cc);

        let mut data = get_test_data();

        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.trusted_next_validator_pub_keys[i][j],
                    data.trusted_next_validator_pub_keys[i][j],
                )
            })
        });
        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_next_validator_vp[i],
                &BigUint::from_u64(data.trusted_next_validator_vp[i]).unwrap(),
            )
        });

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });

        let mut trusted_next_intersect_indices = data.trusted_next_intersect_indices.clone();
        let mut untrusted_intersect_indices = data.untrusted_intersect_indices.clone();

        (1..cc.N_INTERSECTION_INDICES).for_each(|i| {
            trusted_next_intersect_indices[i] = 63;
            untrusted_intersect_indices[i] = 63;
        });

        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.untrusted_intersect_indices[i],
                F::from_canonical_u8(untrusted_intersect_indices[i]),
            )
        });
        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.trusted_next_intersect_indices[i],
                F::from_canonical_u8(trusted_next_intersect_indices[i]),
            )
        });
        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_insufficient_border_trusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let cc = load_chain_config();

        let mut witness = PartialWitness::new();

        let target = add_virtual_trusted_quorum_target(&mut builder, cc);

        let mut data = get_test_data();

        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..get_n_validator_targets_for_intersection(cc)).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.trusted_next_validator_pub_keys[i][j],
                    data.trusted_next_validator_pub_keys[i][j],
                )
            })
        });

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_next_validator_vp[i],
                &BigUint::from_u64(data.trusted_next_validator_vp[i]).unwrap(),
            )
        });

        (0..cc.N_SIGNATURE_INDICES).for_each(|i| {
            witness.set_target(
                target.signature_indices[i],
                F::from_canonical_u8(data.signature_indices[i]),
            )
        });
        // first find the index where 3 * one_third > total in
        // trusted_next_intersect_indices

        let mut total = 0;
        for i in data.trusted_next_validator_vp.clone() {
            total += i;
        }

        let mut one_third = 0;
        let mut idx = 0;

        for i in 0..data.trusted_next_intersect_indices.clone().len() {
            one_third += data.trusted_next_validator_vp.clone()
                [data.trusted_next_intersect_indices.clone()[i] as usize];
            if 3 * one_third > total {
                idx = i;
                break;
            }
        }

        // so at idx - 1  should not satisfy the 1/3 rd condition
        // meaning if we give incorrect indices after idx - 1
        // the condition should fail

        let mut trusted_next_intersect_indices = data.trusted_next_intersect_indices.clone();
        let mut untrusted_intersect_indices = data.untrusted_intersect_indices.clone();

        (idx..cc.N_INTERSECTION_INDICES).for_each(|i| {
            trusted_next_intersect_indices[i] = 63;
            untrusted_intersect_indices[i] = 63;
        });

        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.untrusted_intersect_indices[i],
                F::from_canonical_u8(untrusted_intersect_indices[i]),
            )
        });
        (0..cc.N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.trusted_next_intersect_indices[i],
                F::from_canonical_u8(trusted_next_intersect_indices[i]),
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

        (0..cc.N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.untrusted_validator_vp[i],
                &BigUint::from_u64(data.untrusted_validator_vp[i]).unwrap(),
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
