#[cfg(test)]
mod tests {
    use crate::constants::*;
    use crate::merkle_targets::{
        bool_to_bytes, bytes_to_bool, get_256_bool_target, get_sha_2block_target,
        get_sha_block_target, merkle_1_block_leaf_root, SHA_BLOCK_BITS,
    };
    use crate::targets::{
        add_virtual_connect_pub_keys_votes_target, add_virtual_connect_sign_message_target,
        add_virtual_connect_sign_message_target_new, add_virtual_connect_timestamp_target,
        add_virtual_trusted_quorum_target, add_virtual_untrusted_quorum_target,
        add_virtual_update_validity_target, is_not_null_signature, validators_hash_target,
        UpdateValidityTarget,
    };
    use crate::test_utils::*;
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
            config::{GenericConfig, PoseidonBn254GoldilocksConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_crypto::biguint::WitnessBigUint;

    const D: usize = 2;
    type C = PoseidonBn254GoldilocksConfig;
    // type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    // TODO: load all test data only once

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
        untrusted_version_block_padded: Vec<bool>,
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
                target.untrusted_version_block_padded[i],
                untrusted_version_block_padded[i],
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

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        set_update_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_block_padded,
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

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();
        set_update_validity_target(
            &mut witness,
            12975357,
            12975356,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_block_padded,
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

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();
        set_update_validity_target(
            &mut witness,
            12975357,
            12975357,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_block_padded,
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

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let untrusted_timestamp = data.trusted_timestamp + TRUSTING_PERIOD as u64 + 1;

        set_update_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            untrusted_timestamp,
            data.trusted_timestamp,
            data.untrusted_version_block_padded,
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

        let target = add_virtual_update_validity_target(&mut builder);

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
            data.untrusted_version_block_padded,
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

        let target = add_virtual_update_validity_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_version_block_padded = data.untrusted_version_block_padded;
        untrusted_version_block_padded[18] = true;

        set_update_validity_target(
            &mut witness,
            data.untrusted_height,
            data.trusted_height,
            data.untrusted_timestamp,
            data.trusted_timestamp,
            untrusted_version_block_padded,
            data.untrusted_chain_id_padded,
            &target,
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_sign_message() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_sign_message_target(&mut builder);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..SIGN_MESSAGE_BITS)
            .for_each(|i| witness.set_bool_target(target.message[i], data.sign_message[i]));
        (0..256)
            .for_each(|i| witness.set_bool_target(target.header_hash[i], data.untrusted_hash[i]));
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_sign_message_wrong_hash() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_sign_message_target(&mut builder);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..SIGN_MESSAGE_BITS)
            .for_each(|i| witness.set_bool_target(target.message[i], data.sign_message[i]));
        let mut hash = data.untrusted_hash;
        hash[0] = true;

        (0..256).for_each(|i| witness.set_bool_target(target.header_hash[i], hash[i]));
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    #[should_panic]
    fn test_connect_sign_message_wrong_height() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_sign_message_target(&mut builder);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..SIGN_MESSAGE_BITS)
            .for_each(|i| witness.set_bool_target(target.message[i], data.sign_message[i]));
        let mut height = data.untrusted_height;
        height += 1;

        (0..256)
            .for_each(|i| witness.set_bool_target(target.header_hash[i], data.untrusted_hash[i]));
        witness.set_biguint_target(&target.height, &BigUint::from_u64(height).unwrap());

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_connect_timestamp() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_timestamp_target(&mut builder);

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

        let target = add_virtual_connect_timestamp_target(&mut builder);

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
    fn test_connect_pub_keys_votes() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_pub_keys_votes_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        (0..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.votes[i],
                &BigUint::from_u64(data.untrusted_validator_votes[i]).unwrap(),
            )
        });
        (0..N_VALIDATORS).for_each(|i| {
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
    fn test_connect_pub_keys_votes_invalid_pubkey() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_pub_keys_votes_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_validator_pub_keys = data.untrusted_validator_pub_keys;
        untrusted_validator_pub_keys[3][3] = false;

        (0..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(target.pub_keys[i][j], untrusted_validator_pub_keys[i][j])
            })
        });
        (0..N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.votes[i],
                &BigUint::from_u64(data.untrusted_validator_votes[i]).unwrap(),
            )
        });
        (0..N_VALIDATORS).for_each(|i| {
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
    fn test_connect_pub_keys_votes_invalid_vote() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_pub_keys_votes_target(&mut builder);

        let mut witness = PartialWitness::new();

        let data = get_test_data();

        let mut untrusted_validator_votes = data.untrusted_validator_votes;
        untrusted_validator_votes[3] = 14141431 + 1;

        (0..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.votes[i],
                &BigUint::from_u64(untrusted_validator_votes[i]).unwrap(),
            )
        });
        (0..N_VALIDATORS).for_each(|i| {
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
    fn test_is_not_null_signature() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let mut signatures_target = vec![(0..SIGNATURE_BITS)
            .map(|_| builder._false())
            .collect::<Vec<BoolTarget>>()];
        let mut temp = vec![builder._true()];
        (0..SIGNATURE_BITS - 1).for_each(|_| temp.push(builder._false()));
        signatures_target.push(temp);

        let is_not_null_signature = is_not_null_signature(&mut builder, signatures_target);
        let one = builder._true();
        let zero = builder._false();
        builder.connect(is_not_null_signature[0].target, zero.target);
        builder.connect(is_not_null_signature[1].target, one.target);

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    // TODO: add negative tests
    #[test]
    fn test_sufficient_trusted_quorum_target() {
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut witness = PartialWitness::new();

        let target = add_virtual_trusted_quorum_target(&mut builder);

        let data = get_test_data();

        (0..N_VALIDATORS_FOR_INTERSECTION).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.untrusted_validator_pub_keys[i][j],
                    data.untrusted_validator_pub_keys[i][j],
                )
            })
        });
        (0..N_VALIDATORS_FOR_INTERSECTION).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(
                    target.trusted_next_validator_pub_keys[i][j],
                    data.trusted_next_validator_pub_keys[i][j],
                )
            })
        });
        (0..N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.trusted_next_validator_votes[i],
                &BigUint::from_u64(data.trusted_next_validator_votes[i]).unwrap(),
            )
        });

        let signatures_target = (0..N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        (0..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(signatures_target[i][j], data.signatures[i][j]);
            })
        });
        let is_not_null_signature = is_not_null_signature(&mut builder, signatures_target);
        (0..N_VALIDATORS).for_each(|i| {
            builder.connect(
                target.is_not_null_signature[i].target,
                is_not_null_signature[i].target,
            )
        });

        (0..N_INTERSECTION_INDICES).for_each(|i| {
            witness.set_target(
                target.untrusted_intersect_indices[i],
                F::from_canonical_u8(data.untrusted_intersect_indices[i]),
            )
        });
        (0..N_INTERSECTION_INDICES).for_each(|i| {
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

        let mut witness = PartialWitness::new();

        let target = add_virtual_untrusted_quorum_target(&mut builder);

        let data = get_test_data();

        (0..N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.untrusted_validator_votes[i],
                &BigUint::from_u64(data.untrusted_validator_votes[i]).unwrap(),
            )
        });
        let signatures_target = (0..N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        (0..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(signatures_target[i][j], data.signatures[i][j]);
            })
        });
        let is_not_null_signature = is_not_null_signature(&mut builder, signatures_target);
        (0..N_VALIDATORS).for_each(|i| {
            builder.connect(
                target.is_not_null_signature[i].target,
                is_not_null_signature[i].target,
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

        let mut witness = PartialWitness::new();

        let target = add_virtual_untrusted_quorum_target(&mut builder);

        let data = get_test_data();

        (0..N_VALIDATORS).for_each(|i| {
            witness.set_biguint_target(
                &target.untrusted_validator_votes[i],
                &BigUint::from_u64(data.untrusted_validator_votes[i]).unwrap(),
            )
        });

        let signatures_target = (0..N_VALIDATORS)
            .map(|_| get_256_bool_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();
        // set first 10 signatures to null
        (0..10).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(signatures_target[i][j], false);
            })
        });
        (10..N_VALIDATORS).for_each(|i| {
            (0..256).for_each(|j| {
                witness.set_bool_target(signatures_target[i][j], data.signatures[i][j]);
            })
        });
        let is_not_null_signature = is_not_null_signature(&mut builder, signatures_target);
        (0..N_VALIDATORS).for_each(|i| {
            builder.connect(
                target.is_not_null_signature[i].target,
                is_not_null_signature[i].target,
            )
        });

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    // TODO:
    #[test]
    fn test_connect_sign_message_new() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let target = add_virtual_connect_sign_message_target_new(&mut builder);

        let data = get_test_data();

        let mut witness = PartialWitness::new();

        (0..N_VALIDATORS).for_each(|i| {
            (0..SHA_BLOCK_BITS * 2).for_each(|j| {
                witness.set_bool_target(
                    target.messages_padded[i][j],
                    data.sign_messages_padded[i][j],
                )
            })
        });
        (0..256)
            .for_each(|i| witness.set_bool_target(target.header_hash[i], data.untrusted_hash[i]));
        witness.set_biguint_target(
            &target.height,
            &BigUint::from_u64(data.untrusted_height).unwrap(),
        );

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }

    #[test]
    fn test_validators_hash() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // TODO: use it from testdata
        let data_str =
            std::fs::read_to_string(format!("src/test_data/untrusted_validator_leaves.json"))
                .unwrap();
        let data: Validators = serde_json::from_str(&data_str).unwrap();
        let validator_leaves = data.leaves;
        let mut validator_leaves_bytes: Vec<Vec<u8>> = vec![];
        validator_leaves
            .iter()
            .for_each(|elm| validator_leaves_bytes.push(bool_to_bytes(elm.clone())));
        let validator_leaves_padded = validator_leaves
            .iter()
            .map(|elm| get_sha_block_for_leaf(elm.clone()))
            .collect::<Vec<Vec<bool>>>();

        let mut witness = PartialWitness::new();

        let validator_leaves_padded_target = (0..N_VALIDATORS)
            .map(|_| get_sha_block_target(&mut builder))
            .collect::<Vec<Vec<BoolTarget>>>();

        (0..N_VALIDATORS_LEAVES).for_each(|i| {
            (0..SHA_BLOCK_BITS).for_each(|j| {
                witness.set_bool_target(
                    validator_leaves_padded_target[i][j],
                    validator_leaves_padded[i][j],
                )
            })
        });

        let hash = validators_hash_target(
            &mut builder,
            &mut witness,
            validator_leaves_padded_target,
            validator_leaves_bytes,
        );

        let expected = [
            true, true, true, false, true, false, false, false, false, true, false, true, true,
            false, false, true, true, true, true, false, false, true, true, false, false, true,
            false, false, true, true, false, true, false, true, false, true, false, true, true,
            false, false, true, true, true, false, false, true, false, false, true, false, false,
            true, true, false, false, false, true, true, true, true, false, true, false, true,
            true, true, false, false, false, false, false, false, true, true, false, false, false,
            false, true, true, false, true, false, true, false, true, false, false, true, false,
            false, true, true, false, false, false, false, true, false, true, false, true, true,
            false, true, true, true, false, true, true, true, false, false, false, true, true,
            true, true, false, true, false, true, true, false, true, true, true, false, true,
            false, true, true, true, false, false, true, false, false, true, true, false, false,
            false, true, false, true, true, false, true, true, true, true, false, true, true, true,
            true, true, false, false, false, true, false, true, true, false, false, true, true,
            true, false, false, false, false, true, false, false, false, false, true, false, false,
            false, false, false, false, false, false, true, true, true, true, true, true, false,
            true, true, false, true, false, false, true, false, false, false, false, false, true,
            false, false, false, false, true, false, false, true, true, true, true, false, true,
            false, true, false, false, false, false, false, true, true, true, false, true, true,
            false, true, true, false, false, true, false, false, false, true, true, false, true,
            true, true, true, true, true, true, false, false,
        ];
        let expected_target = get_256_bool_target(&mut builder);
        (0..256).for_each(|i| witness.set_bool_target(expected_target[i], expected[i]));

        (0..256).for_each(|i| builder.connect(hash[i].target, expected_target[i].target));

        let data = builder.build::<C>();
        prove_and_verify(data, witness);
    }
}
