use std::{fs, marker::PhantomData, time::Instant};

use plonky2::{field::extension::Extendable, hash::hash_types::RichField, plonk::{circuit_data::{CircuitData, CommonCircuitData, ProverOnlyCircuitData, VerifierOnlyCircuitData}, config::{AlgebraicHasher, GenericConfig, Hasher}}};
use serde::{Deserialize, Serialize};

use crate::serializer::{CustomGateSerializer, CustomGeneratorSerializer};

#[derive(Serialize, Deserialize)]
struct Data {
    bytes: Vec<u8>
}

pub fn dump_bytes_to_json(bytes: Vec<u8>, json_path: &str) {
    // Serialize Vec<u8> to json
    let serialized_data = serde_json::to_string(&Data { bytes: bytes.clone() })
        .expect("Failed to serialize data");
    // Write json to file
    fs::write(json_path, serialized_data).expect("Failed to write to file");
}

pub fn read_bytes_from_json(json_path: &str) -> Vec<u8> {
    // Read json data
    let json_data = fs::read_to_string(json_path).expect("Failed to read from file");
    // Deserialize json back to Vec<u8>
    let deserialized_data: Data = serde_json::from_str(&json_data).expect("Failed to deserialize data");
    deserialized_data.bytes
}

pub fn dump_circuit_data<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + 'static, const D: usize> (
    data: &CircuitData<F, C, D>,
    storage_dir: &str
)
where
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>, 
{
    let cd_bytes = data.common.clone().to_bytes(&CustomGateSerializer).unwrap();
    dump_bytes_to_json(cd_bytes, format!("{storage_dir}/circuit_data/common_data.json").as_str());
    let prover_only_bytes = data.prover_only.to_bytes(&CustomGeneratorSerializer::<C, D> {_phantom: PhantomData::<C>}, &data.common).unwrap();
    dump_bytes_to_json(prover_only_bytes, format!("{storage_dir}/circuit_data/prover_only.json").as_str());
    let verifier_only_bytes = data.verifier_only.to_bytes().unwrap();
    dump_bytes_to_json(verifier_only_bytes, format!("{storage_dir}/circuit_data/verifier_only.json").as_str());
}

pub fn load_circuit_dat_from_dir<F: RichField + Extendable<D>, C: GenericConfig<D, F=F> + 'static, const D: usize> (
    storage_dir: &str
) -> CircuitData<F, C, D>
where
    [(); C::Hasher::HASH_SIZE]:, <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>
{
    println!("Reconstructing common data");
    let t_cd = Instant::now();
    let cd_bytes = read_bytes_from_json(format!("{storage_dir}/circuit_data/common_data.json").as_str());
    let common_data = CommonCircuitData::<F, D>::from_bytes(cd_bytes, &CustomGateSerializer).unwrap();
    println!("Common data reconstructed in {:?}", t_cd.elapsed());

    println!("Reconstructing prover only data");
    let t_po = Instant::now();
    let prover_only_bytes = read_bytes_from_json(format!("{storage_dir}/circuit_data/prover_only.json").as_str());
    let prover_only = ProverOnlyCircuitData::<F, C, D>::from_bytes(
        prover_only_bytes.as_slice(),
        &CustomGeneratorSerializer::<C, D> {_phantom: PhantomData::<C>},
        &common_data
    ).unwrap();
    println!("Prover only data reconstructed in {:?}", t_po.elapsed());    

    println!("Reconstructing verifier only data");
    let t_vo = Instant::now();
    let verifier_only_bytes = read_bytes_from_json(format!("{storage_dir}/circuit_data/verifier_only.json").as_str());
    let verifier_only = VerifierOnlyCircuitData::<C, D>::from_bytes(verifier_only_bytes).unwrap();
    println!("Verifier only data reconstructed in {:?}", t_vo.elapsed());

    CircuitData::<F, C, D> {
        prover_only,
        verifier_only,
        common: common_data,
    }
}