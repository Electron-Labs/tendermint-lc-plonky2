pub const VP_BITS: usize = 64; // VOTING POWER
pub const SIGNATURE_BITS: usize = 64 * 8;
pub const N_VALIDATORS: usize = 150;
pub const HEADER_VALIDATORS_HASH_PROOF_SIZE: usize = 4;
pub const HEADER_TIME_PROOF_SIZE: usize = 4;
pub const HEADER_NEXT_VALIDATORS_HASH_PROOF_SIZE: usize = 4;
pub const HEADER_CHAIN_ID_PROOF_SIZE: usize = 4;
pub const HEADER_VERSION_PROOF_SIZE: usize = 4;
pub const HEIGHT_BITS: usize = 64;
pub const TIMESTAMP_BITS: usize = 35; // will be able to accomodate for new blocks till the year 3058
pub const TRUSTING_PERIOD: usize = 1209600; // 2 weeks in seconds
                                            // N_SIGNATURE_INDICES => Number of signatures we wanna check for sig verification and 2/3rd majority
pub const N_SIGNATURE_INDICES: usize = 45;
pub const N_INTERSECTION_INDICES: usize = 45;
pub const TOP_N_VALIDATORS_FOR_INTERSECTION: usize = 64; // must be a power of two
pub const TOP_N_SIGNATURES: usize = 64; // must be a power of two
pub const LEB128_GROUP_SIZE: usize = 7;
pub const N_VALIDATORS_LEAVES: usize = N_VALIDATORS;

pub const CHAIN_ID: [bool; 9 * 8] = [
    false, true, true, false, true, true, true, true, false, true, true, true, false, false, true,
    true, false, true, true, false, true, true, false, true, false, true, true, false, true, true,
    true, true, false, true, true, true, false, false, true, true, false, true, true, false, true,
    false, false, true, false, true, true, true, false, false, true, true, false, false, true,
    false, true, true, false, true, false, false, true, true, false, false, false, true,
];
pub const VERSION_BLOCK: [bool; 8] = [false, false, false, false, true, false, true, true];
