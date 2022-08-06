use crate::zk::CircomParams;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const PROVING_KEY_FILE: &str = "circuit.zkey";
pub const VERIFYING_KEY_FILE: &str = "verification.key";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkConfig {
    pub prop_verifier_dir: PathBuf,
    pub data_encryption_dir: PathBuf,
    pub data_encryption_limit: usize,
    pub key_encryption_dir: PathBuf,
    pub circom_params: CircomParams,
}

// impl Default for ZkConfig {
//     fn default() -> Self {
//         let default_build_dir = PathBuf::from("./build");
//         Self {
//             prop_verifier_dir: default_build_dir.join("data_encryption"),
//             data_encryption_limit: 100,
//             key_encryption_dir: default_build_dir.join("key_encryption"),
//             circom_params: CircomParams {
//                 plaintext_field_name: "plaintext".to_string(),
//                 wasm_path: PathBuf::from("./circom/build/dummy.r1cs"),
//                 r1cs_path: PathBuf::from("./circom/build/dummy_js/dummy.wasm"),
//             },
//         }
//     }
// }
