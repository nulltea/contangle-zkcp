mod encryption;
mod parameters;
mod utils;

pub use crate::encryption::*;
pub use crate::utils::*;
pub use parameters::*;

pub use ark_bls12_381::Bls12_381;
pub use ark_ed_on_bls12_381::{
    constraints::EdwardsVar, EdwardsParameters, EdwardsProjective as JubJub,
};

pub use ark_crypto_primitives::encryption::elgamal::{PublicKey, SecretKey};
use ark_ec::TEModelParameters;
pub use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ed_on_bls12_381::EdwardsAffine;
pub use ark_groth16::{Proof, ProvingKey, VerifyingKey};

pub type Encryption = EncryptCircuit<JubJub, EdwardsVar>;
