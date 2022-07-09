use std::str::FromStr;
use anyhow::anyhow;
use secp256kfun::{g, Point, Scalar};
use secp256kfun::hex::HexError;
use secp256kfun::marker::{Mark, Normal};

pub fn keypair_gen() -> (Scalar, Point) {
    let sk = Scalar::random(&mut rand::thread_rng());
    let pk = g!(sk * G).mark::<Normal>();
    (sk, pk)
}

pub fn keypair_from(hex: &str) -> Result<(Scalar, Point), HexError> {
    let sk = Scalar::from_str(hex)?;
    let pk = g!(sk * G).mark::<Normal>();
    Ok((sk, pk))
}

pub fn encrypt(pk: &Point, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pk = pk.to_bytes();
    ecies::encrypt(&pk, plaintext).map_err(|e| anyhow!("encryption failed: {e}"))
    // todo: do should be a verifiable encryption with ECDH implemented as an `akrworks` circuit
}

pub fn decrypt(sk: &Scalar, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let sk = sk.to_bytes();
    ecies::decrypt(&sk, ciphertext).map_err(|e| anyhow!("decryption failed: {e}"))
}
