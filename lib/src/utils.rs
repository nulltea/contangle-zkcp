use anyhow::anyhow;
use bip39::{Language, Mnemonic};
use ethers::prelude::coins_bip39::English;
use ethers::prelude::MnemonicBuilder;
use secp256kfun::hex::HexError;
use secp256kfun::marker::{Mark, NonZero, Normal};
use secp256kfun::{g, Point, Scalar, G};
use std::fs;
use std::path::Path;
use std::str::FromStr;

pub fn keypair_gen() -> (Scalar, Point) {
    let sk = Scalar::random(&mut rand::thread_rng());
    let pk = g!(sk * G).mark::<Normal>();
    (sk, pk)
}

pub fn keypair_from_hex(hex: &str) -> anyhow::Result<(Scalar, Point)> {
    let sk = Scalar::from_str(hex).map_err(|e| anyhow!("error parsing hex: {e}"))?;
    let pk = g!(sk * G).mark::<Normal>();
    Ok((sk, pk))
}

pub fn keypair_from_bip39(phrase: &str) -> anyhow::Result<(Scalar, Point)> {
    let sk_bytes = MnemonicBuilder::<English>::default()
        .phrase(phrase)
        .build()
        .map_err(|e| anyhow!("error parsing mnemonic: {e}"))?
        .signer()
        .to_bytes();
    let sk = Scalar::from_slice(sk_bytes.as_slice())
        .unwrap()
        .mark::<NonZero>()
        .unwrap();
    let pk = g!(sk * G).mark::<Normal>();
    Ok((sk, pk))
}

pub fn write_to_keystore<D: AsRef<Path>, S: AsRef<str>, P: AsRef<[u8]>>(
    sk: Scalar,
    dir: D,
    name: S,
    password: P,
) -> anyhow::Result<()> {
    let _ = fs::create_dir_all(&dir);
    eth_keystore::encrypt_key(
        dir,
        &mut rand::thread_rng(),
        &sk.to_bytes(),
        password,
        Some(name.as_ref()),
    )
    .map_err(|e| anyhow!("error encrypting key: {e}"))
    .map(|_| ())
}

pub fn read_from_keystore<P: AsRef<Path>, S: AsRef<[u8]>>(
    path: P,
    password: S,
) -> anyhow::Result<(Scalar, Point)> {
    let sk_bytes = eth_keystore::decrypt_key(path, password)
        .map_err(|e| anyhow!("error decrypting key: {e}"))?;
    let sk = Scalar::from_slice(sk_bytes.as_slice())
        .unwrap()
        .mark::<NonZero>()
        .unwrap();
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
