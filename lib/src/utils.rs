use anyhow::anyhow;

use ethers::prelude::coins_bip39::English;
use ethers::prelude::MnemonicBuilder;

use crate::{PROVING_KEY_FILE, VERIFYING_KEY_FILE};
use ark_ec::PairingEngine;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use circuits::{ark_from_bytes, ark_to_bytes};
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

pub fn keypair_from_bytes<B: AsRef<[u8]>>(buf: B) -> anyhow::Result<(Scalar, Point)> {
    match Scalar::from_slice(buf.as_ref()).map(|s| s.mark::<NonZero>()) {
        Some(Some(sk)) => {
            let sk = sk;
            let pk = g!(sk * G).mark::<Normal>();
            Ok((sk, pk))
        }
        _ => Err(anyhow!("failed to decoding secp256k1 key from bytes")),
    }
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

pub fn write_circuit_artifacts<P: AsRef<Path>, E: PairingEngine>(
    path: P,
    pk: &ProvingKey<E>,
    vk: &VerifyingKey<E>,
) -> anyhow::Result<()> {
    let mut pk_buf = vec![];
    pk.serialize_unchecked(&mut pk_buf)
        .map_err(|e| anyhow!("error encoding proving key"))?;

    let mut vk_buf =
        ark_to_bytes(vk.clone()).map_err(|e| anyhow!("error encoding verifying key"))?;

    fs::write(path.as_ref().join(PROVING_KEY_FILE), pk_buf)
        .map_err(|e| anyhow!("error writing proving key: {e}"))?;
    fs::write(path.as_ref().join(VERIFYING_KEY_FILE), vk_buf)
        .map_err(|e| anyhow!("error writing verifying key: {e}"))?;

    Ok(())
}

pub fn read_proving_key<P: AsRef<Path>, E: PairingEngine>(
    path: P,
) -> anyhow::Result<ProvingKey<E>> {
    let mut buf = fs::read(path.as_ref()).map_err(|e| anyhow!("error reading proving key: {e}"))?;
    ProvingKey::<E>::deserialize_unchecked(&*buf)
        .map_err(|e| anyhow!("error decoding proving key: {e}"))
}

pub fn read_verifying_key<P: AsRef<Path>, E: PairingEngine>(
    path: P,
) -> anyhow::Result<VerifyingKey<E>> {
    let mut pk_buf =
        fs::read(path.as_ref()).map_err(|e| anyhow!("error reading verifying key: {e}"))?;
    ark_from_bytes(&*pk_buf).map_err(|e| anyhow!("error decoding verifying key: {e}"))
}

#[cfg(test)]
mod test {
    use crate::keypair_from_hex;

    #[test]
    fn test_keypair_from_hex() {
        let (sk, pk) =
            keypair_from_hex(&"ea734cef7d66a4a51df3fe20f4d6a21f9439cf325e64342234c67cc04db1050a")
                .unwrap();

        println!("sk: {}", hex::encode(sk.to_bytes()));
        println!("pk: {}", hex::encode(pk.to_bytes()));
    }
}
