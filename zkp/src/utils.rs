use crate::{Ciphertext, Parameters, Plaintext};
use anyhow::anyhow;
use ark_ec::group::Group;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, Field, PrimeField};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

pub fn write_artifacts_json<P: AsRef<Path>, E: PairingEngine>(
    path: P,
    pk: ProvingKey<E>,
    vk: VerifyingKey<E>,
) -> anyhow::Result<()> {
    let mut pk_buf = ark_to_bytes(pk).map_err(|e| anyhow!("error encoding proving key"))?;

    let mut vk_buf = ark_to_bytes(vk).map_err(|e| anyhow!("error encoding verifying key"))?;

    fs::write(path.as_ref().join("circuit.pk"), pk_buf)
        .map_err(|e| anyhow!("error writing proving key: {e}"))?;
    fs::write(path.as_ref().join("circuit.vk"), vk_buf)
        .map_err(|e| anyhow!("error writing verifying key: {e}"))?;

    Ok(())
}

pub fn read_proving_key<P: AsRef<Path>, E: PairingEngine>(
    path: P,
) -> anyhow::Result<ProvingKey<E>> {
    let mut buf = fs::read(path.as_ref()).map_err(|e| anyhow!("error reading proving key: {e}"))?;
    ark_from_bytes(buf).map_err(|e| anyhow!("error decoding proving key: {e}"))
}

pub fn read_verifying_key<P: AsRef<Path>, E: PairingEngine>(
    path: P,
) -> anyhow::Result<VerifyingKey<E>> {
    let mut pk_buf =
        fs::read(path.as_ref()).map_err(|e| anyhow!("error reading verifying key: {e}"))?;
    ark_from_bytes(&*pk_buf).map_err(|e| anyhow!("error decoding verifying key: {e}"))
}

pub fn ark_from_bytes<B: AsRef<[u8]>, O: CanonicalDeserialize>(
    bytes: B,
) -> Result<O, SerializationError> {
    O::deserialize(bytes.as_ref())
}

pub fn ark_to_bytes<I: CanonicalSerialize>(f: I) -> Result<Vec<u8>, SerializationError> {
    let mut buf = vec![];
    f.serialize(&mut buf)?;
    Ok(buf)
}

pub fn bytes_to_plaintext_chunks<C: ProjectiveCurve, B: AsRef<[u8]>>(
    bytes: B,
) -> anyhow::Result<Vec<Plaintext<C>>> {
    let mut reader = BufReader::new(bytes.as_ref());

    let mut chunks = vec![];
    loop {
        let mut buf = [0; 32];
        if !matches!(reader.read(&mut buf), Ok(n) if n != 0) {
            break;
        }

        chunks.push(buf);
    }

    let plaintext_chunks: Option<Vec<_>> = chunks
        .into_iter()
        .map(|chunk| C::ScalarField::from_random_bytes(&chunk))
        .collect();

    match plaintext_chunks {
        Some(res) => Ok(res),
        None => Err(anyhow!("failed to cast bytes to scalars")),
    }
}

pub fn plaintext_chunks_to_bytes<C: ProjectiveCurve>(
    chunks: Vec<Plaintext<C>>,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = vec![0; chunks.len() * 32];
    let mut writer = BufWriter::new(&mut *buf);

    for chunk in chunks {
        if let Ok(bytes) = to_bytes!(chunk) {
            let mut bytes = bytes
                .into_iter()
                .rev()
                .skip_while(|&b| b == 0)
                .collect::<Vec<_>>();
            bytes.reverse();
            writer
                .write(&bytes)
                .map_err(|e| anyhow!("error filling buffer: {e}"))?;
        }
    }

    Ok(writer.buffer().to_vec())
}

pub fn ciphertext_to_bytes<C: ProjectiveCurve>(
    ciphertext: Ciphertext<C>,
) -> anyhow::Result<Vec<u8>> {
    let c1_bytes = ark_to_bytes(ciphertext.0.into_affine())
        .map_err(|e| anyhow!("error encoding ciphertext.c1"))?;
    let c2_bytes =
        ark_to_bytes(ciphertext.1).map_err(|e| anyhow!("error encoding ciphertext.c2"))?;

    Ok(c1_bytes
        .into_iter()
        .chain(c2_bytes.into_iter())
        .collect::<Vec<_>>())
}

pub fn ciphertext_from_bytes<C: ProjectiveCurve, B: AsRef<[u8]>>(
    bytes: B,
) -> anyhow::Result<Ciphertext<C>> {
    let mut reader = BufReader::new(bytes.as_ref());
    let mut buf = vec![0; 48];
    reader
        .read(&mut buf)
        .map_err(|e| anyhow!("error reader buffer: {e}"))?;

    let c1: C::Affine = ark_from_bytes(buf).map_err(|e| anyhow!("error decoding ciphertext.c1"))?;

    let mut buf = vec![0; 32];
    reader
        .read(&mut buf)
        .map_err(|e| anyhow!("error reader buffer: {e}"))?;
    let c2: C::ScalarField =
        ark_from_bytes(buf).map_err(|e| anyhow!("error decoding ciphertext.c2"))?;

    Ok((c1.into_projective(), c2))
}

#[cfg(test)]
mod test {
    use crate::{
        ark_from_bytes, ark_to_bytes, bytes_to_plaintext_chunks, ciphertext_from_bytes,
        ciphertext_to_bytes, plaintext_chunks_to_bytes, Ciphertext,
    };
    use ark_bls12_377::{Fr, G1Projective};
    use ark_crypto_primitives::encryption::elgamal::{Plaintext, PublicKey};
    use ark_ec::twisted_edwards_extended::GroupProjective;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ed_on_bls12_381::EdwardsProjective;
    use ark_ff::Field;
    use ark_std::rand::RngCore;
    use ark_std::test_rng;
    use std::io::{BufReader, Read};
    use std::ops::Add;

    const ALICE_SK: &str = "ea734cef7d66a4a51df3fe20f4d6a21f9439cf325e64342234c67cc04db1050a";
    const ALICE_PK: &str = "48657b938074f43846d64b69c5f1dad0ad35775abf3ba38ef7af164572a57d3379e3bb877878ff7a4dc0e05c5a3e4780";

    #[test]
    fn test_public_key_decode() {
        let bytes = hex::decode(ALICE_PK).unwrap();
        let pk: G1Projective = ark_from_bytes(&bytes).unwrap();
    }

    #[test]
    fn test_secret_key_decode() {
        let bytes = hex::decode(ALICE_SK).unwrap();
        let sk: Fr = ark_from_bytes(&bytes).unwrap();
    }

    #[test]
    fn test_small_plaintext_decode() {
        let mut bytes = vec![1, 2, 3];

        let plaintext_chunks = bytes_to_plaintext_chunks::<G1Projective, _>(bytes.clone()).unwrap();

        let res = plaintext_chunks_to_bytes::<G1Projective>(plaintext_chunks).unwrap();
        assert_eq!(bytes, res);
    }

    #[test]
    fn test_large_plaintext_decode() {
        let mut bytes = vec![1; 64];

        let plaintext_chunks = bytes_to_plaintext_chunks::<G1Projective, _>(bytes.clone()).unwrap();
        let res = plaintext_chunks_to_bytes::<G1Projective>(plaintext_chunks).unwrap();

        assert_eq!(bytes, res)
    }

    #[test]
    fn test_ciphertext_decode() {
        let mut rng = test_rng();
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        let c2 = Fr::from_random_bytes(&bytes).unwrap();
        let ciphertext = (G1Projective::prime_subgroup_generator(), c2);

        let cipher = ciphertext_to_bytes(ciphertext).unwrap();
        let decoded = ciphertext_from_bytes::<G1Projective, _>(&cipher).unwrap();

        assert_eq!(ciphertext, decoded)
    }
}
