use crate::{JubJub, JUB_JUB_PARAMETERS};
use anyhow::anyhow;
use ark_crypto_primitives::encryption::elgamal::{Ciphertext, Parameters, Plaintext};
use ark_ec::group::Group;
use ark_ec::twisted_edwards_extended::GroupAffine;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ed_on_bls12_381::EdwardsParameters;
use ark_ff::{Field, PrimeField};
use ark_groth16::{Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use std::fs;
use std::io::{BufReader, BufWriter, Read};
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

pub fn bytes_to_plaintext_chunks<B: AsRef<[u8]>>(
    bytes: B,
) -> anyhow::Result<Vec<Plaintext<JubJub>>> {
    let mut reader = BufReader::new(bytes.as_ref());

    let mut chunks = vec![];
    loop {
        let mut buf = [1; 32];
        if !matches!(reader.read(&mut buf), Ok(n) if n != 0) {
            break;
        }

        chunks.push(buf);
    }

    let plaintext_chunks: Option<Vec<_>> = chunks
        .into_iter()
        .map(|chunk| {
            <JubJub as ProjectiveCurve>::ScalarField::from_random_bytes(&chunk).map(|s| {
                <GroupAffine<EdwardsParameters> as AffineCurve>::mul(
                    &JUB_JUB_PARAMETERS.generator.into(),
                    s,
                )
                .into_affine()
            })
        })
        .collect();

    match plaintext_chunks {
        Some(res) => Ok(res),
        None => Err(anyhow!("failed to cast bytes to affine points")),
    }
}

pub fn plaintext_chunks_to_bytes(chunks: Vec<Plaintext<JubJub>>) -> anyhow::Result<Vec<u8>> {
    // let buf = vec![0; chunks.len() * 32];
    // let mut reader = BufWriter::new(&*buf);

    let g = JUB_JUB_PARAMETERS.generator.clone();
    let g_inv = -g;

    for chunk in chunks {
        // let x = <GroupAffine<EdwardsParameters> as AffineCurve>::mul(&chunk, g_inv);
        // todo: [affine * g_inv = scalar] is this possible?
    }

    Ok(vec![])
}

#[cfg(test)]
mod test {
    use crate::{
        ark_from_bytes, bytes_to_plaintext_chunks, plaintext_chunks_to_bytes, JubJub,
        JUB_JUB_PARAMETERS,
    };
    use ark_crypto_primitives::encryption::elgamal::{Plaintext, PublicKey};
    use ark_ec::twisted_edwards_extended::GroupProjective;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ed_on_bls12_381::EdwardsProjective;
    use ark_ff::Field;
    use std::io::{BufReader, Read};
    use std::ops::Add;

    const ALICE_SK: &str = "ea734cef7d66a4a51df3fe20f4d6a21f9439cf325e64342234c67cc04db1050a";
    const ALICE_PK: &str = "49868e1b8895a1697c670167672f11580fcacdddd264a4c87bd2a48298ccd30b";

    #[test]
    fn test_public_key_decode() {
        let bytes = hex::decode(ALICE_PK).unwrap();
        let pk: <JubJub as ProjectiveCurve>::Affine = ark_from_bytes(&bytes).unwrap();
    }

    #[test]
    fn test_secret_key_decode() {
        let bytes = hex::decode(ALICE_SK).unwrap();
        let sk: <JubJub as ProjectiveCurve>::ScalarField = ark_from_bytes(&bytes).unwrap();
    }

    #[test]
    fn test_small_plaintext_decode() {
        let mut bytes = vec![1, 2, 3];

        let plaintext_chunks = bytes_to_plaintext_chunks(bytes).unwrap();

        println!("{:?}", plaintext_chunks_to_bytes(plaintext_chunks));
    }

    #[test]
    fn test_large_plaintext_decode() {
        let mut bytes = vec![1; 64];

        let plaintext_chunks = bytes_to_plaintext_chunks(bytes).unwrap();

        println!("{:?}", plaintext_chunks);
    }
}
