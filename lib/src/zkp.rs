use crate::{
    keypair_from_bytes, read_proving_key, read_verifying_key, write_circuit_artifacts, CurveVar,
    Fq, PairingEngine, ProjectiveCurve,
};
use anyhow::anyhow;
use ark_ff::Field;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::UniformRand;
use circuits::{
    ark_from_bytes, ark_to_bytes, bytes_to_plaintext_chunks, encryption, plaintext_chunks_to_bytes,
    Ciphertext, EncryptCircuit, PublicKey, SecretKey,
};
use rand::{CryptoRng, Rng, RngCore};
use secp256kfun::{Point, Scalar};
use std::fs;
use std::path::{Path, PathBuf};

pub const PROVING_KEY_FILE: &str = "circuit.zkey";
pub const VERIFYING_KEY_FILE: &str = "verification.key";

#[derive(Clone, Debug)]
pub struct ZkConfig {
    pub data_encryption_dir: PathBuf,
    pub data_encryption_limit: usize,
    pub key_encryption_dir: PathBuf,
}

impl Default for ZkConfig {
    fn default() -> Self {
        let default_build_dir = PathBuf::from("./build");
        Self {
            data_encryption_dir: default_build_dir.join("data_encryption"),
            data_encryption_limit: 100,
            key_encryption_dir: default_build_dir.join("key_encryption"),
        }
    }
}

pub struct ZkEncryption {
    build_dir: PathBuf,
    params: encryption::Parameters<ProjectiveCurve>,
    proving_key: Option<ProvingKey<PairingEngine>>,
    verifying_key: Option<VerifyingKey<PairingEngine>>,
}

impl ZkEncryption {
    pub fn new<P: AsRef<Path>>(
        build_dir: P,
        params: encryption::Parameters<ProjectiveCurve>,
    ) -> Self {
        let proving_key =
            read_proving_key(build_dir.as_ref().join(PROVING_KEY_FILE)).map_or(None, |k| Some(k));
        let verifying_key = proving_key.as_ref().map(|pk| pk.vk.clone());
        Self {
            build_dir: PathBuf::from(build_dir.as_ref()),
            params,
            proving_key,
            verifying_key,
        }
    }

    pub fn new_verifier<P: AsRef<Path>>(
        build_dir: P,
        params: encryption::Parameters<ProjectiveCurve>,
    ) -> Self {
        let verifying_key = read_verifying_key(build_dir.as_ref().join(VERIFYING_KEY_FILE))
            .expect("verification key missing");
        Self {
            build_dir: PathBuf::from(build_dir.as_ref()),
            params,
            proving_key: None,
            verifying_key: Some(verifying_key),
        }
    }

    pub fn encrypt<M: AsRef<[u8]>, R: CryptoRng + RngCore>(
        &self,
        msg: M,
        pk: PublicKey<ProjectiveCurve>,
        mut rng: &mut R,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let mut msg = bytes_to_plaintext_chunks::<ProjectiveCurve, _>(msg.as_ref())
            .map_err(|e| anyhow!("error casting plaintext: {e}"))?;

        let circuit = EncryptCircuit::<ProjectiveCurve, CurveVar>::new(
            pk,
            msg,
            self.params.clone(),
            &mut rng,
        )?;
        let ciphertext = circuit.enc.clone();
        let proving_key = self.proving_key.as_ref().expect("proving key expected");
        let proof = Groth16::<PairingEngine>::prove(proving_key, circuit, &mut rng)
            .map_err(|e| anyhow!("error proving encryption: {e}"))?;

        let ciphertext_encoded = ark_to_bytes(ciphertext.clone())
            .map_err(|e| anyhow!("error encoding ciphertext: {e}"))?;

        let proof_encoded = ark_to_bytes(proof)?;

        Ok((ciphertext_encoded, proof_encoded))
    }

    pub fn decrypt<K: AsRef<[u8]>, B: AsRef<[u8]>>(
        &self,
        sk: K,
        ciphertext: B,
    ) -> anyhow::Result<Vec<u8>> {
        let sk: SecretKey<ProjectiveCurve> =
            ark_from_bytes(sk.as_ref()).map_err(|e| anyhow!("error casting secret key: {e}"))?;
        let ciphertext = ark_from_bytes(ciphertext.as_ref())
            .map_err(|e| anyhow!("error casting ciphertext: {e}"))?;
        let plaintext =
            EncryptCircuit::<ProjectiveCurve, CurveVar>::decrypt(ciphertext, sk, &self.params)?;
        plaintext_chunks_to_bytes::<ProjectiveCurve>(plaintext)
            .map_err(|e| anyhow!("error casting plaintext: {e}"))
    }

    pub fn keygen<R: CryptoRng + RngCore>(
        &self,
        mut rng: &mut R,
    ) -> anyhow::Result<(SecretKey<ProjectiveCurve>, PublicKey<ProjectiveCurve>)> {
        EncryptCircuit::<ProjectiveCurve, CurveVar>::keygen(&mut rng)
    }

    pub fn keygen_derive<R: CryptoRng + RngCore>(
        &self,
        mut rng: &mut R,
    ) -> anyhow::Result<(PublicKey<ProjectiveCurve>, Scalar, Point)> {
        loop {
            let (native_sk, native_pk) = self.keygen(&mut rng)?;

            let sk_bytes = ark_to_bytes(native_sk)
                .map_err(|e| anyhow!("error encoding elgamal secret key: {e}"))?;

            match keypair_from_bytes(sk_bytes) {
                Ok((secp_sk, secp_pk)) => return Ok((native_pk, secp_sk, secp_pk)),
                Err(_) => continue,
            }
        }
    }

    pub fn verify_proof<PB: AsRef<[u8]>, CB: AsRef<[u8]>>(
        &self,
        proof: PB,
        ciphertext: CB,
    ) -> anyhow::Result<bool> {
        let proof = ark_from_bytes(proof)?;
        let ciphertext = ark_from_bytes(ciphertext.as_ref())
            .map_err(|_e| anyhow!("error casting ciphertext"))?;
        let verifying_key = self
            .verifying_key
            .as_ref()
            .expect("verifying key was expected");

        EncryptCircuit::<ProjectiveCurve, CurveVar>::verify_proof::<PairingEngine>(
            verifying_key,
            proof,
            ciphertext,
            &self.params,
        )
    }

    pub fn compile<R: Rng + CryptoRng>(
        &self,
        mut rng: &mut R,
    ) -> anyhow::Result<(ProvingKey<PairingEngine>, VerifyingKey<PairingEngine>)> {
        let pk = ProjectiveCurve::rand(&mut rng);
        let msg = vec![Fq::from_random_bytes(&*vec![]).unwrap()];
        let c = EncryptCircuit::<ProjectiveCurve, CurveVar>::new(
            pk,
            msg,
            self.params.clone(),
            &mut rng,
        )
        .unwrap();
        let (pk, vk) = Groth16::<PairingEngine>::setup(c, &mut rng)
            .map_err(|e| anyhow!("error compiling circuit: {e}"))?;

        fs::create_dir_all(&self.build_dir)
            .map_err(|e| anyhow!("error creating build dir: {e}"))?;
        write_circuit_artifacts(&self.build_dir, &pk, &vk)?;
        Ok((pk, vk))
    }
}
