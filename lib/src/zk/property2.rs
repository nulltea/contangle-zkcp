use crate::zk::traits::PropertyVerifier;
use crate::zk::ZkEncryption;
use crate::{
    read_proving_key, read_verifying_key, write_circuit_artifacts, CurveVar, PairingEngine,
    ProjectiveCurve, PROVING_KEY_FILE, VERIFYING_KEY_FILE,
};
use anyhow::anyhow;
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use circuits::{
    ark_from_bytes, ark_to_bytes, bytes_to_plaintext_chunks, bytes_to_plaintext_chunks_direct,
    bytes_to_plaintext_chunks_fixed_size, encryption, CircomWrapper, EncryptCircuit, PublicKey,
    SecretKey,
};
use num_bigint::BigInt;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub struct ZkPropertyVerifier2<PV: PropertyVerifier> {
    build_dir: PathBuf,
    encryption: ZkEncryption,
    verifier: PV,
    proving_key: Option<ProvingKey<PairingEngine>>,
    verifying_key: Option<VerifyingKey<PairingEngine>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiableEncryption {
    pub ciphertext: Vec<u8>,
    pub proof_of_encryption: Vec<u8>,
    pub proofs_of_property: Vec<ProofOfProperty>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfProperty {
    pub proof: Vec<u8>,
    pub arguments: Vec<(String, Vec<u8>)>,
}

impl<PV: PropertyVerifier> ZkPropertyVerifier2<PV> {
    pub fn new<P: AsRef<Path>>(
        build_dir: P,
        verifier: PV,
        enc_params: encryption::Parameters<ProjectiveCurve>,
    ) -> Self {
        let proving_key =
            read_proving_key(build_dir.as_ref().join(PROVING_KEY_FILE)).map_or(None, |k| Some(k));
        let verifying_key = proving_key.as_ref().map(|pk| pk.vk.clone());

        Self {
            build_dir: PathBuf::from(build_dir.as_ref()),
            encryption: ZkEncryption::new_inner(enc_params),
            verifier,
            proving_key,
            verifying_key,
        }
    }

    pub fn new_verifier<P: AsRef<Path>>(
        build_dir: P,
        verifier: PV,
        enc_params: encryption::Parameters<ProjectiveCurve>,
    ) -> Self {
        let verifying_key = read_verifying_key(build_dir.as_ref().join(VERIFYING_KEY_FILE))
            .expect("verification key missing");

        Self {
            build_dir: PathBuf::from(build_dir.as_ref()),
            encryption: ZkEncryption::new_inner(enc_params),
            verifier,
            proving_key: None,
            verifying_key: Some(verifying_key),
        }
    }

    pub fn assess_property_and_encrypt<M: AsRef<[u8]>, R: CryptoRng + RngCore>(
        &self,
        msg: M,
        sk: SecretKey<ProjectiveCurve>,
        pk: PublicKey<ProjectiveCurve>,
        mut rng: &mut R,
    ) -> anyhow::Result<VerifiableEncryption> {
        let mut msg = bytes_to_plaintext_chunks_direct::<ProjectiveCurve, _>(
            msg.as_ref(),
            self.encryption.params.n,
        )
        .map_err(|e| anyhow!("error casting plaintext: {e}"))?;

        let mut proofs_of_property = self.verifier.assess_plaintext(msg.clone(), &mut rng)?;

        let enc_circuit = self.encryption.build_circuit(msg, pk, &mut rng)?;

        let ciphertext = enc_circuit.resulted_ciphertext.clone();
        let proving_key = self.proving_key.as_ref().expect("proving key expected");

        let proof = Groth16::<PairingEngine>::prove(proving_key, enc_circuit, &mut rng)
            .map_err(|e| anyhow!("error proving encryption: {e}"))?;

        let ciphertext_encoded = ark_to_bytes(ciphertext.clone())
            .map_err(|e| anyhow!("error encoding ciphertext: {e}"))?;

        let proof_encoded = ark_to_bytes(proof)?;

        proofs_of_property.append(&mut self.verifier.assess_ciphertext(
            ciphertext.clone(),
            sk,
            &mut rng,
        )?);

        Ok(VerifiableEncryption {
            ciphertext: ciphertext_encoded,
            proof_of_encryption: proof_encoded,
            proofs_of_property,
        })
    }

    pub fn verify_proof(&self, proof: &VerifiableEncryption) -> anyhow::Result<bool> {
        let public_inputs = self.verifier.prepare_public_inputs(&proof.ciphertext)?;
        let is_valid_enc = self
            .encryption
            .verify_proof(&proof.proof_of_encryption, &proof.ciphertext)?;
        let is_valid_property = proof
            .proofs_of_property
            .iter()
            .map(|proof| {
                self.verifier
                    .verify_proof(proof.clone(), public_inputs.clone())
            })
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .all(|c| c);

        Ok(is_valid_enc && is_valid_property)
    }

    pub fn compile<R: Rng + CryptoRng>(&self, mut rng: &mut R) -> anyhow::Result<()> {
        let _ = self.encryption.compile(&mut rng)?;
        let _ = self.verifier.compile(&mut rng)?;
        Ok(())
    }

    pub fn decrypt<K: AsRef<[u8]>, B: AsRef<[u8]>>(
        &self,
        sk: K,
        ciphertext: B,
    ) -> anyhow::Result<Vec<u8>> {
        self.encryption.decrypt(sk, ciphertext)
    }

    pub fn keygen<R: CryptoRng + RngCore>(
        &self,
        mut rng: &mut R,
    ) -> anyhow::Result<(SecretKey<ProjectiveCurve>, PublicKey<ProjectiveCurve>)> {
        self.encryption.keygen(&mut rng)
    }
}
