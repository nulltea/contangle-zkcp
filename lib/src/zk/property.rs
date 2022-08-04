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
    ark_from_bytes, ark_to_bytes, bytes_to_plaintext_chunks_direct, encryption, CircomWrapper,
    PublicKey, SecretKey,
};
use num_bigint::BigInt;
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircomParams {
    pub plaintext_field_name: String,
    pub wasm_path: PathBuf,
    pub r1cs_path: PathBuf,
}

pub struct ZkPropertyVerifier {
    build_dir: PathBuf,
    encryption: ZkEncryption,
    circom_params: CircomParams,
    circom_builder: CircomBuilder<PairingEngine, ProjectiveCurve>,
    proving_key: Option<ProvingKey<PairingEngine>>,
    verifying_key: Option<VerifyingKey<PairingEngine>>,
}

impl ZkPropertyVerifier {
    pub fn new<P: AsRef<Path>>(
        build_dir: P,
        circom_params: CircomParams,
        enc_params: encryption::Parameters<ProjectiveCurve>,
    ) -> Self {
        let proving_key =
            read_proving_key(build_dir.as_ref().join(PROVING_KEY_FILE)).map_or(None, |k| Some(k));
        let verifying_key = proving_key.as_ref().map(|pk| pk.vk.clone());
        let circom_builder = {
            let mut circom_cfg = CircomConfig::<PairingEngine>::new(
                circom_params.wasm_path.clone(),
                circom_params.r1cs_path.clone(),
            )
            .unwrap();
            circom_cfg.sanity_check = false;

            CircomBuilder::<_, ProjectiveCurve>::new(circom_cfg)
        };

        Self {
            build_dir: PathBuf::from(build_dir.as_ref()),
            encryption: ZkEncryption::new_inner(enc_params),
            circom_params,
            circom_builder,
            proving_key,
            verifying_key,
        }
    }

    pub fn new_verifier<P: AsRef<Path>>(
        build_dir: P,
        circom_params: CircomParams,
        enc_params: encryption::Parameters<ProjectiveCurve>,
    ) -> Self {
        let verifying_key = read_verifying_key(build_dir.as_ref().join(VERIFYING_KEY_FILE))
            .expect("verification key missing");
        let circom_builder = {
            let mut circom_cfg = CircomConfig::<PairingEngine>::new(
                circom_params.wasm_path.clone(),
                circom_params.r1cs_path.clone(),
            )
            .unwrap();
            circom_cfg.sanity_check = false;

            CircomBuilder::<_, ProjectiveCurve>::new(circom_cfg)
        };
        Self {
            build_dir: PathBuf::from(build_dir.as_ref()),
            encryption: ZkEncryption::new_inner(enc_params),
            circom_params,
            circom_builder,
            proving_key: None,
            verifying_key: Some(verifying_key),
        }
    }

    pub fn assess_property_and_encrypt<
        M: AsRef<[u8]>,
        R: CryptoRng + RngCore,
        AV: Iterator<Item = (String, Vec<BigInt>)>,
    >(
        &self,
        msg: M,
        pk: PublicKey<ProjectiveCurve>,
        additional_values: AV,
        mut rng: &mut R,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let msg = bytes_to_plaintext_chunks_direct::<ProjectiveCurve, _>(
            msg.as_ref(),
            self.encryption.params.n,
        )
        .map_err(|e| anyhow!("error casting plaintext: {e}"))?;

        let circom_circuit = {
            let mut builder = self.circom_builder.clone();
            msg.clone().into_iter().for_each(|m| {
                builder.push_variable(self.circom_params.plaintext_field_name.clone(), m)
            });
            additional_values
                .flat_map(|(n, vs)| vs.into_iter().map(move |v| (n.clone(), v)))
                .for_each(|(var_name, value)| builder.push_input(var_name, value));
            builder.build()
        }
        .map_err(|e| anyhow!("error building circom circuit: {e}"))?;

        let enc_circuit = self.encryption.build_circuit(msg, pk, &mut rng)?;

        let ciphertext = enc_circuit.resulted_ciphertext.clone();
        let proving_key = self.proving_key.as_ref().expect("proving key expected");

        let circuit = CircomWrapper::new(
            enc_circuit,
            circom_circuit,
            self.circom_params.plaintext_field_name.clone(),
        );

        let proof = Groth16::<PairingEngine>::prove(proving_key, circuit, &mut rng)
            .map_err(|e| anyhow!("error proving encryption: {e}"))?;

        let ciphertext_encoded = ark_to_bytes(ciphertext.clone())
            .map_err(|e| anyhow!("error encoding ciphertext: {e}"))?;

        let proof_encoded = ark_to_bytes(proof)?;

        Ok((ciphertext_encoded, proof_encoded))
    }

    pub fn verify_proof<
        PB: AsRef<[u8]>,
        CB: AsRef<[u8]>,
        AV: Iterator<Item = (String, Vec<BigInt>)>,
    >(
        &self,
        proof: PB,
        ciphertext: CB,
        additional_values: AV,
    ) -> anyhow::Result<bool> {
        let circom_inputs = {
            let mut builder = self.circom_builder.clone();
            additional_values
                .flat_map(|(n, vs)| vs.into_iter().map(move |v| (n.clone(), v)))
                .for_each(|(var_name, value)| builder.push_input(var_name, value));
            builder.build().map(|c| c.get_public_inputs().unwrap())
        }
        .unwrap();
        let proof = ark_from_bytes(proof)?;
        let ciphertext = ark_from_bytes(ciphertext.as_ref())
            .map_err(|_e| anyhow!("error casting ciphertext"))?;
        let verifying_key = self
            .verifying_key
            .as_ref()
            .expect("verifying key was expected");

        let public_inputs =
            CircomWrapper::<PairingEngine, ProjectiveCurve, CurveVar>::get_public_inputs(
                circom_inputs,
                &ciphertext,
                &self.encryption.params,
            );

        Groth16::verify(&verifying_key, &public_inputs, &proof)
            .map_err(|_e| anyhow!("error verifying Groth'16 proof"))
    }

    pub fn compile<R: Rng + CryptoRng>(
        &self,
        mut rng: &mut R,
    ) -> anyhow::Result<(ProvingKey<PairingEngine>, VerifyingKey<PairingEngine>)> {
        let enc_circuit = self.encryption.setup_circuit();
        let circom_circuit = self.circom_builder.setup();
        let circuit = CircomWrapper::new(
            enc_circuit,
            circom_circuit,
            self.circom_params.plaintext_field_name.clone(),
        );
        let (pk, vk) = Groth16::<PairingEngine>::setup(circuit, &mut rng)
            .map_err(|e| anyhow!("error compiling circuit: {e}"))?;

        fs::create_dir_all(&self.build_dir)
            .map_err(|e| anyhow!("error creating build dir: {e}"))?;
        write_circuit_artifacts(&self.build_dir, &pk, &vk)?;
        Ok((pk, vk))
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
