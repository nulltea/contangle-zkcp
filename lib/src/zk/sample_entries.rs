use crate::zk::{ProofOfProperty, PropertyVerifier};
use crate::{
    read_proving_key, read_verifying_key, write_circuit_artifacts, CurveVar, Fq, PairingEngine,
    ProjectiveCurve as Curve, PROVING_KEY_FILE, VERIFYING_KEY_FILE,
};
use anyhow::anyhow;
use ark_ec::ProjectiveCurve;
use ark_ed_on_bls12_381::Fr;
use ark_ff::{ToConstraintField, Zero};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::SerializationError;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use circuits::poseidon::get_poseidon_params;
use circuits::{
    ark_from_bytes, ark_to_bytes, encryption, Ciphertext, Plaintext, SampleEntries, SecretKey,
};
use rand::{CryptoRng, Rng, RngCore};
use std::fs;
use std::path::{Path, PathBuf};

pub struct ZkSampleEntries {
    build_dir: PathBuf,
    params: encryption::Parameters<Curve>,
    proving_key: Option<ProvingKey<PairingEngine>>,
    verifying_key: Option<VerifyingKey<PairingEngine>>,
}

impl ZkSampleEntries {
    pub fn new<P: AsRef<Path>>(build_dir: P, n: usize) -> Self {
        let proving_key =
            read_proving_key(build_dir.as_ref().join(PROVING_KEY_FILE)).map_or(None, |k| Some(k));
        let verifying_key = proving_key.as_ref().map(|pk| pk.vk.clone());

        assert_eq!(n % 2, 0);

        Self {
            build_dir: PathBuf::from(build_dir.as_ref()),
            params: encryption::Parameters::<Curve> {
                n,
                poseidon: get_poseidon_params::<Curve>(2),
            },
            proving_key,
            verifying_key,
        }
    }

    pub fn new_verifier<P: AsRef<Path>>(build_dir: P, n: usize) -> Self {
        let verifying_key = read_verifying_key(build_dir.as_ref().join(VERIFYING_KEY_FILE))
            .expect("verification key missing");
        Self {
            build_dir: PathBuf::from(build_dir.as_ref()),
            params: encryption::Parameters::<Curve> {
                n,
                poseidon: get_poseidon_params::<Curve>(2),
            },
            proving_key: None,
            verifying_key: Some(verifying_key),
        }
    }
}

impl PropertyVerifier for ZkSampleEntries {
    fn assess_plaintext<R: CryptoRng + RngCore>(
        &self,
        _plaintext: Plaintext<Curve>,
        _rng: &mut R,
    ) -> anyhow::Result<Vec<ProofOfProperty>> {
        return Ok(vec![]);
    }

    fn assess_ciphertext<R: CryptoRng + RngCore>(
        &self,
        mut ciphertext: Ciphertext<Curve>,
        sk: SecretKey<Curve>,
        mut rng: &mut R,
    ) -> anyhow::Result<Vec<ProofOfProperty>> {
        assert!(ciphertext.1.len() <= self.params.n);
        ciphertext.1.resize_with(self.params.n, || Fq::zero());
        let circuit =
            SampleEntries::<_, CurveVar>::new(ciphertext, sk, 1, self.params.poseidon.clone());
        let proving_key = self.proving_key.as_ref().expect("proving key expected");

        let sample_value = ark_to_bytes(circuit.sample_value.clone())
            .map_err(|e| anyhow!("error encoding ciphertext: {e}"))?;

        let proof = Groth16::<PairingEngine>::prove(proving_key, circuit, &mut rng)
            .map_err(|e| anyhow!("error proving encryption: {e}"))?;

        let proof_encoded = ark_to_bytes(proof)?;

        Ok(vec![ProofOfProperty {
            proof: proof_encoded,
            arguments: vec![("sample_value".to_string(), sample_value)],
        }])
    }

    fn prepare_public_inputs<CT: AsRef<[u8]>>(&self, ciphertext: CT) -> anyhow::Result<Vec<Fq>> {
        let ciphertext = ark_from_bytes(ciphertext.as_ref())
            .map_err(|_e| anyhow!("error casting ciphertext"))?;

        Ok(
            SampleEntries::<Curve, CurveVar>::build_merkle_tree(ciphertext, &self.params.poseidon)?
                .root()
                .to_field_elements()
                .unwrap(),
        )
    }

    fn verify_proof(
        &self,
        args: ProofOfProperty,
        mut public_inputs: Vec<Fq>,
    ) -> anyhow::Result<bool> {
        let proof = ark_from_bytes(args.proof)?;
        let mut sample_value = args
            .arguments
            .into_iter()
            .map(|(_, a)| ark_from_bytes(a))
            .collect::<Result<Vec<_>, SerializationError>>()
            .map_err(|_e| anyhow!("error decoding proof argument to scalar"))?;
        public_inputs.append(&mut sample_value);
        let verifying_key = self
            .verifying_key
            .as_ref()
            .expect("verifying key was expected");

        Groth16::verify(&verifying_key, &public_inputs, &proof)
            .map_err(|e| anyhow!("error verifying proof of property: {e}"))
    }

    fn compile<R: Rng + CryptoRng>(
        &self,
        mut rng: &mut R,
    ) -> anyhow::Result<(ProvingKey<PairingEngine>, VerifyingKey<PairingEngine>)> {
        let ciphertext = (
            Curve::prime_subgroup_generator(),
            (0..self.params.n).map(|_| Fq::zero()).collect::<Vec<_>>(),
        );
        let sk = Fr::zero();
        let circuit =
            SampleEntries::<_, CurveVar>::new(ciphertext, sk, 1, self.params.poseidon.clone());
        let (pk, vk) = Groth16::<PairingEngine>::setup(circuit, &mut rng)
            .map_err(|e| anyhow!("error compiling circuit: {e}"))?;

        fs::create_dir_all(&self.build_dir)
            .map_err(|e| anyhow!("error creating build dir: {e}"))?;
        write_circuit_artifacts(&self.build_dir, &pk, &vk)?;
        Ok((pk, vk))
    }
}
