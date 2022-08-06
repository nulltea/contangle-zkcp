use crate::zk::ProofOfProperty;
use crate::{Fq, PairingEngine, ProjectiveCurve};
use ark_groth16::{ProvingKey, VerifyingKey};
use circuits::{Ciphertext, Plaintext, SecretKey};
use rand::{CryptoRng, Rng, RngCore};

pub trait PropertyVerifier {
    fn assess_plaintext<R: CryptoRng + RngCore>(
        &self,
        plaintext: Plaintext<ProjectiveCurve>,
        rng: &mut R,
    ) -> anyhow::Result<Vec<ProofOfProperty>>;

    fn assess_ciphertext<R: CryptoRng + RngCore>(
        &self,
        ciphertext: Ciphertext<ProjectiveCurve>,
        sk: SecretKey<ProjectiveCurve>,
        rng: &mut R,
    ) -> anyhow::Result<Vec<ProofOfProperty>>;

    fn prepare_public_inputs<CT: AsRef<[u8]>>(&self, ciphertext: CT) -> anyhow::Result<Vec<Fq>>;

    fn verify_proof(&self, proof: ProofOfProperty, public_inputs: Vec<Fq>) -> anyhow::Result<bool>;

    fn compile<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> anyhow::Result<(ProvingKey<PairingEngine>, VerifyingKey<PairingEngine>)>;
}
