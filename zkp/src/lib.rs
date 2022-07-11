use ark_crypto_primitives::encryption::elgamal::{
    Ciphertext, ElGamal, Parameters, Randomness, SecretKey,
};
use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_crypto_primitives::Error;
use ark_ec::ProjectiveCurve;
use ark_ff::{BitIteratorLE, PrimeField};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::poseidon::{constraints::PoseidonSpongeVar, PoseidonParameters, PoseidonSponge};
use ark_sponge::{constraints::AbsorbGadget, Absorb, CryptographicSponge};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::vec::Vec;
use ark_std::UniformRand;

pub struct EncryptCircuit<C>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField, // Prime for constraint CV
{
    r: Randomness<C>,
    msg: Vec<C::Affine>,
    pk: C::Affine,
    sk: SecretKey<C>,
    pub enc: Vec<Ciphertext<C>>,
    params: Parameters<C>,
}

impl<C> EncryptCircuit<C>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
{
    pub fn new<R: Rng>(msg: Vec<C::Affine>, rng: &mut R) -> Result<Self, Error> {
        //let r = C::ScalarField::rand(rng);
        let params = ElGamal::<C>::setup(rng)?;
        let (pk, sk) = ElGamal::<C>::keygen(&params, rng).unwrap();
        let r = Randomness::rand(rng);

        let enc: Result<Vec<_>, Error> = msg
            .iter()
            .map(|msg| ElGamal::<C>::encrypt(&params, &pk, msg, &r))
            .collect();

        Ok(Self {
            r,
            msg,
            pk,
            sk,
            enc: enc?,
            params,
        })
    }

    pub fn verify_encryption(&self) -> Result<(), SynthesisError> {
        Ok(())
    }
}

impl<C> ConstraintSynthesizer<C::BaseField> for EncryptCircuit<C>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField + Absorb,
    C::Affine: Absorb,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        self.verify_encryption()
    }
}

#[cfg(test)]
mod test {
    use ark_std::{test_rng, UniformRand};

    use ark_bls12_381::Bls12_381 as P;
    use ark_ed_on_bls12_381::{EdwardsProjective as JubJub, Fq};

    use crate::EncryptCircuit;
    use ark_crypto_primitives::encryption::elgamal::{ElGamal, Randomness};
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_crypto_primitives::merkle_tree::MerkleTree;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};

    #[test]
    fn test_elgamal_encryption() {
        let mut rng = test_rng();
        let msg = JubJub::rand(&mut rng).into();

        let circuit = EncryptCircuit::<JubJub>::new(vec![msg], &mut rng).unwrap();
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        println!("Num constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
        let circuit = EncryptCircuit::<JubJub>::new(vec![msg], &mut rng).unwrap();
        let (pk, vk) = Groth16::<P>::setup(circuit, &mut rng).unwrap();
        let circuit = EncryptCircuit::<JubJub>::new(vec![msg], &mut rng).unwrap();
        let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();
        let valid_proof = Groth16::verify(&vk, &vec![], &proof).unwrap();
        assert!(valid_proof);
    }
}
