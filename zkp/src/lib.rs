use ark_crypto_primitives::encryption::elgamal::constraints::{ConstraintF, ElGamalEncGadget};
use ark_crypto_primitives::encryption::elgamal::{
    Ciphertext, ElGamal, Parameters, Randomness, SecretKey,
};
use ark_crypto_primitives::encryption::{AsymmetricEncryptionGadget, AsymmetricEncryptionScheme};
use ark_crypto_primitives::Error;
use ark_ec::ProjectiveCurve;

use ark_ff::{PrimeField};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use ark_sponge::constraints::CryptographicSpongeVar;

use ark_sponge::{CryptographicSponge};
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::vec::Vec;
use ark_std::UniformRand;

pub struct EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    r: Randomness<C>,
    msg: C::Affine,
    pk: C::Affine,
    sk: SecretKey<C>,
    pub enc: Ciphertext<C>,
    params: Parameters<C>,
    _curve_var: PhantomData<CV>,
}

impl<C, CV> EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    pub fn new<R: Rng>(msg: Vec<C::Affine>, rng: &mut R) -> Result<Self, Error> {
        let params = ElGamal::<C>::setup(rng)?;
        let (pk, sk) = ElGamal::<C>::keygen(&params, rng).unwrap();
        let r = Randomness::rand(rng);

        // let enc: Result<Vec<_>, Error> = msg
        //     .iter()
        //     .map(|msg| ElGamal::<C>::encrypt(&params, &pk, msg, &r))
        //     .collect();

        let enc = ElGamal::<C>::encrypt(&params, &pk, &msg[0], &r)?;

        Ok(Self {
            r,
            msg: msg[0],
            pk,
            sk,
            enc,
            params,
            _curve_var: PhantomData,
        })
    }

    pub fn verify_encryption(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let randomness_var = <ElGamalEncGadget<C, CV> as AsymmetricEncryptionGadget<
            ElGamal<C>,
            C::BaseField,
        >>::RandomnessVar::new_witness(
            ark_relations::ns!(cs, "gadget_randomness"),
            || Ok(&self.r),
        )?;

        let parameters_var = <ElGamalEncGadget<C, CV> as AsymmetricEncryptionGadget<
            ElGamal<C>,
            C::BaseField,
        >>::ParametersVar::new_constant(
            ark_relations::ns!(cs, "gadget_parameters"), &self.params
        )?;

        let msg_var = <ElGamalEncGadget<C, CV> as AsymmetricEncryptionGadget<
            ElGamal<C>,
            C::BaseField,
        >>::PlaintextVar::new_witness(
            ark_relations::ns!(cs, "gadget_message"), || Ok(&self.msg)
        )?;

        let pk_var = <ElGamalEncGadget<C, CV> as AsymmetricEncryptionGadget<
            ElGamal<C>,
            C::BaseField,
        >>::PublicKeyVar::new_witness(
            ark_relations::ns!(cs, "gadget_public_key"),
            || Ok(&self.pk),
        )?;

        // use gadget
        let result_var = <ElGamalEncGadget<C, CV> as AsymmetricEncryptionGadget<
            ElGamal<C>,
            C::BaseField,
        >>::encrypt(&parameters_var, &msg_var, &randomness_var, &pk_var)?;

        // check that result equals expected ciphertext in the constraint system
        let expected_var = <ElGamalEncGadget<C, CV> as AsymmetricEncryptionGadget<
            ElGamal<C>,
            C::BaseField,
        >>::OutputVar::new_input(
            ark_relations::ns!(cs, "gadget_expected"), || Ok(&self.enc)
        )?;

        expected_var.enforce_equal(&result_var)
    }
}

impl<C, CV> ConstraintSynthesizer<C::BaseField> for EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        self.verify_encryption(cs)
    }
}

#[cfg(test)]
mod test {
    use crate::EncryptCircuit;
    use ark_std::{test_rng, UniformRand};

    use ark_bls12_381::Bls12_381 as P;
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};

    
    
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_groth16::Groth16;
    
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};

    type TestEnc = EncryptCircuit<JubJub, EdwardsVar>;

    #[test]
    fn test_elgamal_encryption() {
        let mut rng = test_rng();
        let msg = JubJub::rand(&mut rng).into();

        let circuit = TestEnc::new(vec![msg], &mut rng).unwrap();
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        println!("Num constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
        let circuit = TestEnc::new(vec![msg], &mut rng).unwrap();
        let (pk, vk) = Groth16::<P>::setup(circuit, &mut rng).unwrap();
        let circuit = TestEnc::new(vec![msg], &mut rng).unwrap();
        let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();
        let valid_proof = Groth16::verify(&vk, &vec![], &proof).unwrap();
        assert!(valid_proof);
    }
}
