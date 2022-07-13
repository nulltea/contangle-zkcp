use crate::JUB_JUB_PARAMETERS;
use anyhow::anyhow;
use ark_crypto_primitives::encryption::elgamal::constraints::{ConstraintF, ElGamalEncGadget};
use ark_crypto_primitives::encryption::elgamal::{
    Ciphertext, ElGamal, Parameters, Plaintext, PublicKey, Randomness, SecretKey,
};
use ark_crypto_primitives::encryption::{AsymmetricEncryptionGadget, AsymmetricEncryptionScheme};
use ark_crypto_primitives::Error;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{PrimeField, ToConstraintField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_sponge::constraints::CryptographicSpongeVar;
use ark_sponge::CryptographicSponge;
use ark_std::marker::PhantomData;
use ark_std::rand::{CryptoRng, Rng, RngCore};
use ark_std::vec::Vec;
use ark_std::UniformRand;

pub struct EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    r: Randomness<C>,
    msg: Plaintext<C>,
    pk: PublicKey<C>,
    pub enc: Ciphertext<C>,
    params: &'static Parameters<C>,
    _curve_var: PhantomData<CV>,
}

impl<C, CV> EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    pub fn new<R: Rng>(
        pk: PublicKey<C>,
        msg: Plaintext<C>,
        params: &'static Parameters<C>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let r = Randomness::rand(rng);

        // let enc: Result<Vec<_>, Error> = msg
        //     .iter()
        //     .map(|msg| ElGamal::<C>::encrypt(&params, &pk, msg, &r))
        //     .collect();
        let enc = ElGamal::<C>::encrypt(&params, &pk, &msg, &r)?;

        Ok(Self {
            r,
            msg,
            pk,
            enc,
            params,
            _curve_var: PhantomData,
        })
    }

    pub fn compile<E: PairingEngine, R>(
        params: &'static Parameters<C>,
        mut rng: &mut R,
    ) -> anyhow::Result<(ProvingKey<E>, VerifyingKey<E>)>
    where
        R: CryptoRng + RngCore,
        Self: ConstraintSynthesizer<E::Fr>,
    {
        let pk = C::rand(&mut rng).into_affine();
        let msg = C::rand(&mut rng).into_affine();
        let c = Self::new(pk, msg, &params, &mut rng).unwrap();
        let (pk, vk) = Groth16::<E>::setup(c, &mut rng)
            .map_err(|e| anyhow!("error compiling circuit: {e}"))?;
        Ok((pk, vk))
    }

    pub fn keygen<R: CryptoRng + RngCore>(
        params: &'static Parameters<C>,
        mut rng: &mut R,
    ) -> anyhow::Result<(SecretKey<C>, PublicKey<C>)> {
        let (pk, sk) = ElGamal::<C>::keygen(params, rng)
            .map_err(|e| anyhow!("error generating ElGamal keypair: {e}"))?;
        Ok((sk, pk))
    }

    pub fn verify_proof<E: PairingEngine>(
        vk: &VerifyingKey<E>,
        proof: Proof<E>,
        cipher: Ciphertext<C>,
    ) -> anyhow::Result<bool>
    where
        C::Affine: ToConstraintField<E::Fr>,
    {
        let public_inputs = cipher
            .0
            .to_field_elements()
            .unwrap()
            .into_iter()
            .chain(cipher.1.to_field_elements().unwrap().into_iter())
            .collect::<Vec<_>>();
        Groth16::<E>::verify(&vk, &public_inputs, &proof)
            .map_err(|e| anyhow!("error verifying proof: {e}"))
    }

    pub fn decrypt<E: PairingEngine>(
        cipher: Ciphertext<C>,
        sk: C::ScalarField,
        params: &Parameters<C>,
    ) -> anyhow::Result<Plaintext<C>>
    where
        C::Affine: ToConstraintField<E::Fr>,
    {
        ElGamal::<C>::decrypt(params, &SecretKey(sk), &cipher)
            .map_err(|e| anyhow!("error decrypting ciphertext: {e}"))
    }

    pub fn prove<E: PairingEngine, R>(
        self,
        pk: &ProvingKey<E>,
        mut rng: &mut R,
    ) -> anyhow::Result<((C::Affine, C::Affine), Proof<E>)>
    where
        R: CryptoRng + RngCore,
        Self: ConstraintSynthesizer<E::Fr>,
    {
        let ciphertext = self.enc.clone();
        let proof = Groth16::<E>::prove(pk, self, &mut rng)
            .map_err(|e| anyhow!("error proving encryption: {e}"))?;

        Ok((ciphertext, proof))
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
            ark_relations::ns!(cs, "gadget_parameters"), self.params
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
        let result_var = ElGamalEncGadget::<C, CV>::encrypt(
            &parameters_var,
            &msg_var,
            &randomness_var,
            &pk_var,
        )?;

        // check that result equals expected ciphertext in the constraint system
        let expected_var = <ElGamalEncGadget<C, CV> as AsymmetricEncryptionGadget<
            ElGamal<C>,
            C::BaseField,
        >>::OutputVar::new_input(
            ark_relations::ns!(cs, "gadget_expected"), || Ok(&self.enc)
        )?;

        println!("number of constraints: {}", cs.num_constraints());

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
    use crate::{ark_to_bytes, EncryptCircuit, JUB_JUB_PARAMETERS};
    use ark_bls12_381::Bls12_381 as P;
    use ark_crypto_primitives::encryption::elgamal::ElGamal;
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_ec::ProjectiveCurve;
    use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective as JubJub, Fq};
    use ark_ff::ToConstraintField;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_std::{test_rng, UniformRand};

    type TestEnc = EncryptCircuit<JubJub, EdwardsVar>;

    #[test]
    fn test_elgamal_encryption() {
        let mut rng = test_rng();
        let msg = JubJub::rand(&mut rng);

        let params = ElGamal::<JubJub>::setup(&mut rng).unwrap();
        let (pub_key, _) = ElGamal::<JubJub>::keygen(&params, &mut rng).unwrap();

        let circuit = TestEnc::new(
            pub_key.clone(),
            msg.clone().into(),
            &JUB_JUB_PARAMETERS,
            &mut rng,
        )
        .unwrap();
        let cs = ConstraintSystem::<Fq>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        println!("Num constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());

        let circuit = TestEnc::new(
            pub_key.clone(),
            msg.clone().into(),
            &JUB_JUB_PARAMETERS,
            &mut rng,
        )
        .unwrap();
        let (pk, vk) = Groth16::<P>::setup(circuit, &mut rng).unwrap();

        let circuit =
            TestEnc::new(pub_key, msg.clone().into(), &JUB_JUB_PARAMETERS, &mut rng).unwrap();
        let enc = circuit.enc.clone();
        let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();

        let valid_proof = TestEnc::verify_proof(&vk, proof, enc).unwrap();
        assert!(valid_proof);
    }

    #[test]
    fn test_elgamal_keygen() {
        let mut rng = test_rng();
        let msg = JubJub::rand(&mut rng);

        let params = ElGamal::<JubJub>::setup(&mut rng).unwrap();
        let (pk, sk) = ElGamal::<JubJub>::keygen(&params, &mut rng).unwrap();

        let pk_bytes = ark_to_bytes(pk).unwrap();
        let sk_bytes = ark_to_bytes(sk.0).unwrap();

        println!("sk: {}", hex::encode(sk_bytes));
        println!("pk: {}", hex::encode(pk_bytes));
    }
}