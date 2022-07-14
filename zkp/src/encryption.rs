use crate::elgamal::constraints::{
    HashElGamalEncGadget, OutputVar, ParametersVar, PlaintextVar, PublicKeyVar, RandomnessVar,
};
use crate::elgamal::{
    Ciphertext, HashElGamal, Parameters, Plaintext, PublicKey, Randomness, SecretKey,
};
use crate::JUB_JUB_PARAMETERS;
use anyhow::anyhow;
use ark_crypto_primitives::encryption::elgamal::constraints::{ConstraintF, ElGamalEncGadget};
use ark_crypto_primitives::encryption::{AsymmetricEncryptionGadget, AsymmetricEncryptionScheme};
use ark_crypto_primitives::snark::NonNativeFieldInputVar;
use ark_crypto_primitives::Error;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, BitIteratorLE, Field, PrimeField, ToConstraintField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_sponge::constraints::{AbsorbGadget, CryptographicSpongeVar};
use ark_sponge::poseidon::PoseidonParameters;
use ark_sponge::{Absorb, CryptographicSponge};
use ark_std::marker::PhantomData;
use ark_std::rand::{CryptoRng, Rng, RngCore};
use ark_std::vec::Vec;
use ark_std::UniformRand;
use std::borrow::Borrow;

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
    params: Parameters<C>,
    _curve_var: PhantomData<CV>,
}

impl<C, CV> EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    CV: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    pub fn new<R: Rng>(
        pk: PublicKey<C>,
        msg: Plaintext<C>,
        params: PoseidonParameters<C::BaseField>,
        rng: &mut R,
    ) -> Result<Self, Error> {
        let r = Randomness::rand(rng);

        let params = Parameters::<C> {
            generator: C::prime_subgroup_generator(),
            poseidon: params,
        };

        // let enc: Result<Vec<_>, Error> = msg
        //     .iter()
        //     .map(|msg| ElGamal::<C>::encrypt(&params, &pk, msg, &r))
        //     .collect();
        let enc = HashElGamal::<C>::encrypt(&params, &pk, &msg, &r)?;

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
        params: PoseidonParameters<C::BaseField>,
        mut rng: &mut R,
    ) -> anyhow::Result<(ProvingKey<E>, VerifyingKey<E>)>
    where
        R: CryptoRng + RngCore,
        Self: ConstraintSynthesizer<E::Fr>,
    {
        let pk = C::rand(&mut rng);
        let msg = C::ScalarField::from_random_bytes(&*vec![]).unwrap();
        let c = Self::new(pk, msg, params, &mut rng).unwrap();
        let (pk, vk) = Groth16::<E>::setup(c, &mut rng)
            .map_err(|e| anyhow!("error compiling circuit: {e}"))?;
        Ok((pk, vk))
    }

    pub fn keygen<R: CryptoRng + RngCore>(
        params: &'static Parameters<C>,
        mut rng: &mut R,
    ) -> anyhow::Result<(SecretKey<C>, PublicKey<C>)> {
        let (pk, sk) = HashElGamal::<C>::keygen(params, rng)
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
        let cs = ConstraintSystem::<<C as ProjectiveCurve>::BaseField>::new_ref();
        let mut public_inputs = cipher.0.into_affine().to_field_elements().unwrap();
        // let x = NonNativeFieldVar::new_input(ark_relations::ns!(cs, ""), || Ok(cipher.1)).unwrap();
        // let cipher_fields: Vec<<E as PairingEngine>::Fr> = x
        //     .to_constraint_field()
        //     .unwrap()
        //     .into_iter()
        //     .flat_map(|c| c.to_field_elements())
        //     .collect();
        // public_inputs.extend(cipher_fields.into_iter());
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
        HashElGamal::<C>::decrypt(params, &SecretKey(sk), &cipher)
            .map_err(|e| anyhow!("error decrypting ciphertext: {e}"))
    }

    pub fn prove<E: PairingEngine, R>(
        self,
        pk: &ProvingKey<E>,
        mut rng: &mut R,
    ) -> anyhow::Result<(Ciphertext<C>, Proof<E>)>
    where
        R: CryptoRng + RngCore,
        Self: ConstraintSynthesizer<E::Fr>,
    {
        let ciphertext = self.enc.clone();
        let proof = Groth16::<E>::prove(pk, self, &mut rng)
            .map_err(|e| anyhow!("error proving encryption: {e}"))?;

        Ok((ciphertext, proof))
    }
}

impl<C, CV> ConstraintSynthesizer<C::BaseField> for EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    CV: CurveVar<C, ConstraintF<C>> + AbsorbGadget<ConstraintF<C>>,
    for<'a> &'a CV: GroupOpsBounds<'a, C, CV>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let randomness_var = RandomnessVar::<C::BaseField>::new_witness(
            ark_relations::ns!(cs, "gadget_randomness"),
            || Ok(&self.r),
        )
        .unwrap();
        let parameters_var = ParametersVar::<C, CV>::new_constant(
            ark_relations::ns!(cs, "gadget_parameters"),
            &self.params,
        )
        .unwrap();
        let msg_var =
            PlaintextVar::<C>::new_witness(ark_relations::ns!(cs, "gadget_message"), || {
                Ok(&self.msg)
            })
            .unwrap();
        let pk_var =
            PublicKeyVar::<C, CV>::new_witness(ark_relations::ns!(cs, "gadget_public_key"), || {
                Ok(&self.pk)
            })
            .unwrap();

        // use gadget
        let result_var = HashElGamalEncGadget::<C, CV>::encrypt(
            cs.clone(),
            &parameters_var,
            &msg_var,
            &randomness_var,
            &pk_var,
        )
        .unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var =
            OutputVar::<C, CV>::new_input(ark_relations::ns!(cs, "gadget_expected"), || {
                Ok(&self.enc)
            })
            .unwrap();

        expected_var.enforce_equal(&result_var)
    }
}

#[cfg(test)]
mod test {
    use crate::elgamal::{poseidon, HashElGamal, Parameters};
    use crate::{ark_to_bytes, EncryptCircuit, JUB_JUB_PARAMETERS};
    use ark_bls12_377::{constraints::G1Var, Bls12_377, Fq, Fr, FrParameters, G1Projective};
    use ark_bw6_761::BW6_761 as P;
    use ark_crypto_primitives::encryption::elgamal::ElGamal;
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_ec::ProjectiveCurve;
    use ark_ff::{BigInteger, Field, Fp256, PrimeField, ToConstraintField};
    use ark_groth16::Groth16;
    use ark_nonnative_field::NonNativeFieldVar;
    use ark_r1cs_std::prelude::AllocVar;
    use ark_r1cs_std::{R1CSVar, ToBytesGadget, ToConstraintFieldGadget};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_sponge::constraints::AbsorbGadget;
    use ark_std::{test_rng, UniformRand};
    use std::borrow::Borrow;

    type TestEnc = EncryptCircuit<G1Projective, G1Var>;

    #[test]
    fn test_elgamal_encryption() {
        let mut rng = test_rng();
        let bytes = [1, 2, 3];
        let msg = Fr::from_random_bytes(&bytes).unwrap();

        let params = Parameters::<G1Projective> {
            generator: G1Projective::prime_subgroup_generator(),
            poseidon: poseidon::get_bls12377_fq_params(2),
        };

        let (pub_key, _) = HashElGamal::<G1Projective>::keygen(&params, &mut rng).unwrap();

        let circuit = TestEnc::new(
            pub_key.clone(),
            msg.clone().into(),
            params.poseidon.clone(),
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
            params.poseidon.clone(),
            &mut rng,
        )
        .unwrap();
        let (pk, vk) = Groth16::<P>::setup(circuit, &mut rng).unwrap();

        let circuit = TestEnc::new(
            pub_key,
            msg.clone().into(),
            params.poseidon.clone(),
            &mut rng,
        )
        .unwrap();
        let enc = circuit.enc.clone();
        let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();

        let valid_proof = TestEnc::verify_proof(&vk, proof, enc).unwrap();
        assert!(valid_proof);
    }

    // #[test]
    // fn test_elgamal_keygen() {
    //     let mut rng = test_rng();
    //     let msg = JubJub::rand(&mut rng);
    //
    //     let params = ElGamal::<JubJub>::setup(&mut rng).unwrap();
    //     let (pk, sk) = ElGamal::<JubJub>::keygen(&params, &mut rng).unwrap();
    //
    //     let pk_bytes = ark_to_bytes(pk).unwrap();
    //     let sk_bytes = ark_to_bytes(sk.0).unwrap();
    //
    //     println!("sk: {}", hex::encode(sk_bytes));
    //     println!("pk: {}", hex::encode(pk_bytes));
    // }
}
