use anyhow::anyhow;
use ark_crypto_primitives::snark::NonNativeFieldInputVar;
use ark_crypto_primitives::Error;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, BigInteger, BitIteratorLE, Field, PrimeField, ToConstraintField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::ns;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_sponge::constraints::{AbsorbGadget, CryptographicSpongeVar};
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_sponge::poseidon::{PoseidonParameters, PoseidonSponge};
use ark_sponge::{Absorb, CryptographicSponge, FieldBasedCryptographicSponge};
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

#[derive(Clone, Debug)]
pub struct Parameters<C: ProjectiveCurve>
where
    <C as ProjectiveCurve>::BaseField: PrimeField,
{
    pub generator: C,
    pub poseidon: PoseidonParameters<C::BaseField>,
}

pub type PublicKey<C> = C;

pub struct SecretKey<C: ProjectiveCurve>(pub C::ScalarField);

pub struct Randomness<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(<C as ProjectiveCurve>::ScalarField::rand(rng))
    }
}

pub type Plaintext<C> = <C as ProjectiveCurve>::ScalarField;

pub type Ciphertext<C> = (C, <C as ProjectiveCurve>::ScalarField);

impl<C, CV> EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    C::BaseField: Absorb,
    CV: CurveVar<C, C::BaseField> + AbsorbGadget<C::BaseField>,
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
        let enc = Self::encrypt(&pk, &msg, &r, &params)?;

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
        params: &Parameters<C>,
        mut rng: &mut R,
    ) -> anyhow::Result<(SecretKey<C>, PublicKey<C>)> {
        // get a random element from the scalar field
        let secret_key = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let mut public_key = params.generator;
        public_key.mul_assign(secret_key.clone());

        Ok((SecretKey(secret_key), public_key))
    }

    pub fn verify_proof<E: PairingEngine>(
        vk: &VerifyingKey<E>,
        proof: Proof<E>,
        cipher: Ciphertext<C>,
        params: &Parameters<C>,
    ) -> anyhow::Result<bool>
    where
        C::BaseField: ToConstraintField<E::Fr>,
    {
        let commit = Self::commit_to_inputs(&cipher, &params);
        let public_inputs = commit.to_field_elements().unwrap();
        Groth16::<E>::verify(&vk, &public_inputs, &proof)
            .map_err(|e| anyhow!("error verifying proof: {e}"))
    }

    fn encrypt(
        pk: &PublicKey<C>,
        msg: &Plaintext<C>,
        r: &Randomness<C>,
        params: &Parameters<C>,
    ) -> Result<Ciphertext<C>, Error> {
        let mut c1 = params.generator.clone();
        c1.mul_assign(r.0.clone());

        let mut p_r = pk.clone();
        p_r.mul_assign(r.0.clone());
        let p_ra = p_r.into_affine();

        let mut sponge = PoseidonSponge::new(&params.poseidon);
        sponge.absorb(&p_ra);
        let dh = sponge.squeeze_field_elements::<C::ScalarField>(1)[0];
        let c2 = dh + msg;
        Ok((c1, c2))
    }

    pub fn decrypt<E: PairingEngine>(
        cipher: Ciphertext<C>,
        sk: SecretKey<C>,
        params: &Parameters<C>,
    ) -> anyhow::Result<Plaintext<C>>
    where
        C::Affine: ToConstraintField<E::Fr>,
    {
        let c1 = cipher.0;
        let c2 = cipher.1;

        // compute s = c1^secret_key
        let mut s = c1;
        s.mul_assign(sk.0);
        let sa = s.into_affine();

        // compute dh = H(s)
        let mut sponge = PoseidonSponge::new(&params.poseidon);
        sponge.absorb(&sa);
        let dh = sponge.squeeze_field_elements::<C::ScalarField>(1)[0];

        // compute message = c2 - s
        Ok(c2 - dh)
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

    pub(crate) fn verify_encryption(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        msg: &NonNativeFieldVar<C::ScalarField, C::BaseField>,
        ciphertext: &(CV, NonNativeFieldVar<C::ScalarField, C::BaseField>),
    ) -> Result<(), SynthesisError> {
        let g = CV::new_constant(ns!(cs, "elgamal_generator"), C::prime_subgroup_generator())?;

        // flatten randomness to little-endian bit vector
        let r = to_bytes![&self.r.0].unwrap();
        let randomness = UInt8::new_witness_vec(ns!(cs, "elgamal_randomness"), &r)?
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        let pk = CV::new_witness(ns!(cs, "elgamal_pubkey"), || Ok(self.pk.clone()))?;

        // compute s = randomness*pk
        let s = pk.clone().scalar_mul_le(randomness.iter())?;

        // compute c1 = randomness*generator
        let c1 = g.clone().scalar_mul_le(randomness.iter())?;

        let mut poseidon = PoseidonSpongeVar::new(cs.clone(), &self.params.poseidon);
        poseidon.absorb(&s)?;
        let c2 = poseidon
            .squeeze_nonnative_field_elements::<C::ScalarField>(1)
            .and_then(|r| Ok(r.0[0].clone() + msg))?;

        c1.enforce_equal(&ciphertext.0)
            .and(c2.enforce_equal(&ciphertext.1))
    }

    pub(crate) fn ciphertext_var(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        mode: AllocationMode,
    ) -> Result<(CV, NonNativeFieldVar<C::ScalarField, C::BaseField>), SynthesisError> {
        let c1 = CV::new_variable(ns!(cs, "elgamal_enc"), || Ok(self.enc.0), mode)?;
        let c2 = NonNativeFieldVar::<C::ScalarField, C::BaseField>::new_variable(
            ns!(cs, "elgamal_enc"),
            || Ok(self.enc.1),
            mode,
        )?;

        Ok((c1, c2))
    }

    pub fn constraint_inputs(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        ciphertext: &(CV, NonNativeFieldVar<C::ScalarField, C::BaseField>),
    ) -> Result<(), SynthesisError> {
        // input commitment
        let ciphertext_commitment_var = FpVar::<C::BaseField>::new_variable(
            ns!(cs, "ciphertext_commitment"),
            || Ok(Self::commit_to_inputs(&self.enc, &self.params)),
            AllocationMode::Input,
        )?;

        let mut sponge = PoseidonSpongeVar::new(cs.clone(), &self.params.poseidon);
        sponge.absorb(&ciphertext.0)?;

        let native = self.enc.1;
        let nonnative = &ciphertext.1;
        let scalar_in_fq = &C::BaseField::from_repr(
            <C::BaseField as PrimeField>::BigInt::from_bits_le(&native.into_repr().to_bits_le()),
        )
        .unwrap(); // because Fr < Fq
        let scalar_var = FpVar::new_witness(ns!(cs.clone(), "scalar fq"), || Ok(scalar_in_fq))?;
        sponge.absorb(&scalar_var)?;
        // Pass from Fq(Fp) -> Bits<Fq)[0..Fp]
        let native_bits = scalar_var.to_bits_le()?;
        let nonnative_bits = nonnative.to_bits_le()?;
        for (fq_base, nonnative_base) in native_bits
            .iter()
            .zip(nonnative_bits.iter())
            .take(C::ScalarField::size_in_bits())
        {
            fq_base.enforce_equal(nonnative_base)?;
        }
        // enforce the rest is 0 so there is no different witness possible
        // for the Fq(Fp) var
        let diff = native_bits.len() - C::ScalarField::size_in_bits();
        let false_var = Boolean::constant(false);
        for unconstrained_bit in native_bits.iter().rev().take(diff) {
            unconstrained_bit.enforce_equal(&false_var)?;
        }

        let exp = sponge
            .squeeze_field_elements(1)
            .and_then(|mut v| Ok(v.remove(0)))?;

        exp.enforce_equal(&ciphertext_commitment_var)
    }

    pub fn commit_to_inputs(ciphertext: &Ciphertext<C>, params: &Parameters<C>) -> C::BaseField {
        let mut sponge = PoseidonSponge::new(&params.poseidon);
        sponge.absorb(&ciphertext.0.into_affine());
        let scalar_in_fq =
            &C::BaseField::from_repr(<C::BaseField as PrimeField>::BigInt::from_bits_le(
                &ciphertext.1.into_repr().to_bits_le(),
            ))
            .unwrap();
        sponge.absorb(&scalar_in_fq);
        sponge.squeeze_field_elements(1).remove(0)
    }
}

impl<C, CV> ConstraintSynthesizer<C::BaseField> for EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    C::BaseField: Absorb,
    CV: CurveVar<C, C::BaseField> + AbsorbGadget<C::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let message = NonNativeFieldVar::<C::ScalarField, C::BaseField>::new_witness(
            ns!(cs, "share_nonnative"),
            || Ok(self.msg),
        )?;
        let ciphertext = self.ciphertext_var(cs.clone(), AllocationMode::Witness)?;

        self.constraint_inputs(cs.clone(), &ciphertext)?;
        self.verify_encryption(cs.clone(), &message, &ciphertext)
    }
}

#[cfg(test)]
mod test {
    use crate::{ark_to_bytes, EncryptCircuit};
    use crate::{poseidon, Parameters};
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

        let (_, pub_key) = TestEnc::keygen(&params, &mut rng).unwrap();

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

        let valid_proof = TestEnc::verify_proof(&vk, proof, enc, &params).unwrap();
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
