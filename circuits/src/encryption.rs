use crate::poseidon::get_poseidon_params;
use anyhow::anyhow;
use ark_crypto_primitives::snark::NonNativeFieldInputVar;
use ark_crypto_primitives::Error;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::{to_bytes, BigInteger, BitIteratorLE, Field, PrimeField, ToConstraintField, Zero};
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
use std::cmp::Ordering;
use std::fmt::Debug;
use std::str::FromStr;

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
    C::BaseField: PrimeField,
{
    pub n: usize,
    pub poseidon: PoseidonParameters<C::BaseField>,
}

impl<C: ProjectiveCurve> Parameters<C>
where
    C::BaseField: PrimeField,
    <C::BaseField as FromStr>::Err: Debug,
{
    pub fn default_multi(n: usize) -> Self {
        Self {
            n,
            poseidon: get_poseidon_params::<C>(2),
        }
    }
}

impl<C: ProjectiveCurve> Default for Parameters<C>
where
    C::BaseField: PrimeField,
    <C::BaseField as FromStr>::Err: Debug,
{
    fn default() -> Self {
        Self {
            n: 1,
            poseidon: get_poseidon_params::<C>(2),
        }
    }
}

pub type PublicKey<C> = C;

pub type SecretKey<C: ProjectiveCurve> = C::ScalarField;

pub struct Randomness<C: ProjectiveCurve>(pub C::ScalarField);

impl<C: ProjectiveCurve> UniformRand for Randomness<C> {
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(<C as ProjectiveCurve>::ScalarField::rand(rng))
    }
}

pub type Plaintext<C: ProjectiveCurve> = Vec<C::BaseField>;

pub type Ciphertext<C: ProjectiveCurve> = (C, Vec<C::BaseField>);

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
        params: Parameters<C>,
        rng: &mut R,
    ) -> anyhow::Result<Self> {
        let r = Randomness::rand(rng);

        let enc = Self::encrypt(&pk, &msg, &r, &params)
            .map_err(|e| anyhow!("error encrypting message: {e}"))?;

        Ok(Self {
            r,
            msg,
            pk,
            enc,
            params,
            _curve_var: PhantomData,
        })
    }

    pub fn keygen<R: CryptoRng + RngCore>(
        mut rng: &mut R,
    ) -> anyhow::Result<(SecretKey<C>, PublicKey<C>)> {
        // get a random element from the scalar field
        let secret_key = C::ScalarField::rand(rng);

        // compute secret_key*generator to derive the public key
        let mut public_key = C::prime_subgroup_generator();
        public_key.mul_assign(secret_key.clone());

        Ok((secret_key, public_key))
    }

    pub fn verify_proof<E: PairingEngine>(
        vk: &VerifyingKey<E>,
        proof: Proof<E>,
        cipher: Ciphertext<C>,
        params: &Parameters<C>,
    ) -> anyhow::Result<bool>
    where
        C::BaseField: ToConstraintField<E::Fr>,
        C: ToConstraintField<E::Fr>,
    {
        let c1_inputs = cipher.0.to_field_elements().unwrap();
        let c2_inputs = (0..params.n)
            .map(|i| cipher.1.get(i).map_or(C::BaseField::zero(), |&c| c))
            .flat_map(|c2| c2.to_field_elements().unwrap());
        let public_inputs = c1_inputs.into_iter().chain(c2_inputs).collect::<Vec<_>>();

        Groth16::<E>::verify(&vk, &public_inputs, &proof)
            .map_err(|e| anyhow!("error verifying proof: {e}"))
    }

    fn encrypt(
        pk: &PublicKey<C>,
        msg: &Plaintext<C>,
        r: &Randomness<C>,
        params: &Parameters<C>,
    ) -> Result<Ciphertext<C>, Error> {
        let mut c1 = C::prime_subgroup_generator();
        c1.mul_assign(r.0.clone());

        let mut p_r = pk.clone();
        p_r.mul_assign(r.0.clone());
        let p_ra = p_r.into_affine();

        let mut sponge = PoseidonSponge::new(&params.poseidon);
        sponge.absorb(&p_ra);
        let dh = sponge.squeeze_field_elements::<C::BaseField>(1).remove(0);
        let c2 = msg.iter().map(|m| dh.clone() + m).collect();
        Ok((c1, c2))
    }

    pub fn decrypt(
        cipher: Ciphertext<C>,
        sk: SecretKey<C>,
        params: &Parameters<C>,
    ) -> anyhow::Result<Plaintext<C>> {
        let c1 = cipher.0;
        let c2 = cipher.1;

        // compute s = c1^secret_key
        let mut s = c1;
        s.mul_assign(sk);
        let sa = s.into_affine();

        // compute dh = H(s)
        let mut sponge = PoseidonSponge::new(&params.poseidon);
        sponge.absorb(&sa);
        let dh = sponge.squeeze_field_elements::<C::BaseField>(1).remove(0);

        // compute message = c2 - s
        Ok(c2.into_iter().map(|c2i| c2i - dh).collect())
    }

    pub(crate) fn verify_encryption(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        plaintext: &Vec<FpVar<C::BaseField>>,
        ciphertext: &(CV, Vec<FpVar<C::BaseField>>),
    ) -> Result<(), SynthesisError> {
        assert!(self.params.n >= plaintext.len());
        assert!(self.params.n >= ciphertext.1.len());

        let g = CV::new_constant(ns!(cs, "generator"), C::prime_subgroup_generator())?;

        // flatten randomness to little-endian bit vector
        let r = to_bytes![&self.r.0].unwrap();
        let randomness = UInt8::new_witness_vec(ns!(cs, "encryption_randomness"), &r)?
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        let pk = CV::new_witness(ns!(cs, "pub_key"), || Ok(self.pk.clone()))?;

        // compute s = randomness*pk
        let s = pk.clone().scalar_mul_le(randomness.iter())?;

        // compute c1 = randomness*generator
        let c1 = g.clone().scalar_mul_le(randomness.iter())?;

        let mut poseidon = PoseidonSpongeVar::new(cs.clone(), &self.params.poseidon);
        poseidon.absorb(&s)?;
        let dh = poseidon
            .squeeze_field_elements(1)
            .and_then(|r| Ok(r[0].clone()))?;

        c1.enforce_equal(&ciphertext.0)?;

        plaintext
            .into_iter()
            .map(|m| dh.clone() + m)
            .zip(ciphertext.1.iter())
            .map(|(c2, exp)| {
                let is_not_empty = exp.is_zero().unwrap().not();
                c2.conditional_enforce_equal(&exp, &is_not_empty)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|_| ())
    }

    pub(crate) fn ciphertext_var(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        mode: AllocationMode,
    ) -> Result<(CV, Vec<FpVar<C::BaseField>>), SynthesisError> {
        let c1 = CV::new_variable(ns!(cs, "ciphertext"), || Ok(self.enc.0), mode)?;
        let c2 = (0..self.params.n)
            .map(|i| {
                FpVar::<C::BaseField>::new_variable(
                    ns!(cs, "ciphertext"),
                    || Ok(self.enc.1.get(i).map_or(C::BaseField::zero(), |c| *c)),
                    mode,
                )
            })
            .collect::<Result<_, _>>()?;

        Ok((c1, c2))
    }
}

impl<C, CV> ConstraintSynthesizer<C::BaseField> for EncryptCircuit<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    C::BaseField: Absorb,
    CV: CurveVar<C, C::BaseField> + AllocVar<C, C::BaseField> + AbsorbGadget<C::BaseField>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let message = (0..self.params.n)
            .map(|i| {
                FpVar::<C::BaseField>::new_witness(ns!(cs, "plaintext"), || {
                    Ok(self.msg.get(i).map_or(C::BaseField::zero(), |c| c.clone()))
                })
            })
            .collect::<Result<_, _>>()?;
        let ciphertext = self.ciphertext_var(cs.clone(), AllocationMode::Input)?;

        self.verify_encryption(cs.clone(), &message, &ciphertext)
    }
}

#[cfg(test)]
mod test {
    use crate::{ark_from_bytes, ark_to_bytes, EncryptCircuit};
    use crate::{poseidon, Parameters};
    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_ec::ProjectiveCurve;
    use ark_ed_on_bls12_381::{
        constraints::EdwardsVar as CurveVar, EdwardsProjective as Curve, Fq, FrParameters,
    };
    // use ark_bls12_377::{
    //     constraints::G1Var as CurveVar, Fq, Fr, FrParameters, G1Projective as Curve,
    // };
    // use ark_bw6_761::BW6_761 as E;
    use ark_ff::{
        BigInteger, BigInteger256, Field, Fp256, One, PrimeField, ToConstraintField, Zero,
    };
    use ark_groth16::{Groth16, ProvingKey};
    use ark_nonnative_field::NonNativeFieldVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::prelude::{AllocVar, AllocationMode, Boolean, EqGadget, FieldVar};
    use ark_r1cs_std::{R1CSVar, ToBytesGadget, ToConstraintFieldGadget};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_sponge::constraints::AbsorbGadget;
    use ark_std::{test_rng, UniformRand};
    use std::borrow::Borrow;

    type TestEnc = EncryptCircuit<Curve, CurveVar>;

    #[test]
    fn test_elgamal_encryption() {
        let mut rng = test_rng();
        let params = Parameters::<Curve> {
            n: 1,
            poseidon: poseidon::get_poseidon_params::<Curve>(2),
        };

        let bytes = [1, 2, 3];
        let msg = Fq::from_random_bytes(&bytes).unwrap();

        let (sk, pk) = TestEnc::keygen(&mut rng).unwrap();

        let circuit =
            TestEnc::new(pk.clone(), vec![msg.clone()], params.clone(), &mut rng).unwrap();

        let plaintext = TestEnc::decrypt(circuit.enc, sk, &params).unwrap();

        assert_eq!(vec![msg], plaintext);
    }

    #[test]
    fn test_encryption_circuit() {
        pretty_env_logger::init();
        let mut rng = test_rng();
        let bytes = [1, 2, 3];
        let msg = vec![Fq::from_random_bytes(&bytes).unwrap()];

        let params = Parameters::<Curve> {
            n: 1,
            poseidon: poseidon::get_poseidon_params::<Curve>(2),
        };
        let (_, pub_key) = TestEnc::keygen(&mut rng).unwrap();

        let circuit = TestEnc::new(
            pub_key.clone(),
            msg.clone().into(),
            params.clone(),
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
            params.clone(),
            &mut rng,
        )
        .unwrap();
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let circuit = TestEnc::new(pub_key, msg.clone().into(), params.clone(), &mut rng).unwrap();
        let enc = circuit.enc.clone();
        let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();

        let valid_proof = TestEnc::verify_proof(&vk, proof, enc, &params).unwrap();
        assert!(valid_proof);
    }

    #[test]
    fn test_elgamal_keygen() {
        let mut rng = test_rng();

        let (sk, pk) = TestEnc::keygen(&mut rng).unwrap();

        let pk_bytes = ark_to_bytes(pk).unwrap();
        let sk_bytes = ark_to_bytes(sk.0).unwrap();

        println!("sk: {}", hex::encode(sk_bytes));
        println!("pk: {}", hex::encode(pk_bytes));
    }
}
