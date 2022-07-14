use crate::elgamal::{Ciphertext, HashElGamal, Parameters, Plaintext, PublicKey, Randomness};
use ark_ec::ProjectiveCurve;
use ark_ff::{
    fields::{Field, PrimeField},
    to_bytes, BigInteger, ToConstraintField, Zero,
};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::ToConstraintFieldGadget;
use ark_relations::r1cs::{ConstraintSystemRef, Namespace, SynthesisError};
use ark_sponge::constraints::{AbsorbGadget, CryptographicSpongeVar};
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_sponge::poseidon::PoseidonParameters;
use ark_sponge::Absorb;
use ark_std::{borrow::Borrow, marker::PhantomData, vec::Vec};
use derivative::Derivative;

pub type ConstraintF<C> = <C as ProjectiveCurve>::BaseField;

#[derive(Clone, Debug)]
pub struct RandomnessVar<F: Field>(Vec<UInt8<F>>);

impl<C, F> AllocVar<Randomness<C>, F> for RandomnessVar<F>
where
    C: ProjectiveCurve,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Randomness<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let r = to_bytes![&f().map(|b| b.borrow().0).unwrap_or(C::ScalarField::zero())].unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct ParametersVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    C::BaseField: PrimeField,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    generator: GG,
    poseidon: PoseidonParameters<C::BaseField>,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GG>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let prep = f().map(|g| (g.borrow().generator, g.borrow().poseidon.clone()));
        let poseidon = prep.as_ref().map(|g| g.borrow().1.clone()).unwrap();
        let generator = GG::new_variable(cs, || prep.map(|g| g.borrow().0), mode)?;
        Ok(Self {
            generator,
            poseidon,
            _curve: PhantomData,
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct PublicKeyVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub pk: GG,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GG>
where
    C: ProjectiveCurve,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pk = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            pk,
            _curve: PhantomData,
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: ProjectiveCurve"))]
pub struct PlaintextVar<C: ProjectiveCurve>
where
    C::BaseField: PrimeField,
{
    pub plaintext: NonNativeFieldVar<Plaintext<C>, ConstraintF<C>>,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C> AllocVar<Plaintext<C>, ConstraintF<C>> for PlaintextVar<C>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
{
    fn new_variable<T: Borrow<Plaintext<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let plaintext = NonNativeFieldVar::<Plaintext<C>, C::BaseField>::new_variable(cs, f, mode)?;
        Ok(Self {
            plaintext,
            _curve: PhantomData,
        })
    }
}

#[derive(Derivative, Debug)]
#[derivative(Clone(bound = "C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>"))]
pub struct OutputVar<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    C::BaseField: PrimeField,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub c1: GG,
    pub c2: NonNativeFieldVar<C::ScalarField, C::BaseField>,
    #[doc(hidden)]
    _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Ciphertext<C>, ConstraintF<C>> for OutputVar<C, GG>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    GG: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn new_variable<T: Borrow<Ciphertext<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| *g.borrow());
        let c1 = GG::new_variable(cs.clone(), || prep.map(|g| g.borrow().0), mode)?;

        let c2 = NonNativeFieldVar::<C::ScalarField, C::BaseField>::new_variable(
            cs.clone(),
            || prep.map(|g| g.borrow().1),
            mode,
        )?;
        // let scalar_in_fq = &C::BaseField::from_repr(<C::ScalarField as PrimeField>::BigInt::from_bits_le(
        //     &native.into_repr().to_bits_le(),
        // ))
        //     .unwrap();

        // c2
        //     .to_constraint_field()
        //     .unwrap()
        //     .into_iter()
        //     .map(|e| e.value().unwrap())
        //     .collect::<Vec<_>>();
        Ok(Self {
            c1,
            c2,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for OutputVar<C, GC>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.c1.is_eq(&other.c1)?.and(&self.c2.is_eq(&other.c2)?)
    }
}

pub struct HashElGamalEncGadget<C: ProjectiveCurve, GG: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    #[doc(hidden)]
    _curve: PhantomData<*const C>,
    _group_var: PhantomData<*const GG>,
}

impl<C, GG> HashElGamalEncGadget<C, GG>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb, // needed for Poseidon sponge
    GG: CurveVar<C, ConstraintF<C>> + AllocVar<C, ConstraintF<C>> + AbsorbGadget<ConstraintF<C>>,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub(crate) fn encrypt(
        cs: ConstraintSystemRef<C::BaseField>,
        parameters: &ParametersVar<C, GG>,
        message: &PlaintextVar<C>,
        randomness: &RandomnessVar<ConstraintF<C>>,
        public_key: &PublicKeyVar<C, GG>,
    ) -> Result<OutputVar<C, GG>, SynthesisError> {
        // flatten randomness to little-endian bit vector
        let randomness = randomness
            .0
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        // compute s = randomness*pk
        let s = public_key.pk.clone().scalar_mul_le(randomness.iter())?;

        // compute c1 = randomness*generator
        let c1 = parameters
            .generator
            .clone()
            .scalar_mul_le(randomness.iter())?;

        let mut poseidon = PoseidonSpongeVar::new(cs.clone(), &parameters.poseidon);
        // TODO: this absorbs both X and Y and Infinity symbol making 3
        // vars per hash, which is way too much - we only need x
        // Making this is hard because of the type system.
        poseidon.absorb(&s)?;
        let c2 = poseidon
            .squeeze_nonnative_field_elements::<C::ScalarField>(1)
            .and_then(|r| Ok(r.0[0].clone() + &message.plaintext))?;

        Ok(OutputVar::<C, GG> {
            c1,
            c2,
            _curve: PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use ark_crypto_primitives::encryption::constraints::AsymmetricEncryptionGadget;
    use ark_std::{test_rng, UniformRand};

    use ark_bls12_377::{constraints::G1Var, Fq, Fr, G1Projective as Bls12377};
    use ark_ff::{Field, ToConstraintField};

    use crate::elgamal::constraints::{
        OutputVar, ParametersVar, PlaintextVar, PublicKeyVar, RandomnessVar,
    };
    use crate::elgamal::{
        constraints::HashElGamalEncGadget, poseidon, HashElGamal, Parameters, Randomness,
    };
    use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
    use ark_ec::ProjectiveCurve;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_elgamal_gadget() {
        let rng = &mut test_rng();

        type MyEnc = HashElGamal<Bls12377>;
        type MyGadget = HashElGamalEncGadget<Bls12377, G1Var>;

        // compute primitive result
        let parameters = Parameters::<Bls12377> {
            generator: Bls12377::prime_subgroup_generator(),
            poseidon: poseidon::get_bls12377_fq_params(2),
        };
        let (pk, _) = MyEnc::keygen(&parameters, rng).unwrap();
        // get msg and encryption randomness
        let bytes = [1, 2, 3];
        let msg = Fr::from_random_bytes(&bytes).unwrap();
        let r = Randomness::rand(rng);
        let primitive_result = MyEnc::encrypt(&parameters, &pk, &msg, &r).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let randomness_var =
            RandomnessVar::<Fq>::new_witness(ark_relations::ns!(cs, "gadget_randomness"), || {
                Ok(&r)
            })
            .unwrap();
        let parameters_var = ParametersVar::<Bls12377, G1Var>::new_constant(
            ark_relations::ns!(cs, "gadget_parameters"),
            &parameters,
        )
        .unwrap();
        let msg_var =
            PlaintextVar::<Bls12377>::new_witness(ark_relations::ns!(cs, "gadget_message"), || {
                Ok(&msg)
            })
            .unwrap();
        let pk_var = PublicKeyVar::<Bls12377, G1Var>::new_witness(
            ark_relations::ns!(cs, "gadget_public_key"),
            || Ok(&pk),
        )
        .unwrap();

        // use gadget
        let result_var = MyGadget::encrypt(
            cs.clone(),
            &parameters_var,
            &msg_var,
            &randomness_var,
            &pk_var,
        )
        .unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var = OutputVar::<Bls12377, G1Var>::new_input(
            ark_relations::ns!(cs, "gadget_expected"),
            || Ok(&primitive_result),
        )
        .unwrap();
        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(primitive_result.0, result_var.c1.value().unwrap());
        assert_eq!(primitive_result.1, result_var.c2.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
