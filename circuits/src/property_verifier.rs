use crate::poseidon::get_poseidon_params;
use crate::{Ciphertext, EncryptCircuit, Parameters};
use anyhow::anyhow;
use ark_circom::CircomCircuit;
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

pub struct Property<E: PairingEngine, C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    encryption: EncryptCircuit<C, CV>,
    property_verifier: CircomCircuit<E, C>,
}

impl<E, C, CV> Property<E, C, CV>
where
    E: PairingEngine,
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField> + AbsorbGadget<C::BaseField>,
    <C as ProjectiveCurve>::BaseField: From<<E as PairingEngine>::Fr>,
{
    pub fn new(
        encryption: EncryptCircuit<C, CV>,
        property_verifier: CircomCircuit<E, C>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            encryption,
            property_verifier,
        })
    }

    pub fn verify_proof<CI: IntoIterator<Item = E::Fr>>(
        vk: &VerifyingKey<E>,
        proof: Proof<E>,
        circom_signals: CI,
        cipher: Ciphertext<C>,
        params: &Parameters<C>,
    ) -> anyhow::Result<bool>
    where
        C::BaseField: ToConstraintField<E::Fr>,
        C: ToConstraintField<E::Fr>,
    {
        //let commit = Self::commit_to_inputs(&cipher, &params);
        let c1_inputs = cipher.0.to_field_elements().unwrap();
        let c2_inputs = (0..params.n)
            .map(|i| cipher.1.get(i).map_or(C::BaseField::zero(), |&c| c))
            .flat_map(|c2| c2.to_field_elements().unwrap());
        let public_inputs = circom_signals
            .into_iter()
            .chain(c1_inputs)
            .chain(c2_inputs)
            .collect::<Vec<_>>();

        Groth16::<E>::verify(&vk, &public_inputs, &proof)
            .map_err(|e| anyhow!("error verifying proof: {e}"))
    }
}

impl<E, C, CV> ConstraintSynthesizer<C::BaseField> for Property<E, C, CV>
where
    E: PairingEngine,
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    C::BaseField: Absorb,
    CV: CurveVar<C, C::BaseField> + AbsorbGadget<C::BaseField>,
    <C as ProjectiveCurve>::BaseField: From<<E as PairingEngine>::Fr>,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let (_, message) = self.property_verifier.allocate_variables(cs.clone())?;
        self.property_verifier.generate_constraints(cs.clone())?;

        let ciphertext = self
            .encryption
            .ciphertext_var(cs.clone(), AllocationMode::Input)?;

        self.encryption
            .verify_encryption(cs.clone(), &message, &ciphertext)
    }
}

#[cfg(test)]
mod test {
    use crate::property_verifier::Property;
    use crate::{ark_from_bytes, ark_to_bytes, EncryptCircuit};
    use crate::{poseidon, Parameters};
    use ark_bls12_381::Bls12_381 as E;
    use ark_circom::{CircomBuilder, CircomConfig};
    use ark_ec::ProjectiveCurve;
    use ark_ed_on_bls12_381::{
        constraints::EdwardsVar as CurveVar, EdwardsProjective as Curve, Fq, Fr, FrParameters,
    };
    use ark_ff::{
        BigInteger, BigInteger256, Field, Fp256, One, PrimeField, ToConstraintField, Zero,
    };
    use ark_groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
        Groth16, ProvingKey,
    };
    use ark_nonnative_field::NonNativeFieldVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::prelude::{AllocVar, AllocationMode, Boolean, EqGadget, FieldVar};
    use ark_r1cs_std::{R1CSVar, ToBytesGadget, ToConstraintFieldGadget};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_sponge::constraints::AbsorbGadget;
    use ark_sponge::poseidon::PoseidonSponge;
    use ark_sponge::CryptographicSponge;
    use ark_std::{test_rng, UniformRand};
    use std::borrow::Borrow;

    type TestEnc = EncryptCircuit<Curve, CurveVar>;
    type TestCircuit = Property<E, Curve, CurveVar>;

    #[test]
    fn test_circuit() {
        let mut rng = test_rng();
        let bytes = [2];
        let msg = vec![Fq::from_random_bytes(&bytes).unwrap()];

        let params = Parameters::<Curve> {
            n: 1,
            poseidon: poseidon::get_poseidon_params::<Curve>(2),
        };
        let (_, pub_key) = TestEnc::keygen(&mut rng).unwrap();

        let enc_circuit = TestEnc::new(
            pub_key.clone(),
            msg.clone().into(),
            params.clone(),
            &mut rng,
        )
        .unwrap();
        let build_property_verifier = || {
            let mut cfg = CircomConfig::<E>::new(
                "../circom/build/dummy_js/dummy.wasm",
                "../circom/build/dummy.r1cs",
            )
            .unwrap();
            cfg.sanity_check = true;

            // Insert our public inputs as key value pairs
            let mut builder = CircomBuilder::<_, Curve>::new(cfg);
            // (0..10).for_each(|i| builder.push_input("plaintext", i));
            msg.clone()
                .into_iter()
                .for_each(|m| builder.push_variable("plaintext", m));
            builder.push_input("challenge", 4);

            // Create an empty instance for setting it up
            let circom = builder.setup();

            // Get the populated instance of the circuit with the witness
            let circom = builder.build().unwrap();
            circom
        };
        let circuit = TestCircuit::new(enc_circuit, build_property_verifier()).unwrap();
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let enc_circuit = TestEnc::new(
            pub_key.clone(),
            msg.clone().into(),
            params.clone(),
            &mut rng,
        )
        .unwrap();
        let enc = enc_circuit.enc.clone();

        let property_verifier = build_property_verifier();
        let mut circom_inputs = property_verifier.get_public_inputs().unwrap();
        let circuit = TestCircuit::new(enc_circuit, property_verifier).unwrap();
        let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();

        let valid_proof =
            TestCircuit::verify_proof(&vk, proof, circom_inputs, enc, &params).unwrap();
        assert!(valid_proof);
    }

    // #[test]
    // fn test_poseidon_hash() {
    //     let rng = &mut test_rng();
    //
    //     let cs = ConstraintSystem::<Fq>::new_ref();
    //     let mut poseidon =
    //         PoseidonSponge::<Fq>::new(&crate::poseidon::get_poseidon_params::<Curve>(2));
    //     poseidon.absorb(&Fq::zero());
    //     let hash = poseidon.squeeze_field_elements::<Fq>(1).remove(0);
    //
    //     let hash_bytes = ark_to_bytes(hash).unwrap();
    //     println!("{}", hex::encode(hash_bytes));
    // }
}
