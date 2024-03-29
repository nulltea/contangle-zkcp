use crate::poseidon::get_poseidon_params;
use crate::{Ciphertext, EncryptCircuit, Parameters, Plaintext, PublicKey};
use anyhow::anyhow;
use ark_circom::{CircomBuilder, CircomCircuit, CircomConfig};
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
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::PathBuf;
use std::str::FromStr;

pub struct CircomWrapper<E: PairingEngine, C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    CV: CurveVar<C, C::BaseField>,
{
    encryption: EncryptCircuit<C, CV>,
    circom: CircomCircuit<E, C>,
    shared_field: String,
}

impl<E, C, CV> CircomWrapper<E, C, CV>
where
    E: PairingEngine,
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    C::BaseField: Absorb,
    CV: CurveVar<C, C::BaseField> + AbsorbGadget<C::BaseField>,
    <C as ProjectiveCurve>::BaseField: From<<E as PairingEngine>::Fr>,
{
    pub fn new(
        encryption: EncryptCircuit<C, CV>,
        circom: CircomCircuit<E, C>,
        shared_field: String,
    ) -> Self {
        Self {
            encryption,
            circom,
            shared_field,
        }
    }

    pub fn get_public_inputs<CI: IntoIterator<Item = E::Fr>>(
        circom_signals: CI,
        cipher: &Ciphertext<C>,
        params: &Parameters<C>,
    ) -> Vec<E::Fr>
    where
        C::BaseField: ToConstraintField<E::Fr>,
        C: ToConstraintField<E::Fr>,
    {
        circom_signals
            .into_iter()
            .chain(EncryptCircuit::<C, CV>::get_public_inputs::<E>(
                cipher, params,
            ))
            .collect()
    }
}

impl<E, C, CV> ConstraintSynthesizer<C::BaseField> for CircomWrapper<E, C, CV>
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
        let (_, mut circom_witnesses) = self.circom.allocate_variables(cs.clone())?;
        let message = circom_witnesses
            .remove(&self.shared_field)
            .map_or(vec![], |vs| vs);
        self.circom.verify_linear_combinations(cs.clone())?;

        // let ciphertext = self
        //     .encryption
        //     .ciphertext_var(cs.clone(), AllocationMode::Input)?;
        //
        // self.encryption
        //     .verify_encryption(cs.clone(), &message, &ciphertext)

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::circom_wrapper::CircomWrapper;
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
    use serde_json::{Map, Value};
    use std::borrow::Borrow;
    use std::fs;

    type TestEnc = EncryptCircuit<Curve, CurveVar>;
    type TestCircuit = CircomWrapper<E, Curve, CurveVar>;

    #[test]
    fn test_circuit() {
        let mut rng = test_rng();
        let image_json = fs::read("../circom/zkPhoto/image/slice0.json").unwrap();
        let image = image_to_bytes(image_json).unwrap();
        let msg = image
            .into_iter()
            .map(|e| Fq::from(e as u128))
            .collect::<Vec<_>>();

        let params = Parameters::<Curve> {
            n: 49152,
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
        let build_property_verifier = |circuit: &str| {
            let mut cfg = CircomConfig::<E>::new(
                format!("../circom/build/{circuit}_js/{circuit}.wasm"),
                format!("../circom/build/{circuit}.r1cs"),
            )
            .unwrap();
            cfg.sanity_check = true;

            // Insert our public inputs as key value pairs
            let mut builder = CircomBuilder::<_, Curve>::new(cfg);
            msg.clone()
                .into_iter()
                .for_each(|m| builder.push_variable("in", m));
            vec![115, 119, 126, 109]
                .into_iter()
                .for_each(|e| builder.push_input("out", e));

            // Create an empty instance for setting it up
            let circom = builder.setup();

            // Get the populated instance of the circuit with the witness
            let circom = builder.build().unwrap();
            circom
        };
        let circuitName = "zkPhoto";
        let circuit = TestCircuit::new(
            enc_circuit,
            build_property_verifier(circuitName),
            "in".to_string(),
        );
        let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

        let enc_circuit = TestEnc::new(
            pub_key.clone(),
            msg.clone().into(),
            params.clone(),
            &mut rng,
        )
        .unwrap();
        let enc = enc_circuit.resulted_ciphertext.clone();

        let property_verifier = build_property_verifier(circuitName);
        let mut circom_inputs = property_verifier.get_public_inputs().unwrap();
        let circuit = TestCircuit::new(enc_circuit, property_verifier, "in".to_string());
        let proof = Groth16::prove(&pk, circuit, &mut rng).unwrap();

        let public_inputs = TestCircuit::get_public_inputs(circom_inputs, &enc, &params);
        let valid_proof = Groth16::<E>::verify(&vk, &public_inputs, &proof).unwrap();
        assert!(valid_proof);
    }

    pub fn image_to_bytes(input: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        let mut map: Map<String, Value> = serde_json::from_slice(&*input).unwrap();

        let colors: Vec<_> = map
            .remove("in")
            .unwrap()
            .as_array()
            .unwrap()
            .into_iter()
            .flat_map(|e| {
                e.as_array()
                    .unwrap()
                    .into_iter()
                    .map(|ei| ei.as_u64().unwrap() as u8)
            })
            .collect();
        Ok(colors)
    }
}
