use crate::poseidon::get_poseidon_params;
use crate::{Ciphertext, EncryptCircuit, Parameters, SecretKey};
use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
use ark_crypto_primitives::crh::poseidon::constraints::{CRHGadget, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::{poseidon, TwoToOneCRHSchemeGadget};
use ark_crypto_primitives::merkle_tree::{
    constraints::{ConfigGadget, PathVar},
    Config, IdentityDigestConverter, LeafParam, TwoToOneParam,
};
use ark_crypto_primitives::{merkle_tree, CRHSchemeGadget, MerkleTree};
use ark_ec::ProjectiveCurve;
use ark_ff::{to_bytes, PrimeField};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::R1CSVar;
use ark_relations::ns;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_sponge::constraints::{AbsorbGadget, CryptographicSpongeVar};
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_sponge::poseidon::PoseidonParameters;
use ark_sponge::Absorb;
use std::collections::HashMap;
use std::marker::PhantomData;

pub(crate) struct MTConfig<C> {
    _c: PhantomData<C>,
}
impl<C: ProjectiveCurve> Config for MTConfig<C>
where
    C::BaseField: PrimeField,
    C::BaseField: Absorb,
{
    type Leaf = [C::BaseField];
    type LeafDigest = C::BaseField;
    type LeafInnerDigestConverter = IdentityDigestConverter<C::BaseField>;
    type InnerDigest = C::BaseField;
    type LeafHash = poseidon::CRH<C::BaseField>;
    type TwoToOneHash = poseidon::TwoToOneCRH<C::BaseField>;
}

impl<C: ProjectiveCurve> ConfigGadget<Self, C::BaseField> for MTConfig<C>
where
    C::BaseField: PrimeField,
    C::BaseField: Absorb,
{
    type Leaf = [FpVar<C::BaseField>];
    type LeafDigest = FpVar<C::BaseField>;
    type LeafInnerConverter = IdentityDigestConverter<FpVar<C::BaseField>>;
    type InnerDigest = FpVar<C::BaseField>;
    type LeafHash = CRHGadget<C::BaseField>;
    type TwoToOneHash = TwoToOneCRHGadget<C::BaseField>;
}

pub struct MTHashParametersVar<CF: PrimeField, MT: Config, MTG: ConfigGadget<MT, CF>> {
    /// parameter for leaf hash function
    pub leaf_params: <<MTG as ConfigGadget<MT, CF>>::LeafHash as CRHSchemeGadget<
        <MT as Config>::LeafHash,
        CF,
    >>::ParametersVar,
    /// parameter for two-to-one hash function
    pub inner_params: <<MTG as ConfigGadget<MT, CF>>::TwoToOneHash as TwoToOneCRHSchemeGadget<
        <MT as Config>::TwoToOneHash,
        CF,
    >>::ParametersVar,
}

pub struct SampleEntries<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField + Absorb,
{
    ciphertext: Ciphertext<C>,
    merkle_root: C::BaseField,
    merkle_path: merkle_tree::Path<MTConfig<C>>,
    sample_idx: usize,
    sample_leaf: C::BaseField,
    pub sample_value: C::BaseField,
    sk: SecretKey<C>,
    hash_params: PoseidonParameters<C::BaseField>,
    _curve_var: PhantomData<CV>,
}

impl<C, CV> SampleEntries<C, CV>
where
    C: ProjectiveCurve,
    C::BaseField: PrimeField,
    C::Affine: Absorb,
    C::BaseField: Absorb,
    CV: CurveVar<C, C::BaseField> + AbsorbGadget<C::BaseField>,
{
    pub fn new(
        ciphertext: Ciphertext<C>,
        sk: SecretKey<C>,
        sample_idx: usize,
        hash_params: PoseidonParameters<C::BaseField>,
    ) -> Self {
        let leaves = ciphertext.1.clone().into_iter().map(|e| vec![e]);
        let tree = MerkleTree::new(&hash_params, &hash_params, leaves).unwrap();
        let merkle_root = tree.root();
        let sample_leaf = ciphertext.1[sample_idx].clone();
        let merkle_path = tree.generate_proof(sample_idx).unwrap();

        let sample_value = EncryptCircuit::<C, CV>::decrypt_at(
            &ciphertext,
            sample_idx,
            sk,
            &Parameters::<C> {
                n: 1,
                poseidon: hash_params.clone(),
            },
        )
        .unwrap();

        Self {
            ciphertext,
            merkle_root,
            merkle_path,
            sample_idx,
            sample_leaf,
            sample_value,
            sk,
            hash_params,
            _curve_var: PhantomData,
        }
    }

    fn verify_membership(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let poseidon_param_var =
            CRHParametersVar::new_constant(cs.clone(), &self.hash_params).unwrap();

        let hash_param_var = MTHashParametersVar::<C::BaseField, MTConfig<C>, MTConfig<C>> {
            leaf_params: poseidon_param_var.clone(),
            inner_params: poseidon_param_var.clone(),
        };

        let path_var = PathVar::<MTConfig<C>, C::BaseField, MTConfig<C>>::new_witness(
            ns!(cs, "path_var"),
            || Ok(&self.merkle_path),
        )?;

        let merkle_root_var =
            FpVar::<C::BaseField>::new_input(ns!(cs, "merkle_root"), || Ok(&self.merkle_root))?;
        let sample_leaf_var =
            FpVar::<C::BaseField>::new_witness(ns!(cs, "sample_leaf"), || Ok(&self.sample_leaf))?;

        let is_member = path_var
            .verify_membership(
                &hash_param_var.leaf_params,
                &hash_param_var.inner_params,
                &merkle_root_var,
                &[sample_leaf_var],
            )
            .unwrap();

        is_member.enforce_equal(&Boolean::TRUE)
    }

    fn compare_decrypted(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        ciphertext: (CV, Vec<FpVar<C::BaseField>>),
        sample_val: FpVar<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let c1 = ciphertext.0;
        let c2 = &ciphertext.1[self.sample_idx];

        let sk = to_bytes![&self.sk].unwrap();
        let sk = UInt8::new_witness_vec(ns!(cs, "secret_key"), &sk)?
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        let s = c1.scalar_mul_le(sk.iter())?;

        let mut poseidon = PoseidonSpongeVar::new(cs.clone(), &self.hash_params);
        poseidon.absorb(&s)?;
        let dh = poseidon
            .squeeze_field_elements(1)
            .and_then(|r| Ok(r[0].clone()))?;

        let decrypted = c2 - dh;

        decrypted.enforce_equal(&sample_val)
    }

    pub(crate) fn ciphertext_var(
        &self,
        cs: ConstraintSystemRef<C::BaseField>,
        mode: AllocationMode,
    ) -> Result<(CV, Vec<FpVar<C::BaseField>>), SynthesisError> {
        let c1 = CV::new_variable(ns!(cs, "ciphertext"), || Ok(self.ciphertext.0), mode)?;
        let c2 = self
            .ciphertext
            .1
            .iter()
            .map(|c| {
                FpVar::<C::BaseField>::new_variable(ns!(cs, "ciphertext"), || Ok(c.clone()), mode)
            })
            .collect::<Result<_, _>>()?;

        Ok((c1, c2))
    }
}

impl<C, CV> ConstraintSynthesizer<C::BaseField> for SampleEntries<C, CV>
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
        let sample_value =
            FpVar::<C::BaseField>::new_input(ns!(cs, "sample_entry"), || Ok(self.sample_value))?;
        let ciphertext = self.ciphertext_var(cs.clone(), AllocationMode::Input)?;

        self.verify_membership(cs.clone())?;

        self.compare_decrypted(cs.clone(), ciphertext, sample_value)
    }
}

#[cfg(test)]
mod test {
    use crate::poseidon::get_poseidon_params;
    use crate::sample_entries::SampleEntries;
    use crate::{ark_from_bytes, ark_to_bytes, EncryptCircuit};
    use crate::{poseidon, Parameters};
    use ark_bls12_381::{Bls12_381 as E, Fr};
    use ark_ec::ProjectiveCurve;
    use ark_ed_on_bls12_381::{
        constraints::EdwardsVar as CurveVar, EdwardsProjective as Curve, Fq, FrParameters,
    };
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
    fn test_merkle_tree() {
        let mut rng = ark_std::test_rng();

        let (sek_key, pub_key) = TestEnc::keygen(&mut rng).unwrap();

        let params = Parameters::<Curve> {
            n: 4,
            poseidon: poseidon::get_poseidon_params::<Curve>(2),
        };

        let plaintext = vec![
            Fq::new(BigInteger256::from(1)),
            Fq::new(BigInteger256::from(2)),
            Fq::new(BigInteger256::from(3)),
            Fq::new(BigInteger256::from(4)),
        ];

        let ciphertext = TestEnc::new(pub_key, plaintext, params.clone(), &mut rng)
            .unwrap()
            .resulted_ciphertext;

        let se = SampleEntries::<Curve, CurveVar>::new(ciphertext, sek_key, 1, params.poseidon);
        let cs = ConstraintSystem::<Fq>::new_ref();
        se.generate_constraints(cs.clone()).unwrap();
        println!("Num constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }
}
