use crate::add_chip::{AddChip, AddConfig};
use crate::constants::PkiFixedBases;
use group::prime::PrimeCurveAffine;
use group::{Curve, Group};
use halo2_gadgets::ecc::chip::{EccChip, EccConfig};
use halo2_gadgets::ecc::{EccInstructions, FixedPoints, Point, ScalarVar};
use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength},
    Hash as PoseidonHash, PoseidonSpongeInstructions, Pow5Chip as PoseidonChip,
    Pow5Config as PoseidonConfig,
};
use halo2_gadgets::utilities::lookup_range_check::LookupRangeCheckConfig;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pasta::Fp;
use halo2_proofs::plonk;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error};
use pasta_curves::{arithmetic::CurveAffine, pallas};
use std::ops::Mul;

/// An instruction set for adding two circuit words (field elements).
pub trait AddInstruction<F: FieldExt>: Chip<F> {
    /// Constraints `a + b` and returns the sum.
    fn add(
        &self,
        layouter: impl Layouter<F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, plonk::Error>;
}

#[derive(Debug, Clone)]
struct ElGamalChip {
    config: ElGamalConfig,
    ecc: EccChip<PkiFixedBases>,
    poseidon: PoseidonChip<Fp, 1, 2>,
    add: AddChip,
}

#[derive(Debug, Clone)]
struct ElGamalConfig {
    ecc_config: EccConfig<PkiFixedBases>,
    poseidon_config: PoseidonConfig<Fp, 1, 2>,
    add_config: AddConfig,
    plaintext_col: Column<Advice>,
    ciphertext_col: Column<Advice>,
}

impl Chip<pallas::Base> for ElGamalChip {
    type Config = ElGamalConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl ElGamalChip {
    fn new(p: ElGamalConfig) -> ElGamalChip {
        ElGamalChip {
            ecc: EccChip::construct(p.ecc_config.clone()),
            poseidon: PoseidonChip::construct(p.poseidon_config.clone()),
            add: AddChip::construct(p.add_config.clone()),
            config: p,
        }
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> ElGamalConfig {
        let advices = [meta.advice_column(); 10];
        let lagrange_coeffs = [meta.fixed_column(); 8];
        // Shared fixed column for loading constants
        let constants = meta.fixed_column();
        meta.enable_constant(constants);

        let range_check =
            LookupRangeCheckConfig::<_, 10>::configure(meta, advices[9], lookup_table);
        let ecc_config =
            EccChip::<PkiFixedBases>::configure(meta, advices, lagrange_coeffs, range_check);

        let poseidon_config::<_, _, 2> = PoseidonChip::configure(
            meta,
            [meta.advice_column()],
            meta.advice_column(),
            [meta.fixed_column()],
            [meta.fixed_column()],
        );

        let plaintext_col = meta.advice_column();
        let ciphertext_col = meta.advice_column();
        let add_config =
            AddChip::configure(meta, meta.advice_column(), plaintext_col, ciphertext_col);

        ElGamalConfig {
            poseidon_config,
            ecc_config,
            add_config,
            plaintext_col,
            ciphertext_col,
        }
    }
}

#[derive(Default)]
struct ElGamalGadget {
    r: pallas::Scalar,
    msg: pallas::Base,
    pk: pallas::Affine,
    pub resulted_ciphertext: (pallas::Affine, pallas::Base),
}

impl ElGamalGadget {
    pub(crate) fn verify_encryption<
        PoseidonChip: PoseidonSpongeInstructions<pallas::Base, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>,
        AddChip: AddInstruction<pallas::Base>,
        EccChip: EccInstructions<
            pallas::Affine,
            FixedPoints = OrchardFixedBases,
            Var = AssignedCell<pallas::Base, pallas::Base>,
        >,
    >(
        mut layouter: impl Layouter<pallas::Base>,
        poseidon_chip: PoseidonChip,
        add_chip: AddChip,
        ecc_chip: EccChip,
        rnd: pallas::Scalar,
        pk: &Point<pallas::Affine, EccChip>,
        m: &AssignedCell<pallas::Base, pallas::Base>,
    ) -> Result<
        (
            Point<pallas::Affine, EccChip>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        plonk::Error,
    > {
        let g = pallas::Point::generator();
        let rand = ecc_chip
            .witness_scalar_var(&mut layouter, Value::known(rnd))
            .unwrap();

        // compute s = randomness*pk
        let (s, _) = ecc_chip.mul(&mut layouter, &rand, pk).unwrap();

        // compute c1 = randomness*generator
        let c1 = g.mul(rnd).to_affine();
        let c1 = ecc_chip
            .witness_point(&mut layouter, Value::known(c1))
            .unwrap();

        // dh = poseidon_hash(randomness*pk)
        let dh = {
            let poseidon_message = [s.x(), s.y()];
            let poseidon_hasher =
                PoseidonHash::init(poseidon_chip, layouter.namespace(|| "Poseidon init"))?;
            poseidon_hasher.hash(
                layouter.namespace(|| "Poseidon hash (randomness*pk)"),
                poseidon_message,
            )?
        };

        // Add hash output to psi.
        // `scalar` = poseidon_hash(nk, rho) + psi.
        let c2 = add_chip.add(
            layouter.namespace(|| "c2 = poseidon_hash(randomness*pk) + m"),
            &dh,
            m,
        )?;

        Ok((c1, c2))
    }
}

impl Circuit<pallas::Base> for ElGamalGadget {
    type Config = ElGamalConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    //type Config = EccConfig;
    fn configure(cs: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        ElGamalChip::configure(cs)
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let chip = ElGamalChip::new(config.clone());

        let pk_var = chip
            .ecc
            .witness_point(&mut layouter, Value::known(self.pk.to_affine()))?;
        let msg_var = layouter.assign_region(
            || "plaintext",
            |mut region| region.assign_advice(|| "plaintext", config.plaintext_col, 0, || msg),
        );

        let (c1, c2) = ElGamalGadget::verify_encryption(
            &mut layouter,
            chip.poseidon,
            chip.add,
            chip.ecc,
            self.r,
            &pk_var,
            &msg_var,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_circuit_elgmal() {
        let circuit: ElGamalGadget = ElGamalGadget {
            r: Default::default(),
            msg: Default::default(),
            pk: Default::default(),
            resulted_ciphertext: (Default::default(), Default::default()),
        };
        let prover = MockProver::run(12, &circuit, vec![]).unwrap();
    }
}
