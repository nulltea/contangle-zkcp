use halo2_snark_aggregator_circuit::fs::*;
use halo2_snark_aggregator_circuit::sample_circuit::{
    sample_circuit_random_run, sample_circuit_setup, TargetCircuit,
};
use halo2_snark_aggregator_circuit::verify_circuit::{
    load_instances, CreateProof, Halo2VerifierCircuit, MultiCircuitsCreateProof,
    MultiCircuitsSetup, Setup, SingleProofPair, SingleProofWitness, VerifyCheck,
};
use pairing_bn256::bn256::{Bn256, Fr, G1Affine};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::ElGamalCircuit;
    use anyhow::anyhow;
    use ark_std::test_rng;
    use halo2_proofs::arithmetic::Field;
    use std::path::PathBuf;

    // #[test]
    // fn test_circuit_elgmal() {
    //     let mut rng = test_rng();
    //
    //     sample_circuit_setup::<G1Affine, Bn256, ElGamalCircuit<G1Affine>>(PathBuf::from("./"));
    // }
}
