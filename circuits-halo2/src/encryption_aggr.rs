#[cfg(test)]
mod tests {
    use crate::encryption::ElGamalCircuit;
    use ark_std::test_rng;
    use halo2_snark_aggregator_circuit::sample_circuit::sample_circuit_setup;
    use pairing_bn256::bn256::{Bn256, G1Affine};
    use std::path::PathBuf;

    // #[test]
    // fn test_circuit_elgmal() {
    //     let mut rng = test_rng();
    //
    //     sample_circuit_setup::<G1Affine, Bn256, ElGamalCircuit<G1Affine>>(PathBuf::from("./"));
    // }
}
