use crate::parameters::*;
use ark_bls12_377::Fq;
use ark_sponge::poseidon::PoseidonParameters;
use std::str::FromStr;

// returns optimized for constraints
pub fn get_bls12377_fq_params(_rate: usize) -> PoseidonParameters<Fq> {
    let arks = P1["ark"]
        .members()
        .map(|ark| {
            ark.members()
                .map(|v| Fq::from_str(v.as_str().unwrap()).unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let mds = P1["mds"]
        .members()
        .map(|m| {
            m.members()
                .map(|v| Fq::from_str(v.as_str().unwrap()).unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    PoseidonParameters::new(
        P1["full_rounds"].as_u32().unwrap(),
        P1["partial_rounds"].as_u32().unwrap(),
        P1["alpha"].as_u64().unwrap(),
        mds,
        arks,
    )
}
