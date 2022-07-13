use ark_crypto_primitives::encryption::elgamal::Parameters;
use ark_ec::TEModelParameters;
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsParameters, EdwardsProjective as JubJub};
use lazy_static::lazy_static;
lazy_static! {
    pub static ref JUB_JUB_PARAMETERS: Parameters<JubJub> = Parameters {
        generator: EdwardsAffine::new(
            EdwardsParameters::AFFINE_GENERATOR_COEFFS.0,
            EdwardsParameters::AFFINE_GENERATOR_COEFFS.1,
        ),
    };
}
