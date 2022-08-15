use halo2_gadgets::ecc::FixedPoints;
use pasta_curves::pallas;
use std::fmt::{Debug, Formatter};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PkiFixedBases;

impl FixedPoints<pallas::Affine> for PkiFixedBases {
    type FullScalar = ();
    type ShortScalar = ();
    type Base = ();
}
