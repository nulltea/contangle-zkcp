use ethers::prelude::Address;
use ethers::utils::keccak256;
use secp256kfun::{Point, Scalar};
use crate::traits::WalletProvider;
use crate::utils::keypair_from;

struct HexWallet {
    sk: Scalar,
    pk: Point,
}

impl HexWallet {
    pub fn new(hex: &str) -> anyhow::Result<Self> {
        let (sk, pk) = keypair_from(hex)?;
        Ok(Self{ sk, pk })
    }
}

impl WalletProvider for HexWallet {
    fn pub_key(&self) -> &Point {
        &self.pk
    }

    fn sec_key(&self) -> &Scalar {
        &self.sk
    }

    fn address(&self) -> Address {
        Address::from_slice(&*keccak256(self.pk.to_bytes()))
    }
}
