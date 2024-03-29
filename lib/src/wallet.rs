use crate::utils::keypair_from_hex;
use crate::{keypair_gen, read_from_keystore};
use secp256kfun::{Point, Scalar};
use std::path::Path;

pub struct LocalWallet {
    sk: Scalar,
    pk: Point,
}

impl LocalWallet {
    pub fn new() -> anyhow::Result<Self> {
        let (sk, pk) = keypair_gen();
        Ok(Self { sk, pk })
    }

    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        let (sk, pk) = keypair_from_hex(hex)?;
        Ok(Self { sk, pk })
    }

    pub fn from_keystore<P: AsRef<Path>, S: AsRef<[u8]>>(
        path: P,
        password: S,
    ) -> anyhow::Result<Self> {
        let (sk, pk) = read_from_keystore(path, password)?;
        Ok(Self { sk, pk })
    }

    pub fn pub_key(&self) -> &Point {
        &self.pk
    }

    pub fn sec_key(&self) -> &Scalar {
        &self.sk
    }
}
