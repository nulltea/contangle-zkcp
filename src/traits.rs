use async_trait::async_trait;
use ecdsa_fun::Signature;
use ethers::prelude::{Address, H256};
use secp256kfun::{Point, Scalar, marker::*};

#[async_trait]
pub trait ChainProvider {
    type Tx;
    type Error;

    fn compose_tx(&self, from: Address, to: Address, amount: f64) -> (Self::Tx, Vec<u8>);

    async fn sent_signed(&self, tx: Self::Tx, sig: &Signature) -> Result<H256, Self::Error>;

    async fn get_signature(&self, hash: H256) -> Result<Option<Signature>, Self::Error>;
}

#[async_trait]
pub trait WalletProvider {
    fn pub_key(&self) -> &Point;
    fn sec_key(&self) -> &Scalar;
    fn address(&self) -> Address;
}
