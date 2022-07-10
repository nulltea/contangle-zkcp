use async_trait::async_trait;
use ecdsa_fun::Signature;
use ethers::prelude::{Address, H256};
use secp256kfun::{marker::*, Point, Scalar};

#[async_trait]
pub trait ChainProvider {
    type Tx;

    fn compose_tx(&self, from: Address, to: Address, amount: u64) -> (Self::Tx, H256);

    async fn sent_signed(&self, tx: Self::Tx, sig: &Signature) -> anyhow::Result<H256>;

    async fn get_signature(&self, hash: H256) -> anyhow::Result<Option<Signature>>;

    fn parse_amount<S: AsRef<str>>(&self, amount: S) -> anyhow::Result<u64>;
}
