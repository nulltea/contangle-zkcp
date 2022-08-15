use crate::zk::VerifiableEncryption;
use async_trait::async_trait;
use ecdsa_fun::Signature;
use ethers::prelude::{Address, H256};
use secp256kfun::Point;

#[async_trait]
pub trait ChainProvider {
    type Tx;

    fn compose_tx(
        &self,
        from: Address,
        to: Address,
        amount: f64,
    ) -> anyhow::Result<(Self::Tx, H256)>;

    async fn sent_signed(&self, tx: Self::Tx, sig: &Signature) -> anyhow::Result<H256>;

    async fn get_signature(&self, hash: H256) -> anyhow::Result<Option<Signature>>;

    fn address_from_pk(&self, pk: &Point) -> Address;
}

#[async_trait]
pub trait CipherHost {
    async fn write(&mut self, proof: VerifiableEncryption) -> anyhow::Result<()>;

    async fn read(&self) -> anyhow::Result<VerifiableEncryption>;

    async fn is_hosted(&self) -> anyhow::Result<bool>;
}

#[async_trait]
pub trait CipherDownloader {
    async fn download(&self) -> anyhow::Result<VerifiableEncryption>;
}

pub trait DataAdaptor {}
