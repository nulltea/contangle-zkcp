use async_trait::async_trait;
use core::panicking::panic;
use anyhow::anyhow;
use crate::traits::ChainProvider;
use ethers::prelude::*;
use ethers::utils::parse_ether;
use secp256kfun::{Scalar, marker::*};
use url::Url;

struct EthereumProvider {
    provider: Provider<Http>,
    chain_id: u64
}

impl EthereumProvider {
    pub async fn new(url: impl Into<Url>) -> Self {
        let provider = Provider::new(Http::new(url));
        let chain_id = provider.get_chainid().await.unwrap();

        Self{
            provider,
            chain_id: chain_id.as_u64()
        }
    }
}

#[async_trait]
impl ChainProvider for EthereumProvider {
    type Tx = TransactionRequest;
    type Error = anyhow::Error;

    fn compose_tx(self, from: Address, to: Address, amount: f64) -> (Self::Tx, Vec<u8>) {
        let tx = TransactionRequest::new()
            .from(from)
            .to(to)
            .value(parse_ether(amount).unwrap());

        (tx, tx.sighash(self.chain_id).as_bytes().to_vec())
    }

    async fn sent_signed(&self, tx: Self::Tx, sig: &ecdsa_fun::Signature) -> Result<H256, Self::Error> {
        let m = tx.sighash(self.chain_id);
        let r = U256::from_big_endian(&sig.R_x.to_bytes());
        let s = U256::from_big_endian(&sig.s.to_bytes());
        let v = {
            let v = to_eip155_v(1, self.chain_id);
            let recid = Signature { r, s, v }.verify(m, from_wallet.address()).is_ok();
            to_eip155_v(recid, self.chain_id)
        };

        let encoded_tx = tx.rlp_signed(&Signature { r, s, v });

        Signature { r, s, v }
            .verify(m, from_wallet.address())
            .map_err(|e| anyhow!("verification error: {e}"))?;

        let pending = self.provider
            .send_raw_transaction(encoded_tx)
            .await
            .map_err(|e| anyhow!("error sending raw decrypted transaction: {e}"))?;

        Ok(match pending.await {
            Ok(Some(rec)) => {
                rec.transaction_hash
            },
            Ok(None) => {
                panic("expected transaction receipt");
            }
            Err(e) => {
                panic("fatal error sending tx");
            }
        })
    }

    async fn get_signature(&self, hash: H256) -> Result<Option<ecdsa_fun::Signature>, Self::Error> {
        self.provider.get_transaction(hash)
            .await
            .map_err(|e| anyhow!("error getting tx: {e}"))
            .map(|v| v.map(|tx| {
                let mut r = [0; 32];
                let mut s = [0; 32];

                posted_tx.r.to_big_endian(&mut r);
                posted_tx.s.to_big_endian(&mut s);

                ecdsa_fun::Signature {
                    R_x: Scalar::from_slice(&r)
                        .unwrap()
                        .mark::<(Public, NonZero)>()
                        .unwrap(),
                    s: Scalar::from_slice(&s)
                        .unwrap()
                        .mark::<(Public, NonZero)>()
                        .unwrap(),
                }
            }))
    }
}
