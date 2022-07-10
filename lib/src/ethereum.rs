use crate::traits::ChainProvider;
use anyhow::anyhow;
use async_trait::async_trait;
use ethers::prelude::*;
use ethers::utils::parse_ether;
use secp256kfun::{marker::*, Scalar};
use url::Url;

pub struct EthereumProvider {
    provider: Provider<Http>,
    chain_id: u64,
}

impl EthereumProvider {
    pub async fn new(url: impl Into<Url>) -> Self {
        let provider = Provider::new(Http::new(url));
        let chain_id = provider.get_chainid().await.unwrap();

        Self {
            provider,
            chain_id: chain_id.as_u64(),
        }
    }
}

#[async_trait]
impl ChainProvider for EthereumProvider {
    type Tx = TransactionRequest;

    fn compose_tx(&self, from: Address, to: Address, amount: u64) -> (Self::Tx, H256) {
        let tx = TransactionRequest::new()
            .chain_id(self.chain_id)
            .from(from)
            .to(to)
            .value(parse_ether(amount).unwrap());

        let tx_hash = tx.sighash();

        (tx, tx_hash)
    }

    async fn sent_signed(&self, tx: Self::Tx, sig: &ecdsa_fun::Signature) -> anyhow::Result<H256> {
        let from = tx.from.unwrap();
        let m = tx.sighash();
        let r = U256::from_big_endian(&sig.R_x.to_bytes());
        let s = U256::from_big_endian(&sig.s.to_bytes());
        let v = {
            let v = to_eip155_v(1, self.chain_id);
            let recid = Signature { r, s, v }.verify(m, from).is_ok();
            to_eip155_v(recid, self.chain_id)
        };

        let encoded_tx = tx.rlp_signed(&Signature { r, s, v });

        Signature { r, s, v }
            .verify(m, from)
            .map_err(|e| anyhow!("verification error: {e}"))?;

        let pending = self
            .provider
            .send_raw_transaction(encoded_tx)
            .await
            .map_err(|e| anyhow!("error sending raw decrypted transaction: {e}"))?;

        Ok(match pending.await {
            Ok(Some(rec)) => rec.transaction_hash,
            Ok(None) => {
                panic!("expected transaction receipt");
            }
            Err(e) => {
                panic!("fatal error sending tx");
            }
        })
    }

    async fn get_signature(&self, hash: H256) -> anyhow::Result<Option<ecdsa_fun::Signature>> {
        self.provider
            .get_transaction(hash)
            .await
            .map_err(|e| anyhow!("error getting tx: {e}"))
            .map(|v| {
                v.map(|tx| {
                    let mut r = [0; 32];
                    let mut s = [0; 32];

                    tx.r.to_big_endian(&mut r);
                    tx.s.to_big_endian(&mut s);

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
                })
            })
    }

    fn parse_amount<S: AsRef<str>>(&self, amount: S) -> anyhow::Result<u64> {
        Ok(parse_ether(amount.as_ref())
            .map_err(|e| anyhow!("error pasring ether: {e}"))?
            .as_u64())
    }
}
