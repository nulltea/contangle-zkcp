use crate::traits::ChainProvider;
use anyhow::anyhow;
use async_trait::async_trait;
use ethers::prelude::*;
pub use ethers::utils::WEI_IN_ETHER;
use ethers::utils::{keccak256, parse_ether};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use secp256kfun::{marker::*, Point, Scalar};
use url::Url;

pub struct Ethereum {
    provider: Provider<Http>,
    chain_id: u64,
}

impl Ethereum {
    pub async fn new(url: impl Into<Url>) -> anyhow::Result<Self> {
        let provider = Provider::new(Http::new(url));
        let chain_id = provider
            .get_chainid()
            .await
            .map_err(|_e| anyhow!("error making request to the specified Ethereum RPC address"))?;

        Ok(Self {
            provider,
            chain_id: chain_id.as_u64(),
        })
    }
}

#[async_trait]
impl ChainProvider for Ethereum {
    type Tx = TransactionRequest;

    fn compose_tx(
        &self,
        from: Address,
        to: Address,
        amount: f64,
    ) -> anyhow::Result<(Self::Tx, H256)> {
        let tx = TransactionRequest::new()
            .chain_id(self.chain_id)
            .from(from)
            .to(to)
            .value(parse_ether(amount).map_err(|e| anyhow!("error parsing ether: {e}"))?);

        let tx_hash = tx.sighash();

        Ok((tx, tx_hash))
    }

    async fn sent_signed(&self, tx: Self::Tx, sig: &ecdsa_fun::Signature) -> anyhow::Result<H256> {
        let from = tx.from.unwrap();
        let m = tx.sighash();
        let r = U256::from_big_endian(&sig.R_x.to_bytes());
        let s = U256::from_big_endian(&sig.s.to_bytes());
        let v = {
            let v = to_eip155_v(1, self.chain_id);
            let recid = Signature { r, s, v }.verify(m, from).is_ok() as u8;
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
            Err(_e) => {
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

    fn address_from_pk(&self, pk: &Point) -> Address {
        let public_key = PublicKey::from_sec1_bytes(pk.to_bytes().as_slice()).unwrap();
        let public_key = public_key.to_encoded_point(false);
        let public_key = public_key.as_bytes();
        debug_assert_eq!(public_key[0], 0x04);
        let hash = keccak256(&public_key[1..]);
        Address::from_slice(&hash[12..])
    }
}
