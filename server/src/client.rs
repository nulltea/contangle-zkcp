use crate::{InfoResponse, Step0Response, Step1Response};
use anyhow::anyhow;
use async_trait::async_trait;
use ecdsa_fun::adaptor::EncryptedSignature;
use ethers::prelude::Address;
use ethers::types::H256;
use scriptless_zkcp::zk::VerifiableEncryption;
use scriptless_zkcp::{CipherDownloader, Step1Msg};
use secp256kfun::Point;
use serde_json::json;
use std::str::FromStr;
use surf::Url;

pub struct SellerClient {
    client: surf::Client,
}

impl SellerClient {
    pub fn new<S: AsRef<str>>(server_url: S) -> anyhow::Result<Self> {
        let url = Url::parse(server_url.as_ref())
            .map_err(|e| anyhow!("error parsing server url: {e}"))?;
        let config = surf::Config::new().set_base_url(url).set_timeout(None);
        Ok(Self {
            client: config.try_into()?,
        })
    }

    pub async fn price(&self) -> anyhow::Result<f64> {
        let InfoResponse { price } = self
            .client
            .get("info")
            .recv_json::<InfoResponse>()
            .await
            .map_err(|e| anyhow!("error requesting price: {e}"))?;

        Ok(price)
    }

    pub async fn step1(&self, address: Address) -> anyhow::Result<Step1Msg> {
        let address = hex::encode(address.to_fixed_bytes());
        let mut resp = self
            .client
            .get(format!("step1/{address}"))
            .await
            .map_err(|e| anyhow!("error requesting step1: {e}"))?;

        if resp.status() != 200 {
            return Err(anyhow!("{}", resp.body_string().await.unwrap()));
        }

        let Step1Response {
            ciphertext,
            proof_of_encryption,
            data_pk,
            address,
        } = resp
            .body_json::<Step1Response>()
            .await
            .map_err(|e| anyhow!("error decoding step1 response: {e}"))?;

        let data_pk = Point::from_str(&data_pk).map_err(|e| anyhow!("bad data_pk: {e}"))?;
        let seller_address =
            Address::from_str(&address).map_err(|e| anyhow!("bad address: {e}"))?;

        Ok(Step1Msg {
            ciphertext,
            proof_of_encryption,
            data_pk,
            seller_address,
        })
    }

    pub async fn step3(&self, pub_key: Point, enc_sig: EncryptedSignature) -> anyhow::Result<H256> {
        let pub_key = hex::encode(pub_key.to_bytes());
        let enc_sig = enc_sig.to_string();

        let mut resp = self
            .client
            .post("step3")
            .body(json!({
                "pub_key": pub_key,
                "enc_sig": enc_sig
            }))
            .await
            .map_err(|e| anyhow!("error requesting step3: {e}"))?;

        if resp.status() != 200 {
            return Err(anyhow!("{}", resp.body_string().await.unwrap()));
        }

        let tx_hash = resp
            .body_string()
            .await
            .map_err(|e| anyhow!("error requesting step1: {e}"))?;

        H256::from_str(&tx_hash).map_err(|_e| anyhow!("error decoding hash"))
    }
}

#[async_trait]
impl CipherDownloader for SellerClient {
    async fn download(&self) -> anyhow::Result<VerifiableEncryption> {
        let mut resp = self
            .client
            .get(format!("step0"))
            .await
            .map_err(|e| anyhow!("error requesting step0: {e}"))?;

        if resp.status() != 200 {
            return Err(anyhow!("{}", resp.body_string().await.unwrap()));
        }

        let Step0Response {
            ciphertext,
            proof_of_encryption,
            proofs_of_property,
        } = resp
            .body_json::<Step0Response>()
            .await
            .map_err(|e| anyhow!("error decoding step1 response: {e}"))?;

        return Ok(VerifiableEncryption {
            ciphertext,
            proof_of_encryption,
            proofs_of_property,
        });
    }
}
