use crate::{InfoResponse, Step1Response};
use anyhow::anyhow;
use ecdsa_fun::adaptor::EncryptedSignature;
use ethers::prelude::Address;
use ethers::types::H256;
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

    pub async fn step1(&self, address: Address) -> anyhow::Result<(Vec<u8>, Point, Address)> {
        let address = hex::encode(address.to_fixed_bytes());
        let Step1Response {
            ciphertext,
            data_pk,
            address,
        } = self
            .client
            .get(format!("step1/{address}"))
            .recv_json::<Step1Response>()
            .await
            .map_err(|e| anyhow!("error requesting step1: {e}"))?;
        let data_pk = Point::from_str(&data_pk).map_err(|e| anyhow!("bad data_pk: {e}"))?;
        let address = Address::from_str(&address).map_err(|e| anyhow!("bad address: {e}"))?;

        Ok((ciphertext, data_pk, address))
    }

    pub async fn step3(&self, pub_key: Point, enc_sig: EncryptedSignature) -> anyhow::Result<H256> {
        let pub_key = hex::encode(pub_key.to_bytes());
        let enc_sig = enc_sig.to_string();

        let tx_hash = self
            .client
            .post("step3")
            .body(json!({
                "pub_key": pub_key,
                "enc_sig": enc_sig
            }))
            .recv_string()
            .await
            .map_err(|e| anyhow!("error requesting step1: {e}"))?;

        H256::from_str(&tx_hash).map_err(|_e| anyhow!("error decoding hash"))
    }
}
