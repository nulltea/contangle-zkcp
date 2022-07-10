#[macro_use]
extern crate rocket;

use anyhow::anyhow;
use ecdsa_fun::adaptor::EncryptedSignature;
use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures_util::{SinkExt, TryFutureExt};
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{response, State};
use scriptless_zkcp::SellerMsg;
use secp256kfun::hex::HexError;
use secp256kfun::Point;
use std::borrow::BorrowMut;
use std::str::FromStr;

struct Runtime {
    tx: mpsc::Sender<SellerMsg>,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct Step1Response {
    ciphertext: Vec<u8>,
    data_pk: String,
    address: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct Step3Request<'r> {
    pub_key: &'r str,
    enc_sig: &'r str,
}

#[get("/step1/<address>")]
async fn step1(
    state: &State<Runtime>,
    address: &str,
) -> Result<Json<Step1Response>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    let address = Address::from_str(&address)
        .map_err(|e| status::Custom(Status::BadRequest, e.to_string()))?;
    state
        .tx
        .clone()
        .send(SellerMsg::Step1 {
            address,
            resp_tx: tx,
        })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let (ciphertext, data_pk, address) = rx
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(Step1Response {
        ciphertext,
        data_pk: data_pk.to_string(),
        address: address.to_string(),
    }))
}

#[post("/step3", data = "<req>")]
async fn step3(
    state: &State<Runtime>,
    req: Json<Step3Request<'_>>,
) -> Result<String, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    let pub_key = Point::from_str(req.pub_key)
        .map_err(|e| status::Custom(Status::BadRequest, format!("bad public key: {e}")))?;
    let enc_sig = EncryptedSignature::from_str(req.enc_sig)
        .map_err(|e| status::Custom(Status::BadRequest, format!("bad public key: {e}")))?;
    state
        .tx
        .clone()
        .send(SellerMsg::Step3 {
            pub_key,
            enc_sig,
            resp_tx: tx,
        })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let tx_hash = rx
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?
        .to_string();

    Ok(tx_hash)
}

#[allow(unused_must_use)]
pub async fn serve(to_runtime: mpsc::Sender<SellerMsg>) {
    rocket::build()
        .manage(Runtime { tx: to_runtime })
        .mount("/", routes![step1, step3])
        .launch()
        .await
        .expect("expect server to run");
}
