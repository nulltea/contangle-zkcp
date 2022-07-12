pub mod client;

#[macro_use]
extern crate rocket;


use ecdsa_fun::adaptor::EncryptedSignature;
use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use futures_util::{SinkExt, TryFutureExt};
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{State};
use scriptless_zkcp::SellerMsg;

use secp256kfun::Point;


use std::str::FromStr;

struct Runtime {
    tx: mpsc::Sender<SellerMsg>,
    price: f64,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct InfoResponse {
    price: f64,
}

#[derive(Serialize, Deserialize)]
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

#[get("/info")]
async fn info(state: &State<Runtime>) -> Json<InfoResponse> {
    Json(InfoResponse { price: state.price })
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
        data_pk: hex::encode(data_pk.to_bytes()),
        address: hex::encode(address.to_fixed_bytes()),
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
        .to_fixed_bytes();

    Ok(hex::encode(tx_hash))
}

#[allow(unused_must_use)]
pub async fn serve(to_runtime: mpsc::Sender<SellerMsg>, price: f64) {
    rocket::build()
        .manage(Runtime {
            tx: to_runtime,
            price,
        })
        .mount("/", routes![info, step1, step3])
        .launch()
        .await
        .expect("expect server to run");
}
