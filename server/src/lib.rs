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
use rocket::State;
use scriptless_zkcp::{SellerMsg, Step1Msg};

use secp256kfun::Point;

use scriptless_zkcp::zk::{ProofOfProperty, VerifiableEncryption};
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
struct Step0Response {
    ciphertext: Vec<u8>,
    proof_of_encryption: Vec<u8>,
    proofs_of_property: Vec<ProofOfProperty>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "rocket::serde")]
struct Step1Response {
    ciphertext: Vec<u8>,
    proof_of_encryption: Vec<u8>,
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

#[get("/step0")]
async fn step0(state: &State<Runtime>) -> Result<Json<Step0Response>, status::Custom<String>> {
    let (tx, rx) = oneshot::channel();
    state
        .tx
        .clone()
        .send(SellerMsg::Step0 { resp_tx: tx })
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?;

    let VerifiableEncryption {
        ciphertext,
        proof_of_encryption,
        proofs_of_property,
    } = rx
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(Step0Response {
        ciphertext,
        proof_of_encryption,
        proofs_of_property,
    }))
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

    let Step1Msg {
        ciphertext,
        proof_of_encryption,
        data_pk,
        seller_address,
    } = rx
        .await
        .map_err(|e| status::Custom(Status::ServiceUnavailable, e.to_string()))?
        .map_err(|e| status::Custom(Status::InternalServerError, e.to_string()))?;

    Ok(Json(Step1Response {
        ciphertext,
        proof_of_encryption,
        data_pk: hex::encode(data_pk.to_bytes()),
        address: hex::encode(seller_address.to_fixed_bytes()),
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
        .mount("/", routes![info, step0, step1, step3])
        .launch()
        .await
        .expect("expect server to run");
}
