#![feature(async_closure)]

use anyhow::anyhow;
use ecdsa_fun::adaptor::{Adaptor, EncryptedSignature, HashTranscript};
use ethers::{prelude::*, utils::parse_ether};
use futures::stream::StreamExt;
use rand_chacha::ChaCha20Rng;
use secp256kfun::hex::HexError;
use secp256kfun::marker::*;
use secp256kfun::nonce::Deterministic;
use secp256kfun::{g, G};
use secp256kfun::{Point, Scalar};
use sha2::Sha256;
use std::str::FromStr;
use tokio::sync::oneshot;
use tokio::task;
use url::Url;

const CHAIN_ID: u64 = 31337;

const ALICE_ADDR: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const ALICE_SK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const BOB_ADDR: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const BOB_SK: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Script-less ZK contingent payment using ECDSA signature adaptors.
    // Alice - seller; Bob - buyer.

    // Setup values
    let data = b"42";
    let alice_wallet = LocalWallet::from_str(ALICE_SK)
        .unwrap()
        .with_chain_id(CHAIN_ID);
    let bob_wallet = LocalWallet::from_str(BOB_SK)
        .unwrap()
        .with_chain_id(CHAIN_ID);
    let bob_address = bob_wallet.address();
    let alice_address = alice_wallet.address();

    let mut alice = Seller::new(alice_wallet);
    let mut bob = Buyer::new(bob_wallet.clone());

    let (ciphertext, data_pk) = alice.step1(data)?;
    let encrypted_sig = bob.step2(&data_pk, alice_address).await?;
    let (tx, rx) = oneshot::channel();
    task::spawn(async move {
        bob.step4(&ciphertext, tx).await.unwrap();
    });
    let _signature = alice.step3(encrypted_sig, bob_address, &bob_wallet).await?;

    let plaintext = rx.await.unwrap();

    assert_eq!(data, &*plaintext);
    println!("decrypted_plaintext: {:?}", String::from_utf8(plaintext));

    Ok(())
}
