#![feature(async_closure)]

extern crate core;

mod buyer;
mod seller;
mod utils;
mod traits;
mod ethereum;

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




#[cfg(test)]
mod tests {
    use crate::{keypair_from, keypair_gen, LocalWallet, TransactionRequest, TypedTransaction};
    use anyhow::anyhow;
    use ecdsa_fun::adaptor::{Adaptor, HashTranscript};
    use ecdsa_fun::ECDSA;
    use ethers::prelude::*;
    use ethers::utils::parse_ether;
    use rand_chacha::ChaCha20Rng;
    use secp256kfun::nonce::Deterministic;
    use sha2::Sha256;
    use sha3::Keccak256;
    use std::str::FromStr;
    use url::Url;

    const ALICE_SK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const BOB_SK: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const CHAIN_ID: u64 = 1;

    #[test]
    fn verify_decrypted_adaptor_on_ethereum() {
        let (sk, pk) = keypair_from(BOB_SK).unwrap();
        println!("sk={}, pk={}", sk, pk);
        let (data_sk, data_pk) = keypair_gen();
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);

        let alice_wallet = LocalWallet::from_str(ALICE_SK).unwrap();
        let bob_wallet = LocalWallet::from_str(BOB_SK).unwrap();
        let bob_address = bob_wallet.address();
        let transfer_tx = TransactionRequest::new()
            .from(bob_wallet.address())
            .to(alice_wallet.address())
            .value(parse_ether(10).unwrap());

        let tx_encoded = transfer_tx.sighash(CHAIN_ID);
        let encrypted_sig = adaptor.encrypted_sign(&sk, &data_pk, tx_encoded.as_fixed_bytes());
        let decrypted_sig = adaptor.decrypt_signature(&data_sk, encrypted_sig.clone());

        let r = U256::from_big_endian(&decrypted_sig.R_x.to_bytes());
        let s = U256::from_big_endian(&decrypted_sig.s.to_bytes());
        let v = to_eip155_v(0, CHAIN_ID);

        println!(
            "r: {}\ns: {}\nv: {}\nhash: {}\na: {}",
            r,
            s,
            v,
            transfer_tx.sighash(CHAIN_ID),
            bob_wallet.address()
        );

        let encoded_signed_tx = transfer_tx.rlp_signed(&Signature { r, s, v });
        let res = Signature { r, s, v }.verify(tx_encoded, bob_wallet.address());

        if let Err(ref e) = res {
            println!("{e}");
        }

        assert!(res.is_ok())
    }
}
