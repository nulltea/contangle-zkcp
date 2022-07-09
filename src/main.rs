#![feature(async_closure)]
extern crate core;

use std::str::FromStr;
use anyhow::anyhow;

use ecdsa_fun::adaptor::{Adaptor, EncryptedSignature, HashTranscript};
use secp256kfun::{
    derive_nonce_rng,
    digest::generic_array::typenum::U32,
    g, G
};

use secp256kfun::marker::*;
use secp256kfun::{Point, Scalar};
use byte_slice_cast::AsByteSlice;

use secp256kfun::nonce::{Deterministic};

use sha2::Sha256;
use sha3::Keccak256;
use rand_chacha::ChaCha20Rng;
use ethers::{prelude::*, utils::parse_ether};
use ethers::utils::keccak256;
use secp256kfun::hex::HexError;
use tokio::sync::oneshot;
use tokio::{select, task};
use url::Url;
use crate::types::transaction::eip2718::TypedTransaction;
use futures::stream::{self, StreamExt};


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
    let alice_wallet = LocalWallet::from_str(ALICE_SK).unwrap().with_chain_id(CHAIN_ID);
    let bob_wallet = LocalWallet::from_str(BOB_SK).unwrap().with_chain_id(CHAIN_ID);
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
    let signature = alice.step3(encrypted_sig, bob_address, &bob_wallet).await?;



    let plaintext = rx.await.unwrap();

    assert_eq!(data, &*plaintext);
    println!("decrypted_plaintext: {:?}", String::from_utf8(plaintext));

    Ok(())
}

struct Seller {
    sk: Scalar,
    pk: Point,
    adaptor: Adaptor<HashTranscript<Sha256, ChaCha20Rng>, Deterministic<Sha256>>,
    data_sk: Option<Scalar>,
    wallet: LocalWallet,
}

impl Seller {
    fn new(wallet: LocalWallet) -> Self {
        let (sk, pk) = keypair_from(ALICE_SK).unwrap();
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);

        Self {
            sk,
            pk,
            adaptor,
            data_sk: None,
            wallet
        }
    }

    /// Step 1: Alice generates new key pair, encrypt data with it, and sends public key and ciphertext to Bob.
    /// open question: does Alice also send Adaptor to Bob?
    fn step1(&mut self, data: &[u8]) -> anyhow::Result<(Vec<u8>, Point)> {
        let (data_sk, data_pk) = keypair_gen();
        let _ = self.data_sk.insert(data_sk);
        let ciphertext = encrypt(&data_pk, data)?;

        return Ok((ciphertext, data_pk))
    }

    /// Step 3: Alice decrypts this signature and publishes it, ie. get paid
    async fn step3<TAddr: Into<Address>>(&self, encrypted_sig: EncryptedSignature, from_addr: TAddr, from_wallet: &LocalWallet) -> anyhow::Result<ecdsa_fun::Signature> {
        let decryption_key = self.data_sk.as_ref().unwrap();
        let decrypted_sig = self.adaptor.decrypt_signature(decryption_key, encrypted_sig.clone());
        let provider = Provider::new(Http::new(Url::parse("http://localhost:8545").unwrap()));

        let tx = TransactionRequest::new().from(from_wallet.address())
            .to(self.wallet.address())
            .value(parse_ether(10).unwrap());

        let r = U256::from_big_endian(&decrypted_sig.R_x.to_bytes());
        let s = U256::from_big_endian(&decrypted_sig.s.to_bytes());
        let mut v = {
            let mut recid = 1;
            let v = to_eip155_v(recid, CHAIN_ID);
            recid = if (Signature{r,s,v}).verify(tx.sighash(CHAIN_ID), from_wallet.address()).is_err() {0} else {1};
            to_eip155_v(recid, CHAIN_ID)
        };

        let encoded_tx = tx.rlp_signed(&Signature{r,s,v});

        Signature{r,s,v}.verify(tx.sighash(CHAIN_ID), from_wallet.address())
            .map_err(|e| anyhow!("verification error: {e}"))?;

        let pt = provider.send_raw_transaction(encoded_tx)
            .await
            .map_err(|e| anyhow!("error sending raw decrypted transaction: {e}"))?;

        return Ok(decrypted_sig)
    }
}

struct Buyer {
    sk: Scalar,
    pk: Point,
    adaptor: Adaptor<HashTranscript<Sha256, ChaCha20Rng>, Deterministic<Sha256>>,
    data_pk: Option<Point>,
    encrypted_sig: Option<EncryptedSignature>,
    wallet: LocalWallet,
    tx_hash: Option<H256>
}

impl Buyer {
    fn new(wallet: LocalWallet) -> Self {
        let (sk, pk) = keypair_from(BOB_SK).unwrap();
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);

        Self {
            sk,
            pk,
            adaptor,
            data_pk: None,
            encrypted_sig: None,
            wallet,
            tx_hash: None
        }
    }

    /// Step 2: Bob signs a transaction to transfer coins to Alice address
    /// and encrypts it with `data_pk` and sends it to Alice.
    async fn step2<TAddr: Into<NameOrAddress>>(&mut self, data_pk: &Point, addr: TAddr) -> anyhow::Result<EncryptedSignature> {
        let _ = self.data_pk.insert(data_pk.clone());
        let transfer_tx = TransactionRequest::new()
            .from(self.wallet.address())
            .to(addr).value(parse_ether(10)?);

        let tx_encoded = transfer_tx.sighash(self.wallet.chain_id());
        let _ = self.tx_hash.insert(tx_encoded.clone());
        let encrypted_sig = self.adaptor.encrypted_sign(&self.sk, data_pk, tx_encoded.as_fixed_bytes());

        let _ = self.encrypted_sig.insert(encrypted_sig.clone());

        return Ok(encrypted_sig)
    }

    /// Step 4: Bob observes signature on-chain and use it to recover `data_sk`
    /// and decrypt the data file from the ciphertext given to him by Alice.
    async fn step4(&mut self, ciphertext: &[u8], tx: oneshot::Sender<Vec<u8>>) -> anyhow::Result<()> {
        let provider = Provider::new(Ws::connect("wss://localhost:8545").await?);

        let mut sub = provider.subscribe_pending_txs().await.unwrap();
        let mut signature = None;
        loop {
            if let Some(tx_hash) = sub.next().await {
                if let Ok(Some(posted_tx)) = provider.get_transaction(tx_hash).await {
                    let mut r = [0; 32];
                    let mut s = [0; 32];

                    posted_tx.r.to_big_endian(&mut r);
                    posted_tx.s.to_big_endian(&mut s);

                    let _ = signature.insert(ecdsa_fun::Signature {
                        R_x: Scalar::from_slice(&r).unwrap().mark::<(Public, NonZero)>().unwrap(),
                        s: Scalar::from_slice(&s).unwrap().mark::<(Public, NonZero)>().unwrap()
                    });
                    break;
                }
            }
        }

        let signature = signature.take().unwrap();
        let recovered_sk = self.adaptor.recover_decryption_key(self.data_pk.as_ref().unwrap(), &signature, self.encrypted_sig.as_ref().unwrap()).unwrap();

        tx.send(decrypt(&recovered_sk, ciphertext)?).map_err(|_| anyhow!("failed to send result"))
    }
}

fn keypair_gen() -> (Scalar, Point) {
    let sk = Scalar::random(&mut rand::thread_rng());
    let pk = g!(sk * G).mark::<Normal>();
    (sk, pk)
}

fn keypair_from(hex: &str) -> Result<(Scalar, Point), HexError> {
    let sk = Scalar::from_str(hex)?;
    let pk = g!(sk * G).mark::<Normal>();
    Ok((sk, pk))
}

fn encrypt(pk: &Point, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pk = pk.to_bytes();
    ecies::encrypt(&pk, plaintext).map_err(|e| anyhow!("encryption failed: {e}"))
    // todo: do should be a verifiable encryption with ECDH implemented as an `akrworks` circuit
    // ElGamal::encrypt()
}

fn decrypt(sk: &Scalar, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let sk = sk.to_bytes();
    ecies::decrypt(&sk, ciphertext).map_err(|e| anyhow!("decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use anyhow::anyhow;
    use ecdsa_fun::adaptor::{Adaptor, HashTranscript};
    use ecdsa_fun::ECDSA;
    use ethers::prelude::*;
    use ethers::utils::parse_ether;
    use rand_chacha::ChaCha20Rng;
    use secp256kfun::nonce::Deterministic;
    use sha2::Sha256;
    use sha3::Keccak256;
    use url::Url;
    use crate::{keypair_from, keypair_gen, LocalWallet, TransactionRequest, TypedTransaction};

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

        println!("r: {}\ns: {}\nv: {}\nhash: {}\na: {}", r, s, v, transfer_tx.sighash(CHAIN_ID), bob_wallet.address());

        let encoded_signed_tx = transfer_tx.rlp_signed(&Signature{r,s,v});
        let res = Signature{r,s,v}.verify(tx_encoded, bob_wallet.address());

        if let Err(ref e) = res {
            println!("{e}");
        }

        assert!(res.is_ok())
    }
}
