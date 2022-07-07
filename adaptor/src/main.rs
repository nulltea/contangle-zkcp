use std::str::FromStr;
use anyhow::anyhow;

use ecdsa_fun::adaptor::{Adaptor, EncryptedSignature, HashTranscript};
use secp256kfun::{g, G};
use secp256kfun::marker::*;
use secp256kfun::{Point, Scalar};


use secp256kfun::nonce::{Deterministic};

use sha2::Sha256;
use rand_chacha::ChaCha20Rng;
use ethers::{prelude::*, utils::parse_ether};
use secp256kfun::hex::HexError;
use url::Url;
use crate::types::transaction::eip2718::TypedTransaction;

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
    let alice_wallet = LocalWallet::from_str(ALICE_SK).unwrap();
    let bob_wallet = LocalWallet::from_str(BOB_SK).unwrap();
    let bob_address = bob_wallet.address();
    let alice_address = alice_wallet.address();

    let mut alice = Seller::new(alice_wallet);
    let mut bob = Buyer::new(bob_wallet.clone());

    let (ciphertext, data_pk) = alice.step1(data)?;
    let (_tx, encrypted_sig) = bob.step2(&data_pk, alice_address).await?;
    let signature = alice.step3(encrypted_sig, bob_address, &bob_wallet).await?;
    let plaintext= bob.step4(&ciphertext, signature)?;

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
        let (sk, pk) = keypair_gen();
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
        let decrypted_sig = self.adaptor.decrypt_signature(self.data_sk.as_ref().unwrap(), encrypted_sig.clone());
        let provider = Provider::new(Http::new(Url::parse("http://localhost:8545").unwrap()));

        let bob_addr = from_addr.into();
        let tx = TransactionRequest::new().from(from_wallet.address())
            .to(self.wallet.address())
            .value(parse_ether(10).unwrap());

        let r = U256::from_big_endian(&decrypted_sig.R_x.to_bytes());
        let s = U256::from_big_endian(&decrypted_sig.s.to_bytes());
        let v = to_eip155_v(1, CHAIN_ID);

        println!("[decrypted adaptor] r: {}\ns: {}\nv: {}\nhash: {}\nchain_id: {}", r, s, v, tx.sighash(from_wallet.chain_id()), CHAIN_ID);

        // sign a normal ECDSA to compare
        let tx_typed: TypedTransaction = tx.clone().into();
        let sig = from_wallet.sign_transaction(&tx_typed).await?;
        println!("[normal ecdsa sign] r: {}\ns: {}\nv: {}\nhash: {}\nchain_id: {}", sig.r, sig.s, sig.v, tx_typed.sighash(from_wallet.chain_id()), from_wallet.chain_id());

        let encoded_tx = tx.rlp_signed(&Signature{r,s,v});
        Signature{r,s,v}.verify(tx_typed.sighash(CHAIN_ID), from_wallet.address())
            .map_err(|e| anyhow!("verification error: {e}"))?; // Signature verification failed. Expected 0x7099…79c8, got `...`

        let _ = provider.send_raw_transaction(encoded_tx)
            .await
            .map_err(|e| anyhow!("error sending raw decrypted transaction: {e}"))?;

        let client = SignerMiddleware::new(provider.clone(), self.wallet.clone());
        let balance = parse_ether(client.get_balance(self.wallet.address(), None).await.unwrap()).unwrap();
        println!("alice balance {}", balance);
        let balance = parse_ether(client.get_balance(bob_addr.clone(), None).await.unwrap()).unwrap();
        println!("bob balance {}", balance);

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
}

impl Buyer {
    fn new(wallet: LocalWallet) -> Self {
        let (sk, pk) = keypair_gen();
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);

        Self {
            sk,
            pk,
            adaptor,
            data_pk: None,
            encrypted_sig: None,
            wallet
        }
    }

    /// Step 2: Bob signs a transaction to transfer coins to Alice address
    /// and encrypts it with `data_pk` and sends it to Alice.
    async fn step2<TAddr: Into<NameOrAddress>>(&mut self, data_pk: &Point, addr: TAddr) -> anyhow::Result<(TransactionRequest, EncryptedSignature)> {
        let _ = self.data_pk.insert(data_pk.clone());
        println!("bobs addr: {}", self.wallet.address());
        let transfer_tx = TransactionRequest::new()
            .from(self.wallet.address())
            .to(addr).value(parse_ether(10)?);

        let tx_encoded = transfer_tx.sighash(self.wallet.chain_id());
        let encrypted_sig = self.adaptor.encrypted_sign(&self.sk, data_pk, tx_encoded.as_fixed_bytes());
        let _ = self.encrypted_sig.insert(encrypted_sig.clone());

        return Ok((transfer_tx, encrypted_sig))
    }

    /// Step 4: Bob observes signature on-chain and use it to recover `data_sk`
    /// and decrypt the data file from the ciphertext given to him by Alice.
    fn step4(&self, ciphertext: &[u8], decrypted_sig: ecdsa_fun::Signature) -> anyhow::Result<Vec<u8>> {
        let recovered_sk = self.adaptor.recover_decryption_key(self.data_pk.as_ref().unwrap(), &decrypted_sig, self.encrypted_sig.as_ref().unwrap()).unwrap();
        let plaintext = decrypt(&recovered_sk, ciphertext)?;

        return Ok(plaintext)
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
    use url::Url;
    use crate::{keypair_from, keypair_gen, LocalWallet, TransactionRequest, TypedTransaction};

    const ALICE_SK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const BOB_SK: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const CHAIN_ID: u64 = 1;

    #[test]
    fn verify_decrypted_adaptor_on_ethereum() {
        let (sk, pk) = keypair_from(BOB_SK).unwrap();
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
        let v = to_eip155_v(1, CHAIN_ID);

        println!("r: {}\ns: {}\nv: {}\nhash: {}\na: {}", r, s, v, transfer_tx.sighash(CHAIN_ID), bob_wallet.address());

        // sign a normal ECDSA to compare
        // let tx_typed: TypedTransaction = transfer_tx.clone().into();
        // let sig = bob_wallet.sign_transaction(&tx_typed).await?;
        // println!("[normal ecdsa sign] r: {}\ns: {}\nv: {}\nhash: {}", sig.r, sig.s, sig.v, tx_typed.sighash(CHAIN_ID));

        let encoded_signed_tx = transfer_tx.rlp_signed(&Signature{r,s,v});
        let res = Signature{r,s,v}.verify(encoded_signed_tx, bob_wallet.address());

        if let Err(ref e) = res {
            println!("{e}");
        }

        assert!(res.is_ok())
    }

    #[test]
    fn verify_plain_ecdsa_on_ethereum() {
        let (sk, pk) = keypair_from(BOB_SK).unwrap();
        let nonce_gen = Deterministic::<Sha256>::default();
        let ecdsa = ECDSA::new(nonce_gen);

        let alice_wallet = LocalWallet::from_str(ALICE_SK).unwrap();
        let bob_wallet = LocalWallet::from_str(BOB_SK).unwrap();
        let bob_address = bob_wallet.address();
        let transfer_tx = TransactionRequest::new()
            .from(bob_wallet.address())
            .to(alice_wallet.address())
            .value(parse_ether(10).unwrap());

        let tx_encoded = transfer_tx.sighash(CHAIN_ID);
        let sig_data = ecdsa.sign(&sk, tx_encoded.as_fixed_bytes());


        let r = U256::from_big_endian(&sig_data.R_x.to_bytes());
        let s = U256::from_big_endian(&sig_data.s.to_bytes());
        let v = to_eip155_v(1, CHAIN_ID);

        println!("r: {}\ns: {}\nv: {}\nhash: {}\na: {}", r, s, v, transfer_tx.sighash(CHAIN_ID), bob_wallet.address());

        // sign a normal ECDSA to compare
        // let tx_typed: TypedTransaction = transfer_tx.clone().into();
        // let sig = bob_wallet.sign_transaction(&tx_typed).await?;
        // println!("[normal ecdsa sign] r: {}\ns: {}\nv: {}\nhash: {}", sig.r, sig.s, sig.v, tx_typed.sighash(CHAIN_ID));

        let encoded_signed_tx = transfer_tx.rlp_signed(&Signature{r,s,v});
        let res = Signature{r,s,v}.verify(encoded_signed_tx, bob_wallet.address());


        if let Err(ref e) = res {
            println!("{e}");
        }

        assert!(res.is_ok())
    }
}
