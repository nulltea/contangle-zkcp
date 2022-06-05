use anyhow::anyhow;
use ecdsa_fun::adaptor::{Adaptor, HashTranscript};
use secp256kfun::{g, G};
use secp256kfun::marker::*;
use secp256kfun::{Point, Scalar};
use secp256kfun::secp256k1::{PublicKey, Secp256k1, SecretKey};
use crypto::aead::Aead;
use rand::rngs::ThreadRng;
use secp256kfun::nonce::{AddTag, Deterministic};
use secp256kfun::serde::Serialize;
use sha2::Sha256;
use rand_chacha::ChaCha20Rng;

fn main() -> anyhow::Result<()> {
    // Script-less ZK contingent payment using ECDSA signature adaptors.
    // Alice - seller; Bob - buyer.

    // Alice - before exchange:
    let (alice_sk, alice_pk) = keypair_gen();
    let data = b"42";

    // Bob - before exchange:
    let (bob_sk, bob_pk) = keypair_gen();

    /// Step 1: Alice generates new key pair, encrypt data with it, and sends public key and ciphertext to Bob.
    /// open question: does Alice also send Adaptor to Bob?
    let (data_sk, data_pk) = keypair_gen();
    let ciphertext = encrypt(&data_pk, data)?;
    let nonce_gen = Deterministic::<Sha256>::default();
    let ecdsa_adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);

    /// Step 2: Bob signs a transaction to transfer coins to Alice address and encrypts it with `data_pk` and sends it to Alice.
    let transfer_tx = b"send 1 ETH to Alice, she is cool";
    let encrypted_sig = ecdsa_adaptor.encrypted_sign(&bob_sk, &data_pk, transfer_tx);

    /// Step 3: Alice decrypts this signature and publishes it, ie. get paid
    let decrypted_sig = ecdsa_adaptor.decrypt_signature(&data_sk, encrypted_sig.clone());

    /// Step 4: Bob observes signature on-chain and use it to recover `data_sk`
    /// and decrypt the data file from the ciphertext given to him by Alice.
    let recovered_sk = ecdsa_adaptor.recover_decryption_key(&data_pk, &decrypted_sig, &encrypted_sig).unwrap();
    assert_eq!(data_sk, recovered_sk);

    let plaintext = decrypt(&recovered_sk, &*ciphertext)?;
    assert_eq!(data, &*plaintext);
    println!("original_data: {:?}, decrypted_plaintext: {:?}", String::from_utf8(data.to_vec()), String::from_utf8(plaintext));

    Ok(())
}

fn keypair_gen() -> (Scalar, Point) {
    let sk = Scalar::random(&mut rand::thread_rng());
    let pk = g!(sk * G).mark::<Normal>();
    (sk, pk)
}

fn encrypt(pk: &Point, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let pk = pk.to_bytes();
    ecies::encrypt(&pk, plaintext).map_err(|e| anyhow!("encryption failed: {e}"))
    // todo: do should be a verifiable encryption with ECDH implemented as an `akrworks` circuit
}

fn decrypt(sk: &Scalar, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let sk = sk.to_bytes();
    ecies::decrypt(&sk, ciphertext).map_err(|e| anyhow!("decryption failed: {e}"))
}

