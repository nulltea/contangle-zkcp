use crate::traits::ChainProvider;

use crate::{
    keypair_from_bytes, CircuitParams, Encryption, PairingEngine, ProjectiveCurve,
};
use anyhow::anyhow;
use ecdsa_fun::adaptor::{Adaptor, EncryptedSignature, HashTranscript};
use ethers::prelude::*;
use futures::channel::{mpsc, oneshot};
use rand::{CryptoRng, Rng};
use rand_chacha::ChaCha20Rng;
use secp256kfun::marker::{Mark, Normal};
use secp256kfun::nonce::Deterministic;
use secp256kfun::{g, Point, Scalar, G};
use sha2::Sha256;
use std::collections::hash_map::Entry;
use std::collections::HashMap;


use zkp::{
    ark_to_bytes, bytes_to_plaintext_chunks,
    ciphertext_to_bytes,
    ProvingKey,
};

pub struct Seller<TChainProvider> {
    data: Vec<u8>,
    cost: f64,
    adaptor: Adaptor<HashTranscript<Sha256, ChaCha20Rng>, Deterministic<Sha256>>,
    chain: TChainProvider,
    wallet: crate::LocalWallet,
    from_buyers: mpsc::Receiver<SellerMsg>,
    data_keys: HashMap<Address, Scalar>,
    circuit_pk: ProvingKey<PairingEngine>,
}

pub enum SellerMsg {
    /// Step 1: Alice generates new key pair, encrypt data with it, and sends public key and ciphertext to Bob.
    Step1 {
        address: Address,
        resp_tx: oneshot::Sender<anyhow::Result<Step1Msg>>,
    },
    /// Step 3: Alice decrypts this signature and publishes it, ie. get paid
    Step3 {
        pub_key: Point,
        enc_sig: EncryptedSignature,
        resp_tx: oneshot::Sender<anyhow::Result<H256>>,
    },
}

pub struct Step1Msg {
    pub ciphertext: Vec<u8>,
    pub proof_of_encryption: Vec<u8>,
    pub data_pk: Point,
    pub seller_address: Address,
}

impl<TChainProvider: ChainProvider> Seller<TChainProvider> {
    pub fn new(
        data: Vec<u8>,
        cost: f64,
        chain: TChainProvider,
        wallet: crate::LocalWallet,
        circuit_pk: ProvingKey<PairingEngine>,
    ) -> anyhow::Result<(Self, mpsc::Sender<SellerMsg>)> {
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);
        let (to_seller, from_buyers) = mpsc::channel(1);
        Ok((
            Self {
                data,
                cost,
                adaptor,
                data_keys: HashMap::default(),
                chain,
                from_buyers,
                wallet,
                circuit_pk,
            },
            to_seller,
        ))
    }

    pub async fn run(mut self) {
        loop {
            if let Some(msg) = self.from_buyers.next().await {
                match msg {
                    SellerMsg::Step1 { address, resp_tx } => {
                        let (elgamal_pk, data_sk, data_pk) = Self::elgamal_gen_derive_secp256k1()
                            .expect("expected generation to succeed or infinite looped");
                        let _ = self.data_keys.insert(address, data_sk);
                        let seller_address = self.chain.address_from_pk(self.wallet.pub_key());
                        if let Err(_) = resp_tx.send(
                            self.encrypt(&*self.data, elgamal_pk, &mut rand::thread_rng())
                                .map(|(ciphertext, proof_of_encryption)| Step1Msg {
                                    ciphertext,
                                    proof_of_encryption,
                                    data_pk,
                                    seller_address,
                                }),
                        ) {
                            self.data_keys.remove(&address); // todo: DoS defense needed.
                        }
                    }
                    SellerMsg::Step3 {
                        pub_key,
                        enc_sig,
                        resp_tx,
                    } => {
                        let local_address = self.chain.address_from_pk(self.wallet.pub_key());
                        let address = self.chain.address_from_pk(&pub_key);
                        let decryption_key = match self.data_keys.entry(address) {
                            Entry::Occupied(e) => e.remove(),
                            Entry::Vacant(_) => {
                                let _ = resp_tx.send(Err(anyhow!("unknown address")));
                                continue;
                            }
                        };

                        let (pay_tx, tx_hash) = self
                            .chain
                            .compose_tx(address, local_address, self.cost)
                            .unwrap();

                        let data_pk = g!(decryption_key * G).mark::<Normal>();
                        if !self.adaptor.verify_encrypted_signature(
                            &pub_key,
                            &data_pk,
                            tx_hash.as_fixed_bytes(),
                            &enc_sig,
                        ) {
                            let _ = resp_tx.send(Err(anyhow!("invalid adaptor signature")));
                            continue;
                        }
                        let decrypted_sig =
                            self.adaptor.decrypt_signature(&decryption_key, enc_sig);

                        let _ = resp_tx.send(self.chain.sent_signed(pay_tx, &decrypted_sig).await);
                    }
                }
            }
        }
    }

    fn elgamal_gen_derive_secp256k1(
    ) -> anyhow::Result<(zkp::PublicKey<ProjectiveCurve>, Scalar, Point)> {
        loop {
            let (elgamal_sk, elgamal_pk) =
                Encryption::keygen(&CircuitParams, &mut rand::thread_rng())?;

            let elgamal_sk_bytes = ark_to_bytes(elgamal_sk)
                .map_err(|e| anyhow!("error encoding elgamal secret key: {e}"))?;

            match keypair_from_bytes(elgamal_sk_bytes) {
                Ok((secp_sk, secp_pk)) => return Ok((elgamal_pk, secp_sk, secp_pk)),
                Err(_) => continue,
            }
        }
    }

    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        plaintext: &[u8],
        pk: zkp::PublicKey<ProjectiveCurve>,
        mut rng: &mut R,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let mut msg = bytes_to_plaintext_chunks::<ProjectiveCurve, _>(&plaintext)
            .map_err(|e| anyhow!("error casting plaintext: {e}"))?;

        let msg = msg.remove(0);

        let encrypt = Encryption::new(pk, msg, &CircuitParams, rng)
            .map_err(|e| anyhow!("error encrypting data: {e}"))?;
        let (ciphertext, proof) = encrypt.prove(&self.circuit_pk, &mut rng)?;

        let ciphertext_encoded = ciphertext_to_bytes::<ProjectiveCurve>(ciphertext.clone())
            .map_err(|e| anyhow!("error encoding ciphertext: {e}"))?;

        let proof_encoded = ark_to_bytes(proof)?;

        Ok((ciphertext_encoded, proof_encoded))
    }
}
