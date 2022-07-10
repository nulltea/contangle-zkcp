use crate::traits::ChainProvider;
use crate::utils::{encrypt, keypair_from_hex, keypair_gen};
use anyhow::anyhow;
use ecdsa_fun::adaptor::{Adaptor, EncryptedSignature, HashTranscript};
use ethers::prelude::*;
use ethers::utils::keccak256;
use futures::channel::{mpsc, oneshot};
use rand_chacha::ChaCha20Rng;
use secp256kfun::marker::{Mark, Normal};
use secp256kfun::nonce::Deterministic;
use secp256kfun::{g, Point, Scalar, G};
use sha2::Sha256;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::str::FromStr;

pub struct Seller<TChainProvider> {
    data: Vec<u8>,
    cost: f64,
    adaptor: Adaptor<HashTranscript<Sha256, ChaCha20Rng>, Deterministic<Sha256>>,
    chain: TChainProvider,
    wallet: crate::LocalWallet,
    from_buyers: mpsc::Receiver<SellerMsg>,
    data_keys: HashMap<Address, Scalar>,
}

pub enum SellerMsg {
    /// Step 1: Alice generates new key pair, encrypt data with it, and sends public key and ciphertext to Bob.
    Step1 {
        address: Address,
        resp_tx: oneshot::Sender<anyhow::Result<(Vec<u8>, Point, Address)>>,
    },
    /// Step 3: Alice decrypts this signature and publishes it, ie. get paid
    Step3 {
        pub_key: Point,
        enc_sig: EncryptedSignature,
        resp_tx: oneshot::Sender<anyhow::Result<H256>>,
    },
}

impl<TChainProvider: ChainProvider> Seller<TChainProvider> {
    pub fn new(
        data: Vec<u8>,
        cost: f64,
        chain: TChainProvider,
        wallet: crate::LocalWallet,
    ) -> (Self, mpsc::Sender<SellerMsg>) {
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);
        let (to_seller, from_buyers) = mpsc::channel(1);

        (
            Self {
                data,
                cost,
                adaptor,
                data_keys: HashMap::default(),
                chain,
                from_buyers,
                wallet,
            },
            to_seller,
        )
    }

    pub async fn run(mut self) {
        loop {
            if let Some(msg) = self.from_buyers.next().await {
                match msg {
                    SellerMsg::Step1 { address, resp_tx } => {
                        let (data_sk, data_pk) = keypair_gen();
                        let _ = self.data_keys.insert(address, data_sk);
                        let local_address = self.chain.address_from_pk(self.wallet.pub_key());
                        if let Err(_) = resp_tx.send(
                            encrypt(&data_pk, &*self.data)
                                .map(|ciphertext| (ciphertext, data_pk, local_address)),
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
}
