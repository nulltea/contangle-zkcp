use crate::encryption::ZkEncryption;
use crate::traits::ChainProvider;
use crate::zk::{ZkEncryption, ZkPropertyVerifier};
use crate::{CipherHost, PairingEngine, ProjectiveCurve, ZkConfig};
use anyhow::anyhow;
use backoff::ExponentialBackoff;
use circuits::{ark_from_bytes, encryption, plaintext_chunks_to_bytes, SecretKey};
use ecdsa_fun::adaptor::{Adaptor, EncryptedSignature, HashTranscript};
use ethers::prelude::{Address, H256};
use num_bigint::BigInt;
use rand_chacha::ChaCha20Rng;
use secp256kfun::nonce::Deterministic;
use secp256kfun::{Point, Scalar};
use sha2::Sha256;

pub struct Buyer<TChainProvider> {
    chain: TChainProvider,
    wallet: crate::LocalWallet,
    adaptor: Adaptor<HashTranscript<Sha256, ChaCha20Rng>, Deterministic<Sha256>>,
    encrypted_key: Option<Vec<u8>>,
    one_time_pk: Option<Point>,
    encrypted_sig: Option<EncryptedSignature>,
    data_encryption: ZkPropertyVerifier,
    key_encryption: ZkEncryption,
}

#[derive(Clone, Debug)]
pub struct BuyerConfig {
    pub zk: ZkConfig,
}

impl<TChainProvider: ChainProvider> Buyer<TChainProvider> {
    pub fn new(cfg: BuyerConfig, chain: TChainProvider, wallet: crate::LocalWallet) -> Self {
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);
        let data_encryption = ZkPropertyVerifier::new_verifier(
            &cfg.zk.prop_verifier_dir,
            cfg.zk.circom_params.clone(),
            encryption::Parameters::default_multi(cfg.zk.data_encryption_limit),
        );
        let key_encryption =
            ZkEncryption::new_verifier(&cfg.zk.key_encryption_dir, Default::default());

        Self {
            chain,
            wallet,
            adaptor,
            encrypted_key: None,
            one_time_pk: None,
            encrypted_sig: None,
            data_encryption,
            key_encryption,
        }
    }

    /// Step 0: Bob verifies data ciphertext.
    pub fn step0_verify<
        CB: AsRef<[u8]>,
        PB: AsRef<[u8]>,
        AV: Iterator<Item = (String, Vec<BigInt>)>,
    >(
        &self,
        encrypted_data: CB,
        proof: PB,
        additional_values: AV,
    ) -> anyhow::Result<bool> {
        self.data_encryption
            .verify_proof(proof, encrypted_data, additional_values)
    }

    /// Step 2: Bob signs a transaction to transfer coins to Alice address
    /// and encrypts it with `data_pk` and sends it to Alice.
    pub async fn step2<KB: AsRef<[u8]>, PB: AsRef<[u8]>>(
        &mut self,
        encrypted_key: KB,
        proof: PB,
        one_time_pk: &Point,
        addr_to: Address,
        amount: f64,
    ) -> anyhow::Result<EncryptedSignature> {
        if !self.key_encryption.verify_proof(proof, &encrypted_key)? {
            return Err(anyhow!("seller sent invalid proof of key encryption"));
        }

        let _ = self.encrypted_key.insert(encrypted_key.as_ref().to_vec());
        let _ = self.one_time_pk.insert(one_time_pk.clone());
        let (_, tx_hash) = self.chain.compose_tx(
            self.chain.address_from_pk(self.wallet.pub_key()),
            addr_to,
            amount,
        )?;

        let encrypted_sig = self.adaptor.encrypted_sign(
            self.wallet.sec_key(),
            one_time_pk,
            tx_hash.as_fixed_bytes(),
        );

        let _ = self.encrypted_sig.insert(encrypted_sig.clone());

        return Ok(encrypted_sig);
    }

    /// Step 4: Bob observes signature on-chain and use it to recover `data_sk`
    /// and decrypt the data file from the ciphertext given to him by Alice.
    pub async fn step4<B: AsRef<[u8]>>(
        &mut self,
        tx_hash: H256,
        encrypted_data: B,
    ) -> anyhow::Result<Vec<u8>> {
        let signature = backoff::future::retry(ExponentialBackoff::default(), || async {
            match self.chain.get_signature(tx_hash).await {
                Ok(Some(sig)) => Ok(sig),
                Ok(None) => Err(backoff::Error::transient(anyhow!("tx not found"))),
                Err(e) => Err(backoff::Error::permanent(e)),
            }
        })
        .await?;

        let recovered_sk = self
            .adaptor
            .recover_decryption_key(
                self.one_time_pk.as_ref().unwrap(),
                &signature,
                self.encrypted_sig.as_ref().unwrap(),
            )
            .unwrap();

        let decryption_key = self
            .key_encryption
            .decrypt(recovered_sk.to_bytes(), self.encrypted_key.take().unwrap())?;
        self.data_encryption.decrypt(decryption_key, encrypted_data)
    }
}
