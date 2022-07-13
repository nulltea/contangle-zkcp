use crate::traits::ChainProvider;
use anyhow::anyhow;
use backoff::ExponentialBackoff;
use ecdsa_fun::adaptor::{Adaptor, EncryptedSignature, HashTranscript};
use std::path::Path;

use ethers::prelude::{Address, H256};
use rand_chacha::ChaCha20Rng;
use secp256kfun::nonce::Deterministic;
use secp256kfun::{Point, Scalar};
use sha2::Sha256;
use zkp::{
    ark_from_bytes, ark_to_bytes, Bls12_381, Encryption, JubJub, VerifyingKey, JUB_JUB_PARAMETERS,
};

pub struct Buyer<TChainProvider> {
    chain: TChainProvider,
    wallet: crate::LocalWallet,
    adaptor: Adaptor<HashTranscript<Sha256, ChaCha20Rng>, Deterministic<Sha256>>,
    ciphertext: Option<Vec<u8>>,
    data_pk: Option<Point>,
    encrypted_sig: Option<EncryptedSignature>,
}

impl<TChainProvider: ChainProvider> Buyer<TChainProvider> {
    pub fn new(chain: TChainProvider, wallet: crate::LocalWallet) -> Self {
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);

        Self {
            chain,
            wallet,
            adaptor,
            ciphertext: None,
            data_pk: None,
            encrypted_sig: None,
        }
    }

    pub fn verify_proof_of_encryption(
        &self,
        vk: VerifyingKey<Bls12_381>,
        proof: Vec<u8>,
        ciphertext: &[u8],
    ) -> anyhow::Result<bool> {
        let proof_of_encryption = ark_from_bytes(proof)?;
        let ciphertext_affine =
            ark_from_bytes(&ciphertext).map_err(|e| anyhow!("error casting ciphertext"))?;

        Encryption::verify_proof::<Bls12_381>(&vk, proof_of_encryption, ciphertext_affine)
    }

    /// Step 2: Bob signs a transaction to transfer coins to Alice address
    /// and encrypts it with `data_pk` and sends it to Alice.
    pub async fn step2(
        &mut self,
        ciphertext: &[u8],
        data_pk: &Point,
        addr_to: Address,
        amount: f64,
    ) -> anyhow::Result<EncryptedSignature> {
        let _ = self.ciphertext.insert(ciphertext.to_vec());
        let _ = self.data_pk.insert(data_pk.clone());
        let (_, tx_hash) = self.chain.compose_tx(
            self.chain.address_from_pk(self.wallet.pub_key()),
            addr_to,
            amount,
        )?;

        let encrypted_sig =
            self.adaptor
                .encrypted_sign(self.wallet.sec_key(), data_pk, tx_hash.as_fixed_bytes());

        let _ = self.encrypted_sig.insert(encrypted_sig.clone());

        return Ok(encrypted_sig);
    }

    /// Step 4: Bob observes signature on-chain and use it to recover `data_sk`
    /// and decrypt the data file from the ciphertext given to him by Alice.
    pub async fn step4(&mut self, tx_hash: H256) -> anyhow::Result<Vec<u8>> {
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
                self.data_pk.as_ref().unwrap(),
                &signature,
                self.encrypted_sig.as_ref().unwrap(),
            )
            .unwrap();

        decrypt(&recovered_sk, &*self.ciphertext.take().unwrap())
    }
}

pub fn decrypt(sk: &Scalar, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let sk = ark_from_bytes(sk.to_bytes()).map_err(|e| anyhow!("error casting secret key: {e}"))?;
    let ciphertext =
        ark_from_bytes(ciphertext).map_err(|e| anyhow!("error casting ciphertext: {e}"))?;
    let plaintext = Encryption::decrypt::<Bls12_381>(ciphertext, sk, &JUB_JUB_PARAMETERS)?;
    ark_to_bytes(plaintext).map_err(|e| anyhow!("error casting plaintext: {e}"))
}
