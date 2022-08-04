use crate::zk::VerifiableEncryption;
use crate::CipherHost;
use anyhow::anyhow;
use async_std::fs;
use async_trait::async_trait;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct LocalHost {
    directory: PathBuf,
}

impl LocalHost {
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        std::fs::create_dir_all(dir.as_ref()).expect("expected dir to be created");

        Self {
            directory: PathBuf::from(dir.as_ref()),
        }
    }
}

#[async_trait]
impl CipherHost for LocalHost {
    async fn write(&mut self, cipher: VerifiableEncryption) -> anyhow::Result<()> {
        fs::write(
            self.directory.join("verifiable_encryption.json"),
            serde_json::to_vec(&cipher)
                .map_err(|e| anyhow!("error encoding verifiable encryption: {e}"))?,
        )
        .await
        .map_err(|e| anyhow!("error writing ciphertext to local director: {e}"))
    }

    async fn read(&self) -> anyhow::Result<VerifiableEncryption> {
        let cipher = fs::read(self.directory.join("verifiable_encryption.json"))
            .await
            .map_err(|e| anyhow!("error reading ciphertext to local director: {e}"))?;

        serde_json::from_slice(&*cipher)
            .map_err(|e| anyhow!("error decoding verifiable encryption: {e}"))
    }

    async fn is_hosted(&self) -> anyhow::Result<bool> {
        Ok(self.directory.join("verifiable_encryption.json").exists())
    }
}

#[derive(Clone)]
pub struct EphemeralHost {
    ciphertext_and_proof: Option<VerifiableEncryption>,
}

impl EphemeralHost {
    pub fn new() -> Self {
        Self {
            ciphertext_and_proof: None,
        }
    }
}

#[async_trait]
impl CipherHost for EphemeralHost {
    async fn write(&mut self, cipher: VerifiableEncryption) -> anyhow::Result<()> {
        let _ = self.ciphertext_and_proof.insert(cipher);
        Ok(())
    }

    async fn read(&self) -> anyhow::Result<VerifiableEncryption> {
        Ok(self.ciphertext_and_proof.clone().unwrap())
    }

    async fn is_hosted(&self) -> anyhow::Result<bool> {
        Ok(self.ciphertext_and_proof.is_some())
    }
}
