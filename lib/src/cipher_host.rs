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

        return Self {
            directory: PathBuf::from(dir.as_ref()),
        };
    }
}

#[async_trait]
impl CipherHost for LocalHost {
    async fn write(&mut self, cipher: Vec<u8>, proof: Vec<u8>) -> anyhow::Result<()> {
        fs::write(self.directory.join("ciphertext"), cipher)
            .await
            .map_err(|e| anyhow!("error writing ciphertext to local director: {e}"))?;

        fs::write(self.directory.join("proof_of_encryption"), proof)
            .await
            .map_err(|e| anyhow!("error reading proof-of-encryption from local director: {e}"))
    }

    async fn read(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let cipher = fs::read(self.directory.join("ciphertext"))
            .await
            .map_err(|e| anyhow!("error reading ciphertext to local director: {e}"))?;

        let proof = fs::read(self.directory.join("proof_of_encryption"))
            .await
            .map_err(|e| anyhow!("error reading proof-of-encryption from local director: {e}"))?;

        return Ok((cipher, proof));
    }

    async fn is_hosted(&self) -> anyhow::Result<bool> {
        Ok(self.directory.join("ciphertext").exists()
            && self.directory.join("proof_of_encryption").exists())
    }
}
