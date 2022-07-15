#![feature(async_closure)]

mod buyer;
mod ethereum;
mod seller;
mod traits;
mod utils;
mod wallet;

pub use buyer::*;
pub use ethereum::*;
pub use seller::*;
pub use traits::*;
pub use utils::*;
pub use wallet::*;

pub use zkp::{
    Bls12_381 as PairingEngine, JubJub as ProjectiveCurve, JubJubParams as CircuitParams,
    JubJubVar as CurveVar,
};

pub type Encryption = zkp::EncryptCircuit<ProjectiveCurve, CurveVar>;

#[cfg(test)]
mod tests {
    use crate::{keypair_from_hex, keypair_gen};

    use ecdsa_fun::adaptor::{Adaptor, HashTranscript};

    use ethers::prelude::*;
    use ethers::utils::parse_ether;
    use rand_chacha::ChaCha20Rng;
    use secp256kfun::nonce::Deterministic;
    use sha2::Sha256;

    use std::str::FromStr;

    const ALICE_SK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const BOB_SK: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const CHAIN_ID: u64 = 1;

    #[test]
    fn verify_decrypted_adaptor_on_ethereum() {
        let (sk, _pk) = keypair_from_hex(BOB_SK).unwrap();
        let (data_sk, data_pk) = keypair_gen();
        let nonce_gen = Deterministic::<Sha256>::default();
        let adaptor = Adaptor::<HashTranscript<Sha256, ChaCha20Rng>, _>::new(nonce_gen);

        let alice_wallet = LocalWallet::from_str(ALICE_SK).unwrap();
        println!(
            "alice sk={}, pk={}, addr={}",
            ALICE_SK,
            hex::encode(alice_wallet.signer().verifying_key().to_bytes()),
            alice_wallet.address()
        );
        let bob_wallet = LocalWallet::from_str(BOB_SK).unwrap();
        println!(
            "bob sk={}, pk={}, addr={}",
            BOB_SK,
            hex::encode(bob_wallet.signer().verifying_key().to_bytes()),
            bob_wallet.address()
        );
        let _bob_address = bob_wallet.address();
        let transfer_tx = TransactionRequest::new()
            .from(bob_wallet.address())
            .to(alice_wallet.address())
            .value(parse_ether(1).unwrap());

        let tx_encoded = transfer_tx.sighash(CHAIN_ID);
        let encrypted_sig = adaptor.encrypted_sign(&sk, &data_pk, tx_encoded.as_fixed_bytes());
        let decrypted_sig = adaptor.decrypt_signature(&data_sk, encrypted_sig.clone());

        let from = bob_wallet.address();
        let m = transfer_tx.sighash(CHAIN_ID);
        let r = U256::from_big_endian(&decrypted_sig.R_x.to_bytes());
        let s = U256::from_big_endian(&decrypted_sig.s.to_bytes());
        let v = {
            let v = to_eip155_v(1, CHAIN_ID);
            let recid = Signature { r, s, v }.verify(m, from).is_ok() as u8;
            println!("recid: {recid}");
            to_eip155_v(recid, CHAIN_ID)
        };

        println!(
            "r: {}\ns: {}\nv: {}\nhash: {}\na: {}",
            r,
            s,
            v,
            transfer_tx.sighash(CHAIN_ID),
            bob_wallet.address()
        );

        let _encoded_signed_tx = transfer_tx.rlp_signed(&Signature { r, s, v });
        let res = Signature { r, s, v }.verify(tx_encoded, bob_wallet.address());

        if let Err(ref e) = res {
            println!("{e}");
        }

        assert!(res.is_ok())
    }
}
