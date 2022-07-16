#![feature(async_closure)]

mod args;

use crate::args::{BuyArgs, CLIArgs, Command, CompileArgs, SellArgs, SetupArgs};
use anyhow::anyhow;
use async_std::fs;
use async_std::path::Path;
use chrono;
use gumdrop::Options;
use inquire::{Confirm, Password, Select, Text};
use scriptless_zkcp::{
    cipher_host, keypair_from_bip39, keypair_from_hex, keypair_gen, verify_proof_of_encryption,
    write_to_keystore, CipherDownloader, CipherHost, Encryption, Ethereum, LocalWallet,
    PairingEngine, Seller, SellerConfig, Step1Msg, ENC_PARAMS,
};
use scriptless_zkcp::{Buyer, ChainProvider};
use server::client;
use std::path::PathBuf;
use std::process;
use tokio::spawn;
use url::Url;
use zkp::{read_verifying_key, write_artifacts_json};

const CHAIN_ID: u64 = 31337;

const ALICE_ADDR: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const ALICE_SK: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const BOB_ADDR: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const BOB_SK: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // pretty_env_logger::init();

    let args: CLIArgs = CLIArgs::parse_args_default_or_exit();
    let command = args.command.unwrap_or_else(|| {
        eprintln!("[command] is required");
        eprintln!("{}", CLIArgs::usage());
        process::exit(2)
    });

    match command {
        Command::Setup(args) => setup(args).await?,
        Command::Sell(args) => sell(args).await?,
        Command::Buy(args) => buy(args).await?,
        Command::Compile(args) => compile(args).await?,
    }

    Ok(())
}

async fn setup(args: SetupArgs) -> anyhow::Result<()> {
    let options = vec![
        "Generate new",
        "Recover from hex",
        "Recover from BIP39 mnemonic",
    ];
    let picked = Select::new("Wallet source?", options.clone())
        .prompt()
        .unwrap();
    let sk = match options
        .iter()
        .position(|e| *e == picked)
        .expect("unexpected option")
    {
        0 => keypair_gen().0,
        1 => keypair_from_hex(&Text::new("Paste hex here:").prompt().unwrap())?.0,
        2 => keypair_from_bip39(&Text::new("Mnemonic phrase:").prompt().unwrap())?.0,
        _ => panic!("unexpected option"),
    };

    let name = Text::new("Wallet name:").prompt().unwrap();
    let password = Password::new("Password:").prompt().unwrap();

    write_to_keystore(sk, args.keystore_dir, name, password)
}

async fn sell(args: SellArgs) -> anyhow::Result<()> {
    let name = args
        .wallet_name
        .unwrap_or_else(|| Text::new("Wallet name:").prompt().unwrap());
    let password = args
        .password
        .unwrap_or_else(|| Password::new("Password:").prompt().unwrap());
    let keystore = Path::new(&args.keystore_dir).join(name);
    let wallet = LocalWallet::from_keystore(keystore, password)?;

    let proving_key = zkp::read_proving_key(args.encryption_proving_key_path)?;

    let rpc_url = Url::parse(&args.rpc_address).map_err(|e| anyhow!("bad rpc address: {e}"))?;
    let eth_provider = Ethereum::new(rpc_url).await;

    let price_str = args
        .price
        .unwrap_or_else(|| Text::new("Price (ETH):").prompt().unwrap());
    let price: f64 = price_str
        .parse()
        .map_err(|e| anyhow!("error parsing price: {e}"))?;

    let mut cipher_host = cipher_host::LocalHost::new(&args.cache_dir);

    let cfg = SellerConfig {
        price,
        cache_dir: PathBuf::from(args.cache_dir),
    };
    let (mut seller, to_runtime) =
        Seller::new(cfg, eth_provider, cipher_host.clone(), wallet, proving_key)?;

    if !cipher_host.is_hosted().await? {
        println!("encrypting data and generation proof of encryption...");
        let data_path = args
            .data_path
            .unwrap_or_else(|| Text::new("File to be sold:").prompt().unwrap());
        let data = fs::read(data_path)
            .await
            .map_err(|e| anyhow!("error reading data: {e}"))?;
        seller.step0_setup(data).await?;
    } else {
        println!("encrypted data was restored from cache.");
    }

    spawn(async {
        seller.run().await;
    });

    server::serve(to_runtime, price).await;

    Ok(())
}

async fn buy(args: BuyArgs) -> anyhow::Result<()> {
    let rpc_url = Url::parse(&args.rpc_address).map_err(|e| anyhow!("bad rpc address: {e}"))?;
    let eth_provider = Ethereum::new(rpc_url).await;

    let client = client::SellerClient::new(args.seller_address)?;
    let price = client.price().await?;

    if !args.non_interactive
        && !Confirm::new(&format!("Price is {price} ETH. Continue? (y/N): "))
            .prompt()
            .unwrap()
    {
        return Ok(());
    }

    let vk = read_verifying_key(args.encryption_verifying_key_path)?;

    println!("downloading encrypted data...");
    let (encrypted_data, proof_of_encryption) = client.download().await?;
    if !verify_proof_of_encryption(&vk, proof_of_encryption, &encrypted_data)? {
        return Err(anyhow!("seller sent invalid proof of encryption"));
    }
    println!("proof of encryption is valid");

    let name = args
        .wallet_name
        .unwrap_or_else(|| Text::new("Wallet name:").prompt().unwrap());
    let password = args
        .password
        .unwrap_or_else(|| Password::new("Password:").prompt().unwrap());
    let keystore = Path::new(&args.keystore_dir).join(name);
    let wallet = LocalWallet::from_keystore(keystore, password)?;
    let address = eth_provider.address_from_pk(wallet.pub_key());
    let pub_key = wallet.pub_key().clone();

    let mut buyer = Buyer::new(eth_provider, wallet);

    let Step1Msg {
        ciphertext,
        proof_of_encryption,
        data_pk,
        seller_address,
    } = client.step1(address).await?;

    if !verify_proof_of_encryption(&vk, proof_of_encryption, &ciphertext)? {
        return Err(anyhow!("seller sent invalid proof of encryption"));
    }

    // todo: cache ciphertext, data_pk, buyer_address.

    if !args.non_interactive
        && !Confirm::new(&format!(
            "Encrypted one-time key received. Sign transfer transaction to address 0x{address}? (y/N): "
        ))
        .prompt()
        .unwrap()
    {
        return Ok(());
    }

    let enc_sig = buyer
        .step2(&ciphertext, &data_pk, seller_address, price)
        .await?;

    let tx_hash = client.step3(pub_key, enc_sig).await?;

    let data = buyer.step4(tx_hash, encrypted_data).await?;

    let data_path = args.data_path.unwrap_or_else(|| {
        Text::new("File decrypted! Where to save the result?:")
            .with_default(&format!("purchase_{}", chrono::Local::today().to_string()))
            .prompt()
            .unwrap()
    });

    let data_path = Path::new(&data_path);
    let _ = fs::create_dir_all(data_path.parent().unwrap()).await;
    fs::write(data_path, data)
        .await
        .map_err(|e| anyhow!("error writing decrypted data: {e}"))?;

    println!(
        "find your purchased data at {}",
        data_path.to_str().unwrap()
    );

    Ok(())
}

async fn compile(args: CompileArgs) -> anyhow::Result<()> {
    println!("compiling circuit...");
    let (pk, vk) = Encryption::compile::<PairingEngine, _>(&ENC_PARAMS, &mut rand::thread_rng())?;

    println!("writing artifacts...");
    write_artifacts_json(args.output_dir, pk, vk)?;

    println!("done!");
    Ok(())
}
