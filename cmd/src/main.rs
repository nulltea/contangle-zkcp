#![feature(async_closure)]

mod args;
use crate::args::{BuyArgs, CLIArgs, Command, CompileArgs, SellArgs, SetupArgs};
use anyhow::anyhow;
use chrono;
use circuits::encryption;
use futures_util::TryFutureExt;
use gumdrop::Options;
use inquire::{Confirm, Password, Select, Text};
use rocket::http::hyper::body::HttpBody;
use scriptless_zkcp::zk::{CircomParams, ZkEncryption, ZkSampleEntries, ZkVerifiableEncryption};
use scriptless_zkcp::{
    cipher_host, keypair_from_bip39, keypair_from_hex, keypair_gen, write_to_keystore, BuyerConfig,
    CipherDownloader, CipherHost, Ethereum, LocalWallet, Seller, SellerConfig, Step1Msg, ZkConfig,
};
use scriptless_zkcp::{Buyer, ChainProvider};
use server::client;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use tokio::spawn;
use url::Url;

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

    let rpc_url = Url::parse(&args.rpc_address).map_err(|e| anyhow!("bad rpc address: {e}"))?;
    let eth_provider = Ethereum::new(rpc_url).await?;

    let price_str = args
        .price
        .unwrap_or_else(|| Text::new("Price (ETH):").prompt().unwrap());
    let price: f64 = price_str
        .parse()
        .map_err(|e| anyhow!("error parsing price: {e}"))?;

    let cipher_host = cipher_host::LocalHost::new(&args.cache_dir);

    if !Path::new("zk-config.json").exists() {
        return Err(anyhow!(
            "'zk-config.json' not found. Use `compile` command to generate one."
        ));
    }

    let cfg = SellerConfig {
        price,
        cache_dir: PathBuf::from(args.cache_dir),
        zk: serde_json::from_slice(
            &*fs::read("zk-config.json").expect("expect zk-config.json to exist"),
        )
        .map_err(|_e| anyhow!("error unmarshalling zk-config.json"))?,
    };
    let property_verifier = ZkSampleEntries::new(
        cfg.zk.prop_verifier_dir.clone(),
        cfg.zk.data_encryption_limit,
    );
    let (mut seller, to_runtime) = Seller::new(
        cfg,
        eth_provider,
        cipher_host.clone(),
        property_verifier,
        wallet,
    )?;

    if !cipher_host.is_hosted().await? {
        println!("encrypting data and generation proof of encryption...");
        let data_path = args
            .data_path
            .unwrap_or_else(|| Text::new("File to be sold:").prompt().unwrap());

        let data = fs::read(data_path).map_err(|e| anyhow!("error reading data: {e}"))?;
        let data: Vec<String> = serde_json::from_slice(&*data).unwrap();
        let data = data.into_iter().map(|e| e.parse().unwrap()).collect();
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
    let eth_provider = Ethereum::new(rpc_url).await?;

    let client = client::SellerClient::new(args.seller_address)?;
    let price = client.price().await?;

    if !args.non_interactive
        && !Confirm::new(&format!("Price is {price} ETH. Continue? (y/N): "))
            .prompt()
            .unwrap()
    {
        return Ok(());
    }

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

    if !Path::new("zk-config.json").exists() {
        return Err(anyhow!(
            "'zk-config.json' file not found. Please ask seller of details."
        ));
    }

    let cfg = BuyerConfig {
        zk: serde_json::from_slice(
            &*fs::read("zk-config.json").expect("expect zk-config.json to exist"),
        )
        .map_err(|_e| anyhow!("error unmarshalling zk-config.json"))?,
    };

    let property_verifier = ZkSampleEntries::new(
        cfg.zk.prop_verifier_dir.clone(),
        cfg.zk.data_encryption_limit,
    );
    let mut buyer = Buyer::new(cfg, eth_provider, property_verifier, wallet);

    println!("downloading encrypted data...");
    let encrypted_data = client.download().await?;
    if !buyer.step0_verify(&encrypted_data)? {
        return Err(anyhow!("seller sent invalid proof of data encryption"));
    }
    println!("proof of encryption is valid");

    let Step1Msg {
        ciphertext,
        proof_of_encryption,
        data_pk,
        seller_address,
    } = client.step1(address).await?;

    // todo: cache ciphertext and data_pk.
    let enc_sig = buyer
        .step2(
            &ciphertext,
            proof_of_encryption,
            &data_pk,
            seller_address,
            price,
        )
        .await?;

    if !args.non_interactive
        && !Confirm::new(&format!(
        "Encrypted one-time key received. Sign transfer transaction to address 0x{address}? (y/N): "
    ))
        .prompt()
        .unwrap()
    {
        return Ok(());
    }

    let tx_hash = client.step3(pub_key, enc_sig).await?;

    let data = buyer.step4(tx_hash, encrypted_data.ciphertext).await?;
    let data = serde_json::to_vec(&data).unwrap();

    let data_path = args.data_path.unwrap_or_else(|| {
        Text::new("File decrypted! Where to save the result?:")
            .with_default(&format!("purchase_{}", chrono::Local::today().to_string()))
            .prompt()
            .unwrap()
    });

    let data_path = Path::new(&data_path);
    let _ = fs::create_dir_all(data_path.parent().unwrap());
    fs::write(data_path, data).map_err(|e| anyhow!("error writing decrypted data: {e}"))?;

    println!(
        "find your purchased data at {}",
        data_path.to_str().unwrap()
    );

    Ok(())
}

async fn compile(args: CompileArgs) -> anyhow::Result<()> {
    let cipher_host = cipher_host::LocalHost::new(&args.cache_dir);

    if cipher_host.is_hosted().await.unwrap() && !Confirm::new(&format!(
        "Proof of encryption cache found. Recompiling circuit will cause it becoming broken. Continue? (y/N): "
    ))
        .prompt()
        .unwrap()
    {
        return Ok(())
    }

    let build_dir = PathBuf::from(args.build_dir);
    let cfg = ZkConfig {
        prop_verifier_dir: build_dir.join("prop_verifier"),
        data_encryption_dir: build_dir.join("data_encryption"),
        data_encryption_limit: args.limit_data_enc_dir,
        key_encryption_dir: build_dir.join("key_encryption"),
        circom_params: CircomParams {
            plaintext_field_name: args.plaintext_field_name,
            wasm_path: PathBuf::from(args.wasm_path),
            r1cs_path: PathBuf::from(args.r1cs_path),
        },
    };

    fs::write(
        "zk-config.json",
        serde_json::to_vec(&cfg).expect("expected zk config to marshal to json"),
    )
    .map_err(|e| anyhow!("error saving zk config: {e}"))?;

    println!("compiling data encryption circuit...");
    let property_verifier =
        ZkSampleEntries::new(cfg.prop_verifier_dir.clone(), cfg.data_encryption_limit);
    let prop_verification = ZkVerifiableEncryption::new(
        &cfg.data_encryption_dir,
        property_verifier,
        encryption::Parameters::default_multi(cfg.data_encryption_limit),
    );
    let _ = prop_verification.compile(&mut rand::thread_rng())?;

    println!("compiling key encryption circuit...");
    let key_encryption = ZkEncryption::new(&cfg.key_encryption_dir, Default::default());
    let _ = key_encryption.compile(&mut rand::thread_rng())?;

    println!("done!");
    Ok(())
}
