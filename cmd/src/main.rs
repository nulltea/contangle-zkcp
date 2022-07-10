#![feature(async_closure)]

mod args;

use crate::args::{CLIArgs, Command, SellArgs, SetupArgs};
use anyhow::anyhow;
use async_std::fs;
use async_std::path::Path;
use async_std::task::Task;
use gumdrop::Options;
use inquire::error::InquireResult;
use inquire::{Confirm, Password, Select, Text};
use scriptless_zkcp::ChainProvider;
use scriptless_zkcp::{
    keypair_from_bip39, keypair_from_hex, keypair_gen, write_to_keystore, EthereumProvider,
    LocalWallet, Seller,
};
use std::error::Error;
use std::ops::Index;
use std::process;
use tokio::spawn;
use url::Url;

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

    let data_path = args
        .data_path
        .unwrap_or_else(|| Text::new("File to be sold:").prompt().unwrap());
    let data = fs::read(data_path)
        .await
        .map_err(|e| anyhow!("error reading data: {e}"))?;
    let rpc_url = Url::parse(&args.rpc_address).map_err(|e| anyhow!("bad rpc address: {e}"))?;
    let eth_provider = EthereumProvider::new(rpc_url).await;

    let price_str = args
        .price
        .unwrap_or_else(|| Text::new("Price (ETH):").prompt().unwrap());
    let price = eth_provider.parse_amount(&price_str)?;

    let (seller, to_runtime) = Seller::new(data, price, eth_provider, wallet);

    spawn(async {
        seller.run().await;
    });

    server::serve(to_runtime).await;

    Ok(())
}
