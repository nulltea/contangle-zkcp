use gumdrop::Options;

#[derive(Debug, Options, Clone)]
pub struct CLIArgs {
    help: bool,
    #[options(command)]
    pub command: Option<Command>,
}

#[derive(Debug, Options, Clone)]
pub enum Command {
    #[options(help = "Setup wallet")]
    Setup(SetupArgs),
    #[options(help = "Deploy seller daemon")]
    Sell(SellArgs),
}

#[derive(Debug, Options, Clone)]
pub struct SetupArgs {
    help: bool,

    #[options(help = "path to keystore location", default = "./keys")]
    pub keystore_dir: String,
}

#[derive(Debug, Options, Clone)]
pub struct SellArgs {
    help: bool,

    #[options(help = "path to the data file being sold")]
    pub data_path: Option<String>,

    #[options(help = "price of the data")]
    pub price: Option<String>,

    #[options(help = "chain RPC address", default = "http://localhost:8545")]
    pub rpc_address: String,

    #[options(help = "chain id", default = "http://localhost:8545")]
    pub chain_id: String,

    #[options(help = "path to keystore location", default = "./keys")]
    pub keystore_dir: String,

    #[options(help = "wallet name")]
    pub wallet_name: Option<String>,

    #[options(help = "wallet password")]
    pub password: Option<String>,
}
