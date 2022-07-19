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
    #[options(help = "Run buyer client")]
    Buy(BuyArgs),
    #[options(help = "Compile circuits")]
    Compile(CompileArgs),
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

    #[options(
        help = "path to the directory where cache is stored",
        default = "./cache"
    )]
    pub cache_dir: String,

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

    #[options(
        help = "path for the key used to prove encryption",
        default = "./circuit.pk"
    )]
    pub encryption_proving_key_path: String,
}

#[derive(Debug, Options, Clone)]
pub struct BuyArgs {
    help: bool,

    #[options(help = "seller server address")]
    pub seller_address: String,

    #[options(help = "path where bought data will be placed")]
    pub data_path: Option<String>,

    #[options(help = "chain RPC address", default = "http://localhost:8545")]
    pub rpc_address: String,

    #[options(help = "chain id", default = "31337")]
    pub chain_id: String,

    #[options(help = "path to keystore location", default = "./keys")]
    pub keystore_dir: String,

    #[options(help = "wallet name")]
    pub wallet_name: Option<String>,

    #[options(help = "wallet password")]
    pub password: Option<String>,

    #[options(
        help = "path for the key used to verify proof of encryption",
        default = "./circuit.vk"
    )]
    pub encryption_verifying_key_path: String,

    #[options(help = "skip confirms", default = "false")]
    pub non_interactive: bool,
}

#[derive(Debug, Options, Clone)]
pub struct CompileArgs {
    help: bool,

    #[options(
        help = "path to the directory where cache is stored",
        default = "./cache"
    )]
    pub cache_dir: String,

    #[options(
        help = "path to the directory where cache is stored",
        default = "./build"
    )]
    pub build_dir: String,

    #[options(
        help = "limit of arbitrary size possible to encrypt with ZK circuit (n * 32b)",
        default = "100"
    )]
    pub limit_data_enc_dir: usize,

    // #[options(help = "build circom circuit as property verifier", default = "true")]
    // pub circom: bool,
    #[options(help = "path to built circom .wasm file")]
    pub wasm_path: String,

    #[options(help = "path to built circom .r1cs file")]
    pub r1cs_path: String,

    #[options(
        help = "field in the circom circuit definition corresponding to plaintext",
        default = "plaintext"
    )]
    pub plaintext_field_name: String,
}
