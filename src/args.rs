use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use humantime::Duration;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Off,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
/// Asynchronously compress and encrypt data streams.
pub struct Cli {
    /// The level at which to filter log messages.
    #[arg(short, long, value_enum, default_value = "info")]
    pub log_level: LogLevel,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
/// Holds the supported subcommands and their args.
pub enum Commands {
    /// Generate a crypto keypair
    GenKey(GenKeyArgs),
    /// Encrypt data streams
    Encrypt(EncryptArgs),
    /// Decrypt previously encrypted data
    Decrypt(DecryptArgs),
}

#[derive(Args)]
pub struct GenKeyArgs {
    /// The path to write the secret key
    #[arg(short, long, value_name = "PATH", default_value = "./aces.sec.key")]
    pub secret: PathBuf,
    /// The path to write the public key
    #[arg(short, long, value_name = "PATH", default_value = "./aces.pub.key")]
    pub public: PathBuf,
}

#[derive(Args)]
pub struct EncryptArgs {
    /// Compress the data stream before encryption
    #[arg(short, long, value_name = "BOOL", default_value = "true")]
    pub compress: Option<bool>, // Option so that the default is shown in help
    /// The path to an aces public key file
    #[arg(value_name = "KEYPATH")]
    pub key: PathBuf,
    #[command(subcommand)]
    pub input: EncryptInputs,
}

#[derive(Args)]
pub struct DecryptArgs {
    /// Decompress the data stream after decryption
    #[arg(short, long, value_name = "BOOL", default_value = "true")]
    pub decompress: Option<bool>, // Option so that the default is shown in help
    /// The path to the plaintext file to write, '-' for stdout, or none for auto
    #[arg(short, long, value_name = "OUTPATH")]
    pub output: Option<PathBuf>,
    /// The path to an aces secret key file
    #[arg(short, long, value_name = "KEYPATH")]
    pub key: PathBuf,
    /// The path to the ciphertext file to decrypt, or '-' for stdin
    #[arg(value_name = "INPATH")]
    pub input: PathBuf,
}

#[derive(Subcommand)]
pub enum EncryptInputs {
    /// Encrypt data from a file or stdin
    File(EncryptFileArgs),
    /// Encrypt data from a running tor process
    Tor(EncryptTorArgs),
}

#[derive(Args)]
pub struct EncryptFileArgs {
    /// The path to the ciphertext file to write, '-' for stdout, or none for auto
    #[arg(short, long, value_name = "OUTPATH")]
    pub output: Option<PathBuf>,
    /// The path to the plaintext file to encrypt, or '-' for stdin
    #[arg(value_name = "INPATH")]
    pub input: PathBuf,
}

#[derive(Args)]
pub struct EncryptTorArgs {
    /// The path to the ciphertext file to write, '-' for stdout, or none for auto
    #[arg(short, long, value_name = "OUTPATH")]
    pub output: Option<PathBuf>,
    /// A duration after which to rotate the output file (only allowed if --output is not set)
    #[arg(short, long, value_name = "HUMANTIME")]
    pub rotate: Option<Duration>,
    /// One or more async Tor events to listen for with SETEVENTS
    #[arg(short, long, default_value = "BW")]
    pub event: Vec<String>,
    /// One or more paths to Tor control unix socket files
    #[arg(value_name = "SOCKPATH")]
    pub socket: Vec<PathBuf>,
}

pub fn parse_cli() -> Cli {
    Cli::parse()
}
