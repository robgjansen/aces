use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

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
    #[arg(short, long, value_enum)]
    pub log_level: Option<LogLevel>,
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
pub struct GenKeyArgs {}

#[derive(Args)]
pub struct EncryptArgs {
    /// The public part of the crypto keypair
    #[arg(short, long, value_name = "PATH")]
    pub key: PathBuf,
    /// Compress the data stream before encryption
    #[arg(short, long, value_name = "BOOL", default_value = "true")]
    pub compress: Option<bool>,
    #[command(subcommand)]
    pub input: EncryptInputs,
}

#[derive(Args)]
pub struct DecryptArgs {
    /// The private part of the crypto keypair
    #[arg(short, long, value_name = "PATH")]
    pub key: PathBuf,
    /// Decompress the data stream after decryption
    #[arg(short, long, value_name = "BOOL", default_value = "true")]
    pub decompress: Option<bool>,
    /// The path to the ciphertext file to decrypt, or '-' for stdin
    #[arg(short, long, value_name = "PATH")]
    pub input: PathBuf,
    /// The path to the plaintext file to write, '-' for stdout, or none for auto
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
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
    /// The path to the plaintext file to encrypt, or '-' for stdin
    #[arg(short, long, value_name = "PATH")]
    pub input: PathBuf,
    /// The path to the ciphertext file to write, '-' for stdout, or none for auto
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct EncryptTorArgs {
    /// One or more paths to Tor control unix socket files
    #[arg(short, long, value_name = "PATH")]
    socket: Vec<PathBuf>,
    /// One or more async Tor events to listen for with SETEVENTS
    #[arg(short, long)]
    event: Vec<String>,
    /// The path to the ciphertext file to write, '-' for stdout, or none for auto
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

pub fn parse_cli() -> Cli {
    Cli::parse()
}
