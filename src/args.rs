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
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
/// Holds the supported subcommands and their args.
pub enum Commands {
    /// Generate a crypto keypair
    GenKey(GenKeyArgs),
    /// Collate data streams into encrypted files
    Encrypt(EncryptArgs),
    /// Decrypt previously encrypted files
    Decrypt(DecryptArgs),
}

#[derive(Args)]
pub struct GenKeyArgs {}

#[derive(Args)]
pub struct EncryptArgs {
    /// The public part of the crypto keypair
    #[arg(short, long, value_name = "FILE")]
    pub key: PathBuf,
    /// Connect to these Tor control ports to receive data.
    #[arg(short, long, value_name = "PORT")]
    pub ports: Vec<u16>,
}

#[derive(Args)]
pub struct DecryptArgs {
    /// The private part of the crypto keypair
    #[arg(short, long, value_name = "FILE")]
    pub key: PathBuf,
    /// The encrypted file to decrypt
    #[arg(short, long, value_name = "FILE")]
    pub ciphertext: PathBuf,
}

pub fn parse_cli() -> Cli {
    Cli::parse()
}
