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
    /// Generate an RSA (Public,Private) keypair
    GenKey(GenKeyArgs),
    /// Collate data streams into compressed and encrypted files
    Construct(ConstructArgs),
    /// Decrypt and decompress previously constructed files
    Deconstruct(DeconstructArgs),
}

#[derive(Args)]
pub struct GenKeyArgs {
    /// Size of the key in bits
    #[arg(short, long, default_value_t = 4096)]
    pub bits: u16,
}

#[derive(Args)]
pub struct ConstructArgs {
    /// The public part of an RSA keypair
    #[arg(short, long, value_name = "FILE")]
    pub key: PathBuf,
}

#[derive(Args)]
pub struct DeconstructArgs {
    /// The private part of an RSA keypair
    #[arg(short, long, value_name = "FILE")]
    pub key: PathBuf,
}

pub fn parse_cli() -> Cli {
    Cli::parse()
}
