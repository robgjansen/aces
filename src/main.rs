mod args;
mod construct;
mod deconstruct;
mod genkey;

use env_logger::{Builder, Target};
use log::LevelFilter;

use crate::args::{Commands, LogLevel};

fn main() {
    let cli = args::parse_cli();

    let level = match &cli.log_level {
        Some(LogLevel::Info) => LevelFilter::Info,
        Some(LogLevel::Warn) => LevelFilter::Warn,
        Some(LogLevel::Error) => LevelFilter::Error,
        Some(LogLevel::Off) => LevelFilter::Off,
        None => LevelFilter::Info,
    };

    Builder::new()
        .target(Target::Stdout)
        .filter_level(level)
        .init();
    log::info!("Parsed CLI args and initialized logger!");

    match cli.command {
        Some(Commands::GenKey(args)) => {
            log::info!("Running gen-key subcommand");
            genkey::run(args)
        }
        Some(Commands::Construct(args)) => {
            log::info!("Running construct subcommand");
            construct::run(args)
        }
        Some(Commands::Deconstruct(args)) => {
            log::info!("Running deconstruct subcommand");
            deconstruct::run(args)
        }
        None => {}
    }
}
