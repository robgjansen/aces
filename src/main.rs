mod args;
mod crypto;

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use chrono::Utc;
use crypto::Decryptor;
use crypto_box::rand_core::{OsRng, RngCore};
use env_logger::{Builder, Target};
use log::LevelFilter;

use crate::{
    args::{Commands, DecryptArgs, EncryptArgs, GenKeyArgs, LogLevel},
    crypto::Encryptor,
};

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

    let result = match cli.command {
        Some(Commands::GenKey(args)) => {
            log::info!("Running gen-key subcommand");
            run_genkey(args)
        }
        Some(Commands::Encrypt(args)) => {
            log::info!("Running encrypt subcommand");
            run_encrypt(args)
        }
        Some(Commands::Decrypt(args)) => {
            log::info!("Running decrypt subcommand");
            run_decrypt(args)
        }
        None => Ok(()),
    };

    if let Err(e) = result {
        log::error!("Error occurred: {}", e);
        log::error!("Caused by: {}", e.root_cause());
    }
    log::info!("Returning cleanly from main");
}

fn run_genkey(_args: GenKeyArgs) -> anyhow::Result<()> {
    log::info!("Generating key pair");

    crypto::generate_and_write_key_pair(
        &PathBuf::from("./aces.sec.key"),
        &PathBuf::from("./aces.pub.key"),
    )?;

    log::info!("Keys written! Use aces.pub.key to encrypt and aces.sec.key to decrypt.");
    Ok(())
}

fn run_encrypt(args: EncryptArgs) -> anyhow::Result<()> {
    let pub_key = crypto::read_public_key(&args.key).context(std::format!(
        "Failed to read public key {}",
        &args.key.to_string_lossy()
    ))?;

    let infile_opt = {
        if args.plaintext.as_os_str().eq("-") {
            None
        } else {
            Some(File::open(&args.plaintext).context(std::format!(
                "Failed to open input file {}",
                &args.plaintext.to_string_lossy()
            ))?)
        }
    };

    let mut outfile = {
        let filename = {
            let random_num = OsRng.next_u32() as u8;
            let current_ts = Utc::now().format("%Y-%m-%d_%H:%M:%S_UTC");
            format!("./aces_msgs_{}_{:03}.txt.enc", current_ts, random_num)
        };

        log::info!("Encrypted output will be written to {}", &filename);

        File::create(Path::new(&filename))
            .context(std::format!("Failed to create output file {}", &filename))?
    };

    log::info!("Encrypting all data from the input stream...");
    match infile_opt {
        Some(mut infile) => Encryptor::new(pub_key)
            .encrypt_all(&mut infile, &mut outfile)
            .context("Failure while running encryptor")?,
        None => Encryptor::new(pub_key)
            .encrypt_all(&mut std::io::stdin(), &mut outfile)
            .context("Failure while running encryptor")?,
    }
    outfile.flush()?;

    log::info!("Success!");
    Ok(())
}

fn run_decrypt(args: DecryptArgs) -> anyhow::Result<()> {
    let sec_key = crypto::read_secret_key(&args.key).context(std::format!(
        "Failed to read secret key {}",
        &args.key.to_string_lossy()
    ))?;

    let mut infile = File::open(&args.ciphertext).context(std::format!(
        "Failed to open input file {}",
        &args.ciphertext.to_string_lossy()
    ))?;

    let mut outfile = {
        let filename = &args
            .ciphertext
            .file_stem()
            .context("Input filename has no stem")?;
        log::info!(
            "Decrypted output will be written to {}",
            &filename.to_string_lossy()
        );
        File::create(Path::new(&filename)).context(std::format!(
            "Failed to create output file {}",
            &filename.to_string_lossy()
        ))?
    };

    log::info!("Decrypting all data from the ciphertext file...");
    Decryptor::new(sec_key)
        .decrypt_all(&mut infile, &mut outfile)
        .context("Failure while running decryptor")?;
    outfile.flush()?;

    log::info!("Success!");
    Ok(())
}
