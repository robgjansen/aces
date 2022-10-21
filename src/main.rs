use std::{
    io::{self, Write},
};

use anyhow::Context;
use env_logger::{Builder, Target};
use log::LevelFilter;
use zstd::stream::write::{Decoder, Encoder};

mod args;
mod crypto;
mod util;

use crate::{
    args::{
        Commands, DecryptArgs, EncryptArgs, EncryptFileArgs, EncryptInputs, EncryptTorArgs,
        GenKeyArgs, LogLevel,
    },
    crypto::{AutoDecryptor, AutoEncryptor},
};

fn main() {
    let cli = args::parse_cli();

    let level = match &cli.log_level {
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Off => LevelFilter::Off,
    };

    Builder::new()
        .target(Target::Stderr)
        .filter_level(level)
        .init();
    log::info!("Parsed CLI args and initialized logger!");

    let result = match cli.command {
        Commands::GenKey(args) => {
            log::info!("Running gen-key subcommand");
            run_genkey(&args)
        }
        Commands::Encrypt(args) => {
            log::info!("Running encrypt subcommand");
            run_encrypt(&args)
        }
        Commands::Decrypt(args) => {
            log::info!("Running decrypt subcommand");
            run_decrypt(&args)
        }
    };

    if let Err(e) = result {
        log::error!("Error occurred: {}", e);
        log::error!("Caused by: {}", e.root_cause());
    }
    log::info!("Returning cleanly from main");
}

fn run_genkey(args: &GenKeyArgs) -> anyhow::Result<()> {
    log::info!("Generating key pair");

    if args.secret.exists() {
        anyhow::bail!(
            "Refusing to overwrite existing file with secret key: {}. Specify with -s.",
            args.secret.to_string_lossy()
        );
    }

    if args.public.exists() {
        anyhow::bail!(
            "Refusing to overwrite existing file with public key: {}. Specify with -p.",
            args.public.to_string_lossy()
        );
    }

    crypto::generate_and_write_key_pair(&args.secret, &args.public)?;

    log::info!(
        "Keys written! Use {} to encrypt and {} to decrypt.",
        args.public.to_string_lossy(),
        args.secret.to_string_lossy()
    );
    Ok(())
}

fn run_encrypt(args: &EncryptArgs) -> anyhow::Result<()> {
    match &args.input {
        EncryptInputs::File(file_args) => {
            log::info!("Running encrypt file subcommand");
            run_encrypt_file(args, file_args)
        }
        EncryptInputs::Tor(tor_args) => {
            log::info!("Running encrypt tor subcommand");
            run_encrypt_tor(args, tor_args)
        }
    }
}

fn run_encrypt_file(args: &EncryptArgs, file_args: &EncryptFileArgs) -> anyhow::Result<()> {
    let pub_key = util::get_pub_key(&args.key)?;

    let mut input = util::get_data_source(&file_args.input)?;
    let output = match &file_args.output {
        Some(path) => util::get_data_sink(path)?,
        None => util::get_data_sink(&util::gen_encrypt_outpath(
            &file_args.input,
            args.compress.unwrap(),
        )?)?,
    };

    let mut encryptor = AutoEncryptor::new(pub_key, output);

    let num_copied = if args.compress.unwrap() {
        log::info!("Compressing-->Encrypting all data from the plaintext input stream...");

        let mut encoder =
            Encoder::new(encryptor, 0).context("Failure initializing zstd encoder")?;
        let num_copied = io::copy(&mut input, &mut encoder)
            .context("Failure running encoder-->encryptor chain")?;
        encryptor = encoder.finish().context("Failure finishing encoder")?;

        num_copied
    } else {
        log::info!("Encrypting all data from the plaintext input stream...");
        io::copy(&mut input, &mut encryptor).context("Failure running encryptor")?
    };

    encryptor.finish().context("Failure finishing encryptor")?;

    log::info!("Success! Processed {} bytes from input stream.", num_copied);
    Ok(())
}

fn run_encrypt_tor(_args: &EncryptArgs, tor_args: &EncryptTorArgs) -> anyhow::Result<()> {
    log::info!("{:?}", tor_args.event);
    log::info!("{:?}", tor_args.rotate);
    todo!()
}

fn run_decrypt(args: &DecryptArgs) -> anyhow::Result<()> {
    let sec_key = util::get_sec_key(&args.key)?;

    let mut input = util::get_data_source(&args.input)?;
    let output = match &args.output {
        Some(path) => util::get_data_sink(path)?,
        None => util::get_data_sink(&util::gen_decrypt_outpath(&args.input, args.decompress.unwrap())?)?,
    };

    let num_copied = if args.decompress.unwrap() {
        log::info!("Decrypting-->Decompressing all data from the ciphertext input stream...");

        let mut decoder = Decoder::new(output).context("Failure initializing zstd decoder")?;
        let mut decryptor = AutoDecryptor::new(sec_key, decoder);

        let num_copied = io::copy(&mut input, &mut decryptor)
            .context("Failure running decryptor-->decoder chain")?;

        decoder = decryptor.finish().context("Failure finishing decryptor")?;
        decoder.flush().context("Failure finishing decoder")?;

        num_copied
    } else {
        log::info!("Decrypting all data from the ciphertext input stream...");

        let mut decryptor = AutoDecryptor::new(sec_key, output);
        let num_copied =
            io::copy(&mut input, &mut decryptor).context("Failure running decryptor")?;
        decryptor.finish().context("Failure finishing decryptor")?;

        num_copied
    };

    log::info!("Success! Processed {} bytes from input stream.", num_copied);
    Ok(())
}
