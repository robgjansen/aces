use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};

use anyhow::Context;
use chrono::Utc;
use crypto_box::{PublicKey, SecretKey};
use env_logger::{Builder, Target};
use log::LevelFilter;
use zstd::stream::write::{Decoder, Encoder};

mod args;
mod crypto;

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
    let pub_key = get_pub_key(&args.key)?;

    let mut input = get_data_source(&file_args.input)?;
    let output = match &file_args.output {
        Some(path) => get_data_sink(path)?,
        None => get_data_sink(&gen_encrypt_outpath(
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
    let sec_key = get_sec_key(&args.key)?;

    let mut input = get_data_source(&args.input)?;
    let output = match &args.output {
        Some(path) => get_data_sink(path)?,
        None => get_data_sink(&gen_decrypt_outpath(&args.input, args.decompress.unwrap())?)?,
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

fn get_pub_key(key: &PathBuf) -> anyhow::Result<PublicKey> {
    Ok(crypto::read_public_key(key).context(std::format!(
        "Failed to read public key {}",
        key.to_string_lossy()
    ))?)
}

fn get_sec_key(key: &PathBuf) -> anyhow::Result<SecretKey> {
    Ok(crypto::read_secret_key(key).context(std::format!(
        "Failed to read secret key {}",
        key.to_string_lossy()
    ))?)
}

fn get_data_source(path: &PathBuf) -> anyhow::Result<Box<dyn Read>> {
    if path.as_os_str().eq("-") {
        log::info!("Using stdin reader");
        Ok(Box::new(std::io::stdin()))
    } else {
        log::info!("Using file reader: {}", path.to_string_lossy());
        let file = File::open(path).context(std::format!(
            "Failed to open input file {}",
            path.to_string_lossy()
        ))?;
        Ok(Box::new(file))
    }
}

fn get_data_sink(path: &PathBuf) -> anyhow::Result<Box<dyn Write>> {
    if path.as_os_str().eq("-") {
        log::info!("Using stdout writer");
        Ok(Box::new(std::io::stdout()))
    } else {
        log::info!("Using file writer: {}", path.to_string_lossy());
        let file = File::create(path).context(std::format!(
            "Failed to create output file {}",
            path.to_string_lossy()
        ))?;
        Ok(Box::new(file))
    }
}

fn gen_base_outpath(input: &PathBuf) -> PathBuf {
    if input.as_os_str().eq("-") {
        let current_ts = Utc::now().format("%Y-%m-%d_%H:%M:%S_UTC");
        PathBuf::from(format!("./data_stream_{}", current_ts))
    } else {
        input.clone()
    }
}

fn gen_encrypt_outpath(input: &PathBuf, compress: bool) -> anyhow::Result<PathBuf> {
    let mut out = gen_base_outpath(input);

    if compress {
        out.set_file_name(format!(
            "{}.zst",
            out.file_name().unwrap().to_string_lossy()
        ));
    }
    out.set_file_name(format!(
        "{}.ace",
        out.file_name().unwrap().to_string_lossy()
    ));

    if out.exists() {
        anyhow::bail!(
            "Refusing to write encrypted output to existing file: {}. Specify with -o.",
            out.to_string_lossy()
        );
    }
    Ok(out)
}

fn gen_decrypt_outpath(input: &PathBuf, decompress: bool) -> anyhow::Result<PathBuf> {
    let mut out = gen_base_outpath(input);

    if let Some(ext) = out.extension() {
        if ext.eq("ace") {
            out.set_extension("");
        }
    }
    if let Some(ext) = out.extension() {
        if decompress && ext.eq("zst") {
            out.set_extension("");
        }
    }

    if out.exists() {
        anyhow::bail!(
            "Refusing to write decrypted output to existing file: {}. Specify with -o.",
            out.to_string_lossy()
        );
    }
    Ok(out)
}
