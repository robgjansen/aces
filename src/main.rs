mod args;
mod crypto;

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

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

    match cli.command {
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
        None => {}
    }
}

fn run_genkey(_args: GenKeyArgs) {
    log::info!("Generating key pair");

    crypto::generate_and_write_key_pair(
        &PathBuf::from("./aces.sec.key"),
        &PathBuf::from("./aces.pub.key"),
    )
    .expect("Unable to write keys");

    log::info!("Keys written! Use aces.pub.key to encrypt and aces.sec.key to decrypt.");
}

fn get_input() -> impl Read {
    File::open("plain").unwrap()
}

fn run_encrypt(args: EncryptArgs) {
    log::info!("Reading public key file at {}", &args.key.to_string_lossy());
    let pub_key = crypto::read_public_key(&args.key).unwrap();

    let mut outfile = {
        let filename = {
            let random_num = OsRng.next_u32() as u8;
            let current_ts = Utc::now().format("%Y-%m-%d_%H:%M:%S_UTC");
            format!("./aces_msgs_{}_{:03}.txt.enc", current_ts, random_num)
        };

        log::info!("Encrypted output will be written to {}", &filename);

        File::create(Path::new(&filename)).unwrap()
    };

    log::info!("Initializing encryptor...");
    let mut encryptor = Encryptor::new(pub_key);
    encryptor.start(&mut outfile).unwrap();

    log::info!("Encrypting all data from the input stream...");
    encryptor
        .encrypt_all(&mut get_input(), &mut outfile)
        .unwrap();
    encryptor.finish(&mut outfile).unwrap();
    outfile.flush().unwrap();

    log::info!("Success!");
}

fn run_decrypt(args: DecryptArgs) {
    let sec_key = crypto::read_secret_key(&args.key).unwrap();

    let infilename = &args.ciphertext;
    let mut infile = File::open(infilename).unwrap();
    let mut outfile = {
        let filename = infilename.file_stem().unwrap();
        log::info!("Decrypted output will be written to {}", &filename.to_string_lossy());
        File::create(Path::new(&filename)).unwrap()
    };

    log::info!("Initializing decryptor...");
    let mut decryptor = Decryptor::new(sec_key);
    decryptor.start(&mut infile).unwrap();

    log::info!("Decrypting all data from the ciphertext file...");
    decryptor.decrypt_all(&mut infile, &mut outfile).unwrap();
    decryptor.finish(&mut outfile).unwrap();
    outfile.flush().unwrap();

    log::info!("Success!");
}
