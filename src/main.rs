mod args;
mod crypto;

use std::{
    fs::File,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

use chrono::Utc;
use crypto::Decryptor;
use crypto_box::rand_core::{OsRng, RngCore};
use env_logger::{Builder, Target};
use log::LevelFilter;

use crate::{
    args::{Commands, ConstructArgs, DeconstructArgs, GenKeyArgs, LogLevel},
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
        Some(Commands::Construct(args)) => {
            log::info!("Running construct subcommand");
            run_construct(args)
        }
        Some(Commands::Deconstruct(args)) => {
            log::info!("Running deconstruct subcommand");
            run_deconstruct(args)
        }
        None => {}
    }
}

fn run_genkey(_args: GenKeyArgs) {
    crypto::generate_and_write_key_pair(
        &PathBuf::from("./aces.sec.key"),
        &PathBuf::from("./aces.pub.key"),
    )
    .expect("Unable to write keys");
}

fn get_input() -> impl Read {
    let mut buf: Vec<u8> = Vec::with_capacity(32);
    buf.extend(std::iter::repeat(7).take(32));
    Cursor::new(buf)
}

fn run_construct(args: ConstructArgs) {
    let pub_key = crypto::read_public_key(&args.key).unwrap();

    let mut outfile = {
        let filename = {
            let random_num = OsRng.next_u32() as u8;
            let current_ts = Utc::now().format("%Y-%m-%d_%H:%M:%S_UTC");
            format!("./aces_msgs_{}_{:03}.txt.enc", current_ts, random_num)
        };
        File::create(Path::new(&filename)).unwrap()
    };

    let mut encryptor = Encryptor::new(pub_key);
    encryptor.start(&mut outfile).unwrap();
    encryptor
        .encrypt_all(&mut get_input(), &mut outfile)
        .unwrap();
    encryptor.finish(&mut outfile).unwrap();
    outfile.flush().unwrap();
}

fn run_deconstruct(args: DeconstructArgs) {
    let sec_key = crypto::read_secret_key(&args.key).unwrap();

    let infilename = &args.ciphertext;
    let mut infile = File::open(infilename).unwrap();
    let mut outfile = {
        let filename = infilename.file_stem().unwrap();
        File::create(Path::new(&filename)).unwrap()
    };

    let mut decryptor = Decryptor::new(sec_key);
    decryptor.start(&mut infile).unwrap();
    decryptor.decrypt_all(&mut infile, &mut outfile).unwrap();
    decryptor.finish(&mut outfile).unwrap();
    outfile.flush().unwrap();
}
