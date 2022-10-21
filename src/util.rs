use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
};

use anyhow::Context;
use chrono::Utc;
use crypto_box::{PublicKey, SecretKey};

use crate::crypto;

pub fn get_pub_key(key: &PathBuf) -> anyhow::Result<PublicKey> {
    Ok(crypto::read_public_key(key).context(std::format!(
        "Failed to read public key {}",
        key.to_string_lossy()
    ))?)
}

pub fn get_sec_key(key: &PathBuf) -> anyhow::Result<SecretKey> {
    Ok(crypto::read_secret_key(key).context(std::format!(
        "Failed to read secret key {}",
        key.to_string_lossy()
    ))?)
}

pub fn get_data_source(path: &PathBuf) -> anyhow::Result<Box<dyn Read>> {
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

pub fn get_data_sink(path: &PathBuf) -> anyhow::Result<Box<dyn Write>> {
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

pub fn gen_base_outpath(input: &PathBuf) -> PathBuf {
    if input.as_os_str().eq("-") {
        let current_ts = Utc::now().format("%Y-%m-%d_%H:%M:%S_UTC");
        PathBuf::from(format!("./data_stream_{}", current_ts))
    } else {
        input.clone()
    }
}

pub fn gen_encrypt_outpath(input: &PathBuf, compress: bool) -> anyhow::Result<PathBuf> {
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

pub fn gen_decrypt_outpath(input: &PathBuf, decompress: bool) -> anyhow::Result<PathBuf> {
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
