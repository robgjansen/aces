use crypto_box::{
    aead::{Aead, AeadCore, OsRng, Payload},
    ChaChaBox, Nonce, PublicKey, SecretKey,
};

use std::{
    fs::File,
    io::{self, Error, ErrorKind, Read, Write},
    path::PathBuf,
};

const PLAINTEXT_MSG_LEN: usize = 2usize.pow(16u32); // 64 KiB per payload
const KEY_LEN: usize = 32; // Size of the public key and secret key
const NONCE_LEN: usize = 24; // Each message has a 24 byte nonce
const MAC_LEN: usize = 16; // Each message has a 16 byte mac
const CIPHERTEXT_MSG_LEN: usize = PLAINTEXT_MSG_LEN + NONCE_LEN + MAC_LEN;

pub fn write_public_key(key: &PublicKey, path: &PathBuf) -> anyhow::Result<()> {
    log::info!("Saving public key to {}", path.to_string_lossy());
    File::create(path)?.write_all(key.as_bytes())?;
    Ok(())
}

pub fn read_public_key(path: &PathBuf) -> anyhow::Result<PublicKey> {
    log::info!("Loading public key from {}", path.to_string_lossy());
    let mut buf = [0; KEY_LEN];
    File::open(path)?.read_exact(&mut buf)?;
    Ok(PublicKey::from(buf))
}

pub fn write_secret_key(key: &SecretKey, path: &PathBuf) -> anyhow::Result<()> {
    log::info!("Saving secret key to {}", path.to_string_lossy());
    File::create(path)?.write_all(key.as_bytes())?;
    Ok(())
}

pub fn read_secret_key(path: &PathBuf) -> anyhow::Result<SecretKey> {
    log::info!("Loading secret key from {}", path.to_string_lossy());
    let mut buf = [0; KEY_LEN];
    File::open(path)?.read_exact(&mut buf)?;
    Ok(SecretKey::from(buf))
}

pub fn generate_and_write_key_pair(sec_path: &PathBuf, pub_path: &PathBuf) -> anyhow::Result<()> {
    let sec_key = SecretKey::generate(&mut OsRng);
    let pub_key = sec_key.public_key();
    write_secret_key(&sec_key, sec_path)?;
    write_public_key(&pub_key, pub_path)
}

/// An Encryptor reads plaintexts from the input, encrypts, and writes
/// ciphertexts to the output.
///
/// This module writes out an encrypted 'package' that consists of:
/// - The public key needed for decryption [32 bytes]
/// - A number of encrypted messages, where each message consists of:
///   - The nonce needed for decryption [24 bytes]
///   - The encrypted version of the plaintext payload [64 KiB]
///   - The message MAC [16 bytes]
///
/// Note that the last message written may be truncated if there was less
/// than 64 KiB of plaintext payload available.
pub struct AutoEncryptor<W: Write> {
    key: PublicKey,
    crypto_box: ChaChaBox,
    msg_buf2: Vec<u8>,
    writer: Option<W>, // so we can take() on finish()/drop()
    wrote_header: bool,
}

impl<W: Write> AutoEncryptor<W> {
    pub fn new(peer_key: PublicKey, writer: W) -> Self {
        let key = SecretKey::generate(&mut OsRng);
        Self {
            key: key.public_key(),
            crypto_box: ChaChaBox::new(&peer_key, &key),
            msg_buf2: Vec::with_capacity(PLAINTEXT_MSG_LEN),
            writer: Some(writer),
            wrote_header: false,
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.write_inner(true)?;
        self.writer.as_mut().unwrap().flush()?;
        Ok(self.writer.take().unwrap())
    }

    /// Encrypt the plaintext input and write the nonce and ciphertext to the
    /// output.
    fn write_encrypted_message(&mut self, msg: &[u8]) -> io::Result<()> {
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);

        let payload = Payload {
            msg,
            aad: nonce.as_ref(),
        };

        let ciphertext = match self.crypto_box.encrypt(&nonce, payload) {
            Ok(vec) => vec,
            Err(e) => return Err(Error::other(e.to_string())),
        };

        self.writer.as_mut().unwrap().write_all(nonce.as_ref())?;
        self.writer
            .as_mut()
            .unwrap()
            .write_all(ciphertext.as_slice())?;
        Ok(())
    }

    fn write_inner(&mut self, finalize: bool) -> io::Result<()> {
        if !self.wrote_header {
            // Writes our generated public key that will be needed to decrypt
            // the encrypted message that we produce.
            self.writer.as_mut().unwrap().write_all(self.key.as_ref())?;
            self.wrote_header = true;
        }

        while self.msg_buf2.len() >= PLAINTEXT_MSG_LEN {
            let msg: Vec<u8> = self.msg_buf2.drain(0..PLAINTEXT_MSG_LEN).collect();
            self.write_encrypted_message(msg.as_slice())?;
        }

        if finalize && !self.msg_buf2.is_empty() {
            // Write remaining buf without requiring a full-length message.
            let remaining: Vec<u8> = self.msg_buf2.drain(..).collect();
            self.write_encrypted_message(remaining.as_slice())?;
        }

        Ok(())
    }
}

impl<W: Write> Drop for AutoEncryptor<W> {
    fn drop(&mut self) {
        // writer might be none if finish was already called.
        if self.writer.is_some() {
            self.write_inner(true).unwrap();
            self.writer.as_mut().unwrap().flush().unwrap();
        }
    }
}

impl<W: Write> Write for AutoEncryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.msg_buf2.extend_from_slice(buf);
        self.write_inner(false)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_inner(false)?;
        self.writer.as_mut().unwrap().flush()
    }
}

/// A Decryptor ciphertexts from the input, decrypts, and writes plaintexts to
/// the output. This module expects the input to contain the encrypted 'package'
/// produced by the `Encryptor` and will extract the decryption material
/// accordingly.
pub struct AutoDecryptor<W: Write> {
    key: SecretKey,
    crypto_box: Option<ChaChaBox>,
    msg_buf: Vec<u8>,
    writer: Option<W>, // so we can take() on finish()/drop()
    read_header: bool,
}

impl<W: Write> AutoDecryptor<W> {
    pub fn new(key: SecretKey, writer: W) -> Self {
        Self {
            key,
            crypto_box: None,
            msg_buf: Vec::with_capacity(CIPHERTEXT_MSG_LEN),
            writer: Some(writer),
            read_header: false,
        }
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.write_inner(true)?;
        self.writer.as_mut().unwrap().flush()?;
        Ok(self.writer.take().unwrap())
    }

    fn write_decrypted_message(&mut self, msg: &[u8]) -> io::Result<()> {
        let crypto_box = match &self.crypto_box {
            Some(cb) => cb,
            None => return Err(Error::other("Crypto box does not exist!")),
        };

        let nonce = {
            let mut nonce_buf: [u8; NONCE_LEN] = [0; NONCE_LEN];
            nonce_buf.copy_from_slice(&msg[0..NONCE_LEN]);
            Nonce::from(nonce_buf)
        };

        let payload = Payload {
            msg: msg[NONCE_LEN..].as_ref(),
            aad: nonce.as_ref(),
        };

        let plaintext = match crypto_box.decrypt(&nonce, payload) {
            Ok(vec) => vec,
            Err(e) => return Err(Error::other(e.to_string())),
        };
        self.writer
            .as_mut()
            .unwrap()
            .write_all(plaintext.as_ref())?;
        Ok(())
    }

    fn write_inner(&mut self, finalize: bool) -> io::Result<()> {
        if !self.read_header {
            if self.msg_buf.len() < KEY_LEN {
                return Err(Error::from(ErrorKind::WouldBlock));
            }

            // Reads the generated public key that was used to encrypt.
            let peer_key = {
                let key_bytes: Vec<u8> = self.msg_buf.drain(0..KEY_LEN).collect();
                let mut key_buf: [u8; KEY_LEN] = [0; KEY_LEN];
                key_buf.copy_from_slice(key_bytes.as_slice());
                PublicKey::from(key_buf)
            };

            self.crypto_box = Some(ChaChaBox::new(&peer_key, &self.key));
            self.read_header = true;
        }

        while self.msg_buf.len() >= CIPHERTEXT_MSG_LEN {
            let msg: Vec<u8> = self.msg_buf.drain(0..CIPHERTEXT_MSG_LEN).collect();
            self.write_decrypted_message(msg.as_slice())?;
        }

        if finalize && self.msg_buf.len() >= NONCE_LEN + MAC_LEN {
            // Write remaining buf without requiring a full-length message.
            let remaining: Vec<u8> = self.msg_buf.drain(..).collect();
            self.write_decrypted_message(remaining.as_slice())?;
        }

        Ok(())
    }
}

impl<W: Write> Drop for AutoDecryptor<W> {
    fn drop(&mut self) {
        // writer might be none if finish was already called.
        if self.writer.is_some() {
            self.write_inner(true).unwrap();
            self.writer.as_mut().unwrap().flush().unwrap();
        }
    }
}

impl<W: Write> Write for AutoDecryptor<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.msg_buf.extend_from_slice(buf);
        self.write_inner(false)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_inner(false)?;
        self.writer.as_mut().unwrap().flush()
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

    use crypto_box::{aead::OsRng, rand_core::RngCore, SecretKey};

    use super::{AutoDecryptor, AutoEncryptor, KEY_LEN, MAC_LEN, NONCE_LEN, PLAINTEXT_MSG_LEN};

    fn make_buffer(val: u8, len: usize) -> Cursor<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        buf.extend(std::iter::repeat_n(val, len));
        Cursor::new(buf)
    }

    fn run_pipeline(plaintext_len: usize) -> anyhow::Result<()> {
        // Once per file: 32 bytes for pub_key
        // Once per msg: 24 bytes for nonce, 16 for mac
        let num_msgs = plaintext_len.div_ceil(PLAINTEXT_MSG_LEN);
        let ciphertext_len = KEY_LEN + ((NONCE_LEN + MAC_LEN) * num_msgs) + plaintext_len;

        let mut plaintext = make_buffer(OsRng.next_u32() as u8, plaintext_len);
        let encrypted = make_buffer(0, ciphertext_len);
        let decrypted = make_buffer(0, plaintext_len);

        // encrypt
        let key = SecretKey::generate(&mut OsRng);
        let mut aenc = AutoEncryptor::new(key.public_key(), encrypted);

        // writes the pub key
        assert!(!aenc.wrote_header);
        aenc.write_inner(false).unwrap();
        assert!(aenc.wrote_header);

        // plaintext completely read
        assert_eq!(
            io::copy(&mut plaintext, &mut aenc).unwrap(),
            plaintext_len as u64
        );

        // ciphertext completely written
        let mut encrypted = aenc.finish().unwrap();
        assert_eq!(encrypted.position() as usize, ciphertext_len);

        // reset encrypted output to use as input to decryption
        encrypted.seek(SeekFrom::Start(0))?;

        // decrypt
        let mut adec = AutoDecryptor::new(key, decrypted);

        // reads the pub key
        assert!(!adec.read_header);
        let mut partial = encrypted.take(KEY_LEN as u64);
        assert_eq!(io::copy(&mut partial, &mut adec).unwrap(), KEY_LEN as u64);
        assert!(adec.read_header);
        let mut encrypted = partial.into_inner();
        assert_eq!(encrypted.position(), KEY_LEN as u64);

        // ciphertext completely read
        assert_eq!(
            io::copy(&mut encrypted, &mut adec).unwrap(),
            (ciphertext_len - KEY_LEN) as u64
        );
        assert_eq!(encrypted.position() as usize, ciphertext_len);

        // plaintext completely written
        let decrypted = adec.finish().unwrap();
        assert_eq!(decrypted.position() as usize, plaintext_len);

        assert_eq!(
            &plaintext.into_inner().as_slice(),
            &decrypted.into_inner().as_slice()
        );

        Ok(())
    }

    #[test]
    fn plaintext_len_zero() {
        assert!(run_pipeline(0).is_ok())
    }

    #[test]
    fn plaintext_len_one() {
        assert!(run_pipeline(1).is_ok())
    }

    #[test]
    fn plaintext_len_n_minus_one() {
        assert!(run_pipeline(PLAINTEXT_MSG_LEN - 1).is_ok())
    }

    #[test]
    fn plaintext_len_n() {
        assert!(run_pipeline(PLAINTEXT_MSG_LEN).is_ok())
    }

    #[test]
    fn plaintext_len_n_plus_one() {
        assert!(run_pipeline(PLAINTEXT_MSG_LEN + 1).is_ok())
    }

    #[test]
    fn plaintext_len_n_times_two() {
        assert!(run_pipeline(PLAINTEXT_MSG_LEN * 2).is_ok())
    }

    #[test]
    fn plaintext_len_n_times_two_plus_one() {
        assert!(run_pipeline(PLAINTEXT_MSG_LEN * 2 + 1).is_ok())
    }

    fn run_encrypt_decrypt_chain(num_msgs: usize) {
        let plaintext_len = num_msgs * PLAINTEXT_MSG_LEN;

        // input and output with both contain plaintext
        let mut input = make_buffer(OsRng.next_u32() as u8, plaintext_len);
        let output = make_buffer(0, plaintext_len);

        let sec_key = SecretKey::generate(&mut OsRng);
        let pub_key = sec_key.public_key().clone();

        // encryptor forwards tp decryptor forwards to output
        let adec = AutoDecryptor::new(sec_key, output);
        let mut aenc = AutoEncryptor::new(pub_key, adec);

        // copy input through the chain
        assert_eq!(
            io::copy(&mut input, &mut aenc).unwrap(),
            plaintext_len as u64
        );

        let adec = aenc.finish().unwrap();
        let output = adec.finish().unwrap();

        assert_eq!(
            &input.into_inner().as_slice().len(),
            &output.into_inner().as_slice().len()
        );
    }

    #[test]
    fn encrypt_decrypt_chain_xsmall() {
        run_encrypt_decrypt_chain(8);
    }

    #[test]
    fn encrypt_decrypt_chain_small() {
        run_encrypt_decrypt_chain(128);
    }

    #[test]
    #[ignore]
    fn encrypt_decrypt_chain_medium() {
        run_encrypt_decrypt_chain(1024);
    }

    #[test]
    #[ignore]
    fn encrypt_decrypt_chain_large() {
        run_encrypt_decrypt_chain(5120);
    }
}
