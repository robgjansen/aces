use bytes::{Buf, BytesMut};

use crypto_box::{
    aead::{Aead, AeadCore, OsRng, Payload},
    ChaChaBox, Nonce, PublicKey, SecretKey,
};

use std::{
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};

pub fn write_public_key(key: &PublicKey, path: &PathBuf) -> io::Result<()> {
    log::info!("Saving public key to {}", path.to_string_lossy());
    File::create(path)?.write_all(key.as_bytes())
}

pub fn read_public_key(path: &PathBuf) -> io::Result<PublicKey> {
    log::info!("Loading public key from {}", path.to_string_lossy());
    let mut buf = [0; 32];
    File::open(path)?.read_exact(&mut buf)?;
    Ok(PublicKey::from(buf))
}

pub fn write_secret_key(key: &SecretKey, path: &PathBuf) -> io::Result<()> {
    log::info!("Saving secret key to {}", path.to_string_lossy());
    File::create(path)?.write_all(key.as_bytes())
}

pub fn read_secret_key(path: &PathBuf) -> io::Result<SecretKey> {
    log::info!("Loading secret key from {}", path.to_string_lossy());
    let mut buf = [0; 32];
    File::open(path)?.read_exact(&mut buf)?;
    Ok(SecretKey::from(buf))
}

pub fn generate_and_write_key_pair(sec_path: &PathBuf, pub_path: &PathBuf) -> io::Result<()> {
    let sec_key = SecretKey::generate(&mut OsRng);
    let pub_key = sec_key.public_key();
    write_secret_key(&sec_key, sec_path)?;
    write_public_key(&pub_key, pub_path)
}

const PLAINTEXT_MSG_LEN: usize = 2usize.pow(16u32); // 16 KiB per payload
const CIPHERTEXT_MSG_LEN: usize = PLAINTEXT_MSG_LEN + 24 + 16; // nonce + mac

pub struct Encryptor {
    key: PublicKey,
    crypto_box: ChaChaBox,
    msg_buf: BytesMut,
}

impl Encryptor {
    /// Create a new encryptor that creates a symmetric shared secret from the
    /// given public key and a newly generated key pair.
    pub fn new(peer_key: PublicKey) -> Self {
        let key = SecretKey::generate(&mut OsRng);
        Self {
            key: key.public_key(),
            crypto_box: ChaChaBox::new(&peer_key, &key),
            msg_buf: BytesMut::with_capacity(PLAINTEXT_MSG_LEN),
        }
    }

    /// Writes our generated public key that will be needed to decrypt the
    /// encrypted message that we produce.
    pub fn start<W>(&self, output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        output.write_all(self.key.as_ref())
    }

    /// Encrypt the plaintext input and write the nonce and ciphertext to the
    /// output.
    pub fn encrypt_all<R, W>(&mut self, input: &mut R, output: &mut W) -> io::Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut read_buf: [u8; PLAINTEXT_MSG_LEN] = [0; PLAINTEXT_MSG_LEN];
        loop {
            let num_read = input.read(&mut read_buf)?;

            match num_read > 0 {
                true => self.msg_buf.extend(&read_buf[..num_read]),
                false => return Ok(()),
            }

            while self.msg_buf.len() >= PLAINTEXT_MSG_LEN {
                let msg = self.msg_buf.split_to(PLAINTEXT_MSG_LEN);
                self.write_encrypted_message(msg, output)?;
            }
        }
    }

    fn write_encrypted_message<W>(&mut self, msg: BytesMut, output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);

        let payload = Payload {
            msg: msg.as_ref(),
            aad: nonce.as_ref(),
        };

        let ciphertext = self.crypto_box.encrypt(&nonce, payload).unwrap();

        output.write_all(nonce.as_ref())?;
        output.write_all(ciphertext.as_slice())
    }

    pub fn finish<W>(&mut self, output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        // If there are leftover bytes in the buffer, write a partial message now.
        if self.msg_buf.len() > 0 {
            let msg = self.msg_buf.split();
            self.write_encrypted_message(msg, output)?;
        }
        Ok(())
    }
}

pub struct Decryptor {
    key: SecretKey,
    crypto_box: Option<ChaChaBox>,
    msg_buf: BytesMut,
}

impl Decryptor {
    pub fn new(key: SecretKey) -> Self {
        Self {
            key,
            crypto_box: None,
            msg_buf: BytesMut::with_capacity(CIPHERTEXT_MSG_LEN),
        }
    }

    pub fn start<R>(&mut self, input: &mut R) -> io::Result<()>
    where
        R: Read,
    {
        let peer_key = {
            let mut key_buf: [u8; 32] = [0; 32];
            input.read_exact(&mut key_buf)?;
            PublicKey::from(key_buf)
        };

        self.crypto_box = Some(ChaChaBox::new(&peer_key, &self.key));
        Ok(())
    }

    pub fn decrypt_all<R, W>(&mut self, input: &mut R, output: &mut W) -> io::Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut read_buf: [u8; CIPHERTEXT_MSG_LEN] = [0; CIPHERTEXT_MSG_LEN];
        loop {
            let num_read = input.read(&mut read_buf)?;

            match num_read > 0 {
                true => self.msg_buf.extend(&read_buf[..num_read]),
                false => return Ok(()),
            }

            while self.msg_buf.len() >= CIPHERTEXT_MSG_LEN {
                let msg = self.msg_buf.split_to(CIPHERTEXT_MSG_LEN);
                self.write_decrypted_message(msg, output)?;
            }
        }
    }

    fn write_decrypted_message<W>(&mut self, mut msg: BytesMut, output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        let crypto_box = match &self.crypto_box {
            Some(o) => o,
            None => panic!("Need to call start first!"),
        };

        let nonce = {
            let mut nonce_bytes = msg.split_to(24);
            let mut nonce_buf: [u8; 24] = [0; 24];
            nonce_bytes.copy_to_slice(&mut nonce_buf);
            Nonce::from(nonce_buf)
        };

        let payload = Payload {
            msg: msg.as_ref(),
            aad: nonce.as_ref(),
        };

        let plaintext = crypto_box.decrypt(&nonce, payload).unwrap();
        output.write_all(plaintext.as_ref())
    }

    pub fn finish<W>(&mut self, output: &mut W) -> io::Result<()>
    where
        W: Write,
    {
        // If there are leftover bytes in the buffer, write a partial message now.
        if self.msg_buf.len() > 0 {
            let msg = self.msg_buf.split();
            self.write_decrypted_message(msg, output)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek, SeekFrom};

    use crypto_box::{aead::OsRng, rand_core::RngCore, SecretKey};

    use super::{Decryptor, Encryptor, PLAINTEXT_MSG_LEN};

    fn make_buffer(val: u8, len: usize) -> Cursor<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::with_capacity(len);
        buf.extend(std::iter::repeat(val).take(len));
        Cursor::new(buf)
    }

    fn run_pipeline(plaintext_len: usize) {
        // Once per file: 32 bytes for pub_key
        // Once per msg: 24 bytes for nonce, 16 for mac
        let num_msgs = (plaintext_len + PLAINTEXT_MSG_LEN - 1) / PLAINTEXT_MSG_LEN;
        let ciphertext_len = 32 + (24 * num_msgs) + plaintext_len + (16 * num_msgs);

        let mut plaintext = make_buffer(OsRng.next_u32() as u8, plaintext_len);
        let mut encrypted = make_buffer(0, ciphertext_len);
        let mut decrypted = make_buffer(0, plaintext_len);

        // encrypt
        let key = SecretKey::generate(&mut OsRng);
        let mut enc = Encryptor::new(key.public_key());

        // writes the pub key
        enc.start(&mut encrypted).unwrap();
        assert_eq!(encrypted.position(), 32);

        // plaintext completely read
        enc.encrypt_all(&mut plaintext, &mut encrypted).unwrap();
        assert_eq!(plaintext.position() as usize, plaintext_len);

        // ciphertext completely written
        enc.finish(&mut encrypted).unwrap();
        assert_eq!(encrypted.position() as usize, ciphertext_len);

        // reset encrypted output to use as input to decryption
        encrypted.seek(SeekFrom::Start(0)).unwrap();

        // decrypt
        let mut dec = Decryptor::new(key);

        // reads the pub key
        dec.start(&mut encrypted).unwrap();
        assert_eq!(encrypted.position(), 32);

        // ciphertext completely read
        dec.decrypt_all(&mut encrypted, &mut decrypted).unwrap();
        assert_eq!(encrypted.position() as usize, ciphertext_len);

        // plaintext completely written
        dec.finish(&mut decrypted).unwrap();
        assert_eq!(decrypted.position() as usize, plaintext_len);

        assert_eq!(
            &plaintext.into_inner().as_slice(),
            &decrypted.into_inner().as_slice()
        );
    }

    #[test]
    fn plaintext_len_zero() {
        run_pipeline(0)
    }

    #[test]
    fn plaintext_len_one() {
        run_pipeline(1)
    }

    #[test]
    fn plaintext_len_n_minus_one() {
        run_pipeline(PLAINTEXT_MSG_LEN - 1)
    }

    #[test]
    fn plaintext_len_n() {
        run_pipeline(PLAINTEXT_MSG_LEN)
    }

    #[test]
    fn plaintext_len_n_plus_one() {
        run_pipeline(PLAINTEXT_MSG_LEN + 1)
    }

    #[test]
    fn plaintext_len_n_times_two() {
        run_pipeline(PLAINTEXT_MSG_LEN * 2)
    }
}
