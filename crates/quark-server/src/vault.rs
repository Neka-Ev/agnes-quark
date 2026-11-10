//! File-backed credential vault.
//!
//! Headless Linux servers usually have no OS keyring, so credentials are
//! encrypted with ChaCha20-Poly1305 and stored inside the SQLite database. The
//! 32-byte master key lives in `master.key` next to the database (mode 0600) or
//! is derived from the `QUARK_VAULT_KEY` environment variable.

use std::io::Write;
use std::path::Path;

use anyhow::{bail, Context};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const KEY_FILE: &str = "master.key";

pub struct Vault {
    key: [u8; KEY_BYTES],
}

impl Vault {
    /// Load the master key from the environment or from `data_dir/master.key`,
    /// generating a new key file on first start.
    pub fn load_or_create(data_dir: &Path) -> anyhow::Result<Self> {
        if let Ok(value) = std::env::var("QUARK_VAULT_KEY") {
            let value = value.trim();
            if !value.is_empty() {
                return Ok(Self {
                    key: derive_env_key(value),
                });
            }
        }

        let path = data_dir.join(KEY_FILE);
        if path.exists() {
            let bytes =
                std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
            if bytes.len() != KEY_BYTES {
                bail!(
                    "{} must contain exactly {KEY_BYTES} bytes; delete it to regenerate the vault",
                    path.display()
                );
            }
            let mut key = [0_u8; KEY_BYTES];
            key.copy_from_slice(&bytes);
            return Ok(Self { key });
        }

        let mut key = [0_u8; KEY_BYTES];
        OsRng.fill_bytes(&mut key);

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(&key)
                    .with_context(|| format!("cannot write {}", path.display()))?;
                file.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                // Another process won the race; use its key.
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("cannot read {}", path.display()))?;
                if bytes.len() != KEY_BYTES {
                    bail!("{} is not a valid vault key", path.display());
                }
                key.copy_from_slice(&bytes);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("cannot create {}", path.display()));
            }
        }

        Ok(Self { key })
    }

    /// Encrypt UTF-8 text and return base64(nonce || ciphertext).
    pub fn encrypt(&self, plaintext: &str) -> anyhow::Result<String> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid vault key length"))?;
        let mut nonce_bytes = [0_u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| anyhow::anyhow!("credential encryption failed"))?;
        let mut payload = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);
        Ok(BASE64.encode(payload))
    }

    /// Decrypt a value produced by [`Vault::encrypt`].
    pub fn decrypt(&self, encoded: &str) -> anyhow::Result<String> {
        let payload = BASE64
            .decode(encoded.trim())
            .context("credential is not valid base64")?;
        if payload.len() <= NONCE_BYTES {
            bail!("credential payload is truncated");
        }
        let (nonce_bytes, ciphertext) = payload.split_at(NONCE_BYTES);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| anyhow::anyhow!("invalid vault key length"))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("credential decryption failed; wrong vault key?"))?;
        String::from_utf8(plaintext).context("credential is not valid UTF-8")
    }
}

#[cfg(test)]
impl Vault {
    pub(crate) fn from_key(key: [u8; KEY_BYTES]) -> Self {
        Self { key }
    }
}

fn derive_env_key(value: &str) -> [u8; KEY_BYTES] {
    if let Ok(bytes) = hex::decode(value) {
        if bytes.len() == KEY_BYTES {
            let mut key = [0_u8; KEY_BYTES];
            key.copy_from_slice(&bytes);
            return key;
        }
    }
    let digest = Sha256::digest(value.as_bytes());
    let mut key = [0_u8; KEY_BYTES];
    key.copy_from_slice(&digest);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_tampering() {
        let vault = Vault {
            key: [7_u8; KEY_BYTES],
        };
        let encrypted = vault.encrypt("__kps=abc; __uid=42").unwrap();
        assert_eq!(vault.decrypt(&encrypted).unwrap(), "__kps=abc; __uid=42");

        let mut tampered = encrypted.into_bytes();
        let last = tampered.len() - 2;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert!(vault.decrypt(&tampered).is_err());
    }
}
