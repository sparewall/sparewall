//! Password-based encryption for what leaves a node in a backup bundle.
//!
//! The format is `SWSEAL1\n`, a 16-byte salt, a 12-byte nonce and the
//! ChaCha20-Poly1305 ciphertext. The key is derived with Argon2id from
//! the backup password (the one secret an operator keeps outside
//! Sparewall), so a bundle restores on a new node with no TPM in common.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Key, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::Error;

const MAGIC: &[u8] = b"SWSEAL1\n";
const SALT: usize = 16;
const NONCE: usize = 12;

fn key(password: &[u8], salt: &[u8]) -> Result<Key<ChaCha20Poly1305>, Error> {
    let mut k = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT)
        .hash_password_into(password, salt, &mut k)
        .map_err(|e| Error::Internal(format!("argon2: {e}")))?;
    Ok(Key::<ChaCha20Poly1305>::from(k))
}

pub fn seal(password: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT];
    let mut nonce = [0u8; NONCE];
    getrandom::fill(&mut salt).map_err(|e| Error::Internal(format!("getrandom: {e}")))?;
    getrandom::fill(&mut nonce).map_err(|e| Error::Internal(format!("getrandom: {e}")))?;
    let ct = ChaCha20Poly1305::new(&key(password, &salt)?)
        .encrypt(&Nonce::from(nonce), plaintext)
        .map_err(|_| Error::Internal("encryption failed".into()))?;
    let mut out = Vec::with_capacity(MAGIC.len() + SALT + NONCE + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(password: &[u8], blob: &[u8]) -> Result<Vec<u8>, Error> {
    let rest = blob
        .strip_prefix(MAGIC)
        .filter(|r| r.len() > SALT + NONCE)
        .ok_or_else(|| Error::Validation(vec!["not a sealed backup section".into()]))?;
    let (salt, rest) = rest.split_at(SALT);
    let (nonce, ct) = rest.split_at(NONCE);
    let nonce: [u8; NONCE] = nonce.try_into().expect("split");
    ChaCha20Poly1305::new(&key(password, salt)?)
        .decrypt(&Nonce::from(nonce), ct)
        .map_err(|_| Error::Validation(vec!["wrong backup password (or a damaged bundle)".into()]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = seal(b"hunter2", b"the vpn key").unwrap();
        assert!(s.starts_with(MAGIC));
        assert_eq!(open(b"hunter2", &s).unwrap(), b"the vpn key");
        assert!(open(b"hunter3", &s).is_err());
        let mut bad = s.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(b"hunter2", &bad).is_err());
        assert!(open(b"hunter2", b"junk").is_err());
        // Fresh salt and nonce every time.
        assert_ne!(seal(b"hunter2", b"the vpn key").unwrap(), s);
    }
}
