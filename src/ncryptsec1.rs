use chacha20poly1305::aead::{Aead, KeyInit};
use secp256k1::rand::TryRngCore;
use unicode_normalization::UnicodeNormalization;

/// key security byte values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySecurityByte {
    KnownToHaveBeenHandledInsecurely = 0x00,
    NotKnownToHaveBeenHandledInsecurely = 0x01,
    ClientDoesNotTrackThisData = 0x02,
}

impl From<u8> for KeySecurityByte {
    fn from(value: u8) -> Self {
        match value {
            0x00 => KeySecurityByte::KnownToHaveBeenHandledInsecurely,
            0x01 => KeySecurityByte::NotKnownToHaveBeenHandledInsecurely,
            _ => KeySecurityByte::ClientDoesNotTrackThisData,
        }
    }
}

impl From<KeySecurityByte> for u8 {
    fn from(ksb: KeySecurityByte) -> Self {
        ksb as u8
    }
}

#[derive(thiserror::Error, Debug)]
pub enum EncryptError {
    #[error("invalid key length for cipher")]
    InvalidCipherKeyLength,

    #[error("scrypt operation failed: {0}")]
    ScryptOperation(#[from] ScryptDerivationError),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
}

/// encrypt a secret key with a password
pub fn encrypt(
    secret_key: &crate::SecretKey,
    password: &str,
    log_n: u8,
    ksb: KeySecurityByte,
) -> Result<String, EncryptError> {
    let mut rng = secp256k1::rand::rng();
    let mut salt = [0u8; 16];
    rng.try_fill_bytes(&mut salt).expect("infallible");

    let key = derive_scrypted_key(password, &salt, log_n)?;

    let mut concat = vec![0u8; 91];
    concat[0] = 0x02; // version
    concat[1] = log_n;
    concat[2..2 + 16].copy_from_slice(&salt);

    let mut nonce = [0u8; 24];
    secp256k1::rand::rng()
        .try_fill_bytes(&mut nonce)
        .expect("infallible");
    concat[2 + 16..2 + 16 + 24].copy_from_slice(&nonce);

    let ad = [ksb.into()];
    concat[2 + 16 + 24] = ad[0];

    let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| EncryptError::InvalidCipherKeyLength)?;
    let xnonce = chacha20poly1305::XNonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(
            xnonce,
            chacha20poly1305::aead::Payload {
                msg: secret_key.as_bytes(),
                aad: &ad,
            },
        )
        .map_err(|err| EncryptError::EncryptionFailed(err.to_string()))?;

    concat[2 + 16 + 24 + 1..].copy_from_slice(&ciphertext);

    let encoded = bech32::encode::<bech32::Bech32>(
        bech32::Hrp::parse_unchecked("ncryptsec"),
        concat.as_slice(),
    )
    .expect("encoding never fails");
    Ok(encoded)
}

#[derive(thiserror::Error, Debug)]
pub enum DecryptError {
    #[error("failed to decode bech32")]
    Bech32(#[from] bech32::DecodeError),

    #[error("scrypt operation failed: {0}")]
    ScryptOperation(#[from] ScryptDerivationError),

    #[error("invalid human-readable prefix")]
    InvalidPrefix,

    #[error("invalid data length: {0}, expected 91")]
    InvalidDataLength(usize),

    #[error("invalid version byte")]
    InvalidVersion,

    #[error("failed to decrypt")]
    ChaCha20Error,

    #[error("decrypted key has unexpected size: {0}")]
    InvalidKeyLength(usize),

    #[error("decrypted key does not belong to field")]
    InvaidSecretKey(#[from] crate::keys::SecretKeyError),
}

/// decrypt to raw bytes
pub fn decrypt(bech32_string: &str, password: &str) -> Result<crate::SecretKey, DecryptError> {
    let (hrp, data) = bech32::decode(bech32_string)?;

    if hrp.as_str() != "ncryptsec" {
        return Err(DecryptError::InvalidPrefix);
    }

    if data.len() != 91 {
        return Err(DecryptError::InvalidDataLength(data.len()));
    }

    let version = data[0];
    if version != 0x02 {
        return Err(DecryptError::InvalidVersion);
    }

    let log_n = data[1];
    let salt = &data[2..2 + 16];
    let nonce = &data[2 + 16..2 + 16 + 24];
    let ad = &data[2 + 16 + 24..2 + 16 + 24 + 1];
    let encrypted_key = &data[2 + 16 + 24 + 1..];

    let key = derive_scrypted_key(password, salt, log_n)?;

    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&key.into());
    let xnonce = chacha20poly1305::XNonce::from_slice(nonce);
    let decrypted = cipher
        .decrypt(
            xnonce,
            chacha20poly1305::aead::Payload {
                msg: encrypted_key,
                aad: ad,
            },
        )
        .map_err(|_| DecryptError::ChaCha20Error)?;

    if decrypted.len() != 32 {
        return Err(DecryptError::InvalidKeyLength(decrypted.len()));
    }

    Ok(crate::SecretKey::from_bytes(decrypted.try_into().unwrap())?)
}

#[derive(thiserror::Error, Debug)]
pub enum ScryptDerivationError {
    #[error("invalid log_n value given to scrypt: {0}")]
    InvalidLogN(u8),

    #[error("scrypt operation error")]
    ScryptOperation(#[from] scrypt::errors::InvalidOutputLen),
}

pub fn derive_scrypted_key(
    password: &str,
    salt: &[u8],
    log_n: u8,
) -> Result<[u8; 32], ScryptDerivationError> {
    // normalize password using NFKC
    let normalized_password: String = password.nfkc().collect();

    let params = scrypt::Params::new(
        log_n, // log_n (not N)
        8,     // r
        1,     // p
        32,    // output length
    )
    .map_err(|_| ScryptDerivationError::InvalidLogN(log_n))?;

    let mut key = [0u8; 32];
    scrypt::scrypt(normalized_password.as_bytes(), salt, &params, &mut key)?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_decrypt() {
        let test_cases = vec![
            (
                ".ksjabdk.aselqwe",
                "14c226dbdd865d5e1645e72c7470fd0a17feb42cc87b750bab6538171b3a3f8a",
                1,
                KeySecurityByte::KnownToHaveBeenHandledInsecurely,
            ),
            (
                "skjdaklrnçurbç l",
                "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
                2,
                KeySecurityByte::NotKnownToHaveBeenHandledInsecurely,
            ),
            (
                "777z7z7z7z7z7z7z",
                "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
                3,
                KeySecurityByte::ClientDoesNotTrackThisData,
            ),
            (
                "",
                "f7f2f77f98890885462764afb15b68eb5f69979c8046ecb08cad7c4ae6b221ab",
                4,
                KeySecurityByte::KnownToHaveBeenHandledInsecurely,
            ),
            (
                "ÅΩẛ̣",
                "11b25a101667dd9208db93c0827c6bdad66729a5b521156a7e9d3b22b3ae8944",
                9,
                KeySecurityByte::NotKnownToHaveBeenHandledInsecurely,
            ),
        ];

        for (password, secret_hex, logn, ksb) in test_cases {
            let sk = secret_hex.parse().unwrap();
            let bech32_code = encrypt(&sk, password, logn, ksb).unwrap();

            assert!(bech32_code.starts_with("ncryptsec1"));
            assert_eq!(bech32_code.len(), 162);

            let decrypted_sk = decrypt(&bech32_code, password).unwrap();
            assert_eq!(sk, decrypted_sk);
        }
    }

    #[test]
    fn test_normalization() {
        let nonce = [1u8; 16];
        let log_n = 8;

        // different Unicode representations of the same string
        let key1 = derive_scrypted_key(
            &String::from_utf8(vec![
                0xE2, 0x84, 0xAB, 0xE2, 0x84, 0xA6, 0xE1, 0xBA, 0x9B, 0xCC, 0xA3,
            ])
            .unwrap(),
            &nonce,
            log_n,
        )
        .unwrap();
        let key2 = derive_scrypted_key(
            &String::from_utf8(vec![0xC3, 0x85, 0xCE, 0xA9, 0xE1, 0xB9, 0xA9]).unwrap(),
            &nonce,
            log_n,
        )
        .unwrap();
        let key3 = derive_scrypted_key("ÅΩẛ̣", &nonce, log_n).unwrap();
        let key4 = derive_scrypted_key("ÅΩẛ̣", &nonce, log_n).unwrap();

        assert_eq!(key1, key2, "normalization failed");
        assert_eq!(key2, key3, "normalization failed");
        assert_eq!(key3, key4, "normalization failed");
    }
}
