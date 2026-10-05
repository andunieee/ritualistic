use lowercase_hex::ToHexExt;

#[derive(thiserror::Error, std::fmt::Debug)]
pub enum SecretKeyError {
    #[error("secret key should be at most 64-char hex, got '{0}'")]
    InvalidLength(String),

    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("unknown secret key format")]
    UnknownFormat,

    #[error("public key error: {0}")]
    PubKeyError(#[from] PubKeyError),

    #[error("invalid bech32 encoding")]
    InvalidBech32,
}

#[derive(thiserror::Error, std::fmt::Debug)]
pub enum PubKeyError {
    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),

    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),

    #[error("unknown public key format")]
    UnknownFormat,

    #[error("public key not in curve")]
    NotInCurve,

    #[error("invalid bech32 encoding")]
    InvalidBech32,
}

/// A 32-byte secret key
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretKey(pub [u8; 32]);

// don't leak the secret through debug output (structs that contain it derive Debug)
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<sk:{}>", self.pubkey().to_hex())
    }
}

impl SecretKey {
    /// generate a new random secret key
    pub fn generate() -> Self {
        let mut rng = secp256k1::rand::rng();
        let keypair = secp256k1::Keypair::new(&mut rng);
        SecretKey(keypair.to_secret_bytes())
    }

    /// create a new secret key from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, SecretKeyError> {
        // ensure it is in the curve
        let _ = secp256k1::SecretKey::from_secret_bytes(bytes)
            .map_err(|_| SecretKeyError::InvalidSecretKey)?;

        Ok(Self(bytes))
    }

    /// get the bytes of the secret key
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// convert to hex string
    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
    }

    pub fn to_nsec(&self) -> String {
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("nsec"), self.as_bytes())
            .expect("failed to encode to nsec")
    }

    /// get the public key for this secret key
    pub fn pubkey(&self) -> PubKey {
        let secret_key = secp256k1::SecretKey::from_secret_bytes(self.0).unwrap();
        let keypair = secp256k1::Keypair::from_secret_key(&secret_key);
        let (xonly_pk, _) = secp256k1::XOnlyPublicKey::from_keypair(&keypair);
        PubKey::from_bytes_unchecked(xonly_pk.to_byte_array())
    }

    pub fn to_ecdsa_key(&self) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_secret_bytes(self.0)
            .expect("should always work as secret keys are pre-validated")
    }
}

impl std::str::FromStr for SecretKey {
    type Err = SecretKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("nsec1") {
            match crate::codes::decode(s).map_err(|_| SecretKeyError::InvalidBech32)? {
                crate::codes::DecodeResult::SecretKey(sk) => Ok(sk),
                _ => Err(SecretKeyError::InvalidSecretKey),
            }
        } else if s.len() == 64 {
            let mut bytes = [0u8; 32];
            lowercase_hex::decode_to_slice(s, &mut bytes)?;

            // ensure it is in the curve
            let _ = secp256k1::SecretKey::from_secret_bytes(bytes)
                .map_err(|_| SecretKeyError::InvalidSecretKey)?;

            Ok(Self(bytes))
        } else {
            Err(SecretKeyError::UnknownFormat)
        }
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<sk={}>", self.to_hex())
    }
}

/// a 32-byte public key
#[derive(Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct PubKey(pub [u8; 32]);

impl PubKey {
    // this one if for when we know we're getting good input from libsecp256k1
    fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, PubKeyError> {
        // ensure the public key is valid
        let _ = secp256k1::XOnlyPublicKey::from_byte_array(bytes)
            .map_err(|_| PubKeyError::NotInCurve)?;

        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short(&self) -> ShortPubKey {
        let bytes: [u8; 8] = self.0[8..16].try_into().unwrap();
        ShortPubKey(u64::from_ne_bytes(bytes))
    }

    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
    }

    pub fn to_npub(&self) -> String {
        bech32::encode::<bech32::Bech32>(bech32::Hrp::parse_unchecked("npub"), self.as_bytes())
            .expect("failed to encode to npub")
    }

    pub fn to_nprofile(&self, relays: &[String]) -> String {
        crate::codes::encode_nprofile(self, relays)
    }

    pub fn to_ecdsa_key(&self) -> secp256k1::PublicKey {
        let mut buf = [0u8; 33];

        buf[0] = 2;
        buf[1..].clone_from_slice(&self.0);

        secp256k1::PublicKey::from_byte_array_compressed(buf)
            .expect("should always work as pubkeys are always pre-validated")
    }
}

impl serde::Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = std::string::String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<pk:{}>", self.to_hex())
    }
}

impl std::fmt::Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<pk={}>", self.to_hex())
    }
}

impl std::str::FromStr for PubKey {
    type Err = PubKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("npub1") || s.starts_with("nprofile1") {
            match crate::codes::decode(s).map_err(|_| PubKeyError::InvalidBech32)? {
                crate::codes::DecodeResult::PubKey(pk) => Ok(pk),
                crate::codes::DecodeResult::Profile(profile) => Ok(profile.pubkey),
                _ => Err(PubKeyError::NotInCurve),
            }
        } else if s.len() == 64 {
            let mut bytes = [0u8; 32];
            lowercase_hex::decode_to_slice(s, &mut bytes)?;

            // ensure the public key is valid
            let _ = secp256k1::XOnlyPublicKey::from_byte_array(bytes)
                .map_err(|_| PubKeyError::NotInCurve)?;

            Ok(Self(bytes))
        } else {
            Err(PubKeyError::UnknownFormat)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShortPubKey(pub u64);

impl std::fmt::Display for ShortPubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<pk={}… (short)>", self.0.to_be_bytes().encode_hex())
    }
}
