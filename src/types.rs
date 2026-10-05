use lowercase_hex::ToHexExt;

#[derive(thiserror::Error, Debug)]
pub enum IDError {
    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),

    #[error("invalid ID length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

#[derive(thiserror::Error, Debug)]
pub enum SignatureError {
    #[error("invalid hex encoding")]
    InvalidHex(#[from] lowercase_hex::FromHexError),

    #[error("invalid signature length: expected 64 bytes, got {0}")]
    InvalidLength(usize),
}

/// A 32-byte event ID
#[derive(Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct ID(pub [u8; 32]);

impl ID {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn short(&self) -> ShortID {
        let bytes: [u8; 8] = self.0[8..16].try_into().unwrap();
        ShortID(u64::from_ne_bytes(bytes))
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, IDError> {
        if hex_str.len() != 64 {
            return Err(IDError::InvalidLength(hex_str.len() / 2));
        }
        let mut bytes = [0u8; 32];
        lowercase_hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
    }
}

impl serde::Serialize for ID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for ID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ID::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<id:{}>", self.to_hex())
    }
}

impl std::fmt::Display for ID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<id={}>", self.to_hex())
    }
}

impl std::str::FromStr for ID {
    type Err = IDError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

// A 8-byte event ID (lossy fragment of the full ID)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShortID(pub u64);

impl std::fmt::Display for ShortID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<id={}… (short)>", self.0.to_be_bytes().encode_hex())
    }
}

impl ArchivedID {
    pub fn short(&self) -> ShortID {
        let bytes: [u8; 8] = self.0[8..16].try_into().unwrap();
        ShortID(u64::from_ne_bytes(bytes))
    }
}

impl PartialEq<ArchivedID> for ArchivedID {
    fn eq(&self, other: &ArchivedID) -> bool {
        self.0 == other.0
    }
}

impl PartialEq<ArchivedID> for ID {
    fn eq(&self, other: &ArchivedID) -> bool {
        self.0 == other.0
    }
}

impl std::fmt::Debug for ArchivedID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<id:{} archived>", lowercase_hex::encode(self.0))
    }
}

impl std::fmt::Display for ArchivedID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<id={} archived>", lowercase_hex::encode(self.0))
    }
}

/// A 64-byte signature
#[derive(Clone, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)]
pub struct Signature(pub [u8; 64]);

impl Signature {
    /// Create a new signature from bytes
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Get the bytes of the signature
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Create signature from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, SignatureError> {
        if hex_str.len() != 128 {
            return Err(SignatureError::InvalidLength(hex_str.len() / 2));
        }
        let mut bytes = [0u8; 64];
        lowercase_hex::decode_to_slice(hex_str, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        lowercase_hex::encode(self.0)
    }
}

impl serde::Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Signature::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<sig:{}>", self.to_hex())
    }
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<sig={}>", self.to_hex())
    }
}

impl std::str::FromStr for Signature {
    type Err = SignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// event kind type
#[derive(
    Copy,
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Kind(pub u16);

impl Kind {
    /// check if this kind is regular (1-9999, excluding 0 and 3)
    pub fn is_regular(&self) -> bool {
        self.0 < 10000 && self.0 != 0 && self.0 != 3
    }

    /// check if this kind is replaceable (0, 3, or 10000-19999)
    pub fn is_replaceable(&self) -> bool {
        self.0 == 0 || self.0 == 3 || (10000..20000).contains(&self.0)
    }

    /// check if this kind is ephemeral (20000-29999)
    pub fn is_ephemeral(&self) -> bool {
        (20000..30000).contains(&self.0)
    }

    /// check if this kind is addressable (30000-39999)
    pub fn is_addressable(&self) -> bool {
        (30000..40000).contains(&self.0)
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for Kind {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<Kind> for u16 {
    fn from(kind: Kind) -> Self {
        kind.0
    }
}

impl TryFrom<u32> for Kind {
    type Error = std::num::TryFromIntError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<u64> for Kind {
    type Error = std::num::TryFromIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<i32> for Kind {
    type Error = std::num::TryFromIntError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<i64> for Kind {
    type Error = std::num::TryFromIntError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<usize> for Kind {
    type Error = std::num::TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}
