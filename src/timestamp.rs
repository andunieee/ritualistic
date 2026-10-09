/// unix timestamp in seconds
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Timestamp(pub u32);

impl Timestamp {
    // std::time::SystemTime::now() panics on wasm32-unknown-unknown, so use the js clock there
    #[cfg(target_arch = "wasm32")]
    pub fn now() -> Self {
        Self((js_sys::Date::now() / 1000.0) as u32)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn now() -> Self {
        Self(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .try_into()
                .unwrap_or(u32::MAX),
        )
    }

    pub fn invert(&self) -> u32 {
        u32::MAX - self.0
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for Timestamp {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for u32 {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0
    }
}

impl TryFrom<i64> for Timestamp {
    type Error = std::num::TryFromIntError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<Timestamp> for i64 {
    fn from(timestamp: Timestamp) -> Self {
        timestamp.0 as i64
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Timestamp::now()
    }
}

// additional conversions from various integer types
impl From<u16> for Timestamp {
    fn from(value: u16) -> Self {
        Self(value as u32)
    }
}

impl TryFrom<u64> for Timestamp {
    type Error = std::num::TryFromIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<i32> for Timestamp {
    type Error = std::num::TryFromIntError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<usize> for Timestamp {
    type Error = std::num::TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl From<std::time::SystemTime> for Timestamp {
    fn from(value: std::time::SystemTime) -> Self {
        let duration = value
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self(duration.as_secs().try_into().unwrap_or(u32::MAX))
    }
}

impl From<Timestamp> for std::time::SystemTime {
    fn from(timestamp: Timestamp) -> Self {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp.0 as u64)
    }
}
