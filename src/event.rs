use sha2::Digest;

/// represents a signed nostr event
#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Event {
    pub id: crate::ID,
    pub pubkey: crate::PubKey,
    pub created_at: crate::Timestamp,
    pub kind: crate::Kind,
    pub tags: crate::Tags,
    pub content: String,
    pub sig: crate::Signature,
}

impl Event {
    /// check that the id matches the event contents and that the signature is valid for it
    pub fn verify_signature(&self) -> bool {
        let pubkey = match secp256k1::XOnlyPublicKey::from_byte_array(self.pubkey.0) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let hash: [u8; 32] = sha2::Sha256::digest(self.serialize()).into();
        if hash != self.id.0 {
            return false;
        }

        let signature = secp256k1::schnorr::Signature::from_byte_array(self.sig.0);
        secp256k1::schnorr::verify(&signature, &hash, &pubkey).is_ok()
    }

    /// check if the event ID matches the computed ID
    pub fn check_id(&self) -> bool {
        let serialized = self.serialize();
        let hash = sha2::Sha256::digest(&serialized);
        let id = crate::ID::from_bytes(hash.into());

        id == self.id
    }

    /// serialize the event for ID computation
    pub fn serialize(&self) -> Vec<u8> {
        let array = serde_json::json!([
            0,
            self.pubkey,
            self.created_at.0,
            self.kind,
            self.tags.0,
            self.content
        ]);
        array.to_string().into_bytes()
    }
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{}", json),
            Err(err) => write!(f, "Event({} >> {})", self.id, err),
        }
    }
}

impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PartialEq<ArchivedEvent> for ArchivedEvent {
    fn eq(&self, other: &ArchivedEvent) -> bool {
        self.id == other.id
    }
}

impl PartialEq<ArchivedEvent> for Event {
    fn eq(&self, other: &ArchivedEvent) -> bool {
        self.id == other.id
    }
}

impl Eq for Event {}

impl std::hash::Hash for Event {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
