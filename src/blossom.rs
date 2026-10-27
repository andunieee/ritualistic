//! blossom (https://github.com/hzrd149/blossom) helpers
//!
//! blossom servers store blobs addressed by their sha256. requests that mutate or access
//! restricted resources carry a nostr event of kind 24242 in the `Authorization` header
//! (`Authorization: Nostr <base64 of the event json>`). this module has what is needed to
//! create and verify these authorization events, and the blob descriptor type returned by
//! servers.

use base64::Engine;
use sha2::Digest;

/// kind of the authorization event (BUD-01)
pub const AUTH_KIND: crate::Kind = crate::Kind(24242);

/// the scheme the `Authorization` header must start with
pub const AUTH_SCHEME: &str = "Nostr";

/// the action an authorization event is valid for, it goes in the `t` tag
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Get,
    Upload,
    List,
    Delete,
    Media,
    /// not part of the spec, servers can use this for their own endpoints
    Custom(&'static str),
}

impl Verb {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verb::Get => "get",
            Verb::Upload => "upload",
            Verb::List => "list",
            Verb::Delete => "delete",
            Verb::Media => "media",
            Verb::Custom(s) => s,
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum AuthError {
    #[error("missing or malformed authorization header")]
    BadHeader,

    #[error("authorization event is not valid json")]
    BadEvent,

    #[error("authorization event has an invalid id or signature")]
    BadSignature,

    #[error("authorization event must be of kind 24242")]
    WrongKind,

    #[error("authorization event was created in the future")]
    FromTheFuture,

    #[error("authorization event has no expiration tag")]
    NoExpiration,

    #[error("authorization event has expired")]
    Expired,

    #[error("authorization event is for a different action, expected \"{0}\"")]
    WrongVerb(&'static str),

    #[error("authorization event does not cover this blob")]
    WrongBlob,

    #[error("authorization event is for a different server")]
    WrongServer,
}

/// a verified authorization event
#[derive(Debug, Clone)]
pub struct Auth {
    pub event: crate::Event,
}

impl Auth {
    pub fn pubkey(&self) -> crate::PubKey {
        self.event.pubkey
    }

    /// the blob hashes (`x` tags) this authorization covers
    pub fn hashes(&self) -> impl Iterator<Item = &str> {
        self.event.tags.find_all("x").map(|t| t[1].as_str())
    }

    /// true if the event has no `x` tags at all (valid for any blob) or has one for this hash
    pub fn covers(&self, sha256: &str) -> bool {
        let mut it = self.hashes().peekable();
        it.peek().is_none() || it.any(|h| h.eq_ignore_ascii_case(sha256))
    }

    /// true if the event has no `server` tags or has one matching this domain (or url)
    pub fn is_for_server(&self, domain: &str) -> bool {
        let mut it = self.event.tags.find_all("server").peekable();
        it.peek().is_none()
            || it.any(|t| {
                let s = t[1].trim_end_matches('/').to_lowercase();
                let s = s.split_once("://").map(|(_, rest)| rest).unwrap_or(&s);
                s == domain.to_lowercase()
            })
    }
}

/// parse the value of an `Authorization` header and check everything that does not depend on
/// the request: kind, id, signature, timestamps and the `t` tag
pub fn verify_auth_header(
    header: &str,
    verb: Verb,
    now: crate::Timestamp,
) -> Result<Auth, AuthError> {
    let (scheme, payload) = header.trim().split_once(' ').ok_or(AuthError::BadHeader)?;
    if !scheme.eq_ignore_ascii_case(AUTH_SCHEME) {
        return Err(AuthError::BadHeader);
    }

    // clients use both the standard and the url-safe alphabets, padded or not
    let payload = payload.trim().trim_end_matches('=');
    let json = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload))
        .map_err(|_| AuthError::BadHeader)?;
    let event: crate::Event = serde_json::from_slice(&json).map_err(|_| AuthError::BadEvent)?;

    verify_auth_event(event, verb, now)
}

/// same as [verify_auth_header] but for an already decoded event
pub fn verify_auth_event(
    event: crate::Event,
    verb: Verb,
    now: crate::Timestamp,
) -> Result<Auth, AuthError> {
    if event.kind != AUTH_KIND {
        return Err(AuthError::WrongKind);
    }
    if !event.verify_signature() {
        return Err(AuthError::BadSignature);
    }
    if event.created_at > now {
        return Err(AuthError::FromTheFuture);
    }

    let expiration = event
        .tags
        .find("expiration")
        .and_then(|t| t[1].parse::<u32>().ok())
        .ok_or(AuthError::NoExpiration)?;
    if expiration <= now.0 {
        return Err(AuthError::Expired);
    }

    if !event
        .tags
        .find_all("t")
        .any(|t| t[1].eq_ignore_ascii_case(verb.as_str()))
    {
        return Err(AuthError::WrongVerb(verb.as_str()));
    }

    Ok(Auth { event })
}

/// build and sign an authorization event, returns the value for the `Authorization` header
pub fn create_auth_header(
    secret_key: &crate::SecretKey,
    verb: Verb,
    hashes: &[&str],
    server: Option<&str>,
    description: &str,
    valid_for_secs: u32,
) -> String {
    let now = crate::Timestamp::now();
    let mut tags = vec![
        vec!["t".to_string(), verb.as_str().to_string()],
        vec![
            "expiration".to_string(),
            now.0.saturating_add(valid_for_secs).to_string(),
        ],
    ];
    for h in hashes {
        tags.push(vec!["x".to_string(), h.to_string()]);
    }
    if let Some(s) = server {
        tags.push(vec!["server".to_string(), s.to_string()]);
    }

    let event = crate::EventTemplate {
        created_at: now,
        kind: AUTH_KIND,
        tags: crate::Tags(tags),
        content: description.to_string(),
    }
    .finalize(secret_key);

    let json = serde_json::to_string(&event).expect("events always serialize");
    format!(
        "{AUTH_SCHEME} {}",
        base64::engine::general_purpose::STANDARD.encode(json)
    )
}

/// returned by servers after storing (or when asked about) a blob (BUD-02)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlobDescriptor {
    pub url: String,
    pub sha256: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub mime: String,
    pub uploaded: u64,
}

/// lowercase hex sha256 of some bytes
pub fn sha256_hex(data: &[u8]) -> String {
    lowercase_hex::encode(sha2::Sha256::digest(data))
}

/// check that a string looks like a sha256 in lowercase hex
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// extract the sha256 from the path of a blob request, which can be `/<sha256>` or
/// `/<sha256>.<ext>` (BUD-01)
pub fn hash_from_path(path: &str) -> Option<&str> {
    let name = path.strip_prefix('/')?;
    let hash = name.split_once('.').map(|(h, _)| h).unwrap_or(name);
    is_sha256_hex(hash).then_some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "b1674191a88ec5cdd733e4240a81803105dc412d6c6708d53ab94fc248f4f553";

    #[test]
    fn sha256() {
        assert_eq!(sha256_hex(b"Hello World!"), "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069");
        assert!(is_sha256_hex(HASH));
        assert!(!is_sha256_hex(&HASH.to_uppercase()));
        assert!(!is_sha256_hex("abc"));
    }

    #[test]
    fn paths() {
        assert_eq!(hash_from_path(&format!("/{HASH}")), Some(HASH));
        assert_eq!(hash_from_path(&format!("/{HASH}.pdf")), Some(HASH));
        assert_eq!(hash_from_path("/upload"), None);
        assert_eq!(hash_from_path(&format!("/a/{HASH}")), None);
    }

    #[test]
    fn roundtrip() {
        let sk = crate::SecretKey::generate();
        let header = create_auth_header(&sk, Verb::Upload, &[HASH], Some("cdn.example.com"), "upload", 60);

        let auth = verify_auth_header(&header, Verb::Upload, crate::Timestamp::now()).unwrap();
        assert_eq!(auth.pubkey(), sk.pubkey());
        assert!(auth.covers(HASH));
        assert!(!auth.covers(&"0".repeat(64)));
        assert!(auth.is_for_server("cdn.example.com"));
        assert!(!auth.is_for_server("other.example.com"));

        assert_eq!(
            verify_auth_header(&header, Verb::Delete, crate::Timestamp::now()).unwrap_err(),
            AuthError::WrongVerb("delete")
        );
    }

    #[test]
    fn timestamps() {
        let sk = crate::SecretKey::generate();
        let header = create_auth_header(&sk, Verb::Get, &[], None, "", 60);
        let now = crate::Timestamp::now();

        // no x or server tags means it covers anything
        let auth = verify_auth_header(&header, Verb::Get, now).unwrap();
        assert!(auth.covers(HASH));
        assert!(auth.is_for_server("anything"));

        assert_eq!(
            verify_auth_header(&header, Verb::Get, crate::Timestamp(now.0 + 3600)).unwrap_err(),
            AuthError::Expired
        );
        assert_eq!(
            verify_auth_header(&header, Verb::Get, crate::Timestamp(now.0 - 3600)).unwrap_err(),
            AuthError::FromTheFuture
        );
    }

    #[test]
    fn rejects_garbage_and_wrong_kind() {
        let now = crate::Timestamp::now();
        assert_eq!(verify_auth_header("Bearer abc", Verb::Get, now).unwrap_err(), AuthError::BadHeader);
        assert_eq!(verify_auth_header("Nostr !!!", Verb::Get, now).unwrap_err(), AuthError::BadHeader);
        assert_eq!(verify_auth_header("Nostr e30", Verb::Get, now).unwrap_err(), AuthError::BadEvent);

        let sk = crate::SecretKey::generate();
        let evt = crate::EventTemplate {
            created_at: now,
            kind: crate::Kind(1),
            ..Default::default()
        }
        .finalize(&sk);
        assert_eq!(verify_auth_event(evt, Verb::Get, now).unwrap_err(), AuthError::WrongKind);
    }

    #[test]
    fn rejects_tampered_event() {
        let sk = crate::SecretKey::generate();
        let header = create_auth_header(&sk, Verb::Upload, &[], None, "hi", 60);
        let payload = header.strip_prefix("Nostr ").unwrap();
        let json = base64::engine::general_purpose::STANDARD.decode(payload).unwrap();
        let mut evt: crate::Event = serde_json::from_slice(&json).unwrap();
        evt.content = "bye".into();
        assert_eq!(
            verify_auth_event(evt, Verb::Upload, crate::Timestamp::now()).unwrap_err(),
            AuthError::BadSignature
        );
    }

    #[test]
    fn descriptor_json() {
        let d = BlobDescriptor {
            url: format!("https://cdn.example.com/{HASH}.pdf"),
            sha256: HASH.into(),
            size: 184292,
            mime: "application/pdf".into(),
            uploaded: 1725105921,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["type"], "application/pdf");
        assert_eq!(serde_json::from_value::<BlobDescriptor>(v).unwrap(), d);
    }
}
