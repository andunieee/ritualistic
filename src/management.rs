//! relay management api (NIP-86)
//!
//! requests are JSON-RPC-like HTTP POSTs to the relay's websocket URI, with the content-type
//! `application/nostr+json+rpc` and a NIP-98 `Authorization` header (with a mandatory `payload`
//! tag). the server module checks the authorization and parses the request into a [`Method`],
//! then hands it to [`crate::server::CustomRelay::handle_management`] along with the caller's
//! pubkey, so relays decide for themselves who can do what and how.

use base64::Engine;
use sha2::Digest;

pub const CONTENT_TYPE: &str = "application/nostr+json+rpc";

/// kind of the NIP-98 http auth event
pub const HTTP_AUTH_KIND: crate::Kind = crate::Kind(27235);

/// how far from the present an auth event's created_at can be
const MAX_AUTH_TIME_DRIFT: u32 = 60;

/// how long a client waits for a relay to answer a management call
const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// the raw request body
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Request {
    pub method: String,
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

/// the raw response body
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Response {
    #[serde(default)]
    pub result: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PubKeyReason {
    pub pubkey: crate::PubKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IDReason {
    pub id: crate::ID,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IPReason {
    pub ip: std::net::IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// a parsed management call
#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    SupportedMethods,

    BanPubKey(crate::PubKey, Option<String>),
    UnbanPubKey(crate::PubKey, Option<String>),
    ListBannedPubKeys,
    AllowPubKey(crate::PubKey, Option<String>),
    UnallowPubKey(crate::PubKey, Option<String>),
    ListAllowedPubKeys,

    ListEventsNeedingModeration,
    AllowEvent(crate::ID, Option<String>),
    UnallowEvent(crate::ID, Option<String>),
    BanEvent(crate::ID, Option<String>),
    UnbanEvent(crate::ID, Option<String>),
    ListBannedEvents,
    ListAllowedEvents,

    ChangeRelayName(String),
    ChangeRelayDescription(String),
    ChangeRelayIcon(String),

    AllowKind(crate::Kind),
    DisallowKind(crate::Kind),
    ListAllowedKinds,
    ListDisallowedKinds,

    BlockIP(std::net::IpAddr, Option<String>),
    UnblockIP(std::net::IpAddr),
    ListBlockedIPs,

    /// anything else (roles, claims, custom methods), passed through as-is
    Other(Request),
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum MethodError {
    #[error("missing parameter {0}")]
    MissingParam(usize),

    #[error("invalid parameter {0}: {1}")]
    InvalidParam(usize, String),
}

impl Method {
    pub fn name(&self) -> &str {
        match self {
            Self::SupportedMethods => "supportedmethods",
            Self::BanPubKey(..) => "banpubkey",
            Self::UnbanPubKey(..) => "unbanpubkey",
            Self::ListBannedPubKeys => "listbannedpubkeys",
            Self::AllowPubKey(..) => "allowpubkey",
            Self::UnallowPubKey(..) => "unallowpubkey",
            Self::ListAllowedPubKeys => "listallowedpubkeys",
            Self::ListEventsNeedingModeration => "listeventsneedingmoderation",
            Self::AllowEvent(..) => "allowevent",
            Self::UnallowEvent(..) => "unallowevent",
            Self::BanEvent(..) => "banevent",
            Self::UnbanEvent(..) => "unbanevent",
            Self::ListBannedEvents => "listbannedevents",
            Self::ListAllowedEvents => "listallowedevents",
            Self::ChangeRelayName(_) => "changerelayname",
            Self::ChangeRelayDescription(_) => "changerelaydescription",
            Self::ChangeRelayIcon(_) => "changerelayicon",
            Self::AllowKind(_) => "allowkind",
            Self::DisallowKind(_) => "disallowkind",
            Self::ListAllowedKinds => "listallowedkinds",
            Self::ListDisallowedKinds => "listdisallowedkinds",
            Self::BlockIP(..) => "blockip",
            Self::UnblockIP(_) => "unblockip",
            Self::ListBlockedIPs => "listblockedips",
            Self::Other(req) => &req.method,
        }
    }

    /// parse a raw request into a typed method call
    pub fn parse(req: Request) -> Result<Self, MethodError> {
        let p = &req.params;

        let string = |i: usize| -> Result<String, MethodError> {
            match p.get(i) {
                Some(serde_json::Value::String(s)) => Ok(s.clone()),
                Some(_) => Err(MethodError::InvalidParam(i, "expected a string".into())),
                None => Err(MethodError::MissingParam(i)),
            }
        };
        let reason = |i: usize| -> Option<String> {
            p.get(i)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        };
        let pubkey = |i: usize| -> Result<crate::PubKey, MethodError> {
            string(i)?
                .parse()
                .map_err(|e: crate::keys::PubKeyError| MethodError::InvalidParam(i, e.to_string()))
        };
        let id = |i: usize| -> Result<crate::ID, MethodError> {
            string(i)?
                .parse()
                .map_err(|e: crate::IDError| MethodError::InvalidParam(i, e.to_string()))
        };
        let ip = |i: usize| -> Result<std::net::IpAddr, MethodError> {
            string(i)?
                .parse()
                .map_err(|e: std::net::AddrParseError| MethodError::InvalidParam(i, e.to_string()))
        };
        let kind = |i: usize| -> Result<crate::Kind, MethodError> {
            match p.get(i) {
                Some(v) => v
                    .as_u64()
                    .and_then(|n| crate::Kind::try_from(n).ok())
                    .ok_or_else(|| MethodError::InvalidParam(i, "expected a kind number".into())),
                None => Err(MethodError::MissingParam(i)),
            }
        };

        Ok(match req.method.as_str() {
            "supportedmethods" => Self::SupportedMethods,
            "banpubkey" => Self::BanPubKey(pubkey(0)?, reason(1)),
            "unbanpubkey" => Self::UnbanPubKey(pubkey(0)?, reason(1)),
            "listbannedpubkeys" => Self::ListBannedPubKeys,
            "allowpubkey" => Self::AllowPubKey(pubkey(0)?, reason(1)),
            "unallowpubkey" => Self::UnallowPubKey(pubkey(0)?, reason(1)),
            "listallowedpubkeys" => Self::ListAllowedPubKeys,
            "listeventsneedingmoderation" => Self::ListEventsNeedingModeration,
            "allowevent" => Self::AllowEvent(id(0)?, reason(1)),
            "unallowevent" => Self::UnallowEvent(id(0)?, reason(1)),
            "banevent" => Self::BanEvent(id(0)?, reason(1)),
            "unbanevent" => Self::UnbanEvent(id(0)?, reason(1)),
            "listbannedevents" => Self::ListBannedEvents,
            "listallowedevents" => Self::ListAllowedEvents,
            "changerelayname" => Self::ChangeRelayName(string(0)?),
            "changerelaydescription" => Self::ChangeRelayDescription(string(0)?),
            "changerelayicon" => Self::ChangeRelayIcon(string(0)?),
            "allowkind" => Self::AllowKind(kind(0)?),
            "disallowkind" => Self::DisallowKind(kind(0)?),
            "listallowedkinds" => Self::ListAllowedKinds,
            "listdisallowedkinds" => Self::ListDisallowedKinds,
            "blockip" => Self::BlockIP(ip(0)?, reason(1)),
            "unblockip" => Self::UnblockIP(ip(0)?),
            "listblockedips" => Self::ListBlockedIPs,
            _ => Self::Other(req),
        })
    }

    /// turn this back into a raw request, for clients
    pub fn to_request(&self) -> Request {
        use serde_json::json;

        fn with_reason(
            first: serde_json::Value,
            reason: &Option<String>,
        ) -> Vec<serde_json::Value> {
            match reason {
                Some(r) => vec![first, json!(r)],
                None => vec![first],
            }
        }

        let params = match self {
            Self::BanPubKey(pk, r)
            | Self::UnbanPubKey(pk, r)
            | Self::AllowPubKey(pk, r)
            | Self::UnallowPubKey(pk, r) => with_reason(json!(pk), r),
            Self::AllowEvent(id, r)
            | Self::UnallowEvent(id, r)
            | Self::BanEvent(id, r)
            | Self::UnbanEvent(id, r) => with_reason(json!(id), r),
            Self::ChangeRelayName(s)
            | Self::ChangeRelayDescription(s)
            | Self::ChangeRelayIcon(s) => {
                vec![json!(s)]
            }
            Self::AllowKind(k) | Self::DisallowKind(k) => vec![json!(k)],
            Self::BlockIP(ip, r) => with_reason(json!(ip), r),
            Self::UnblockIP(ip) => vec![json!(ip)],
            Self::Other(req) => return req.clone(),
            _ => vec![],
        };

        Request {
            method: self.name().to_string(),
            params,
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum AuthError {
    #[error("missing authorization header")]
    Missing,

    #[error("authorization header must be 'Nostr <base64 event>'")]
    BadScheme,

    #[error("authorization event is not valid base64 json")]
    BadEncoding,

    #[error("authorization event has the wrong kind")]
    WrongKind,

    #[error("authorization event signature is invalid")]
    InvalidSignature,

    #[error("authorization event is too old or too far in the future")]
    BadTimestamp,

    #[error("authorization event 'u' tag doesn't match this relay")]
    WrongUrl,

    #[error("authorization event 'method' tag doesn't match")]
    WrongMethod,

    #[error("authorization event 'payload' tag doesn't match the request body")]
    WrongPayload,
}

/// validate a NIP-98 `Authorization` header value for a request to `host` + `path` with the
/// given http method and body, returning the pubkey that signed it.
///
/// the scheme of the `u` tag is ignored since relays are commonly behind TLS-terminating proxies.
pub fn validate_auth(
    header: Option<&str>,
    host: &str,
    path: &str,
    http_method: &str,
    body: &[u8],
) -> Result<crate::PubKey, AuthError> {
    let header = header.ok_or(AuthError::Missing)?;
    let encoded = header
        .strip_prefix("Nostr ")
        .ok_or(AuthError::BadScheme)?
        .trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AuthError::BadEncoding)?;
    let event: crate::Event =
        serde_json::from_slice(&decoded).map_err(|_| AuthError::BadEncoding)?;

    if event.kind != HTTP_AUTH_KIND {
        return Err(AuthError::WrongKind);
    }
    if !event.verify_signature() {
        return Err(AuthError::InvalidSignature);
    }
    if crate::Timestamp::now().0.abs_diff(event.created_at.0) > MAX_AUTH_TIME_DRIFT {
        return Err(AuthError::BadTimestamp);
    }

    let u = event.tags.find("u").ok_or(AuthError::WrongUrl)?;
    let u = url::Url::parse(&u[1]).map_err(|_| AuthError::WrongUrl)?;
    let u_host = match (u.host_str(), u.port()) {
        (Some(h), Some(p)) => format!("{}:{}", h, p),
        (Some(h), None) => h.to_string(),
        (None, _) => return Err(AuthError::WrongUrl),
    };
    if !u_host.eq_ignore_ascii_case(host)
        || u.path().trim_end_matches('/') != path.trim_end_matches('/')
    {
        return Err(AuthError::WrongUrl);
    }

    match event.tags.find("method") {
        Some(m) if m[1].eq_ignore_ascii_case(http_method) => {}
        _ => return Err(AuthError::WrongMethod),
    }

    let payload_hash = lowercase_hex::encode(sha2::Sha256::digest(body));
    match event.tags.find("payload") {
        Some(p) if p[1].eq_ignore_ascii_case(&payload_hash) => {}
        _ => return Err(AuthError::WrongPayload),
    }

    Ok(event.pubkey)
}

/// build a NIP-98 `Authorization` header value
pub fn make_auth_header(
    secret_key: &crate::SecretKey,
    url: &str,
    http_method: &str,
    body: &[u8],
) -> String {
    let event = crate::EventTemplate {
        created_at: crate::Timestamp::now(),
        kind: HTTP_AUTH_KIND,
        tags: crate::Tags(vec![
            vec!["u".to_string(), url.to_string()],
            vec!["method".to_string(), http_method.to_string()],
            vec![
                "payload".to_string(),
                lowercase_hex::encode(sha2::Sha256::digest(body)),
            ],
        ]),
        content: String::new(),
    }
    .finalize(secret_key);

    format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event.to_string())
    )
}

#[derive(thiserror::Error, Debug)]
pub enum CallError {
    #[error("invalid relay url: {0}")]
    Url(#[from] url::ParseError),

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("relay returned status {0}")]
    Status(u16),

    #[error("relay returned an error: {0}")]
    Relay(String),

    #[error("relay returned an unexpected result: {0}")]
    UnexpectedResult(#[from] serde_json::Error),
}

/// call a management method on a relay, returning its result
pub async fn call(
    relay_url: &str,
    secret_key: &crate::SecretKey,
    method: &Method,
) -> Result<serde_json::Value, CallError> {
    let ws_url = crate::normalize_url(relay_url)?;
    let http_url = format!("http{}", &ws_url.as_str()[2..]);
    let body = serde_json::to_vec(&method.to_request()).expect("request always serializes");

    let response = reqwest::Client::builder()
        .timeout(CALL_TIMEOUT)
        .build()?
        .post(&http_url)
        .header("content-type", CONTENT_TYPE)
        .header(
            "authorization",
            make_auth_header(secret_key, &http_url, "POST", &body),
        )
        .body(body)
        .send()
        .await?;

    let status = response.status();
    let response: Response = match response.json().await {
        Ok(r) => r,
        Err(_) if !status.is_success() => return Err(CallError::Status(status.as_u16())),
        Err(err) => return Err(err.into()),
    };

    match response.error {
        Some(err) => Err(CallError::Relay(err)),
        None if !status.is_success() => Err(CallError::Status(status.as_u16())),
        None => Ok(response.result),
    }
}

/// call a management method and deserialize its result, e.g. into a `Vec<PubKeyReason>` for
/// [`Method::ListAllowedPubKeys`] or a `bool` for most of the others
pub async fn call_as<T: serde::de::DeserializeOwned>(
    relay_url: &str,
    secret_key: &crate::SecretKey,
    method: &Method,
) -> Result<T, CallError> {
    Ok(serde_json::from_value(
        call(relay_url, secret_key, method).await?,
    )?)
}

/// call any management method by name with raw params, including ones [`Method`] doesn't know
pub async fn call_raw(
    relay_url: &str,
    secret_key: &crate::SecretKey,
    method: &str,
    params: Vec<serde_json::Value>,
) -> Result<serde_json::Value, CallError> {
    let method = Method::Other(Request {
        method: method.to_string(),
        params,
    });
    call(relay_url, secret_key, &method).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_roundtrip() {
        let pk = crate::SecretKey::generate().pubkey();
        let methods = vec![
            Method::SupportedMethods,
            Method::AllowPubKey(pk, Some("friend".into())),
            Method::UnallowPubKey(pk, None),
            Method::BanEvent(crate::ID([7; 32]), None),
            Method::ChangeRelayName("x".into()),
            Method::AllowKind(crate::Kind(30023)),
            Method::BlockIP("10.0.0.1".parse().unwrap(), Some("spam".into())),
            Method::UnblockIP("::1".parse().unwrap()),
            Method::Other(Request {
                method: "createrole".into(),
                params: vec![serde_json::json!("a")],
            }),
        ];
        for method in methods {
            assert_eq!(Method::parse(method.to_request()).unwrap(), method);
        }
    }

    #[test]
    fn test_parse_errors() {
        let req = |method: &str, params: serde_json::Value| Request {
            method: method.into(),
            params: serde_json::from_value(params).unwrap(),
        };
        assert_eq!(
            Method::parse(req("allowpubkey", serde_json::json!([]))),
            Err(MethodError::MissingParam(0))
        );
        assert!(matches!(
            Method::parse(req("allowpubkey", serde_json::json!(["nope"]))),
            Err(MethodError::InvalidParam(0, _))
        ));
        assert!(matches!(
            Method::parse(req("allowkind", serde_json::json!([70000]))),
            Err(MethodError::InvalidParam(0, _))
        ));
        assert!(matches!(
            Method::parse(req("blockip", serde_json::json!(["1.2.3"]))),
            Err(MethodError::InvalidParam(0, _))
        ));
    }

    #[test]
    fn test_auth() {
        let sk = crate::SecretKey::generate();
        let body = br#"{"method":"supportedmethods","params":[]}"#;
        let header = make_auth_header(&sk, "https://relay.example.com", "POST", body);

        let ok = validate_auth(Some(&header), "relay.example.com", "/", "POST", body);
        assert_eq!(ok, Ok(sk.pubkey()));

        assert_eq!(
            validate_auth(None, "relay.example.com", "/", "POST", body),
            Err(AuthError::Missing)
        );
        assert_eq!(
            validate_auth(Some(&header), "other.example.com", "/", "POST", body),
            Err(AuthError::WrongUrl)
        );
        assert_eq!(
            validate_auth(Some(&header), "relay.example.com", "/sub", "POST", body),
            Err(AuthError::WrongUrl)
        );
        assert_eq!(
            validate_auth(Some(&header), "relay.example.com", "/", "GET", body),
            Err(AuthError::WrongMethod)
        );
        assert_eq!(
            validate_auth(Some(&header), "relay.example.com", "/", "POST", b"{}"),
            Err(AuthError::WrongPayload)
        );
    }
}
