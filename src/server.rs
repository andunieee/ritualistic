//! Nostr relay server implementation using hyper
//!
//! This module provides a complete Nostr relay server implementation
//! using hyper for HTTP and WebSocket handling.

use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite;

#[derive(thiserror::Error, Debug)]
pub enum RelayError {
    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("websocket error: {0}")]
    WebSocket(#[from] hyper_tungstenite::tungstenite::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("custom relay error: {0}")]
    CustomRelay(String),
}

/// trait for custom relay implementations
pub trait CustomRelay: Send + Sync {
    fn handle_event(&mut self, _event: &crate::Event) -> std::result::Result<(), String> {
        Err("can't handle anything".to_string())
    }

    fn handle_request(
        &mut self,
        _filter: &crate::Filter,
    ) -> std::result::Result<Vec<crate::Event>, String> {
        Err("can't handle anything".to_string())
    }

    /// called before any http request (websocket upgrades included) is handled,
    /// returning an error rejects it with a 403
    fn check_ip(&mut self, _ip: &std::net::IpAddr) -> std::result::Result<(), String> {
        Ok(())
    }

    /// the management methods (NIP-86) the given authenticated caller can use,
    /// if this is empty the caller gets a 401
    fn supported_management_methods(&mut self, _caller: &crate::PubKey) -> Vec<String> {
        Vec::new()
    }

    /// handle a management call, only called for methods listed by
    /// `supported_management_methods` for this caller (except for "supportedmethods", which is
    /// answered automatically). changes to `info` are reflected in the relay information document
    fn handle_management(
        &mut self,
        _caller: &crate::PubKey,
        _method: &crate::management::Method,
        _info: &mut crate::relay_information::RelayInformationDocument,
    ) -> std::result::Result<serde_json::Value, String> {
        Err("not supported".to_string())
    }
}

/// main relay server
pub struct RelayInternals {
    /// relay metadata
    pub info: std::sync::RwLock<crate::relay_information::RelayInformationDocument>,

    /// the actual relay methods
    pub custom_relay: Box<tokio::sync::Mutex<dyn CustomRelay>>,
}

#[derive(thiserror::Error, Debug)]
pub enum StartError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum ServiceError {
    #[error("websocket error")]
    WebSocket,

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("custom relay error: {0}")]
    CustomRelay(String),

    #[error("hyper error: {0}")]
    Hyper(#[from] hyper::Error),
}

/// start the relay server
pub async fn start(
    ri: std::sync::Arc<RelayInternals>,
    addr: std::net::SocketAddr,
) -> Result<(), StartError> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    log::info!("relay listening on {}", addr);
    serve(ri, listener).await
}

/// serve the relay on an already bound listener
pub async fn serve(
    ri: std::sync::Arc<RelayInternals>,
    listener: tokio::net::TcpListener,
) -> Result<(), StartError> {
    async fn service(
        req: hyper::Request<hyper::body::Incoming>,
        ri: std::sync::Arc<RelayInternals>,
        peer_ip: std::net::IpAddr,
    ) -> std::result::Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, ServiceError>
    {
        let ip = client_ip(&req, peer_ip);
        if let Err(reason) = ri.custom_relay.lock().await.check_ip(&ip) {
            return Ok(hyper::Response::builder()
                .status(hyper::StatusCode::FORBIDDEN)
                .body(http_body_util::Full::new(bytes::Bytes::from(reason)))
                .unwrap());
        }

        match (req.method(), req.uri().path()) {
            (&hyper::Method::OPTIONS, "/") => Ok(hyper::Response::builder()
                .status(hyper::StatusCode::NO_CONTENT)
                .header("access-control-allow-origin", "*")
                .header("access-control-allow-methods", "GET, POST, OPTIONS")
                .header(
                    "access-control-allow-headers",
                    "authorization, content-type, accept",
                )
                .body(http_body_util::Full::new(bytes::Bytes::new()))
                .unwrap()),
            (&hyper::Method::POST, "/")
                if req
                    .headers()
                    .get("content-type")
                    .is_some_and(|ct| ct == crate::management::CONTENT_TYPE) =>
            {
                Ok(handle_management_request(&ri, req).await)
            }
            (&hyper::Method::GET, "/") => {
                // check if this is a websocket upgrade request
                if hyper_tungstenite::is_upgrade_request(&req) {
                    match hyper_tungstenite::upgrade(req, None) {
                        Ok((response, websocket)) => {
                            let ri = ri.clone();
                            tokio::spawn(async move {
                                match websocket.await {
                                    Ok(ws_stream) => {
                                        let (tx, mut rx) = ws_stream.split();
                                        let tx = std::sync::Arc::new(tokio::sync::Mutex::new(tx));

                                        // handle incoming messages
                                        tokio::spawn(async move {
                                            while let Some(Ok(msg)) = rx.next().await {
                                                if let tungstenite::Message::Text(msg_text) = msg {
                                                    match serde_json::from_str::<
                                                        crate::envelopes::Envelope,
                                                    >(
                                                        msg_text.as_str()
                                                    ) {
                                                        Ok(crate::envelopes::Envelope::Req {
                                                            subscription_id,
                                                            filters,
                                                        }) => {
                                                            let _ = handle_req_envelope(
                                                                &ri,
                                                                tx.clone(),
                                                                subscription_id,
                                                                &filters,
                                                            )
                                                            .await;
                                                        }
                                                        // Ok(Envelope::CountAsk { subscription_id, filter }) => {
                                                        //     handle_count_ask(
                                                        //         &ri, tx, subscription_id, filter,
                                                        //     )
                                                        //     .await;
                                                        // }
                                                        Ok(
                                                            crate::envelopes::Envelope::OutEvent {
                                                                event,
                                                            },
                                                        ) => {
                                                            let _ = handle_event_envelope(
                                                                &ri,
                                                                tx.clone(),
                                                                &event,
                                                            )
                                                            .await;
                                                        }
                                                        Ok(crate::envelopes::Envelope::Close {
                                                            ..
                                                        }) => {
                                                            // nothing to do, we don't keep subscriptions open
                                                        }
                                                        Ok(envelope) => {
                                                            let notice = serde_json::json!([
                                                                "NOTICE",
                                                                format!(
                                                                    "we don't know how to handle this {}",
                                                                    envelope.label()
                                                                )
                                                            ]);
                                                            let _ = tx
                                                                .lock()
                                                                .await
                                                                .send(tungstenite::Message::text(
                                                                    notice.to_string(),
                                                                ))
                                                                .await;
                                                        }
                                                        Err(err) => {
                                                            let notice = serde_json::json!([
                                                                "NOTICE",
                                                                format!(
                                                                    "failed to parse message: {}",
                                                                    err
                                                                )
                                                            ]);
                                                            let _ = tx
                                                                .lock()
                                                                .await
                                                                .send(tungstenite::Message::text(
                                                                    notice.to_string(),
                                                                ))
                                                                .await;
                                                        }
                                                    }
                                                }
                                            }
                                        });
                                    }
                                    Err(e) => {
                                        log::debug!("websocket upgrade failed: {}", e);
                                    }
                                }
                            });

                            Ok::<hyper::Response<http_body_util::Full<bytes::Bytes>>, ServiceError>(
                                response,
                            )
                        }
                        Err(e) => {
                            log::debug!("websocket upgrade error: {}", e);
                            Err(ServiceError::WebSocket)
                        }
                    }
                } else {
                    // is this a metadata request?
                    if let Some(accept) = req.headers().get("accept")
                        && accept == "application/nostr+json"
                    {
                        let info_json = match serde_json::to_string(&*ri.info.read().unwrap()) {
                            Ok(json) => json,
                            Err(e) => return Err(ServiceError::Json(e)),
                        };
                        return Ok(hyper::Response::builder()
                            .status(hyper::StatusCode::OK)
                            .header("content-type", "application/nostr+json")
                            .header("access-control-allow-origin", "*")
                            .body(http_body_util::Full::new(bytes::Bytes::from(info_json)))
                            .unwrap());
                    }

                    // default response
                    let name = ri.info.read().unwrap().name.clone();
                    Ok(hyper::Response::builder()
                        .status(hyper::StatusCode::OK)
                        .body(http_body_util::Full::new(bytes::Bytes::from(
                            if name.is_empty() {
                                "ritualistic nostr relay".to_string()
                            } else {
                                name
                            },
                        )))
                        .unwrap())
                }
            }
            _ => Ok(hyper::Response::builder()
                .status(hyper::StatusCode::NOT_FOUND)
                .body(http_body_util::Full::new(bytes::Bytes::from("not found")))
                .unwrap()),
        }
    }

    loop {
        let (tcp, peer) = listener.accept().await?;
        let io = hyper_util::rt::TokioIo::new(tcp);
        let ri_ = ri.clone();
        let peer_ip = peer.ip();

        tokio::task::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            let conn = http
                .serve_connection(
                    io,
                    hyper::service::service_fn(|req| service(req, ri_.clone(), peer_ip)),
                )
                .with_upgrades();

            if let Err(err) = conn.await {
                log::debug!("error serving connection: {:?}", err);
            }
        });
    }
}

/// the ip of the client, taken from the proxy headers if the connection comes from localhost
fn client_ip<B>(req: &hyper::Request<B>, peer_ip: std::net::IpAddr) -> std::net::IpAddr {
    if !peer_ip.is_loopback() {
        return peer_ip;
    }

    let header = |name: &str| req.headers().get(name).and_then(|v| v.to_str().ok());
    header("x-forwarded-for")
        .and_then(|v| v.split(',').next())
        .or_else(|| header("x-real-ip"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(peer_ip)
}

/// max size of a management request body
const MAX_MANAGEMENT_BODY: usize = 64 * 1024;

async fn handle_management_request(
    ri: &std::sync::Arc<RelayInternals>,
    req: hyper::Request<hyper::body::Incoming>,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    use http_body_util::BodyExt;

    let respond = |status: hyper::StatusCode, response: crate::management::Response| {
        hyper::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .body(http_body_util::Full::new(bytes::Bytes::from(
                serde_json::to_string(&response).expect("response always serializes"),
            )))
            .unwrap()
    };
    let fail = |status: hyper::StatusCode, error: String| {
        respond(
            status,
            crate::management::Response {
                result: serde_json::Value::Null,
                error: Some(error),
            },
        )
    };

    let headers = req.headers().clone();
    let path = req.uri().path().to_string();
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let host = header("x-forwarded-host")
        .or_else(|| header("host"))
        .unwrap_or_default()
        .to_string();

    let body = match http_body_util::Limited::new(req.into_body(), MAX_MANAGEMENT_BODY)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return fail(
                hyper::StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large or unreadable".to_string(),
            );
        }
    };

    let caller = match crate::management::validate_auth(
        header("authorization"),
        &host,
        &path,
        "POST",
        &body,
    ) {
        Ok(pubkey) => pubkey,
        Err(err) => return fail(hyper::StatusCode::UNAUTHORIZED, err.to_string()),
    };

    let request: crate::management::Request = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(err) => {
            return fail(
                hyper::StatusCode::BAD_REQUEST,
                format!("invalid request: {}", err),
            );
        }
    };

    let mut relay = ri.custom_relay.lock().await;
    let supported = relay.supported_management_methods(&caller);
    if supported.is_empty() {
        return fail(hyper::StatusCode::UNAUTHORIZED, "unauthorized".to_string());
    }

    let method = match crate::management::Method::parse(request) {
        Ok(method) => method,
        Err(err) => return fail(hyper::StatusCode::OK, err.to_string()),
    };

    let result = match &method {
        crate::management::Method::SupportedMethods => Ok(serde_json::json!(supported)),
        method if !supported.iter().any(|name| name == method.name()) => {
            Err(format!("method '{}' not supported", method.name()))
        }
        method => {
            let mut info = ri.info.write().unwrap();
            relay.handle_management(&caller, method, &mut info)
        }
    };
    drop(relay);

    match result {
        Ok(result) => respond(
            hyper::StatusCode::OK,
            crate::management::Response {
                result,
                error: None,
            },
        ),
        Err(err) => fail(hyper::StatusCode::OK, err),
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HandleReqEnvelopeError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("websocket error: {0}")]
    WebSocket(#[from] hyper_tungstenite::tungstenite::Error),

    #[error("custom relay error: {0}")]
    CustomRelay(String),
}

async fn handle_req_envelope(
    ri: &std::sync::Arc<RelayInternals>,
    tx: std::sync::Arc<
        tokio::sync::Mutex<
            futures::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
                >,
                tungstenite::Message,
            >,
        >,
    >,
    subscription_id: String,
    filters: &[crate::Filter],
) -> Result<(), HandleReqEnvelopeError> {
    for filter in filters {
        // query events
        match ri.custom_relay.lock().await.handle_request(filter) {
            Ok(events) => {
                for event in events {
                    let event_env = serde_json::json!(["EVENT", subscription_id, event]);
                    tx.lock()
                        .await
                        .send(tungstenite::Message::text(event_env.to_string()))
                        .await?;
                }
            }
            Err(e) => {
                let notice = serde_json::json!(["NOTICE", format!("query error: {}", e)]);
                tx.lock()
                    .await
                    .send(tungstenite::Message::text(notice.to_string()))
                    .await?;
            }
        }
    }

    // send EOSE
    let eose_json = serde_json::json!(["EOSE", subscription_id]);
    tx.lock()
        .await
        .send(tungstenite::Message::text(eose_json.to_string()))
        .await?;

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub enum HandleEventEnvelopeError {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("websocket error: {0}")]
    WebSocket(#[from] hyper_tungstenite::tungstenite::Error),

    #[error("custom relay error: {0}")]
    CustomRelay(String),
}

async fn handle_event_envelope(
    ri: &std::sync::Arc<RelayInternals>,
    tx: std::sync::Arc<
        tokio::sync::Mutex<
            futures::stream::SplitSink<
                tokio_tungstenite::WebSocketStream<
                    hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>,
                >,
                tungstenite::Message,
            >,
        >,
    >,
    event: &crate::Event,
) -> Result<(), HandleEventEnvelopeError> {
    // check event ID
    if !event.check_id() {
        let ok_json =
            serde_json::json!(["OK", event.id, false, "invalid: id is computed incorrectly"]);
        tx.lock()
            .await
            .send(tungstenite::Message::text(ok_json.to_string()))
            .await?;
        return Ok(());
    }

    // check signature
    if !event.verify_signature() {
        let ok_json = serde_json::json!(["OK", event.id, false, "invalid: signature is invalid"]);
        tx.lock()
            .await
            .send(tungstenite::Message::text(ok_json.to_string()))
            .await?;
        return Ok(());
    }

    // possibly save event
    match ri.custom_relay.lock().await.handle_event(event) {
        Ok(()) => {
            let ok_json = serde_json::json!(["OK", event.id, true, ""]);
            tx.lock()
                .await
                .send(tungstenite::Message::text(ok_json.to_string()))
                .await?;
        }
        Err(e) => {
            let msg = if let Some(colon_pos) = e.find(": ")
                && !e[..colon_pos].contains(' ')
            {
                e.to_string()
            } else {
                format!("error: {}", e)
            };

            let ok_json = serde_json::json!(["OK", event.id, false, msg]);
            tx.lock()
                .await
                .send(tungstenite::Message::text(ok_json.to_string()))
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::Occurrence;
    use crate::relay_information::RelayInformationDocument;
    use crate::*;
    use std::cmp::min;

    struct InMemoryRelay {
        events: Vec<Event>,
    }

    impl CustomRelay for InMemoryRelay {
        fn handle_event(&mut self, event: &Event) -> std::result::Result<(), String> {
            self.events.push(event.clone());
            Ok(())
        }

        fn handle_request(&mut self, filter: &Filter) -> std::result::Result<Vec<Event>, String> {
            let mut resp = Vec::with_capacity(min(
                filter.limit.unwrap_or(500),
                filter.get_theoretical_limit(),
            ));
            for event in &self.events {
                if filter.matches(event) {
                    resp.push(event.clone());
                }
            }
            Ok(resp)
        }
    }

    struct EvenTimestampRelay {
        events: Vec<Event>,
    }

    impl CustomRelay for EvenTimestampRelay {
        fn handle_event(&mut self, event: &Event) -> std::result::Result<(), String> {
            if event.created_at.0.is_multiple_of(2) {
                self.events.push(event.clone());
                Ok(())
            } else {
                Err("only even timestamps allowed".to_string())
            }
        }

        fn handle_request(&mut self, filter: &Filter) -> std::result::Result<Vec<Event>, String> {
            let mut resp = Vec::with_capacity(min(
                filter.limit.unwrap_or(500),
                filter.get_theoretical_limit(),
            ));
            for event in &self.events {
                if filter.matches(event) {
                    resp.push(event.clone());
                }
            }
            Ok(resp)
        }
    }

    struct OddTimestampRelay {
        events: Vec<Event>,
    }

    impl CustomRelay for OddTimestampRelay {
        fn handle_event(&mut self, event: &Event) -> std::result::Result<(), String> {
            if event.created_at.0 % 2 == 1 {
                self.events.push(event.clone());
                Ok(())
            } else {
                Err("only odd timestamps allowed".to_string())
            }
        }

        fn handle_request(&mut self, filter: &Filter) -> std::result::Result<Vec<Event>, String> {
            let mut resp = Vec::with_capacity(min(
                filter.limit.unwrap_or(500),
                filter.get_theoretical_limit(),
            ));
            for event in &self.events {
                if filter.matches(event) {
                    resp.push(event.clone());
                }
            }
            Ok(resp)
        }
    }

    struct MultipleOfThreeRelay {
        events: Vec<Event>,
    }

    impl CustomRelay for MultipleOfThreeRelay {
        fn handle_event(&mut self, event: &Event) -> std::result::Result<(), String> {
            if event.created_at.0.is_multiple_of(3) {
                self.events.push(event.clone());
                Ok(())
            } else {
                Err("only timestamps that are multiples of 3 allowed".to_string())
            }
        }

        fn handle_request(&mut self, filter: &Filter) -> std::result::Result<Vec<Event>, String> {
            let mut resp = Vec::with_capacity(min(
                filter.limit.unwrap_or(500),
                filter.get_theoretical_limit(),
            ));
            for event in &self.events {
                if filter.matches(event) {
                    resp.push(event.clone());
                }
            }
            Ok(resp)
        }
    }

    struct ManagedRelay {
        admin: PubKey,
        blocked: Vec<std::net::IpAddr>,
    }

    impl CustomRelay for ManagedRelay {
        fn check_ip(&mut self, ip: &std::net::IpAddr) -> std::result::Result<(), String> {
            if self.blocked.contains(ip) {
                Err("blocked".to_string())
            } else {
                Ok(())
            }
        }

        fn supported_management_methods(&mut self, caller: &PubKey) -> Vec<String> {
            if *caller == self.admin {
                vec!["changerelayname".to_string(), "blockip".to_string()]
            } else {
                vec![]
            }
        }

        fn handle_management(
            &mut self,
            _caller: &PubKey,
            method: &crate::management::Method,
            info: &mut RelayInformationDocument,
        ) -> std::result::Result<serde_json::Value, String> {
            use crate::management::Method;
            match method {
                Method::ChangeRelayName(name) => info.name = name.clone(),
                Method::BlockIP(ip, _) => self.blocked.push(*ip),
                _ => return Err("unexpected".to_string()),
            }
            Ok(serde_json::Value::Bool(true))
        }
    }

    #[tokio::test]
    async fn test_management() {
        use crate::management::{CallError, Method, call, call_as, call_raw};

        let admin = SecretKey::generate();
        let (url, server) = testing::spawn_relay(
            "managed",
            ManagedRelay {
                admin: admin.pubkey(),
                blocked: vec![],
            },
        )
        .await;

        // strangers can't do anything
        let stranger = SecretKey::generate();
        let err = call(&url, &stranger, &Method::SupportedMethods)
            .await
            .unwrap_err();
        assert!(matches!(err, CallError::Relay(e) if e == "unauthorized"));

        // the admin can
        let methods: Vec<String> = call_as(&url, &admin, &Method::SupportedMethods)
            .await
            .unwrap();
        assert_eq!(methods, ["changerelayname", "blockip"]);

        // methods can also be called by name, known or not
        let methods = call_raw(&url, &admin, "supportedmethods", vec![])
            .await
            .unwrap();
        assert_eq!(methods, serde_json::json!(["changerelayname", "blockip"]));
        let err = call_raw(&url, &admin, "createrole", vec![serde_json::json!("mod")])
            .await
            .unwrap_err();
        assert!(matches!(err, CallError::Relay(_)));

        let err = call(&url, &admin, &Method::ChangeRelayIcon("x".into()))
            .await
            .unwrap_err();
        assert!(matches!(err, CallError::Relay(_)));

        let res = call(&url, &admin, &Method::ChangeRelayName("renamed".into()))
            .await
            .unwrap();
        assert_eq!(res, serde_json::Value::Bool(true));
        let info = crate::relay_information::fetch(&url).await.unwrap();
        assert_eq!(info.name, "renamed");

        // now block ourselves
        call(
            &url,
            &admin,
            &Method::BlockIP("127.0.0.1".parse().unwrap(), None),
        )
        .await
        .unwrap();
        let err = call(&url, &admin, &Method::SupportedMethods)
            .await
            .unwrap_err();
        assert!(matches!(err, CallError::Status(403)));
        assert!(Relay::connect(url.parse().unwrap(), None).await.is_err());

        server.abort();
    }

    #[tokio::test]
    async fn test_metadata_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "ksowknex".to_string(),
                ..Default::default()
            }
            .into(),
            custom_relay: Box::new(tokio::sync::Mutex::new(InMemoryRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        // start server in background
        let server_handle = tokio::spawn(serve(relay, listener));

        // request metadata
        let client = reqwest::Client::new();
        let response = client
            .get(format!("http://{}/", addr))
            .header("accept", "application/nostr+json")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/nostr+json"
        );

        let info: RelayInformationDocument = response.json().await.unwrap();
        assert_eq!(info.name, "ksowknex");
        assert_eq!(info.description, "");

        // cleanup
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_relay_connect_publish_subscribe() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay_internals = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "test-relay".to_string(),
                ..Default::default()
            }
            .into(),
            custom_relay: Box::new(tokio::sync::Mutex::new(InMemoryRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        // start server in background
        let server_handle = tokio::spawn(serve(relay_internals, listener));

        // connect to the relay
        let relay_url = format!("ws://{}", addr).parse().unwrap();
        let relay = Relay::connect(relay_url, None).await.unwrap();

        // create and publish an event
        let secret_key = SecretKey::generate();
        let event_template = EventTemplate {
            created_at: Timestamp::now(),
            kind: Kind(1),
            tags: crate::Tags::default(),
            content: "hello from test".to_string(),
        };
        let event = event_template.finalize(&secret_key);
        let event_id = event.id;

        // publish the event
        relay
            .publish(event.clone(), crate::PublishOptions::default())
            .await
            .unwrap();

        // subscribe to events
        let filter = Filter {
            kinds: Some(vec![Kind(1)]),
            limit: Some(10),
            ..Default::default()
        };

        let mut subscription = relay
            .subscribe(filter, crate::relay::SubscriptionOptions::default())
            .await;

        // wait for the event to be received
        let mut received_event = None;
        let mut got_eose = false;

        while let Some(occurrence) = subscription.recv().await {
            match occurrence {
                Occurrence::Event(evt) => {
                    if evt.id == event_id {
                        received_event = Some(evt);
                    }
                }
                Occurrence::Eose => {
                    got_eose = true;
                    break;
                }
                Occurrence::Close(_) => {
                    break;
                }
            }
        }

        // verify we received the event
        assert!(received_event.is_some());
        assert!(got_eose);
        let received = received_event.unwrap();
        assert_eq!(received.id, event_id);
        assert_eq!(received.content, "hello from test");
        assert_eq!(received.kind, Kind(1));

        // cleanup
        server_handle.abort();
    }

    #[tokio::test]
    async fn test_pool_with_filtered_relays() {
        // start three relays with different filtering logic
        let even_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let odd_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiple_of_three_listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let even_url = format!("ws://{}", even_listener.local_addr().unwrap());
        let odd_url = format!("ws://{}", odd_listener.local_addr().unwrap());
        let multiple_of_three_url =
            format!("ws://{}", multiple_of_three_listener.local_addr().unwrap());

        let even_relay = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "even-relay".to_string(),
                ..Default::default()
            }
            .into(),
            custom_relay: Box::new(tokio::sync::Mutex::new(EvenTimestampRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        let odd_relay = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "odd-relay".to_string(),
                ..Default::default()
            }
            .into(),
            custom_relay: Box::new(tokio::sync::Mutex::new(OddTimestampRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        let multiple_of_three_relay = std::sync::Arc::new(RelayInternals {
            info: RelayInformationDocument {
                name: "multiple-of-three-relay".to_string(),
                ..Default::default()
            }
            .into(),
            custom_relay: Box::new(tokio::sync::Mutex::new(MultipleOfThreeRelay {
                events: Vec::with_capacity(1024),
            })),
        });

        // start servers in background
        let even_handle = tokio::spawn(serve(even_relay, even_listener));
        let odd_handle = tokio::spawn(serve(odd_relay, odd_listener));
        let multiple_of_three_handle =
            tokio::spawn(serve(multiple_of_three_relay, multiple_of_three_listener));

        // create pool and relay urls
        let mut pool = Network::new();
        let relay_urls = vec![
            even_url.clone(),
            odd_url.clone(),
            multiple_of_three_url.clone(),
        ];

        // create events with different timestamps
        let secret_key = SecretKey::generate();
        let mut events = Vec::new();

        // create events with timestamps: 100, 101, 102, 103, 104, 105, 106, 107, 108, 109
        for i in 100..110 {
            let event_template = EventTemplate {
                created_at: Timestamp(i),
                kind: Kind(1),
                tags: crate::Tags::default(),
                content: format!("event with timestamp {}", i),
            };
            let event = event_template.finalize(&secret_key);
            events.push(event);
        }

        // publish all events to all relays
        for event in &events {
            let mut publish_results = pool
                .publish_many(
                    relay_urls.clone(),
                    event.clone(),
                    crate::PublishOptions::default(),
                )
                .await;

            // wait for all publish results
            let mut results = Vec::new();
            while let Some(result) = publish_results.recv().await {
                results.push(result);
            }

            // we expect 3 results (one from each relay)
            assert_eq!(results.len(), 3);
        }

        // query each relay individually
        let filter = Filter {
            kinds: Some(vec![Kind(1)]),
            limit: Some(20),
            ..Default::default()
        };

        // query even relay (should have events with timestamps: 100, 102, 104, 106, 108)
        let even_events = pool
            .query(
                vec![even_url.clone()],
                filter.clone(),
                SubscriptionOptions::default(),
            )
            .await;
        assert_eq!(even_events.len(), 5);
        for event in &even_events {
            assert_eq!(
                event.created_at.0 % 2,
                0,
                "even relay should only have events with even timestamps"
            );
        }

        // query odd relay (should have events with timestamps: 101, 103, 105, 107, 109)
        let odd_events = pool
            .query(
                vec![odd_url.clone()],
                filter.clone(),
                SubscriptionOptions::default(),
            )
            .await;
        assert_eq!(odd_events.len(), 5);
        for event in &odd_events {
            assert_eq!(
                event.created_at.0 % 2,
                1,
                "odd relay should only have events with odd timestamps"
            );
        }

        // query multiple of three relay (should have events with timestamps: 102, 105, 108)
        let multiple_of_three_events = pool
            .query(
                vec![multiple_of_three_url.clone()],
                filter.clone(),
                SubscriptionOptions::default(),
            )
            .await;
        assert_eq!(multiple_of_three_events.len(), 3);
        for event in &multiple_of_three_events {
            assert_eq!(
                event.created_at.0 % 3,
                0,
                "multiple of three relay should only have events with timestamps that are multiples of 3"
            );
        }

        // verify specific timestamps
        let even_timestamps: Vec<u32> = even_events.iter().map(|e| e.created_at.0).collect();
        assert!(even_timestamps.contains(&100));
        assert!(even_timestamps.contains(&102));
        assert!(even_timestamps.contains(&104));
        assert!(even_timestamps.contains(&106));
        assert!(even_timestamps.contains(&108));

        let odd_timestamps: Vec<u32> = odd_events.iter().map(|e| e.created_at.0).collect();
        assert!(odd_timestamps.contains(&101));
        assert!(odd_timestamps.contains(&103));
        assert!(odd_timestamps.contains(&105));
        assert!(odd_timestamps.contains(&107));
        assert!(odd_timestamps.contains(&109));

        let multiple_of_three_timestamps: Vec<u32> = multiple_of_three_events
            .iter()
            .map(|e| e.created_at.0)
            .collect();
        assert!(multiple_of_three_timestamps.contains(&102));
        assert!(multiple_of_three_timestamps.contains(&105));
        assert!(multiple_of_three_timestamps.contains(&108));

        // cleanup
        even_handle.abort();
        odd_handle.abort();
        multiple_of_three_handle.abort();
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use crate::EventDatabase;

    /// a relay backed by the in-memory database
    #[derive(Default)]
    pub(crate) struct DatabaseRelay {
        pub(crate) db: crate::BTreeEventDatabase,
    }

    impl CustomRelay for DatabaseRelay {
        fn handle_event(&mut self, event: &crate::Event) -> std::result::Result<(), String> {
            self.db.save_event(event).map_err(|err| err.to_string())
        }

        fn handle_request(
            &mut self,
            filter: &crate::Filter,
        ) -> std::result::Result<Vec<crate::Event>, String> {
            Ok(self
                .db
                .query_events(&mut [filter.clone()])
                .map_err(|err| err.to_string())?
                .map(|event| {
                    rkyv::deserialize::<crate::Event, rkyv::rancor::Error>(&*event)
                        .expect("archived type must deserialize")
                })
                .collect())
        }
    }

    /// start a relay on a random local port, returns its url and the server task
    pub(crate) async fn spawn_relay(
        name: &str,
        custom_relay: impl CustomRelay + 'static,
    ) -> (String, tokio::task::JoinHandle<Result<(), StartError>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let ri = std::sync::Arc::new(RelayInternals {
            info: crate::relay_information::RelayInformationDocument {
                name: name.to_string(),
                ..Default::default()
            }
            .into(),
            custom_relay: Box::new(tokio::sync::Mutex::new(custom_relay)),
        });
        (url, tokio::spawn(serve(ri, listener)))
    }

    /// a relay preloaded with the given events
    pub(crate) async fn spawn_relay_with_events(
        name: &str,
        events: &[crate::Event],
    ) -> (String, tokio::task::JoinHandle<Result<(), StartError>>) {
        let relay = DatabaseRelay::default();
        for event in events {
            relay.db.save_event(event).unwrap();
        }
        spawn_relay(name, relay).await
    }

    /// generate signed kind:1 events with sequential timestamps
    pub(crate) fn make_events(count: u32) -> Vec<crate::Event> {
        let sk = crate::SecretKey::generate();
        (0..count)
            .map(|i| {
                crate::EventTemplate {
                    created_at: crate::Timestamp(1_000_000 + i),
                    kind: crate::Kind(1),
                    tags: crate::Tags::default(),
                    content: format!("event {}", i),
                }
                .finalize(&sk)
            })
            .collect()
    }
}
