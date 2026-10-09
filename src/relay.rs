use crate::{
    Event, EventTemplate, Filter, ID, Kind, Tags, Timestamp,
    envelopes::Envelope,
    finalizer::Finalizer,
    helpers::{
        SubscriptionKey, extract_event_id, extract_key_from_sub_id, key_from_sub_id,
        sub_id_from_key,
    },
};
use dashmap::{DashMap, DashSet};
use slotmap::{SecondaryMap, SlotMap};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use url::Url;

#[cfg(target_arch = "wasm32")]
use tokio_with_wasm::alias as tokio;

/// how long we'll wait for a websocket connection to be established
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(7);

/// how long we'll wait for an OK after publishing an event
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(thiserror::Error, Debug)]
pub enum PublishError {
    #[error("ok=false, relay message: {0}")]
    NotOK(String),

    #[error("internal channel error, relay connection might have closed")]
    Channel,

    #[error("relay didn't reply with an OK in time")]
    Timeout,
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error("relay connection error")]
    Websocket,

    #[error("relay connection timed out")]
    Timeout,
}

#[derive(Debug)]
pub(crate) struct SubSender {
    pub(crate) ocurrences_sender: mpsc::Sender<Occurrence>,
    pub(crate) filter: Filter,
    pub(crate) auth_automatically: Option<Finalizer>,
}

#[derive(Debug)]
pub enum CloseReason {
    RelayConnectionClosedByUs,
    RelayConnectionClosedByThem(Option<String>),
    RelayConnectionError,
    ClosedByUs,
    ClosedByThemWithReason(String),
    Unknown,
}

#[derive(Default, Clone)]
pub struct SubscriptionOptions {
    pub label: Option<String>,
    pub timeout: Option<Duration>,
    pub auth_automatically: Option<Finalizer>,

    pub(crate) skip_ids: Option<Arc<DashSet<ID>>>,
}

impl std::fmt::Debug for SubscriptionOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("label", &self.label)
            .field("timeout", &self.timeout)
            .field("auth_automatically", &self.auth_automatically)
            .field("skip_ids", &self.skip_ids)
            .finish()
    }
}

#[derive(Default, Clone, Debug)]
pub struct PublishOptions {
    /// when the relay rejects the event with "auth-required:", perform NIP-42 AUTH with this
    /// and publish again (only once)
    pub auth_automatically: Option<Finalizer>,
}

#[derive(Debug)]
pub enum Occurrence {
    Event(Event),
    Eose,
    Close(CloseReason),
}

#[derive(Debug, Clone)]
pub struct Relay {
    pub url: Url,
    // by connection
    write_queue: mpsc::Sender<String>,
    challenge: Arc<RwLock<Option<String>>>,

    // by subscription
    pub(crate) sub_sender_map: Arc<Mutex<SlotMap<SubscriptionKey, SubSender>>>,
    id_skippers_map: Arc<Mutex<SecondaryMap<SubscriptionKey, Arc<DashSet<ID>>>>>,

    // by publish
    ok_callbacks: Arc<DashMap<ID, oneshot::Sender<Result<(), String>>>>,

    // only used to know when the last clone of this handle is dropped
    handle: Arc<()>,
}

impl Relay {
    #[cfg(target_arch = "wasm32")]
    pub async fn connect(
        url: Url,
        mut on_close: Option<oneshot::Sender<String>>,
    ) -> Result<Self, ConnectError> {
        use wasm_bindgen::{JsCast, JsValue, closure::Closure};
        use web_sys::{CloseEvent, ErrorEvent, MessageEvent, WebSocket};

        // create websocket
        let (write_sender, mut write_receiver) = mpsc::channel(1);

        let relay = Self {
            url: url.clone(),
            write_queue: write_sender,
            sub_sender_map: Arc::new(Mutex::new(SlotMap::with_capacity_and_key(8))),
            id_skippers_map: Arc::new(Mutex::new(SecondaryMap::with_capacity(8))),
            challenge: Arc::new(RwLock::new(None)),
            ok_callbacks: Arc::new(DashMap::new()),
            handle: Arc::new(()),
        };

        let ws = Arc::new(WebSocket::new(url.as_str()).map_err(|_| ConnectError::Websocket)?);

        // start write queue handler
        let queue_writer = ws.clone();
        tokio::spawn(async move {
            while let Some(text) = write_receiver.recv().await {
                let _ = queue_writer.send_with_str(&text);
            }
        });

        // setup message handler
        let write_queue = relay.write_queue.clone();
        let id_skippers_map = relay.id_skippers_map.clone();
        let sub_sender_map = relay.sub_sender_map.clone();
        let relay_challenge = relay.challenge.clone();
        let ok_callbacks = relay.ok_callbacks.clone();
        let relay_url = relay.url.to_string();

        let on_message = Closure::wrap(Box::new(move |e: MessageEvent| {
            if let Ok(text) = e.data().dyn_into::<js_sys::JsString>() {
                let message: String = text.into();

                log::debug!("got message from {}: {}", &relay_url, &message);

                let write_queue = write_queue.clone();
                let id_skippers_map = id_skippers_map.clone();
                let sub_sender_map = sub_sender_map.clone();
                let relay_challenge = relay_challenge.clone();
                let ok_callbacks = ok_callbacks.clone();
                let relay_url = relay_url.to_string();

                tokio::spawn(async move {
                    handle_nostr_envelope(
                        message,
                        write_queue,
                        relay_challenge,
                        sub_sender_map,
                        id_skippers_map,
                        ok_callbacks,
                        relay_url,
                    )
                    .await;
                });
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        ws.set_onmessage(Some(on_message.into_js_value().unchecked_ref()));

        // setup error handler
        let on_error = Closure::once(Box::new(move |e: ErrorEvent| {
            log::info!("websocket error: {:?}", e.message());
        }) as Box<dyn FnOnce(ErrorEvent)>);
        ws.set_onerror(Some(on_error.into_js_value().unchecked_ref()));

        // setup close handler
        let sub_sender_map_close = relay.sub_sender_map.clone();
        let on_close_handler = Closure::once(Box::new(move |e: CloseEvent| {
            log::info!("websocket closed: code={} reason={}", e.code(), e.reason());

            // notify all subscriptions
            let sub_sender_map_close = sub_sender_map_close.clone();
            tokio::spawn(async move {
                for (_, sub) in sub_sender_map_close.lock().await.drain() {
                    let _ = sub.ocurrences_sender.send(Occurrence::Close(
                        CloseReason::RelayConnectionClosedByThem(None),
                    ));
                }
            });

            if let Some(on_close) = on_close.take() {
                let _ = on_close.send(format!("closed: {:?}", e.reason()));
            }
        }) as Box<dyn FnOnce(CloseEvent)>);
        ws.set_onclose(Some(on_close_handler.into_js_value().unchecked_ref()));

        // setup open handler for connection ready
        let (sender, receiver) = oneshot::channel();
        let mut opt = Some(sender);
        let on_open = Closure::once(Box::new(move |_: JsValue| {
            if let Some(sender) = opt.take() {
                let _ = sender.send(());
            }
        }) as Box<dyn FnOnce(JsValue)>);
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));

        match tokio::time::timeout(CONNECT_TIMEOUT, receiver).await {
            Ok(Ok(())) => Ok(relay),
            Ok(Err(_)) => Err(ConnectError::Websocket),
            Err(_) => {
                ws.close().ok();
                Err(ConnectError::Timeout)
            }
        }
    }

    // the returned future is boxed with an explicit type to break the type inference cycle
    // relay -> finalizer -> bunker -> network -> relay
    #[cfg(not(target_arch = "wasm32"))]
    pub fn connect(
        url: Url,
        on_close: Option<oneshot::Sender<String>>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Self, ConnectError>> + Send>> {
        Box::pin(Self::connect_native(url, on_close))
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn connect_native(
        url: Url,
        mut on_close: Option<oneshot::Sender<String>>,
    ) -> Result<Self, ConnectError> {
        use futures::{SinkExt, StreamExt};
        use tokio::time::interval;
        use tokio_tungstenite::{
            connect_async_tls_with_config,
            tungstenite::{Message, client::IntoClientRequest},
        };

        let (write_sender, mut write_receiver) = mpsc::channel(1);

        // connect
        let (ws_stream, _) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_async_tls_with_config(
                url.as_str()
                    .into_client_request()
                    .map_err(|_| ConnectError::Websocket)?,
                None,
                false,
                None,
            ),
        )
        .await
        .map_err(|_| ConnectError::Timeout)?
        .map_err(|_| ConnectError::Websocket)?;

        let (conn_write, mut conn_read) = ws_stream.split();
        let writer = Arc::new(Mutex::new(conn_write));

        let relay = Self {
            url: url.clone(),
            sub_sender_map: Arc::new(Mutex::new(SlotMap::with_capacity_and_key(8))),
            id_skippers_map: Arc::new(Mutex::new(SecondaryMap::with_capacity(8))),
            challenge: Arc::new(RwLock::new(None)),
            ok_callbacks: Arc::new(DashMap::new()),
            write_queue: write_sender,
            handle: Arc::new(()),
        };

        // start write queue handler
        let queue_writer = writer.clone();
        tokio::spawn(async move {
            while let Some(text) = write_receiver.recv().await {
                let _ = queue_writer.lock().await.send(Message::text(text)).await;
            }
        });

        // start ping handler
        let ping_writer = writer.clone();
        tokio::spawn(async move {
            let mut ping_interval = interval(Duration::from_secs(29));
            loop {
                ping_interval.tick().await;
                if let Err(err) = ping_writer
                    .lock()
                    .await
                    .send(Message::Ping(vec![].into()))
                    .await
                {
                    log::info!("ping failed: {}", err);
                    break;
                }
            }
        });

        // start message reader
        let pong_writer = writer.clone();
        let id_skippers_map = relay.id_skippers_map.clone();
        let sub_sender_map = relay.sub_sender_map.clone();
        let relay_challenge = relay.challenge.clone();
        let ok_callbacks = relay.ok_callbacks.clone();
        let write_queue = relay.write_queue.clone();
        let relay_url = relay.url.clone();
        tokio::spawn(async move {
            loop {
                let message = match conn_read.next().await {
                    Some(Ok(Message::Text(text))) => text.to_string(),
                    Some(Ok(Message::Ping(payload))) => {
                        let _ = pong_writer.lock().await.send(Message::Pong(payload)).await;
                        continue;
                    }
                    Some(Ok(Message::Close(frame))) => {
                        let close_msg = frame.map_or("broken close".to_string(), |c| {
                            format!("close ({}) {}", c.code, c.reason)
                        });

                        if let Some(on_close) = on_close.take() {
                            let _ = on_close.send(close_msg.clone());
                        }
                        for (_, sub) in sub_sender_map.lock().await.drain() {
                            let _ = sub
                                .ocurrences_sender
                                .send(Occurrence::Close(CloseReason::RelayConnectionClosedByThem(
                                    Some(close_msg.clone()),
                                )))
                                .await;
                        }
                        return;
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(err)) => {
                        if let Some(on_close) = on_close.take() {
                            let _ = on_close.send(format!("error: {}", err));
                        }
                        for (_, sub) in sub_sender_map.lock().await.drain() {
                            let _ = sub
                                .ocurrences_sender
                                .send(Occurrence::Close(CloseReason::RelayConnectionError))
                                .await;
                        }
                        return;
                    }
                    None => {
                        // stream ended without a close frame
                        if let Some(on_close) = on_close.take() {
                            let _ = on_close.send("connection ended".to_string());
                        }
                        for (_, sub) in sub_sender_map.lock().await.drain() {
                            let _ = sub
                                .ocurrences_sender
                                .send(Occurrence::Close(CloseReason::RelayConnectionClosedByThem(
                                    None,
                                )))
                                .await;
                        }
                        return;
                    }
                };

                handle_nostr_envelope(
                    message,
                    write_queue.clone(),
                    relay_challenge.clone(),
                    sub_sender_map.clone(),
                    id_skippers_map.clone(),
                    ok_callbacks.clone(),
                    relay_url.to_string(),
                )
                .await;
            }
        });

        Ok(relay)
    }

    pub async fn publish(&self, event: Event, opts: PublishOptions) -> Result<(), PublishError> {
        let result = self.send_event(&event).await;

        if let Err(PublishError::NotOK(reason)) = &result
            && reason.starts_with("auth-required:")
            && let Some(finalizer) = &opts.auth_automatically
            && let Some(challenge) = self.challenge.read().await.clone()
            // boxed because this can recurse: publish -> finalizer -> bunker -> publish
            && Box::pin(perform_auth(
                &self.write_queue,
                &self.ok_callbacks,
                self.url.as_str(),
                challenge,
                finalizer,
            ))
            .await
        {
            // now that we're authenticated we try again, but only once
            return self.send_event(&event).await;
        }

        result
    }

    /// send an EVENT and wait for the OK
    async fn send_event(&self, event: &Event) -> Result<(), PublishError> {
        let id = event.id;
        let (tx, rx) = oneshot::channel();
        self.ok_callbacks.insert(id, tx);

        let msg = serde_json::json!(["EVENT", event]);

        if self.write_queue.send(msg.to_string()).await.is_err() {
            self.ok_callbacks.remove(&id);
            return Err(PublishError::Channel);
        }

        match tokio::time::timeout(PUBLISH_TIMEOUT, rx).await {
            Ok(Ok(result)) => result.map_err(PublishError::NotOK),
            Ok(Err(_)) => Err(PublishError::Channel),
            Err(_) => {
                self.ok_callbacks.remove(&id);
                Err(PublishError::Timeout)
            }
        }
    }

    /// subscribe to events matching a filter
    pub async fn subscribe(
        &self,
        filter: Filter,
        opts: SubscriptionOptions,
    ) -> mpsc::Receiver<Occurrence> {
        let mut reqmsg = String::new();
        let mut closemsg = String::new();
        let (occurrences_sender, occurrences) = mpsc::channel::<Occurrence>(1);

        let key = self.sub_sender_map.lock().await.insert_with_key(|key| {
            // use the key here to prepare the REQ msg
            let id = sub_id_from_key(&key, &opts.label);
            reqmsg = format!(
                "[\"REQ\",\"{}\",{}]",
                id,
                serde_json::to_string(&filter).unwrap()
            );
            closemsg = format!("[\"CLOSE\",\"{}\"]", id);

            // and store this tuple
            SubSender {
                ocurrences_sender: occurrences_sender.clone(),
                filter,
                auth_automatically: opts.auth_automatically,
            }
        });

        if let Some(skip_ids) = opts.skip_ids {
            self.id_skippers_map.lock().await.insert(key, skip_ids);
        }

        let write_queue = self.write_queue.clone();
        let sub_sender_map = self.sub_sender_map.clone();
        let id_skippers_map = self.id_skippers_map.clone();
        tokio::spawn(async move {
            // when the listener stops listening from this subscription we close it automatically
            occurrences_sender.closed().await;
            sub_sender_map.lock().await.remove(key);
            id_skippers_map.lock().await.remove(key);
            let _ = write_queue.send(closemsg).await;
        });

        let _ = self.write_queue.send(reqmsg).await.map_err(|err| {
            log::warn!(
                "[{}] failed to fire subscription: {}",
                self.url.as_str(),
                err
            )
        });

        occurrences
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // this handle is cloned all around (e.g. by Network), so only end the subscriptions when
        // the last one goes away
        if Arc::strong_count(&self.handle) > 1 {
            return;
        }

        let sub_sender_map = self.sub_sender_map.clone();

        tokio::spawn(async move {
            for (_, sub) in sub_sender_map.lock().await.drain() {
                let _ = sub
                    .ocurrences_sender
                    .send(Occurrence::Close(CloseReason::RelayConnectionClosedByUs))
                    .await;
            }
        });
    }
}

impl std::fmt::Display for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<relay url={}>", self.url)
    }
}

/// sign a NIP-42 AUTH event for the given challenge, send it and wait for the relay's OK
async fn perform_auth(
    write_queue: &mpsc::Sender<String>,
    ok_callbacks: &DashMap<ID, oneshot::Sender<Result<(), String>>>,
    relay_url: &str,
    challenge: String,
    finalizer: &Finalizer,
) -> bool {
    let Ok(auth_event) = finalizer
        .finalize_event(EventTemplate {
            created_at: Timestamp::now(),
            kind: Kind(22242),
            content: "".to_string(),
            tags: Tags(vec![
                vec!["relay".to_string(), relay_url.to_string()],
                vec!["challenge".to_string(), challenge],
            ]),
        })
        .await
    else {
        return false;
    };

    let auth_id = auth_event.id;
    let (tx, rx) = oneshot::channel();
    ok_callbacks.insert(auth_id, tx);
    let _ = write_queue
        .send(serde_json::to_string(&Envelope::AuthEvent { event: auth_event }).unwrap())
        .await;

    let ok = matches!(
        tokio::time::timeout(PUBLISH_TIMEOUT, rx).await,
        Ok(Ok(Ok(())))
    );
    ok_callbacks.remove(&auth_id);
    ok
}

#[inline]
async fn handle_nostr_envelope(
    message: String,
    write_queue: mpsc::Sender<String>,
    relay_challenge: Arc<RwLock<Option<String>>>,
    sub_sender_map: Arc<Mutex<SlotMap<SubscriptionKey, SubSender>>>,
    id_skippers_map: Arc<Mutex<SecondaryMap<SubscriptionKey, Arc<DashSet<ID>>>>>,
    ok_callbacks: Arc<DashMap<ID, oneshot::Sender<Result<(), String>>>>,
    relay_url: String,
) {
    // fast path: skip events we've already seen in this subscription before even parsing them
    // (we only check here, ids are only added after the event is verified below, otherwise a relay
    // could send a forged event with a given id and prevent the real one from being delivered)
    if let Some(sub_key) = extract_key_from_sub_id(&message)
        && let Some(id) = extract_event_id(&message)
        && let Some(skip_ids) = id_skippers_map.lock().await.get(sub_key)
        && skip_ids.contains(&id)
    {
        return;
    }

    // parse the message
    match serde_json::from_str::<Envelope>(&message) {
        Ok(Envelope::InEvent {
            subscription_id,
            event,
        }) => {
            let Some(key) = key_from_sub_id(subscription_id.as_str()) else {
                return;
            };
            if let Some(sub) = sub_sender_map.lock().await.get(key) {
                if sub.filter.matches(&event) && event.verify_signature() {
                    if let Some(skip_ids) = id_skippers_map.lock().await.get(key)
                        && !skip_ids.insert(event.id)
                    {
                        // we got this same event from another relay in the meantime
                        return;
                    }

                    let _ = sub.ocurrences_sender.send(Occurrence::Event(event)).await;
                } else {
                    // TODO: penalize this relay?
                }
            };
        }
        Ok(Envelope::Eose { subscription_id }) => {
            let Some(key) = key_from_sub_id(subscription_id.as_str()) else {
                return;
            };
            let mut map = sub_sender_map.lock().await;
            if let Some(occfilter) = map.get_mut(key) {
                // since we got an EOSE our internal filter won't check for since/until anymore
                occfilter.filter.since = None;
                occfilter.filter.until = None;

                // and we dispatch this to the listener
                let _ = occfilter.ocurrences_sender.send(Occurrence::Eose).await;
            };
        }
        Ok(Envelope::Ok {
            event_id,
            ok,
            reason,
        }) => match ok_callbacks.remove(&event_id) {
            Some((_, sender)) => {
                let _ = sender.send(match ok {
                    true => Ok(()),
                    false => Err(reason),
                });
            }
            None => {
                log::info!(
                    "received OK for unknown event {}: {} - {}",
                    event_id,
                    ok,
                    reason
                );
            }
        },
        Ok(Envelope::Notice(notice)) => {
            log::info!("[{}] received notice: {}", relay_url.as_str(), notice);
        }
        Ok(Envelope::Closed {
            subscription_id,
            reason,
        }) => {
            let Some(key) = key_from_sub_id(&subscription_id) else {
                return;
            };
            let mut ssm = sub_sender_map.lock().await;

            if reason.starts_with("auth-required:")
                && let Some(sub) = ssm.get_mut(key)
                && let Some(challenge) = relay_challenge.read().await.clone()
                // take it so we only try this once and prevent an infinite AUTH loop
                && let Some(finalizer) = sub.auth_automatically.take()
            {
                // instead of ending here after a CLOSED we will perform AUTH and then restart the
                // subscription. this must happen in a separate task and without holding the lock, as
                // the OK for the AUTH will only be read once this function returns
                let filter = sub.filter.clone();
                drop(ssm);

                tokio::spawn(async move {
                    let authenticated = perform_auth(
                        &write_queue,
                        &ok_callbacks,
                        &relay_url,
                        challenge,
                        &finalizer,
                    )
                    .await;

                    if authenticated {
                        // then restart the subscription
                        let _ = write_queue
                            .send(
                                serde_json::to_string(&Envelope::Req {
                                    subscription_id,
                                    filters: vec![filter],
                                })
                                .unwrap(),
                            )
                            .await;
                    } else if let Some(sub) = sub_sender_map.lock().await.remove(key) {
                        let _ = sub
                            .ocurrences_sender
                            .send(Occurrence::Close(CloseReason::ClosedByThemWithReason(
                                reason,
                            )))
                            .await;
                    }
                });

                return;
            }

            // otherwise remove this subscription and issue the final `Close`
            if let Some(sub) = ssm.remove(key) {
                let _ = sub
                    .ocurrences_sender
                    .send(Occurrence::Close(CloseReason::ClosedByThemWithReason(
                        reason,
                    )))
                    .await;
            }
        }
        Ok(Envelope::AuthChallenge { challenge }) => {
            let _ = relay_challenge.write().await.insert(challenge);
        }
        Ok(envelope) => {
            log::info!("[{}] unexpected message: {}", &relay_url, envelope.label());
        }
        Err(err) => {
            log::info!("[{}] wrong message: {}", &relay_url, err);
        }
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
mod tests {
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn test_subscribe() {
        // wasm tests would go here
        // note: testing websockets in wasm requires a test server
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::{Filter, Kind};

    #[tokio::test]
    async fn test_subscribe() {
        let events = crate::server::testing::make_events(10);
        let (url, server) = crate::server::testing::spawn_relay_with_events("test", &events).await;
        let relay = Relay::connect(url.parse().unwrap(), None).await.unwrap();

        let filter = Filter {
            kinds: Some(vec![Kind(1)]),
            limit: Some(5),
            ..Default::default()
        };

        let mut sub = relay
            .subscribe(filter, SubscriptionOptions::default())
            .await;

        let mut pre_eose_count = 0;
        while let Some(occ) = sub.recv().await {
            match occ {
                Occurrence::Event(_) => {
                    pre_eose_count += 1;
                }
                Occurrence::Eose => {
                    break;
                }
                Occurrence::Close(_) => {
                    panic!("shouldn't close");
                }
            }
        }

        assert_eq!(pre_eose_count, 5);
        server.abort();
    }

    #[tokio::test]
    async fn test_dropping_a_clone_keeps_subscriptions() {
        let events = crate::server::testing::make_events(3);
        let (url, server) = crate::server::testing::spawn_relay_with_events("test", &events).await;
        let relay = Relay::connect(url.parse().unwrap(), None).await.unwrap();

        let mut sub = relay
            .subscribe(Filter::default(), SubscriptionOptions::default())
            .await;
        drop(relay.clone());

        let mut count = 0;
        while let Some(occ) = sub.recv().await {
            match occ {
                Occurrence::Event(_) => count += 1,
                Occurrence::Eose => break,
                Occurrence::Close(reason) => panic!("shouldn't close: {:?}", reason),
            }
        }
        assert_eq!(count, 3);
        server.abort();
    }

    /// a relay that sends an AUTH challenge on connect and only accepts events after a valid AUTH
    async fn spawn_auth_required_relay() -> (String, tokio::task::JoinHandle<()>) {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (conn, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(conn).await.unwrap();
            ws.send(Message::text(r#"["AUTH","chall"]"#)).await.unwrap();

            let mut authed = false;
            while let Some(Ok(msg)) = ws.next().await {
                let Message::Text(text) = msg else { continue };
                let reply = match serde_json::from_str::<Envelope>(&text) {
                    Ok(Envelope::AuthEvent { event }) => {
                        authed = event.verify_signature()
                            && event
                                .tags
                                .0
                                .contains(&vec!["challenge".to_string(), "chall".to_string()]);
                        serde_json::json!(["OK", event.id, authed, ""])
                    }
                    Ok(Envelope::OutEvent { event }) if authed => {
                        serde_json::json!(["OK", event.id, true, ""])
                    }
                    Ok(Envelope::OutEvent { event }) => {
                        serde_json::json!(["OK", event.id, false, "auth-required: who are you"])
                    }
                    _ => continue,
                };
                ws.send(Message::text(reply.to_string())).await.unwrap();
            }
        });

        (url, server)
    }

    #[tokio::test]
    async fn test_publish_auth_required() {
        let sk = crate::SecretKey::generate();
        let event = EventTemplate {
            created_at: Timestamp::now(),
            kind: Kind(1),
            content: "hello".to_string(),
            tags: Tags(vec![]),
        }
        .finalize(&sk);

        // without a finalizer we get the relay's rejection back
        let (url, server) = spawn_auth_required_relay().await;
        let relay = Relay::connect(url.parse().unwrap(), None).await.unwrap();
        let err = relay
            .publish(event.clone(), PublishOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, PublishError::NotOK(r) if r.starts_with("auth-required:")));
        server.abort();

        // with one we authenticate and publish again
        let (url, server) = spawn_auth_required_relay().await;
        let relay = Relay::connect(url.parse().unwrap(), None).await.unwrap();
        relay
            .publish(
                event,
                PublishOptions {
                    auth_automatically: Some(Finalizer::Plain(sk)),
                },
            )
            .await
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn test_connect_timeout() {
        // a listener that accepts tcp connections but never answers the websocket handshake
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let _server = tokio::spawn(async move {
            let mut conns = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                conns.push(conn);
            }
        });

        let start = std::time::Instant::now();
        let result = Relay::connect(url.parse().unwrap(), None).await;
        assert!(matches!(result, Err(ConnectError::Timeout)));
        assert!(start.elapsed() < CONNECT_TIMEOUT + Duration::from_secs(2));
    }
}
