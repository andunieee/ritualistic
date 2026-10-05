use tokio_with_wasm::alias as tokio;

#[derive(thiserror::Error, Debug)]
pub enum EnsureError {
    #[error("URL normalization error")]
    Normalize(#[from] url::ParseError),

    #[error("failed to connect: {0}")]
    Connect(#[from] crate::relay::ConnectError),
}

type RelaySlot = std::sync::Arc<tokio::sync::OnceCell<crate::Relay>>;

#[derive(Debug)]
pub struct Network {
    // each relay gets a slot that is filled once the connection succeeds, so different relays can be
    // connected to concurrently while concurrent callers for the same relay wait for the same connection
    relays: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, RelaySlot>>>,
}

pub struct PublishResult {
    pub error: Option<String>,
    pub relay_url: String,
}

#[derive(Debug)]
pub enum Occurrence {
    Event(Box<crate::Event>, url::Url),
    EOSE,
    Close,
}

impl Default for Network {
    fn default() -> Self {
        Self::new()
    }
}

impl Network {
    pub fn new() -> Self {
        Self {
            relays: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// get an existing relay connection if it exists, do not try to open a new one
    pub async fn get_relay(&self, url: &str) -> Option<crate::Relay> {
        let normalized_url = crate::normalize_url(url).ok()?;
        self.relays
            .lock()
            .await
            .get(normalized_url.as_str())
            .and_then(|slot| slot.get().cloned())
    }

    /// get or create a relay connection to the given url
    pub async fn ensure_relay<S>(&self, url: S) -> Result<crate::Relay, EnsureError>
    where
        S: AsRef<str>,
    {
        let normalized_url = crate::normalize_url(url.as_ref())?;

        // get the slot for this relay, only holding the lock for a moment
        let slot = self
            .relays
            .lock()
            .await
            .entry(normalized_url.to_string())
            .or_default()
            .clone();

        let result = slot
            .get_or_try_init(|| async {
                let (on_close, handle_close) = tokio::sync::oneshot::channel::<String>();
                let relay = crate::Relay::connect(normalized_url.clone(), Some(on_close)).await?;

                let nm_ = normalized_url.clone();
                let slot_ = slot.clone();
                let relay_map_on_close = self.relays.clone();
                tokio::spawn(async move {
                    match handle_close.await {
                        Ok(reason) => {
                            log::info!("[{}] relay connection closed: {}", nm_.as_str(), reason);
                        }
                        Err(err) => {
                            log::info!(
                                "got an error from the handle_close oneshot for {}: {}",
                                nm_.as_str(),
                                err
                            );
                        }
                    }

                    // the relay connection will be dropped from the map when it disconnects
                    remove_slot(&relay_map_on_close, nm_.as_str(), &slot_).await;
                });

                Ok::<_, crate::relay::ConnectError>(relay)
            })
            .await
            .cloned();

        match result {
            Ok(relay) => Ok(relay),
            Err(err) => {
                // don't keep empty slots around for relays we failed to connect to
                if !slot.initialized() {
                    remove_slot(&self.relays, normalized_url.as_str(), &slot).await;
                }
                Err(EnsureError::Connect(err))
            }
        }
    }

    /// publish an event to multiple relays
    pub async fn publish_many<S, T>(
        &mut self,
        urls: T,
        event: crate::Event,
    ) -> tokio::sync::mpsc::UnboundedReceiver<PublishResult>
    where
        S: AsRef<str>,
        T: AsRef<[S]>,
    {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        for url in urls.as_ref() {
            let tx = tx.clone();
            let event = event.clone();
            let pool = self.clone();

            if let Ok(url) = crate::normalize_url(url.as_ref()) {
                tokio::spawn(async move {
                    let result = match pool.ensure_relay(&url).await {
                        Ok(relay) => match relay.publish(event).await {
                            Ok(_) => PublishResult {
                                error: None,
                                relay_url: url.to_string(),
                            },
                            Err(err) => PublishResult {
                                error: Some(err.to_string()),
                                relay_url: url.to_string(),
                            },
                        },
                        Err(err) => PublishResult {
                            error: Some(err.to_string()),
                            relay_url: url.to_string(),
                        },
                    };

                    let _ = tx.send(result);
                });
            }
        }

        rx
    }

    /// subscribe to events from multiple relays, stop on EOSE, return a sorted list
    pub async fn query<S, T>(
        &self,
        urls: T,
        filter: crate::Filter,
        subscription_options: crate::SubscriptionOptions,
    ) -> Vec<crate::Event>
    where
        S: AsRef<str>,
        T: AsRef<[S]>,
    {
        let mut events = Vec::with_capacity(
            filter
                .limit
                .unwrap_or(500)
                .min(1000)
                .saturating_mul(urls.as_ref().len())
                / 2,
        );

        let mut occurrences = self.subscribe(urls, filter, subscription_options).await;
        while let Some(occ) = occurrences.recv().await {
            match occ {
                Occurrence::Event(event, _) => {
                    events.push(*event);
                }
                _ => {
                    break;
                }
            }
        }

        glidesort::sort_by_key(&mut events, |event| u32::MAX - event.created_at.0);
        events
    }

    /// subscribe to events from multiple relays, returns a channel that will receive occurrences
    pub async fn subscribe<S, T>(
        &self,
        urls: T,
        filter: crate::Filter,
        subscription_options: crate::SubscriptionOptions,
    ) -> tokio::sync::mpsc::Receiver<Occurrence>
    where
        S: AsRef<str>,
        T: AsRef<[S]>,
    {
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let skip_ids = std::sync::Arc::new(dashmap::DashSet::new());
        let eose_counter =
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(urls.as_ref().len()));
        let closed_counter =
            std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(urls.as_ref().len()));
        let eosed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        for url in urls.as_ref() {
            let filter = filter.clone();
            let pool = self.clone();
            let opts = crate::SubscriptionOptions {
                skip_ids: Some(skip_ids.clone()),
                ..subscription_options.clone()
            };
            let tx = tx.clone();
            let eose_counter = eose_counter.clone();
            let closed_counter = closed_counter.clone();
            let eosed = eosed.clone();

            let url_owned = url.as_ref().to_owned();
            tokio::spawn(async move {
                // each relay must only count once towards the eose_counter
                let mut counted_eose = false;

                if let Ok(relay) = pool.ensure_relay(&url_owned).await {
                    let mut sub = relay.subscribe(filter, opts).await;
                    while let Some(occ) = sub.recv().await {
                        match occ {
                            crate::relay::Occurrence::Event(event) => {
                                if tx
                                    .send(Occurrence::Event(Box::new(event), relay.url.clone()))
                                    .await
                                    .is_err()
                                {
                                    // receiver dropped
                                    return;
                                }
                            }
                            crate::relay::Occurrence::Eose => {
                                counted_eose = true;
                                if eose_counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
                                    == 1
                                    && !eosed.swap(true, std::sync::atomic::Ordering::SeqCst)
                                    && tx.send(Occurrence::EOSE).await.is_err()
                                {
                                    // receiver dropped
                                    return;
                                }
                            }
                            crate::relay::Occurrence::Close(_) => break,
                        }
                    }
                }

                // if we are here, it means ensure_relay or subscribe failed or the subscription ended.
                if !counted_eose
                    && eose_counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1
                    && !eosed.swap(true, std::sync::atomic::Ordering::SeqCst)
                    && tx.send(Occurrence::EOSE).await.is_err()
                {
                    // receiver dropped
                    return;
                }

                if closed_counter.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) == 1
                    && tx.send(Occurrence::Close).await.is_err()
                {
                    // receiver dropped
                }
            });
        }

        drop(tx);
        rx
    }
}

/// remove a slot from the map, but only if it wasn't replaced by a newer one in the meantime
async fn remove_slot(
    relays: &tokio::sync::Mutex<std::collections::HashMap<String, RelaySlot>>,
    url: &str,
    slot: &RelaySlot,
) {
    let mut relay_map = relays.lock().await;
    if relay_map
        .get(url)
        .is_some_and(|current| std::sync::Arc::ptr_eq(current, slot))
    {
        relay_map.remove(url);
    }
}

// we can clone the pool because its fields are just arcs
impl Clone for Network {
    fn clone(&self) -> Self {
        Self {
            relays: self.relays.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::testing::{make_events, spawn_relay_with_events};
    use crate::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_pool_subscribe_multiple() {
        let pool = Network::new();
        let events = make_events(20);

        // each relay has an overlapping window of events
        let mut urls = Vec::new();
        let mut servers = Vec::new();
        for i in 0..5 {
            let (url, server) =
                spawn_relay_with_events("test", &events[i * 3..i * 3 + 6]).await;
            urls.push(url);
            servers.push(server);
        }

        let filter = Filter {
            kinds: Some(vec![Kind(1), Kind(1111)]),
            limit: Some(5),
            ..Default::default()
        };

        let results = pool
            .query(
                &urls,
                filter,
                SubscriptionOptions {
                    label: Some("test".to_string()),
                    ..Default::default()
                },
            )
            .await;

        // each relay returns its 5 newest, which overlap with the next relay's
        let expected: HashSet<ID> = (0..5)
            .flat_map(|i| events[i * 3 + 1..i * 3 + 6].iter().map(|e| e.id))
            .collect();
        let got: HashSet<ID> = results.iter().map(|e| e.id).collect();
        assert_eq!(results.len(), got.len(), "there should be no duplicates");
        assert_eq!(got, expected);

        // and they are sorted from newest to oldest
        assert!(results.windows(2).all(|w| w[0].created_at >= w[1].created_at));

        for server in servers {
            server.abort();
        }
    }

    #[tokio::test]
    async fn test_pool_ensure() {
        let pool = Network::new();
        let (url, server) = spawn_relay_with_events("test", &[]).await;

        let relay1 = pool.ensure_relay(&url).await.unwrap();
        let relay2 = pool.ensure_relay(&url).await.unwrap();

        // should return the same relay instance
        assert!(std::ptr::eq(
            relay1.sub_sender_map.as_ref() as *const _,
            relay2.sub_sender_map.as_ref() as *const _
        ));
        assert!(pool.get_relay(&url).await.is_some());

        server.abort();
    }

    #[tokio::test]
    async fn test_hanging_relay_does_not_block_others() {
        let pool = Network::new();
        let (good_url, server) = spawn_relay_with_events("test", &[]).await;

        // a listener that never completes the websocket handshake
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let hanging_url = format!("ws://{}", listener.local_addr().unwrap());
        let _hanging = tokio::spawn(async move {
            let mut conns = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                conns.push(conn);
            }
        });

        let pool_ = pool.clone();
        let hanging = tokio::spawn(async move { pool_.ensure_relay(&hanging_url).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            pool.ensure_relay(&good_url),
        )
        .await
        .expect("connecting to a good relay shouldn't wait for the hanging one")
        .unwrap();

        hanging.abort();
        server.abort();
    }
}
