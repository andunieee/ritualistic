use slotmap::Key;
use tokio_with_wasm::alias as tokio;

#[derive(Debug, serde::Serialize)]
struct Request<'a> {
    id: String,
    method: &'a str,
    params: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct Response {
    pub id: String,
    pub result: Option<String>,
    pub error: Option<String>,
}

pub struct AuthURLHandler(Box<dyn Fn(&str) + Send + Sync>);

impl std::fmt::Debug for AuthURLHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fn")
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RPCError {
    #[error("we're not connected to any relay")]
    NoRelays(Vec<String>),

    #[error("response channel closed")]
    NoResponse,

    #[error("request timed out")]
    Timeout,

    #[error("request encryption failed: {0}")]
    Encryption(#[from] crate::message_encryption::EncryptError),

    #[error("response decryption failed: {0}")]
    Decryption(#[from] crate::message_encryption::DecryptError),

    #[error("bunker replied with an error: {0}")]
    Response(String),
}

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error("rpc call failed: {0}")]
    RPC(#[from] RPCError),

    #[error("bunker uri is invalid")]
    URI(#[from] url::ParseError),

    #[error("bunker uri contains an invalid public key")]
    InvalidPublicKeyHost(#[from] crate::keys::PubKeyError),
}

#[derive(thiserror::Error, Debug)]
pub enum GetPublicKeyError {
    #[error("rpc call failed: {0}")]
    RPC(#[from] RPCError),

    #[error("got an invalid public key")]
    InvalidPublicKey(#[from] crate::keys::PubKeyError),
}

#[derive(thiserror::Error, Debug)]
pub enum FinalizeError {
    #[error("bunker gave us an invalid event")]
    InvalidEvent,

    #[error("bunker gave us an event with an invalid signature")]
    InvalidSignature,

    #[error("rpc call failed: {0}")]
    RPC(#[from] RPCError),
}

slotmap::new_key_type! { struct RequestKey ; }

#[derive(Clone, Debug)]
pub struct BunkerClient {
    client_secret_key: crate::SecretKey,
    pool: crate::Network,
    target: crate::PubKey,
    relays: Vec<String>,
    conversation_key: [u8; 32],
    awaiting_responses: std::sync::Arc<
        tokio::sync::Mutex<slotmap::SlotMap<RequestKey, tokio::sync::oneshot::Sender<Response>>>,
    >,
    on_auth_url: std::sync::Arc<Option<AuthURLHandler>>,

    // number of relays for which we've either started listening for responses or given up on
    subscriptions_ready: tokio::sync::watch::Receiver<usize>,

    // memoized
    get_pubkey_response: std::sync::Arc<tokio::sync::Mutex<Option<crate::PubKey>>>,
}

impl BunkerClient {
    pub fn new(
        client_secret_key: crate::SecretKey,
        target_pubkey: crate::PubKey,
        relays: Vec<String>,
        pool: crate::Network,
        on_auth_url: Option<AuthURLHandler>,
    ) -> Self {
        let client_pubkey = client_secret_key.pubkey();
        let conversation_key = crate::message_encryption::generate_conversation_key(
            &target_pubkey,
            &client_secret_key,
        );

        let (ready_sender, subscriptions_ready) = tokio::sync::watch::channel(0usize);
        let ready_sender = std::sync::Arc::new(ready_sender);

        let bunker = Self {
            client_secret_key,
            pool,
            target: target_pubkey,
            relays,
            conversation_key,
            awaiting_responses: std::sync::Arc::new(tokio::sync::Mutex::new(
                slotmap::SlotMap::with_capacity_and_key(10),
            )),
            on_auth_url: std::sync::Arc::new(on_auth_url),
            subscriptions_ready,
            get_pubkey_response: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        };

        let pool = bunker.pool.clone();
        let relays = bunker.relays.clone();
        let on_auth_url = bunker.on_auth_url.clone();
        let awaiting_responses = bunker.awaiting_responses.clone();
        tokio::spawn(async move {
            let filter = crate::Filter {
                kinds: Some(vec![crate::Kind(24133)]),
                tags: Some(vec![crate::filter::TagQuery(
                    "p".to_string(),
                    vec![client_pubkey.to_hex()],
                )]),
                since: Some(crate::Timestamp::now()),
                ..Default::default()
            };

            for url in relays.iter() {
                let url = url.clone();
                let filter = filter.clone();

                let pool = pool.clone();
                let on_auth_url = on_auth_url.clone();
                let awaiting_responses = awaiting_responses.clone();
                let ready_sender = ready_sender.clone();
                tokio::spawn(async move {
                    let relay = pool.ensure_relay(&url).await;
                    let sub = match &relay {
                        // the REQ is already in the relay's write queue once this returns
                        Ok(relay) => Some(relay.subscribe(filter, Default::default()).await),
                        Err(_) => None,
                    };
                    ready_sender.send_modify(|n| *n += 1);

                    if let Some(mut sub) = sub {
                        while let Some(occ) = sub.recv().await {
                            if let crate::relay::Occurrence::Event(event) = occ {
                                if event.kind.0 != 24133 {
                                    continue;
                                }

                                if let Ok(plain) = crate::message_encryption::decrypt(
                                    &event.content,
                                    &conversation_key,
                                ) && let Ok(resp) = serde_json::from_str::<Response>(&plain)
                                {
                                    let rk =
                                        match lowercase_hex::decode_to_array::<&str, 8>(&resp.id) {
                                            Ok(bytes) => RequestKey(slotmap::KeyData::from_ffi(
                                                u64::from_le_bytes(bytes),
                                            )),
                                            Err(_) => continue,
                                        };

                                    if resp.result.as_deref() == Some("auth_url")
                                        && let Some(auth_url) = &resp.error
                                    {
                                        if let Some(on_auth_fn) = on_auth_url.as_ref() {
                                            on_auth_fn.0(auth_url);
                                        }

                                        // the actual response will come later with this same id
                                        continue;
                                    }

                                    if let Some(dispatcher) =
                                        awaiting_responses.lock().await.remove(rk)
                                    {
                                        let _ = dispatcher.send(resp);
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });

        bunker
    }

    pub async fn connect(
        client_secret_key: crate::SecretKey,
        bunker_url: &str,
        pool: crate::Network,
        on_auth_url: Option<AuthURLHandler>,
    ) -> Result<Self, ConnectError> {
        let url = url::Url::parse(bunker_url)?;
        let host = url
            .host_str()
            .ok_or(ConnectError::URI(url::ParseError::EmptyHost))?;
        let pk: crate::PubKey = host.parse()?;
        let relays = url
            .query_pairs()
            .filter(|(k, _)| k == "relay")
            .map(|(_, v)| v.to_string())
            .collect();
        let secret = url
            .query_pairs()
            .find(|(k, _)| k == "secret")
            .map(|(_, v)| v.to_string());

        let mut params = vec![pk.to_hex()];
        if let Some(secret) = secret {
            params.push(secret);
        }

        let bunker = Self::new(client_secret_key, pk, relays, pool, on_auth_url);

        bunker.rpc("connect", params).await?;
        Ok(bunker)
    }

    pub async fn ping(&self) -> Result<(), RPCError> {
        self.rpc("ping", vec![]).await?;
        Ok(())
    }

    pub async fn get_public_key(&self) -> Result<crate::PubKey, GetPublicKeyError> {
        let mut guard = self.get_pubkey_response.lock().await;

        if let Some(pk) = guard.as_ref() {
            return Ok(pk.to_owned());
        }

        let resp = self.rpc("get_public_key", vec![]).await?;
        let pk: crate::PubKey = resp.parse()?;

        *guard = Some(pk);
        Ok(pk)
    }

    pub async fn finalize_event(
        &self,
        event_template: crate::EventTemplate,
    ) -> Result<crate::Event, FinalizeError> {
        let event_json = serde_json::json!(event_template).to_string();
        let resp = self.rpc("sign_event", vec![event_json]).await?;
        let event: crate::Event =
            serde_json::from_str(&resp).map_err(|_| FinalizeError::InvalidEvent)?;

        if !event.verify_signature() {
            return Err(FinalizeError::InvalidSignature);
        }

        Ok(event)
    }

    pub async fn nip44_encrypt(
        &self,
        target_pubkey: &crate::PubKey,
        plaintext: &str,
    ) -> Result<String, RPCError> {
        self.rpc(
            "nip44_encrypt",
            vec![target_pubkey.to_hex(), plaintext.to_string()],
        )
        .await
    }

    pub async fn nip44_decrypt(
        &self,
        target_pubkey: &crate::PubKey,
        ciphertext: &str,
    ) -> Result<String, RPCError> {
        self.rpc(
            "nip44_decrypt",
            vec![target_pubkey.to_hex(), ciphertext.to_string()],
        )
        .await
    }

    pub async fn nip04_encrypt(
        &self,
        target_pubkey: &crate::PubKey,
        plaintext: &str,
    ) -> Result<String, RPCError> {
        self.rpc(
            "nip04_encrypt",
            vec![target_pubkey.to_hex(), plaintext.to_string()],
        )
        .await
    }

    pub async fn nip04_decrypt(
        &self,
        target_pubkey: &crate::PubKey,
        ciphertext: &str,
    ) -> Result<String, RPCError> {
        self.rpc(
            "nip04_decrypt",
            vec![target_pubkey.to_hex(), ciphertext.to_string()],
        )
        .await
    }

    async fn rpc(&self, method: &str, params: Vec<String>) -> Result<String, RPCError> {
        // make sure we're listening for the response before sending the request, otherwise we might
        // miss it (kind 24133 is ephemeral, relays won't store it)
        let _ = self
            .subscriptions_ready
            .clone()
            .wait_for(|n| *n >= self.relays.len())
            .await;

        // prepare response listener
        let (tx, rx) = tokio::sync::oneshot::channel::<Response>();
        let rk = self.awaiting_responses.lock().await.insert(tx);

        let req = Request {
            id: lowercase_hex::encode(rk.data().as_ffi().to_le_bytes()),
            method,
            params,
        };
        let req_json =
            serde_json::to_string(&req).expect("request should not fail to encode as json");
        let content = crate::message_encryption::encrypt(&req_json, &self.conversation_key, None)?;

        let event = crate::EventTemplate {
            content,
            created_at: crate::Timestamp::now(),
            kind: crate::Kind(24133),
            tags: crate::Tags(vec![vec!["p".to_string(), self.target.to_hex()]]),
        }
        .finalize(&self.client_secret_key);

        // publish
        let mut sent = false;
        for url in self.relays.iter() {
            if let Ok(relay) = self.pool.ensure_relay(url).await
                && relay.publish(event.clone()).await.is_ok()
            {
                sent = true;
            }
        }

        if !sent {
            return Err(RPCError::NoRelays(self.relays.clone()));
        }

        // wait for response
        match tokio::time::timeout(std::time::Duration::from_secs(15), rx).await {
            Ok(Ok(resp)) => {
                if let Some(err) = resp.error {
                    Err(RPCError::Response(err))
                } else {
                    Ok(resp.result.unwrap_or_default())
                }
            }
            Ok(Err(_)) => {
                self.awaiting_responses.lock().await.remove(rk);
                Err(RPCError::NoResponse)
            }
            Err(_) => {
                self.awaiting_responses.lock().await.remove(rk);
                Err(RPCError::Timeout)
            }
        }
    }
}
