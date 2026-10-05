#[derive(thiserror::Error, std::fmt::Debug)]
pub enum EnvelopeError {
    #[error("empty message")]
    EmptyMessage,

    #[error("invalid label")]
    InvalidLabel,

    #[error("invalid {0} envelope")]
    InvalidEnvelope(String),

    #[error("unknown envelope label: {0}")]
    UnknownLabel(String),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decoding error")]
    Hex(#[from] lowercase_hex::FromHexError),

    #[error("ID parsing error")]
    IdParsing(#[from] crate::types::IDError),

    #[error("invalid subscription ID")]
    InvalidSubscriptionId,

    #[error("REQ must have at least one filter")]
    ReqNoFilter,

    #[error("invalid count")]
    InvalidCount,

    #[error("invalid HLL length")]
    InvalidHllLength,

    #[error("invalid count value")]
    InvalidCountValue,

    #[error("invalid auth event kind")]
    InvalidAuthEventKind,

    #[error("invalid challenge")]
    InvalidChallenge,
}

/// nostr message envelopes ("commands")
#[derive(std::fmt::Debug, Clone, PartialEq, Eq)]
pub enum Envelope {
    /// EVENT envelope (incoming from relay)
    InEvent {
        subscription_id: String,
        event: crate::Event,
    },
    /// EVENT envelope (outgoing to relay)
    OutEvent { event: crate::Event },
    /// REQ envelope
    Req {
        subscription_id: String,
        filters: Vec<crate::Filter>,
    },
    /// COUNT envelope (ask)
    CountAsk {
        subscription_id: String,
        filter: crate::Filter,
    },
    /// COUNT envelope (reply)
    CountReply {
        subscription_id: String,
        count: u32,
        hyperloglog: Option<Vec<u8>>,
    },
    /// NOTICE envelope
    Notice(String),
    /// EOSE envelope
    Eose { subscription_id: String },
    /// CLOSE envelope
    Close { subscription_id: String },
    /// CLOSED envelope
    Closed {
        subscription_id: String,
        reason: String,
    },
    /// OK envelope
    Ok {
        event_id: crate::ID,
        ok: bool,
        reason: String,
    },
    /// AUTH envelope (challenge)
    AuthChallenge { challenge: String },
    /// AUTH envelope (event)
    AuthEvent { event: crate::Event },
}

impl serde::Serialize for Envelope {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        match self {
            Envelope::InEvent {
                subscription_id,
                event,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("EVENT")?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(event)?;
                seq.end()
            }
            Envelope::OutEvent { event } => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("EVENT")?;
                seq.serialize_element(event)?;
                seq.end()
            }
            Envelope::Req {
                subscription_id,
                filters,
            } => {
                let mut seq = serializer.serialize_seq(Some(2 + filters.len()))?;
                seq.serialize_element("REQ")?;
                seq.serialize_element(subscription_id)?;
                for filter in filters {
                    seq.serialize_element(filter)?;
                }
                seq.end()
            }
            Envelope::CountAsk {
                subscription_id,
                filter,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("COUNT")?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(filter)?;
                seq.end()
            }
            Envelope::CountReply {
                subscription_id,
                count,
                hyperloglog,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("COUNT")?;
                seq.serialize_element(subscription_id)?;

                let mut result = serde_json::Map::new();
                result.insert(
                    "count".to_string(),
                    serde_json::Value::Number((*count).into()),
                );

                if let Some(hll) = hyperloglog {
                    let hll_hex = lowercase_hex::encode(hll);
                    result.insert("hll".to_string(), serde_json::Value::String(hll_hex));
                }

                seq.serialize_element(&result)?;
                seq.end()
            }
            Envelope::Notice(message) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("NOTICE")?;
                seq.serialize_element(message)?;
                seq.end()
            }
            Envelope::Eose { subscription_id } => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("EOSE")?;
                seq.serialize_element(subscription_id)?;
                seq.end()
            }
            Envelope::Close { subscription_id } => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("CLOSE")?;
                seq.serialize_element(subscription_id)?;
                seq.end()
            }
            Envelope::Closed {
                subscription_id,
                reason,
            } => {
                let mut seq = serializer.serialize_seq(Some(3))?;
                seq.serialize_element("CLOSED")?;
                seq.serialize_element(subscription_id)?;
                seq.serialize_element(reason)?;
                seq.end()
            }
            Envelope::Ok {
                event_id,
                ok,
                reason,
            } => {
                let mut seq = serializer.serialize_seq(Some(4))?;
                seq.serialize_element("OK")?;
                seq.serialize_element(&event_id.to_hex())?;
                seq.serialize_element(ok)?;
                seq.serialize_element(reason)?;
                seq.end()
            }
            Envelope::AuthChallenge { challenge } => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("AUTH")?;
                seq.serialize_element(challenge)?;
                seq.end()
            }
            Envelope::AuthEvent { event } => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element("AUTH")?;
                seq.serialize_element(event)?;
                seq.end()
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Envelope {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct MsgVisitor;

        impl<'de> serde::de::Visitor<'de> for MsgVisitor {
            type Value = Envelope;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a Nostr client message array")
            }

            fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Envelope, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let msg_type: String = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;

                match msg_type.as_str() {
                    "EVENT" => {
                        // check if this is a 2-element or 3-element array
                        let second_element: serde_json::Value = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                        if let Ok(Some(third_element)) = seq.next_element::<serde_json::Value>() {
                            // 3-element array: ["EVENT", subscription_id, event]
                            let subscription_id = second_element
                                .as_str()
                                .ok_or_else(|| {
                                    serde::de::Error::custom(
                                        EnvelopeError::InvalidSubscriptionId.to_string(),
                                    )
                                })?
                                .to_string();
                            let event: crate::Event = serde_json::from_value(third_element)
                                .map_err(serde::de::Error::custom)?;
                            Ok(Envelope::InEvent {
                                subscription_id,
                                event,
                            })
                        } else {
                            // 2-element array: ["EVENT", event]
                            let event: crate::Event = serde_json::from_value(second_element)
                                .map_err(serde::de::Error::custom)?;
                            Ok(Envelope::OutEvent { event })
                        }
                    }
                    "REQ" => {
                        let subscription_id: String = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                        let mut filters = Vec::new();
                        while let Some(filter_value) = seq.next_element::<serde_json::Value>()? {
                            let filter: crate::Filter = serde_json::from_value(filter_value)
                                .map_err(serde::de::Error::custom)?;
                            filters.push(filter);
                        }

                        if filters.is_empty() {
                            return Err(serde::de::Error::custom(
                                EnvelopeError::ReqNoFilter.to_string(),
                            ));
                        }

                        Ok(Envelope::Req {
                            subscription_id,
                            filters,
                        })
                    }
                    "COUNT" => {
                        let subscription_id: String = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                        let third_element: serde_json::Value = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                        match serde_json::from_value::<serde_json::Map<String, serde_json::Value>>(
                            third_element.clone(),
                        ) {
                            Ok(count_result) if count_result.get("count").is_some() => {
                                // COUNT reply
                                let mut count = 0;
                                let mut hyperloglog = None;

                                if let Some(count_val) = count_result.get("count") {
                                    count = count_val.as_i64().ok_or_else(|| {
                                        serde::de::Error::custom(
                                            EnvelopeError::InvalidCountValue.to_string(),
                                        )
                                    })? as u32;
                                }
                                if let Some(hll) = count_result.get("hll")
                                    && let Some(hll_str) = hll.as_str()
                                {
                                    if hll_str.len() != 512 {
                                        return Err(serde::de::Error::custom(
                                            EnvelopeError::InvalidHllLength.to_string(),
                                        ));
                                    }
                                    hyperloglog = lowercase_hex::decode(hll_str).ok();
                                }

                                Ok(Envelope::CountReply {
                                    subscription_id,
                                    count,
                                    hyperloglog,
                                })
                            }
                            _ => {
                                if let Ok(filter) =
                                    serde_json::from_value::<crate::Filter>(third_element.clone())
                                {
                                    // COUNT ask
                                    Ok(Envelope::CountAsk {
                                        subscription_id,
                                        filter,
                                    })
                                } else {
                                    Err(serde::de::Error::custom(
                                        EnvelopeError::InvalidCount.to_string(),
                                    ))
                                }
                            }
                        }
                    }
                    "OK" => {
                        let event_id_str: String = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        let event_id =
                            crate::ID::from_hex(&event_id_str).map_err(serde::de::Error::custom)?;
                        let ok: bool = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                        let reason: String = seq
                            .next_element()?
                            .or_else(|| if ok { Some("".to_string()) } else { None })
                            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                        Ok(Envelope::Ok {
                            event_id,
                            ok,
                            reason,
                        })
                    }
                    "NOTICE" => {
                        let reason: String = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(Envelope::Notice(reason))
                    }
                    "EOSE" => {
                        let subscription_id: String = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(Envelope::Eose { subscription_id })
                    }
                    "CLOSE" => {
                        let subscription_id: String = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        Ok(Envelope::Close { subscription_id })
                    }
                    "CLOSED" => {
                        let subscription_id: String = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                        let reason: String = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                        Ok(Envelope::Closed {
                            subscription_id,
                            reason,
                        })
                    }
                    "AUTH" => {
                        let second_element: serde_json::Value = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;

                        if second_element.is_object() {
                            let event: crate::Event = serde_json::from_value(second_element)
                                .map_err(serde::de::Error::custom)?;
                            if event.kind == crate::Kind(22242) {
                                Ok(Envelope::AuthEvent { event })
                            } else {
                                Err(serde::de::Error::custom(
                                    EnvelopeError::InvalidAuthEventKind.to_string(),
                                ))
                            }
                        } else {
                            let challenge = second_element
                                .as_str()
                                .ok_or_else(|| {
                                    serde::de::Error::custom(
                                        EnvelopeError::InvalidChallenge.to_string(),
                                    )
                                })?
                                .to_string();
                            Ok(Envelope::AuthChallenge { challenge })
                        }
                    }
                    other => Err(serde::de::Error::unknown_variant(
                        other,
                        &[
                            "EVENT", "REQ", "COUNT", "OK", "NOTICE", "EOSE", "CLOSE", "CLOSED",
                            "AUTH",
                        ],
                    )),
                }
            }
        }

        deserializer.deserialize_seq(MsgVisitor)
    }
}

impl Envelope {
    /// get the label for this envelope type
    pub fn label(&self) -> &'static str {
        match self {
            Envelope::InEvent { .. } => "EVENT",
            Envelope::OutEvent { .. } => "EVENT",
            Envelope::Req { .. } => "REQ",
            Envelope::CountAsk { .. } => "COUNT",
            Envelope::CountReply { .. } => "COUNT",
            Envelope::Notice(_) => "NOTICE",
            Envelope::Eose { .. } => "EOSE",
            Envelope::Close { .. } => "CLOSE",
            Envelope::Closed { .. } => "CLOSED",
            Envelope::Ok { .. } => "OK",
            Envelope::AuthChallenge { .. } => "AUTH",
            Envelope::AuthEvent { .. } => "AUTH",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ID, Kind};

    #[test]
    fn test_decode_in_event() {
        let json = r#"["EVENT", "sub123", {"id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5","pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"kind":1,"tags":[],"content":"hello world","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c"}]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::InEvent {
                subscription_id,
                event,
            } => {
                assert_eq!(subscription_id, "sub123");
                assert_eq!(
                    event.id,
                    ID::from_hex(
                        "9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5"
                    )
                    .unwrap()
                );
                assert_eq!(event.content, "hello world");
                assert_eq!(event.kind, Kind(1));
            }
            _ => panic!("expected InEvent envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_out_event() {
        let json = r#"["EVENT", {"id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5","pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"kind":1,"tags":[],"content":"hello world","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c"}]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::OutEvent { event } => {
                assert_eq!(
                    event.id,
                    ID::from_hex(
                        "9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5"
                    )
                    .unwrap()
                );
                assert_eq!(event.content, "hello world");
                assert_eq!(event.kind, Kind(1));
            }
            _ => panic!("expected OutEvent envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_req() {
        let json = r#"["REQ", "sub456", {"kinds":[1,2],"limit":10}, {"authors":["37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba"]}]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::Req {
                subscription_id,
                filters,
            } => {
                assert_eq!(subscription_id, "sub456");
                assert_eq!(filters.len(), 2);
                assert_eq!(filters[0].kinds, Some(vec![Kind(1), Kind(2)]));
                assert_eq!(filters[0].limit, Some(10));
                assert_eq!(
                    filters[1].authors,
                    Some(vec![
                        "37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba"
                            .parse()
                            .unwrap()
                    ])
                );
            }
            _ => panic!("expected Req envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_count_ask() {
        let json = r#"["COUNT", "sub789", {"kinds":[1]}]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::CountAsk {
                subscription_id,
                filter,
            } => {
                assert_eq!(subscription_id, "sub789");
                assert_eq!(filter.kinds, Some(vec![Kind(1)]));
            }
            got => panic!("expected CountAsk envelope, got {:?}", got),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_count_reply() {
        let json = r#"["COUNT", "sub789", {"count":42}]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::CountReply {
                subscription_id,
                count,
                hyperloglog,
            } => {
                assert_eq!(subscription_id, "sub789");
                assert_eq!(count, 42);
                assert_eq!(hyperloglog, None);
            }
            _ => panic!("expected CountReply envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_count_reply_with_hll() {
        let hll_str = "0".repeat(512); // 512 character hex string
        let json = format!(r#"["COUNT", "sub789", {{"count":42,"hll":"{}"}}]"#, hll_str);

        let envelope: Envelope = serde_json::from_str(&json).unwrap();

        match envelope.clone() {
            Envelope::CountReply {
                subscription_id,
                count,
                hyperloglog,
            } => {
                assert_eq!(subscription_id, "sub789");
                assert_eq!(count, 42);
                assert!(hyperloglog.is_some());
                assert_eq!(hyperloglog.unwrap().len(), 256); // 512 hex chars = 256 bytes
            }
            _ => panic!("expected CountReply envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_notice() {
        let json = r#"["NOTICE", "this is a notice message"]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::Notice(message) => {
                assert_eq!(message, "this is a notice message");
            }
            _ => panic!("expected Notice envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_eose() {
        let json = r#"["EOSE", "sub123"]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::Eose { subscription_id } => {
                assert_eq!(subscription_id, "sub123");
            }
            _ => panic!("expected Eose envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_close() {
        let json = r#"["CLOSE", "sub123"]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::Close { subscription_id } => {
                assert_eq!(subscription_id, "sub123");
            }
            _ => panic!("expected Close envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_closed() {
        let json = r#"["CLOSED", "sub123", "auth-required: please authenticate"]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::Closed {
                subscription_id,
                reason,
            } => {
                assert_eq!(subscription_id, "sub123");
                assert_eq!(reason, "auth-required: please authenticate");
            }
            _ => panic!("expected Closed envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_ok() {
        let json = r#"["OK", "9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5", true, ""]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::Ok {
                event_id,
                ok,
                reason,
            } => {
                assert_eq!(
                    event_id,
                    ID::from_hex(
                        "9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5"
                    )
                    .unwrap()
                );
                assert!(ok);
                assert_eq!(reason, "");
            }
            _ => panic!("expected Ok envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_ok_false() {
        let json = r#"["OK", "9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5", false, "invalid: signature verification failed"]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::Ok {
                event_id,
                ok,
                reason,
            } => {
                assert_eq!(
                    event_id,
                    ID::from_hex(
                        "9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5"
                    )
                    .unwrap()
                );
                assert!(!ok);
                assert_eq!(reason, "invalid: signature verification failed");
            }
            _ => panic!("expected Ok envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_auth_challenge() {
        let json = r#"["AUTH", "challenge-string-here"]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::AuthChallenge { challenge } => {
                assert_eq!(challenge, "challenge-string-here");
            }
            _ => panic!("expected AuthChallenge envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_auth_event() {
        let json = r#"["AUTH", {"id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5","pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"kind":22242,"tags":[],"content":"","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c"}]"#;

        let envelope: Envelope = serde_json::from_str(json).unwrap();

        match envelope.clone() {
            Envelope::AuthEvent { event } => {
                assert_eq!(
                    event.id,
                    ID::from_hex(
                        "9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5"
                    )
                    .unwrap()
                );
                assert_eq!(event.kind, Kind(22242));
            }
            _ => panic!("expected AuthEvent envelope"),
        }

        // test serialization round-trip
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(envelope, deserialized);
    }

    #[test]
    fn test_decode_invalid_things() {
        {
            let json = r#"["UNKNOWN", "some", "data"]"#;
            let result: std::result::Result<Envelope, _> = serde_json::from_str(json);
            assert!(result.is_err());
        }

        {
            let json = r#"[]"#;
            let result: std::result::Result<Envelope, _> = serde_json::from_str(json);
            assert!(result.is_err());
        }

        {
            let json = r#"["REQ", "sub123"]"#;
            let result: std::result::Result<Envelope, _> = serde_json::from_str(json);
            assert!(result.is_err());
        }
    }
}
