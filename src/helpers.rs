use slotmap::Key;

/// escape a string for JSON encoding
pub fn escape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');

    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\u{08}' => result.push_str("\\b"),
            '\u{09}' => result.push_str("\\t"),
            '\u{0A}' => result.push_str("\\n"),
            '\u{0C}' => result.push_str("\\f"),
            '\u{0D}' => result.push_str("\\r"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }

    result.push('"');
    result
}

// extract subscription ID from JSON string
slotmap::new_key_type! { pub struct SubscriptionKey; }

pub fn sub_id_from_key(key: &SubscriptionKey, label: &Option<String>) -> String {
    let key_data = key.data().as_ffi();

    if let Some(label) = label {
        let mut idd = vec![0u8; 8 * 2 + 1 + label.len()];
        lowercase_hex::encode_to_slice(key_data.to_le_bytes(), &mut idd[0..8 * 2]).unwrap();
        idd[8 * 2] = 58; // ':'
        idd[8 * 2 + 1..].copy_from_slice(label.as_bytes());
        unsafe { std::str::from_utf8_unchecked(&idd).to_string() }
    } else {
        let mut idd = vec![0u8; 8 * 2];
        lowercase_hex::encode_to_slice(key_data.to_le_bytes(), &mut idd).unwrap();
        unsafe { std::str::from_utf8_unchecked(&idd).to_string() }
    }
}

pub fn extract_key_from_sub_id(json_str: &str) -> Option<SubscriptionKey> {
    // look for "EVENT" pattern
    let start = json_str.find("\"EVENT\"")?;
    let remaining = &json_str[start + 7..];

    // find the next quote
    let quote_start = remaining.find('"')?;
    let remaining = &remaining[quote_start + 1..];

    // the subscription id should start with the 8 hex bytes we put there, but the relay can send anything
    key_from_sub_id(remaining)
}

pub fn key_from_sub_id(sub_id: &str) -> Option<SubscriptionKey> {
    let buf = sub_id.get(..8 * 2)?;

    // do the slotmap thing
    let key_data = u64::from_le_bytes(lowercase_hex::decode_to_array::<_, 8>(buf).ok()?);
    let key = slotmap::KeyData::from_ffi(key_data);

    Some(SubscriptionKey(key))
}

/// extract event ID from JSON string
pub fn extract_event_id(json_str: &str) -> Option<crate::ID> {
    let start = json_str.find("\"id\"")?;
    let remaining = &json_str[start + 4..];

    let quote_start = remaining.find('"')?;
    let id_str = remaining.get(quote_start + 1..quote_start + 1 + 64)?;

    crate::ID::from_hex(id_str).ok()
}

/// extract event public key from JSON string
pub fn extract_event_pubkey(json_str: &str) -> Option<crate::PubKey> {
    let start = json_str.find("\"pubkey\"")?;
    let remaining = &json_str[start + 8..];

    let quote_start = remaining.find('"')?;
    let pk_str = remaining.get(quote_start + 1..quote_start + 1 + 64)?;

    pk_str.parse().ok()
}

/// extract d tag from JSON string
pub fn extract_d_tag(json_str: &str) -> Option<String> {
    let start = json_str.find("[\"d\"")?;
    let remaining = &json_str[start + 4..];

    let quote_start = remaining.find('"')?;
    let remaining = &remaining[quote_start + 1..];

    let quote_end = remaining.find('"')?;

    Some(remaining[..quote_end].to_string())
}

/// extract timestamp from JSON string
pub fn extract_timestamp(json_str: &str) -> Option<crate::Timestamp> {
    let start = json_str.find("\"created_at\"")?;
    let remaining = &json_str[start + 12..];

    // find the next number
    let mut num_start = None;
    for (i, c) in remaining.char_indices() {
        if c.is_ascii_digit() {
            num_start = Some(i);
            break;
        }
    }

    let num_start = num_start?;
    let remaining = &remaining[num_start..];

    // find the end of the number
    let mut num_end = remaining.len();
    for (i, c) in remaining.char_indices() {
        if matches!(c, ',' | '}' | ' ') {
            num_end = i;
            break;
        }
    }

    let num_str = &remaining[..num_end];
    num_str.parse::<u32>().ok().map(crate::Timestamp)
}

/// check if a URL is a valid relay URL (ws:// or wss://)
pub fn is_valid_relay_url(url_str: &str) -> bool {
    match url::Url::parse(url_str) {
        Ok(url) => matches!(url.scheme(), "ws" | "wss"),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sub_id_and_key() {
        let key_data_u64 = // do this roundabount thing here in the test thing to ensure consistency
            // (if we just pass '38' it will be changed in the way in because whatever,
            // the "from_ffi" function only cares about keys it has produced itself)
            SubscriptionKey(slotmap::KeyData::from_ffi(38u64)).data().as_ffi();
        let as_hex = lowercase_hex::encode(key_data_u64.to_le_bytes());
        let expected_hex = "2600000001000000";
        assert_eq!(expected_hex, as_hex);

        let subkey = SubscriptionKey(slotmap::KeyData::from_ffi(key_data_u64));
        let label = "x34654o9x09jcoznajnawkbr-034ukjs";
        let expected_id = format!("{}:{}", expected_hex, label);
        assert_eq!(
            sub_id_from_key(&subkey, &Some(label.to_string())),
            expected_id,
        );

        assert_eq!(
            extract_key_from_sub_id(&format!(
                r#"["EVENT", "{}", {{"kind":1,"id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5","pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"tags":[],"content":"hello world","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c"}}]"#,
                expected_id
            )),
            Some(subkey),
        );

        assert_eq!(
            extract_key_from_sub_id(
                r#"["CLOSED", "xo9x09jcoznajnawkbr-034ukjs", "auth-required: blabla"]"#
            ),
            None,
        );

        // relays can send garbage, we must not panic on it
        assert_eq!(key_from_sub_id("x"), None);
        assert_eq!(key_from_sub_id("zzzzzzzzzzzzzzzzzz"), None);
        assert_eq!(extract_key_from_sub_id(r#"["EVENT","é",{}]"#), None);
    }

    #[test]
    fn test_extract_event_id() {
        let id =
            crate::ID::from_hex("9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5")
                .ok();

        assert_eq!(
            extract_event_id(
                r#"{"kind":1,"id":"9429b2e11640bfd86971f0d9f7435199b57e121a363213df11d5b426807e49f5","pubkey":"37a4aef1f8423ca076e4b7d99a8cabff40ddb8231f2a9f01081f15d7fa65c1ba","created_at":1750711742,"tags":[],"content":"hello world","sig":"a1ecbf1636f5e752f1b918a86b065a8031b1387f0785f0ca19b84cc155d7937fece1f3ae53b79d347fbce5555a0f2da8db96334cab154f8d92300f8c1936710c"}"#
            ),
            id,
        );

        assert_eq!(
            id,
            Some(crate::ID([
                0x94, 0x29, 0xb2, 0xe1, 0x16, 0x40, 0xbf, 0xd8, 0x69, 0x71, 0xf0, 0xd9, 0xf7, 0x43,
                0x51, 0x99, 0xb5, 0x7e, 0x12, 0x1a, 0x36, 0x32, 0x13, 0xdf, 0x11, 0xd5, 0xb4, 0x26,
                0x80, 0x7e, 0x49, 0xf5,
            ]))
        );

        assert_eq!(extract_event_id(r#"{"id":"abc"}"#), None);
        assert_eq!(extract_event_id(r#"{"id":"ééééééééééééééééééééééééééééééééé"}"#), None);
        assert_eq!(extract_event_pubkey(r#"{"pubkey":"abc"}"#), None);
    }
}
