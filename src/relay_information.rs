#[derive(thiserror::Error, Debug)]
pub enum RelayInformationError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL normalization error")]
    Normalize(#[from] url::ParseError),
}

pub type Result<T> = std::result::Result<T, RelayInformationError>;

/// relay information document
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct RelayInformationDocument {
    #[serde(skip)]
    pub url: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub pubkey: Option<crate::PubKey>,
    #[serde(default)]
    pub icon: String,
}

/// fetch the metadata for a relay
pub async fn fetch(url: &str) -> Result<RelayInformationDocument> {
    let normalized_url = crate::normalize_url(url)?;

    let mut info = RelayInformationDocument {
        url: normalized_url.to_string(),
        name: normalized_url
            .host_str()
            .map(|s| s.to_string())
            .unwrap_or("".to_string()),
        description: String::new(),
        pubkey: None,
        icon: String::new(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(7))
        .build()?;

    let response = client
        .get(format!("http{}", &normalized_url.as_str()[2..]))
        .header("Accept", "application/nostr+json")
        .send()
        .await?;

    if response.status().is_success() {
        let received_info: RelayInformationDocument = response.json().await?;
        info.name = received_info.name;
        info.description = received_info.description;
        info.icon = received_info.icon;
        if received_info.pubkey.is_some() {
            info.pubkey = received_info.pubkey;
        }
    }

    if info.icon.is_empty() {
        let mut icon = normalized_url.clone();
        icon.set_path("/favicon.ico");
        info.icon = format!("http{}", &icon.as_str()[2..]);
    }

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch() {
        let (url, server) =
            crate::server::testing::spawn_relay_with_events("local relay", &[]).await;

        // ws:// gets turned into http://
        let info = fetch(&url).await.unwrap();
        assert_eq!(info.url, format!("{}/", url));
        assert_eq!(info.name, "local relay");

        // and so does a missing scheme
        let info = fetch(url.trim_start_matches("ws://")).await.unwrap();
        assert_eq!(info.name, "local relay");

        server.abort();

        // nothing listening there anymore
        assert!(fetch(&url).await.is_err());
    }
}
