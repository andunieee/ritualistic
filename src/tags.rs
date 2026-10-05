/// a single tag (array of strings)
pub type Tag = Vec<String>;

/// collection of tags
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub struct Tags(pub Vec<Tag>);

impl Tags {
    /// get the first "d" tag value or empty string
    pub fn get_d(&self) -> String {
        for tag in &self.0 {
            if tag.len() >= 2 && tag[0] == "d" {
                return tag[1].clone();
            }
        }
        String::new()
    }

    /// find the first tag with the given key that has at least one value
    pub fn find(&self, key: &str) -> Option<&Tag> {
        self.0
            .iter()
            .find(|&tag| tag.len() >= 2 && tag[0] == key)
            .map(|v| v as _)
    }

    /// find all tags with the given key that have at least one value
    pub fn find_all<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a Tag> {
        self.0
            .iter()
            .filter(move |tag| tag.len() >= 2 && tag[0] == key)
    }

    /// find tag with specific key and value
    pub fn find_with_value(&self, key: &str, value: &str) -> Option<&Tag> {
        self.0
            .iter()
            .find(|&tag| tag.len() >= 2 && tag[0] == key && tag[1] == value)
            .map(|v| v as _)
    }

    /// find the last tag with the given key
    pub fn find_last(&self, key: &str) -> Option<&Tag> {
        self.0
            .iter()
            .rev()
            .find(|&tag| tag.len() >= 2 && tag[0] == key)
            .map(|v| v as _)
    }

    /// find the last tag with specific key and value
    pub fn find_last_with_value(&self, key: &str, value: &str) -> Option<&Tag> {
        self.0
            .iter()
            .rev()
            .find(|&tag| tag.len() >= 2 && tag[0] == key && tag[1] == value)
            .map(|v| v as _)
    }

    /// check if tags contain any of the given values for a tag name
    pub fn contains_any(&self, tag_name: &str, values: &[String]) -> bool {
        for tag in &self.0 {
            if tag.len() < 2 || tag[0] != tag_name {
                continue;
            }
            if values.contains(&tag[1]) {
                return true;
            }
        }
        false
    }

    pub fn iter(&self) -> std::slice::Iter<'_, Tag> {
        self.0.iter()
    }
}

impl IntoIterator for Tags {
    type Item = Tag;
    type IntoIter = std::vec::IntoIter<Tag>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl std::fmt::Display for Tags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match serde_json::to_string(self) {
            Ok(json) => write!(f, "{json}"),
            Err(err) => write!(f, "Tags({err})"),
        }
    }
}

impl From<Vec<Tag>> for Tags {
    fn from(tags: Vec<Tag>) -> Self {
        Self(tags)
    }
}

impl From<Tags> for Vec<Tag> {
    fn from(tags: Tags) -> Self {
        tags.0
    }
}
