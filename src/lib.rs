//! # ritualistic
//!
//! nostr types and utilities
//!
//! this library provides types and utilities for working with the Nostr protocol,
//! including events, filters, relays, and connections.

pub mod bunker_client;
pub mod codes;
pub mod envelopes;
pub mod event;
pub mod event_template;
pub mod filter;
pub mod helpers;
pub mod keys;
pub mod message_encryption;
pub mod metadata;
pub mod ncryptsec1;
pub mod pointers;
pub mod profile;
pub mod timestamp;

#[cfg(not(target_arch = "wasm32"))]
pub mod addresses;
#[cfg(not(target_arch = "wasm32"))]
pub mod management;
#[cfg(not(target_arch = "wasm32"))]
pub mod relay_information;
#[cfg(not(target_arch = "wasm32"))]
pub mod server;

mod btree;
pub mod database;
mod finalizer;
#[cfg(all(feature = "lmdb", not(target_arch = "wasm32")))]
mod lmdb;
mod network;
#[cfg(all(feature = "redb", target_arch = "wasm32"))]
mod opfs;
#[cfg(all(feature = "redb", any(test, target_arch = "wasm32")))]
mod pages;
#[cfg(feature = "redb")]
mod redb;
mod relay;
mod tags;
mod types;
mod util;

// re-export commonly used types
pub use btree::BTreeEventDatabase;
pub use database::EventDatabase;
pub use event::{ArchivedEvent, Event};
pub use event_template::EventTemplate;
pub use filter::{Filter, TagQuery};
pub use keys::{PubKey, SecretKey};
#[cfg(all(feature = "lmdb", not(target_arch = "wasm32")))]
pub use lmdb::LMDBEventDatabase;
pub use metadata::Metadata;
pub use network::{Network, Occurrence, PublishResult};
#[cfg(all(feature = "redb", target_arch = "wasm32"))]
pub use opfs::OpfsBackend;
pub use pointers::{AddressPointer, EventPointer, Pointer, ProfilePointer};
pub use profile::Profile;
#[cfg(feature = "redb")]
pub use redb::RedbEventDatabase;
pub use relay::{CloseReason, PublishOptions, Relay, SubscriptionOptions};
pub use tags::{Tag, Tags};
pub use timestamp::Timestamp;
pub use types::*;
pub use util::*;
