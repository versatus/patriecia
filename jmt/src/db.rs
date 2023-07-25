use pmt::Key;
use std::collections::HashMap;

use crate::{storage::NodeBatch, KeyHash, OwnedValue, Version};

/// "DB" defines the "trait" of trie and database interaction.
/// You should first write the data to the cache and write the data
/// to the database in bulk after the end of a set of operations.
pub trait VersionedDatabase: Send + Sync + Clone + Default + std::fmt::Debug {
    type Error: std::error::Error;

    fn get(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>, Self::Error>;

    /// Insert data into the cache.
    fn insert(&self, key: Key, value: Vec<u8>) -> Result<(), Self::Error>;

    /// Remove data with given key.
    fn remove(&self, key: Key) -> Result<(), Self::Error>;

    /// Insert a batch of data into the cache.
    fn insert_batch(&self, node_batch: &NodeBatch) -> Result<(), Self::Error>;

    /// Remove a batch of data from the cache.
    fn remove_batch(&self, keys: &[Vec<u8>]) -> Result<(), Self::Error>;

    // TODO: figure if flush is actually necessary
    /// Flush data to the DB from the cache.
    fn flush(&self) -> Result<(), Self::Error>;

    fn len(&self) -> Result<usize, Self::Error>;

    /// Replaces `Database::values()`. Returns a clone of the value history HashMap which
    /// has a `.values()` method returning `Values<KeyHash, Vec<(Version, Option<OwnedValue>)>>`
    /// for iteration over `jmt::VersionedDatabase`.
    fn value_history(&self) -> HashMap<KeyHash, Vec<(Version, Option<OwnedValue>)>>;

    fn is_empty(&self) -> Result<bool, Self::Error>;
}
