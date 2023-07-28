use anyhow::Result;
use pmt::Key;
use std::collections::HashMap;

use crate::{
    storage::{Node, NodeBatch, NodeKey},
    KeyHash, OwnedValue, Version,
};

/// "DB" defines the "trait" of trie and database interaction.
/// You should first write the data to the cache and write the data
/// to the database in bulk after the end of a set of operations.
pub trait VersionedDatabase: Send + Sync + Clone + Default + std::fmt::Debug {
    fn get(&self, node_key: &NodeKey) -> Result<Option<Node>>;

    /// Insert data into the cache.
    fn insert(&self, key: Key, value: Vec<u8>) -> Result<()>;

    /// Remove data with given key.
    fn remove(&self, key: Key) -> Result<()>;

    /// Insert a batch of data into the cache.
    fn insert_batch(&self, node_batch: &NodeBatch) -> Result<()>;

    /// Remove a batch of data from the cache.
    fn remove_batch(&self, keys: &[Vec<u8>]) -> Result<()>;

    // TODO: figure if flush is actually necessary
    /// Flush data to the DB from the cache.
    fn flush(&self) -> Result<()>;

    /// Returns the number of `Some` values within `value_history`
    /// for all keys at the latest version.
    ///
    /// ### Example:
    /// ```rust, ignore
    /// use crate::mock::MockTreeStore;
    /// use sha2::Sha256;
    ///
    /// let db = MockTreeStore::default();
    /// db.data.value_history.insert(KeyHash::with::<Sha256>(b"old_vers"), vec![(1, Some(vec![0u8; 32]))]);
    /// db.data.value_history.insert(KeyHash::with::<Sha256>(b"new_vers"), vec![(2, Some(vec![0u8; 32]))]);
    /// db.data.value_history.insert(KeyHash::with::<Sha256>(b"is_empty"), vec![(2, None)]);
    ///
    /// assert_eq!(db.len(), 1);
    /// ```
    fn len(&self) -> Result<usize>;

    /// Replaces `Database::values()`. Returns a clone of the nodes HashMap which
    /// has a `.values()` method returning `Values<NodeKey, Node>`
    /// for iteration over `jmt::VersionedDatabase`.
    ///
    /// ### Example:
    /// ```rust, ignore
    /// use crate::mock::MockTreeStore;
    ///
    /// let db = MockTreeStore::default();
    /// for (key, node) in db.nodes().values() {
    ///     println!("{key}: {node}");
    /// }
    /// ```
    fn nodes(&self) -> HashMap<NodeKey, Node>;

    /// Replaces `Database::values()`. Returns a clone of the value history HashMap which
    /// has a `.values()` method returning `Values<KeyHash, Vec<(Version, Option<OwnedValue>)>>`
    /// for iteration over `jmt::VersionedDatabase`.
    fn value_history(&self) -> HashMap<KeyHash, Vec<(Version, Option<OwnedValue>)>>;

    // values is empty? which part of DB is this checking?
    fn is_empty(&self) -> Result<bool>;
}
