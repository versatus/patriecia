use crate::{storage::TreeUpdateBatch, OwnedValue, Version};
use anyhow::Result;
#[cfg(not(feature = "std"))]
use hashbrown::HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

/// Defines the interaction between a database and the node versioning strategy
/// of the `JellyfishMerkleTree`.
pub trait VersionedDatabase: Send + Sync + Clone + Default + std::fmt::Debug {
    type KeyHash: std::hash::Hash + std::cmp::Eq;
    type NodeKey;
    type Node;
    type NodeIter: Iterator<Item = (Self::NodeKey, Self::Node)>;
    type HistoryIter: Iterator<Item = (Self::KeyHash, Vec<(Version, Option<OwnedValue>)>)>;
    /// Get the associated `OwnedValue` to a given `KeyHash`, and `Version` threshold.
    fn get(&self, max_version: Version, node_key: Self::KeyHash) -> Result<Option<OwnedValue>>;

    /// A convenience wrapper for `VersionedDatabase::update_batch` when updating singular key-value pairs.
    ///
    /// Replaces `Database::insert()` & `Database::Remove()` since a `VersionedDatabase` relies on
    /// versioning that the `JellyfishMerkleTree` provides. To insert, give `Some(v)` & to remove give `None`.
    ///
    /// *Note:* To get batch updates to apply with this method, use `JellyfishMerkleTree::put_value_set(s)`.
    ///
    /// ### Example:
    /// Based on [`jmt::tests::helper::init_mock_db_with_deletions_afterwards`](jmt/src/tests/helper.rs).
    ///
    /// ```rust, ignore
    /// use crate::mock::MockTreeStore;
    /// use sha2::Sha256;
    /// use crate::Sha256Jmt;
    ///
    /// let to_insert = HashMap::from(HashKey::with::<Sha256>(b"temp"), Some(vec![0u8; 32]));
    /// let to_remove = HashMap::from(HashKey::with::<Sha256>(b"temp"), None);
    /// let db = MockTreeStore::default();
    /// let tree = Sha256Jmt::new(&db);
    ///
    /// for (i, (key, value)) in to_insert.clone().into_iter().enumerate() {
    ///     let (_root_hash, write_batch) = tree
    ///         .put_value_set(vec![(key, value)], i as Version)
    ///         .unwrap();
    ///     db.update(write_batch).unwrap();
    /// }
    /// assert!(!db.is_empty());
    ///
    /// let after_insertions_version = kvs.len();
    /// for (i, (key, value)) in to_remove.clone().into_iter().enumerate() {
    ///     let (_root_hash, write_batch) = tree
    ///         .put_value_set(
    ///             vec![(key, value)],
    ///             (after_insertions_version + i) as Version
    ///         )
    ///         .unwrap();
    ///     db.update(write_batch).unwrap();
    /// }
    /// assert!(db.is_empty());
    /// ```
    fn update(&self, tree_update_batch: TreeUpdateBatch) -> Result<()> {
        self.update_batch(tree_update_batch)
    }

    /// Wrapper around [`TreeWriter::write_node_batch`](jmt/src/writer.rs) that also updates stale nodes.
    ///
    /// *Note:* To get batch updates to apply with this method, use `JellyfishMerkleTree::put_value_set(s)`.
    ///
    /// See [`jmt::tests::jellyfish_merkle::test_batch_insertion`](jmt/src/tests/jellyfish_merkle.rs)
    /// for a detailed example.
    fn update_batch(&self, tree_update_batch: TreeUpdateBatch) -> Result<()>;

    /// Returns the number of `Some` values within `value_history`
    /// for all keys at the latest version.
    ///
    /// ### Example:
    /// ```rust, ignore
    /// use crate::mock::MockTreeStore;
    /// use sha2::Sha256;
    ///
    /// let db = MockTreeStore::default();
    /// let tree = Sha256Jmt::new(&db);
    ///
    /// // add old set version 0
    /// let key = b"old_vers";
    /// let value = vec![0u8; 32];
    /// let (_new_root_hash, batch) = tree
    ///     .put_value_set(vec![(KeyHash::with::<Sha256>(key), Some(value.clone()))], 0)
    ///     .unwrap();
    ///
    /// db.write_tree_update_batch(batch).unwrap();
    /// assert_eq!(db.len(), 1);
    ///
    /// // add new set version 1
    /// let key = b"new_vers";
    /// let value = vec![0u8; 32];
    /// let (_new_root_hash, batch) = tree
    ///     .put_value_set(vec![(KeyHash::with::<Sha256>(key), Some(value.clone()))], 1)
    ///     .unwrap();
    ///
    /// db.write_tree_update_batch(batch).unwrap();
    /// assert_eq!(db.len(), 2);
    ///
    /// // remove old set version 2
    /// let key = b"old_vers";
    /// let (_new_root_hash, batch) = tree
    ///     .put_value_set(vec![(KeyHash::with::<Sha256>(key), None)], 2)
    ///     .unwrap();
    ///
    /// db.write_tree_update_batch(batch).unwrap();
    /// assert_eq!(db.len(), 1);
    /// ```
    fn len(&self) -> usize {
        let map: HashMap<Self::KeyHash, Vec<(Version, Option<OwnedValue>)>> =
            self.value_history().collect();
        map.values()
            .filter(|vals| vals.last().and_then(|(_, val)| val.as_ref()).is_some())
            .count()
    }

    /// Get the latest [`Version`] of the tree stored in the value history.
    fn version(&self) -> Version {
        let mut latest: Version = Version::default();
        let map: HashMap<Self::KeyHash, Vec<(Version, Option<OwnedValue>)>> =
            self.value_history().collect();
        for values in map.values() {
            for (ver, _) in values.iter() {
                if ver > &latest {
                    latest = *ver;
                }
            }
        }
        latest
    }

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
    fn nodes(&self) -> Self::NodeIter;

    /// Replaces `Database::values()`. Returns a clone of the value history HashMap which
    /// has a `.values()` method returning `Values<KeyHash, Vec<(Version, Option<OwnedValue>)>>`
    /// for iteration over `jmt::VersionedDatabase`.
    ///
    /// ### Example:
    /// ```rust, ignore
    /// use crate::mock::MockTreeStore;
    ///
    /// let db = MockTreeStore::default();
    /// for (key, (ver, val)) in db.value_history().values() {
    ///     println!("{key}: {ver} - {val}");
    /// }
    /// ```
    fn value_history(&self) -> Self::HistoryIter;

    /// Returns true if there are no nodes with `OwnedValue`s for the latest
    /// `Version` in `VersionedDatabase::value_history()`
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
