// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! A mock, in-memory tree store useful for testing.

use alloc::{collections::BTreeSet, vec::Vec};
use anyhow::{bail, ensure, Result};
use parking_lot::RwLock;
use pmt::Key;
use thiserror::Error;

#[cfg(not(feature = "std"))]
use hashbrown::{hash_map::Entry, HashMap};
#[cfg(feature = "std")]
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
};

use crate::{
    db::VersionedDatabase,
    node_type::{LeafNode, Node, NodeKey},
    reader::Preimage,
    storage::{HasPreimage, NodeBatch, StaleNodeIndex, TreeReader, TreeUpdateBatch, TreeWriter},
    types::Version,
    KeyHash, OwnedValue, SimpleHasher,
};

#[derive(Error, Debug, Clone)]
pub enum MockTreeStoreError {}

#[derive(Default, Debug)]
struct MockTreeStoreInner {
    nodes: HashMap<NodeKey, Node>,
    stale_nodes: BTreeSet<StaleNodeIndex>,
    value_history: HashMap<KeyHash, Vec<(Version, Option<OwnedValue>)>>,
    /// Key is a KeyHash of the Preimage, and value is the Preimage itself
    preimages: HashMap<KeyHash, Preimage>,
}

/// A mock, in-memory tree store useful for testing.
///
/// The tree store is internally represented with a `HashMap`.  This structure
/// is exposed for use only by downstream crates' tests, and it should obviously
/// not be used in production.
#[derive(Debug, Clone)]
pub struct MockTreeStore {
    data: Arc<RwLock<MockTreeStoreInner>>,
    allow_overwrite: bool,
}

impl Default for MockTreeStore {
    fn default() -> Self {
        Self {
            data: Arc::new(RwLock::new(Default::default())),
            allow_overwrite: false,
        }
    }
}

impl VersionedDatabase for MockTreeStore {
    // val
    fn get(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.get_node_option(node_key).expect("failed to get value"))
    }

    // use put set method
    fn insert(&self, key: Key, value: Vec<u8>) -> Result<()> {
        todo!()
    }

    // use put set method without value
    fn remove(&self, key: Key) -> Result<()> {
        todo!()
    }

    fn flush(&self) -> Result<()> {
        todo!()
    }

    fn len(&self) -> Result<usize> {
        Ok(self
            .value_history()
            .values()
            .filter(|vals| vals.last().and_then(|(_, val)| val.as_ref()).is_some())
            .count())
    }

    fn nodes(&self) -> HashMap<NodeKey, Node> {
        self.data.read().nodes.clone()
    }

    fn value_history(&self) -> HashMap<KeyHash, Vec<(Version, Option<OwnedValue>)>> {
        self.data.read().value_history.clone()
    }

    fn is_empty(&self) -> Result<bool> {
        Ok(self.num_nodes() == 0)
    }

    fn insert_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        Ok(self
            .write_node_batch(node_batch)
            .expect("failed to write node batch to: {self:?}"))
    }

    fn remove_batch(&self, keys: &[Vec<u8>]) -> Result<()> {
        todo!()
    }
}

impl TreeReader for MockTreeStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        Ok(self.data.read().nodes.get(node_key).cloned())
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let locked = self.data.read();
        let mut node_key_and_node: Option<(NodeKey, LeafNode)> = None;

        for (key, value) in locked.nodes.iter() {
            if let Node::Leaf(leaf_node) = value {
                if node_key_and_node.is_none()
                    || leaf_node.key_hash() > node_key_and_node.as_ref().unwrap().1.key_hash()
                {
                    node_key_and_node.replace((key.clone(), leaf_node.clone()));
                }
            }
        }

        Ok(node_key_and_node)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: crate::KeyHash,
    ) -> Result<Option<crate::OwnedValue>> {
        match self.data.read().value_history.get(&key_hash) {
            Some(version_history) => {
                for (version, value) in version_history.iter().rev() {
                    if *version <= max_version {
                        return Ok(value.clone());
                    }
                }
                Ok(None)
            }
            None => Ok(None),
        }
    }
}

impl HasPreimage for MockTreeStore {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Preimage>> {
        Ok(self.data.read().preimages.get(&key_hash).cloned())
    }
}

impl TreeWriter for MockTreeStore {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        let mut locked = self.data.write();
        for (node_key, node) in node_batch.nodes() {
            let replaced = locked.nodes.insert(node_key.clone(), node.clone());
            if !self.allow_overwrite {
                assert_eq!(replaced, None);
            }
        }
        for ((version, key_hash), value) in node_batch.values() {
            put_value(
                &mut locked.value_history,
                *version,
                *key_hash,
                value.clone(),
            )?
        }
        Ok(())
    }
}

/// Place a value into the provided value history map. Versions must be pushed in non-decreasing order per key.
pub fn put_value(
    value_history: &mut HashMap<KeyHash, Vec<(Version, Option<OwnedValue>)>>,
    version: Version,
    key: KeyHash,
    value: Option<OwnedValue>,
) -> Result<()> {
    match value_history.entry(key) {
        Entry::Occupied(mut occupied) => {
            if let Some((last_version, last_value)) = occupied.get_mut().last_mut() {
                match version.cmp(last_version) {
                    core::cmp::Ordering::Less => bail!("values must be pushed in order"),
                    core::cmp::Ordering::Equal => {
                        *last_value = value;
                        return Ok(());
                    }
                    // If the new value has a higher version than the previous one, fall through and push it to the array
                    core::cmp::Ordering::Greater => {}
                }
            }
            occupied.get_mut().push((version, value));
        }
        Entry::Vacant(vacant) => {
            vacant.insert(vec![(version, value)]);
        }
    }
    Ok(())
}

impl MockTreeStore {
    pub fn new(allow_overwrite: bool) -> Self {
        Self {
            allow_overwrite,
            ..Default::default()
        }
    }

    pub fn put_leaf(&self, node_key: NodeKey, leaf: LeafNode, value: Vec<u8>) -> Result<()> {
        let key_hash = leaf.key_hash();
        let version = node_key.version();
        let mut locked = self.data.write();
        match locked.nodes.entry(node_key) {
            Entry::Occupied(o) => bail!("Key {:?} exists.", o.key()),
            Entry::Vacant(v) => {
                v.insert(leaf.into());
            }
        }
        put_value(&mut locked.value_history, version, key_hash, Some(value))
    }

    pub fn put_key_preimage<H: SimpleHasher>(&self, preimage: &Preimage) {
        let key_hash: KeyHash = KeyHash::with::<H>(preimage.key());
        self.data
            .write()
            .preimages
            .insert(key_hash, preimage.clone());
    }

    fn put_stale_node_index(&self, index: StaleNodeIndex) -> Result<()> {
        let is_new_entry = self.data.write().stale_nodes.insert(index);
        ensure!(is_new_entry, "Duplicated retire log.");
        Ok(())
    }

    pub fn write_tree_update_batch(&self, batch: TreeUpdateBatch) -> Result<()> {
        self.write_node_batch(&batch.node_batch)?;
        batch
            .stale_node_index_batch
            .into_iter()
            .map(|i| self.put_stale_node_index(i))
            .collect::<Result<Vec<_>>>()?;
        Ok(())
    }

    pub fn purge_stale_nodes(&self, least_readable_version: Version) -> Result<()> {
        let mut wlocked = self.data.write();

        // Only records retired before or at `least_readable_version` can be purged in order
        // to keep that version still readable.
        let to_prune = wlocked
            .stale_nodes
            .iter()
            .take_while(|log| log.stale_since_version <= least_readable_version)
            .cloned()
            .collect::<Vec<_>>();

        for log in to_prune {
            let removed = wlocked.nodes.remove(&log.node_key).is_some();
            ensure!(removed, "Stale node index refers to non-existent node.");
            wlocked.stale_nodes.remove(&log);
        }

        Ok(())
    }

    pub fn num_nodes(&self) -> usize {
        self.data.read().nodes.len()
    }
}
