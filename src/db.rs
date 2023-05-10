/// Trait definition and basic db struct taken from https://github.com/carver/eth-trie.rs
/// Meant to be refactor into its own crate later on
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::error::MemDBError;

/// "DB" defines the "trait" of trie and database interaction.
/// You should first write the data to the cache and write the data
/// to the database in bulk after the end of a set of operations.
pub trait Database: Send + Sync + Clone + Default + std::fmt::Debug {
    type Error: Error;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Insert data into the cache.
    fn insert(&self, key: &[u8], value: Vec<u8>, node_type: NodeType) -> Result<(), Self::Error>;

    /// Remove data with given key.
    fn remove(&self, key: &[u8]) -> Result<(), Self::Error>;

    /// Insert a batch of data into the cache.
    fn insert_batch(
        &self,
        keys: Vec<Vec<u8>>,
        values: Vec<(Vec<u8>, NodeType)>,
    ) -> Result<(), Self::Error> {
        for i in 0..keys.len() {
            let key = &keys[i];
            let (value, node_type) = values[i].clone();
            self.insert(key, value, node_type)?;
        }
        Ok(())
    }

    /// Remove a batch of data from the cache.
    fn remove_batch(&self, keys: &[Vec<u8>]) -> Result<(), Self::Error> {
        for key in keys {
            self.remove(key)?;
        }
        Ok(())
    }

    // TODO: figure if flush is actually necessary
    /// Flush data to the DB from the cache.
    fn flush(&self) -> Result<(), Self::Error>;

    fn len(&self) -> Result<usize, Self::Error>;

    fn values(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Self::Error>;

    fn is_empty(&self) -> Result<bool, Self::Error>;
}

#[derive(Default, Debug, Clone)]
pub struct MemoryDB {
    // If "light" is true, the data is deleted from the database at the time of submission.
    light: bool,
    storage: Arc<RwLock<HashMap<Vec<u8>, (Vec<u8>, NodeType)>>>,
}

impl MemoryDB {
    pub fn new(light: bool) -> Self {
        MemoryDB {
            light,
            storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeType {
    Leaf,
    Extension,
    Branch,
    HashNode,
}

impl Database for MemoryDB {
    type Error = MemDBError;

    fn get(&self, key: &[u8], node_type: NodeType) -> Result<Option<Vec<u8>>, Self::Error> {
        if let Some(value) = self.storage.read().get(key) {
            Ok(Some(value.clone()))
        } else {
            Ok(None)
        }
    }

    fn insert(&self, key: &[u8], value: Vec<u8>, node_type: NodeType) -> Result<(), Self::Error> {
        self.storage.write().insert(key.to_vec(), value);
        Ok(())
    }

    fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        if self.light {
            self.storage.write().remove(key);
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn len(&self) -> Result<usize, Self::Error> {
        Ok(self.storage.try_read().unwrap().len())
    }

    fn is_empty(&self) -> Result<bool, Self::Error> {
        Ok(self.storage.try_read().unwrap().is_empty())
    }

    fn values(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Self::Error> {
        let mut values = Vec::new();

        if let Some(handle) = self.storage.try_read() {
            for (k, node_data) in handle.iter() {
                let (v, t) = (node_data.clone(), NodeType::Leaf);
                if t == &NodeType::Leaf {
                    values.push((k.clone(), v.clone()));
                }
            }
        }

        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memdb_get() {
        let memdb = MemoryDB::new(true);
        memdb.insert(b"test-key", b"test-value".to_vec()).unwrap();
        let v = memdb.get(b"test-key").unwrap().unwrap();

        assert_eq!(v, b"test-value")
    }

    #[test]
    fn test_memdb_remove() {
        let memdb = MemoryDB::new(true);
        memdb.insert(b"test", b"test".to_vec()).unwrap();

        memdb.remove(b"test").unwrap();
        let contains = memdb.get(b"test").unwrap();
        assert_eq!(contains, None)
    }
}
