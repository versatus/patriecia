/// Heavily inspired by https://github.com/carver/eth-trie.rs which is a fork of https://github.com/citahub/cita-trie
///
pub mod db;
pub mod error;
pub mod inner;
pub mod result;
pub mod trie;
pub mod trie_iterator;

pub mod common;
pub use common::*;
pub use db::*;
pub use error::*;
pub use inner::*;
pub use result::*;
pub use trie::*;
pub use trie_iterator::*;

pub(crate) mod nibbles;
pub(crate) mod node;

pub use jmt::{db::VersionedDatabase, trie::VersionedTrie};
pub use serde_hash::H256;

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use rand::{distributions::Alphanumeric, seq::SliceRandom, thread_rng, Rng};

    use crate::{
        db::{Database, MemoryDB},
        error::TrieError,
        nibbles::Nibbles,
        serde_hash::{keccak, H256},
    };
    use crate::{InnerTrie, Trie};

    #[test]
    fn test_trie_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
    }

    #[test]
    fn test_trie_get() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
        let v = trie.get(b"test").unwrap();

        assert_eq!(Some(b"test".to_vec()), v)
    }

    #[test]
    fn test_trie_get_missing() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
        let v = trie.get(b"no-val").unwrap();

        assert_eq!(None, v)
    }

    fn corrupt_trie() -> (InnerTrie<MemoryDB>, H256, H256) {
        let memdb = Arc::new(MemoryDB::new(true));
        let corruptor_db = memdb.clone();
        let mut trie = InnerTrie::new(memdb);
        trie.insert(b"test1-key", b"really-long-value1-to-prevent-inlining")
            .unwrap();
        trie.insert(b"test2-key", b"really-long-value2-to-prevent-inlining")
            .unwrap();
        let actual_root_hash = trie.root_hash().unwrap();

        // Manually corrupt the database by removing a trie node
        // This is the hash for the leaf node for test2-key
        let node_hash_to_delete = b"\xcb\x15v%j\r\x1e\te_TvQ\x8d\x93\x80\xd1\xa2\xd1\xde\xfb\xa5\xc3hJ\x8c\x9d\xb93I-\xbd";
        assert_ne!(corruptor_db.get(node_hash_to_delete).unwrap(), None);
        corruptor_db.remove(node_hash_to_delete).unwrap();
        assert_eq!(corruptor_db.get(node_hash_to_delete).unwrap(), None);

        (
            trie,
            actual_root_hash,
            H256::from_slice(node_hash_to_delete),
        )
    }

    #[test]
    /// When a database entry is missing, get returns a MissingTrieNode error
    fn test_trie_get_corrupt() {
        let (trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.get(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, delete returns a MissingTrieNode error
    fn test_trie_delete_corrupt() {
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.remove(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, delete returns a MissingTrieNode error
    fn test_trie_delete_refactor_corrupt() {
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.remove(b"test1-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: None,
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test1-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, get_proof returns a MissingTrieNode
    /// error
    fn test_trie_get_proof_corrupt() {
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.get_proof(b"test2-key");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: None,
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-key".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    /// When a database entry is missing, insert returns a MissingTrieNode error
    fn test_trie_insert_corrupt() {
        let (mut trie, actual_root_hash, deleted_node_hash) = corrupt_trie();

        let result = trie.insert(b"test2-neighbor", b"any");

        if let Err(missing_trie_node) = result {
            let expected_error = TrieError::MissingTrieNode {
                node_hash: deleted_node_hash,
                traversed: Some(Nibbles::from_hex(&[7, 4, 6, 5, 7, 3, 7, 4, 3, 2])),
                root_hash: Some(actual_root_hash),
                err_key: Some(b"test2-neighbor".to_vec()),
            };
            assert_eq!(missing_trie_node, expected_error);
        } else {
            // The only acceptable result here was a MissingTrieNode
            panic!(
                "Must get a MissingTrieNode when database entry is missing, but got {:?}",
                result
            );
        }
    }

    #[test]
    fn test_trie_random_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);

        for _ in 0..1000 {
            let rand_str: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();
            let val = rand_str.as_bytes();
            trie.insert(val, val).unwrap();

            let v = trie.get(val).unwrap();
            assert_eq!(v.map(|v| v.to_vec()), Some(val.to_vec()));
        }
    }

    #[test]
    fn test_trie_contains() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
        assert!(trie.contains(b"test").unwrap());
        assert!(!trie.contains(b"test2").unwrap());
    }

    #[test]
    fn test_trie_remove() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);
        trie.insert(b"test", b"test").unwrap();
        let removed = trie.remove(b"test").unwrap();
        assert!(removed)
    }

    #[test]
    fn test_trie_random_remove() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);

        for _ in 0..1000 {
            let rand_str: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(30)
                .map(char::from)
                .collect();
            let val = rand_str.as_bytes();
            trie.insert(val, val).unwrap();

            let removed = trie.remove(val).unwrap();
            assert!(removed);
        }
    }

    #[test]
    fn test_trie_at_root_six_keys() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = InnerTrie::new(memdb.clone());
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.root_hash().unwrap()
        };

        let mut trie = InnerTrie::new(memdb).at_root(root);
        let v1 = trie.get(b"test33").unwrap();
        assert_eq!(Some(b"test".to_vec()), v1);
        let v2 = trie.get(b"test44").unwrap();
        assert_eq!(Some(b"test".to_vec()), v2);
        let root2 = trie.root_hash().unwrap();
        assert_eq!(hex::encode(root), hex::encode(root2));
    }

    #[test]
    fn test_trie_at_root_and_insert() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = InnerTrie::new(Arc::clone(&memdb));
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.root_hash().unwrap()
        };

        let mut trie = InnerTrie::new(memdb).at_root(root);
        trie.insert(b"test55", b"test55").unwrap();
        trie.root_hash().unwrap();
        let v = trie.get(b"test55").unwrap();
        assert_eq!(Some(b"test55".to_vec()), v);
    }

    #[test]
    fn test_trie_at_root_and_delete() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root = {
            let mut trie = InnerTrie::new(Arc::clone(&memdb));
            trie.insert(b"test", b"test").unwrap();
            trie.insert(b"test1", b"test").unwrap();
            trie.insert(b"test2", b"test").unwrap();
            trie.insert(b"test23", b"test").unwrap();
            trie.insert(b"test33", b"test").unwrap();
            trie.insert(b"test44", b"test").unwrap();
            trie.root_hash().unwrap()
        };

        let mut trie = InnerTrie::new(memdb).at_root(root);
        let removed = trie.remove(b"test44").unwrap();
        assert!(removed);
        let removed = trie.remove(b"test33").unwrap();
        assert!(removed);
        let removed = trie.remove(b"test23").unwrap();
        assert!(removed);
    }

    #[test]
    fn test_multiple_trie_roots() {
        let k0: ethereum_types::H256 = ethereum_types::H256::zero();
        let k1: ethereum_types::H256 = ethereum_types::H256::random();
        let v: ethereum_types::H256 = ethereum_types::H256::random();

        let root1 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = InnerTrie::new(memdb);
            trie.insert(k0.as_bytes(), v.as_bytes()).unwrap();
            trie.root_hash().unwrap()
        };

        let root2 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie = InnerTrie::new(memdb);
            trie.insert(k0.as_bytes(), v.as_bytes()).unwrap();
            trie.insert(k1.as_bytes(), v.as_bytes()).unwrap();
            trie.root_hash().unwrap();
            trie.remove(k1.as_ref()).unwrap();
            trie.root_hash().unwrap()
        };

        let root3 = {
            let memdb = Arc::new(MemoryDB::new(true));
            let mut trie1 = InnerTrie::new(Arc::clone(&memdb));
            trie1.insert(k0.as_bytes(), v.as_bytes()).unwrap();
            trie1.insert(k1.as_bytes(), v.as_bytes()).unwrap();
            trie1.root_hash().unwrap();
            let root = trie1.root_hash().unwrap();
            let mut trie2 = trie1.at_root(root);
            trie2.remove(k1.as_bytes()).unwrap();
            trie2.root_hash().unwrap()
        };

        assert_eq!(root1, root2);
        assert_eq!(root2, root3);
    }

    #[test]
    fn test_delete_stale_keys_with_random_insert_and_delete() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);

        let mut rng = rand::thread_rng();
        let mut keys = vec![];
        for _ in 0..100 {
            let random_bytes: Vec<u8> = (0..rng.gen_range(2..30))
                .map(|_| rand::random::<u8>())
                .collect();
            trie.insert(&random_bytes, &random_bytes).unwrap();
            keys.push(random_bytes.clone());
        }
        trie.root_hash().unwrap();
        let slice = &mut keys;
        slice.shuffle(&mut rng);

        for key in slice.iter() {
            trie.remove(key).unwrap();
        }
        trie.root_hash().unwrap();

        let empty_node_key = keccak(&rlp::NULL_RLP);
        let value = trie.db().get(empty_node_key.as_ref()).unwrap().unwrap();
        assert_eq!(value, &rlp::NULL_RLP)
    }

    #[test]
    fn insert_full_branch() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb);

        trie.insert(b"test", b"test").unwrap();
        trie.insert(b"test1", b"test").unwrap();
        trie.insert(b"test2", b"test").unwrap();
        trie.insert(b"test23", b"test").unwrap();
        trie.insert(b"test33", b"test").unwrap();
        trie.insert(b"test44", b"test").unwrap();
        trie.root_hash().unwrap();

        let v = trie.get(b"test").unwrap();
        assert_eq!(Some(b"test".to_vec()), v);
    }

    #[test]
    fn iterator_trie() {
        let memdb = Arc::new(MemoryDB::new(true));
        let root1: H256;

        let mut kv = HashMap::new();

        kv.insert(b"test".to_vec(), b"test".to_vec());
        kv.insert(b"test1".to_vec(), b"test1".to_vec());
        kv.insert(b"test11".to_vec(), b"test2".to_vec());
        kv.insert(b"test14".to_vec(), b"test3".to_vec());
        kv.insert(b"test16".to_vec(), b"test4".to_vec());
        kv.insert(b"test18".to_vec(), b"test5".to_vec());
        kv.insert(b"test2".to_vec(), b"test6".to_vec());
        kv.insert(b"test23".to_vec(), b"test7".to_vec());
        kv.insert(b"test9".to_vec(), b"test8".to_vec());

        {
            let mut trie = InnerTrie::new(memdb.clone());

            let mut kv = kv.clone();

            kv.iter().for_each(|(k, v)| {
                trie.insert(k, v).unwrap();
            });

            root1 = trie.root_hash().unwrap();

            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));

            assert!(kv.is_empty());
        }

        {
            let mut trie = InnerTrie::new(memdb.clone());
            let mut kv2 = HashMap::new();

            kv2.insert(b"test".to_vec(), b"test11".to_vec());
            kv2.insert(b"test1".to_vec(), b"test12".to_vec());
            kv2.insert(b"test14".to_vec(), b"test13".to_vec());
            kv2.insert(b"test22".to_vec(), b"test14".to_vec());
            kv2.insert(b"test9".to_vec(), b"test15".to_vec());
            kv2.insert(b"test16".to_vec(), b"test16".to_vec());
            kv2.insert(b"test2".to_vec(), b"test17".to_vec());
            kv2.iter().for_each(|(k, v)| {
                trie.insert(k, v).unwrap();
            });

            trie.root_hash().unwrap();

            let mut kv_delete = HashSet::new();
            kv_delete.insert(b"test".to_vec());
            kv_delete.insert(b"test1".to_vec());
            kv_delete.insert(b"test14".to_vec());

            kv_delete.iter().for_each(|k| {
                trie.remove(k).unwrap();
            });

            kv2.retain(|k, _| !kv_delete.contains(k));

            trie.root_hash().unwrap();
            trie.iter()
                .for_each(|(k, v)| assert_eq!(kv2.remove(&k).unwrap(), v));
            assert!(kv2.is_empty());
        }

        let trie = InnerTrie::new(memdb).at_root(root1);
        trie.iter()
            .for_each(|(k, v)| assert_eq!(kv.remove(&k).unwrap(), v));
        assert!(kv.is_empty());
    }

    #[test]
    fn test_small_trie_at_root() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb.clone());
        trie.insert(b"key", b"val").unwrap();
        let new_root_hash = trie.commit().unwrap();

        let empty_trie = InnerTrie::new(memdb);
        // Can't find key in new trie at empty root
        assert_eq!(empty_trie.get(b"key").unwrap(), None);

        let trie_view = empty_trie.at_root(new_root_hash);
        assert_eq!(&trie_view.get(b"key").unwrap().unwrap(), b"val");

        // Previous trie was not modified
        assert_eq!(empty_trie.get(b"key").unwrap(), None);
    }

    #[test]
    fn test_large_trie_at_root() {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = InnerTrie::new(memdb.clone());
        trie.insert(
            b"pretty-long-key",
            b"even-longer-val-to-go-more-than-32-bytes",
        )
        .unwrap();
        let new_root_hash = trie.commit().unwrap();

        let empty_trie = InnerTrie::new(memdb);

        // Can't find key in new trie at empty root
        assert_eq!(empty_trie.get(b"pretty-long-key").unwrap(), None);

        let trie_view = empty_trie.at_root(new_root_hash);
        assert_eq!(
            &trie_view.get(b"pretty-long-key").unwrap().unwrap(),
            b"even-longer-val-to-go-more-than-32-bytes"
        );

        // Previous trie was not modified
        assert_eq!(empty_trie.get(b"pretty-long-key").unwrap(), None);
    }
}
