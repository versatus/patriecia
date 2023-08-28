use crate::{
    db::VersionedDatabase, mock::MockTreeStore, tree::Sha256Jmt, trie::VersionedTrie, KeyHash,
};
use alloc::sync::Arc;
use sha2::Sha256;

#[test]
fn test_versioned_db_len() {
    let db = Arc::new(MockTreeStore::default());
    let tree = Sha256Jmt::new(db);

    // add old set
    let key = b"old_vers";
    let value = vec![0u8; 32];
    let (_new_root_hash, batch) = tree
        .put_value_set(vec![(KeyHash::with::<Sha256>(key), Some(value.clone()))], 0)
        .unwrap();

    tree.reader().write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.reader().len(), 1);

    // add new set
    let key = b"new_vers";
    let value = vec![0u8; 32];
    let (_new_root_hash, batch) = tree
        .put_value_set(vec![(KeyHash::with::<Sha256>(key), Some(value.clone()))], 1)
        .unwrap();

    tree.reader().write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.reader().len(), 2);

    // remove old set
    let key = b"old_vers";
    let (_new_root_hash, batch) = tree
        .put_value_set(vec![(KeyHash::with::<Sha256>(key), None)], 2)
        .unwrap();

    tree.reader().write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.reader().len(), 1);
}

#[test]
fn test_versioned_db_is_empty() {
    let db = Arc::new(MockTreeStore::default());
    let tree = Sha256Jmt::new(db);

    // add old set
    let key = b"old_vers";
    let value = vec![0u8; 32];
    let (_new_root_hash, batch) = tree
        .put_value_set(vec![(KeyHash::with::<Sha256>(key), Some(value.clone()))], 0)
        .unwrap();

    tree.reader().write_tree_update_batch(batch).unwrap();
    assert_eq!(tree.reader().len(), 1);

    // remove old set
    let key = b"old_vers";
    let (_new_root_hash, batch) = tree
        .put_value_set(vec![(KeyHash::with::<Sha256>(key), None)], 2)
        .unwrap();

    tree.reader().write_tree_update_batch(batch).unwrap();
    assert!(tree.reader().is_empty());
}
