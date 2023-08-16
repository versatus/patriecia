use crate::{
    db::VersionedDatabase, proof::SparseMerkleProof, storage::TreeReader, JellyfishMerkleIterator,
    KeyHash, OwnedValue, RootHash, SimpleHasher, Version,
};
use alloc::sync::Arc;
use anyhow::Result;

/// Exposes additional convenience methods for the [`JellyfishMerkleTree`](./jmt/tree).
pub trait VersionedTrie<R, H>
where
    R: TreeReader + VersionedDatabase,
    H: SimpleHasher,
{
    /// Equivalent to [`get_value_option`](TreeReader::get_value_option).
    fn get(&self, key: KeyHash, version: Version) -> Result<Option<OwnedValue>>;

    /// Returns true if the `KeyHash` at `Version` is present within the tree.
    fn contains(&self, key: KeyHash, version: Version) -> Result<bool> {
        Ok(self.get(key, version)?.is_some())
    }

    /// Returns only the corresponding merkle proof from [`JellyfishMerkleTree::get_with_proof`]
    fn get_proof(&self, key: KeyHash, version: Version) -> Result<SparseMerkleProof<H>>;

    /// Wrapper around `SparseMerkleProof::verify`.
    ///
    /// If element_value is present, verifies an element whose key is element_key
    /// and value is element_value exists in the Sparse Merkle Tree using the provided proof.
    /// Otherwise verifies the proof is a valid non-inclusion proof that shows this key doesn't exist in the tree.
    fn verify_proof(
        &self,
        element_key: KeyHash,
        version: Version,
        expected_root_hash: RootHash,
        proof: SparseMerkleProof<H>,
    ) -> Result<()>;

    /// Create a [`JellyfishMerkleIterator`] from the reader: R, to iterate
    /// over values in the tree starting at the given key and version.
    fn iter(&self, version: Version, starting_key: KeyHash) -> Result<JellyfishMerkleIterator<R>>;

    /// Get the number of `Some(value)`s from the latest version of the tree stored in the `VersionedDatabase`.
    fn len(&self) -> usize;

    /// Returns true if there are no nodes with `OwnedValue`s for the latest
    /// `Version` in `VersionedDatabase::value_history()`
    fn is_empty(&self) -> bool;

    /// Get the latest [`Version`] of the tree from the tree store's value history.
    fn version(&self) -> Version;

    fn reader(&self) -> &Arc<R>;
}
