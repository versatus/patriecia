use crate::{
    proof::SparseMerkleProof,
    storage::{NodeKey, TreeReader},
    KeyHash, OwnedValue, RootHash, SimpleHasher, ValueHash, Version,
};
use pmt::{Database, Result as TrieResult};

pub trait Jmt<R, H>
where
    R: TreeReader + Database,
    H: SimpleHasher,
{
    /// Returns the value for key stored in the trie.
    fn get(&self, key: KeyHash, version: Version) -> TrieResult<Option<OwnedValue>>;

    /// Returns true if the key is present within the trie
    fn contains(&self, key: KeyHash) -> TrieResult<bool>;

    /// Inserts value into trie and updates it if it exists
    fn insert(
        &mut self,
        key: NodeKey,
        version: Version,
        value: Option<ValueHash>,
    ) -> TrieResult<()>;

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: KeyHash) -> TrieResult<bool>;

    /// Returns the root hash of the trie. This is an expensive operation as it commits every node
    /// in the cache to the database to recalculate the root.
    fn root_hash(&self, version: Version) -> TrieResult<RootHash>;

    /// Commits all cached nodes to the database and returns the root hash of the trie.
    fn commit(&mut self) -> TrieResult<H>;

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    // TODO refactor encode_raw() so that it doesn't need a &mut self
    // TODO (Daniel): refactor and potentially submit a patch upstream
    fn get_proof(&self, key: KeyHash, version: Version) -> TrieResult<SparseMerkleProof<H>>;

    /// Returns a value if key exists, None if key doesn't exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: RootHash,
        key: KeyHash,
        proof: SparseMerkleProof<H>,
    ) -> TrieResult<Option<OwnedValue>>;
}
