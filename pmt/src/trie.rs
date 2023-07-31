use crate::common::{Key, OwnedValue, Value};
use crate::db::Database;
use crate::result::Result;
use crate::serde_hash::H256;

#[deprecated(since = "1.0.0", note = "replaced by VersionedTrie")]
pub trait Trie<D: Database> {
    /// Returns the value for key stored in the trie.
    fn get(&self, key: Key) -> Result<Option<OwnedValue>>;

    /// Returns true if the key is present within the trie
    fn contains(&self, key: Key) -> Result<bool>;

    /// Inserts value into trie and updates it if it exists
    fn insert(&mut self, key: Key, value: Value) -> Result<()>;

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: Key) -> Result<bool>;

    /// Returns the root hash of the trie. This is an expensive operation as it commits every node
    /// in the cache to the database to recalculate the root.
    fn root_hash(&mut self) -> Result<H256>;

    /// Commits all cached nodes to the database and returns the root hash of the trie.
    fn commit(&mut self) -> Result<H256>;

    /// Prove constructs a merkle proof for key. The result contains all encoded nodes
    /// on the path to the value at key. The value itself is also included in the last
    /// node and can be retrieved by verifying the proof.
    ///
    /// If the trie does not contain a value for key, the returned proof contains all
    /// nodes of the longest existing prefix of the key (at least the root node), ending
    /// with the node that proves the absence of the key.
    // TODO refactor encode_raw() so that it doesn't need a &mut self
    // TODO (Daniel): refactor and potentially submit a patch upstream
    fn get_proof(&mut self, key: Key) -> Result<Vec<OwnedValue>>;

    /// Returns a value if key exists, None if key doesn't exist, Error if proof is wrong
    fn verify_proof(
        &self,
        root_hash: H256,
        key: Key,
        proof: Vec<Vec<u8>>,
    ) -> Result<Option<OwnedValue>>;
}
