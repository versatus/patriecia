/// Adapted from https://github.com/carver/eth-trie.rs which is a fork of https://github.com/citahub/cita-trie
/// Beware there's a significant amount of TODOs scattered around the file,
/// these will be addressed in due time.
use std::borrow::BorrowMut;
use std::sync::Arc;

use hashbrown::{HashMap, HashSet};
use keccak_hash::{keccak, H256};
use rlp::{Prototype, Rlp, RlpStream};

use crate::{
    common::{Key, OwnedValue, Value},
    db::{Database, MemoryDB},
    error::TrieError,
    nibbles::Nibbles,
    node::{BranchNode, ExtensionNode, HashNode, Node},
    result::Result,
    trie::Trie,
    TrieIterator,
};

const HASHED_LENGTH: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct InnerTrie<D>
where
    D: Database,
{
    root: Node,
    /// 32 byte hash of the trie's root node.
    root_hash: H256,

    db: Arc<D>,

    /// The batch of pending new nodes to write
    cache: HashMap<Vec<u8>, Vec<u8>>,
    passing_keys: HashSet<Vec<u8>>,
    gen_keys: HashSet<Vec<u8>>,
}

enum EncodedNode {
    Hash(H256),
    Inline(Vec<u8>),
}

impl<D> InnerTrie<D>
where
    D: Database,
{
    pub fn new(db: Arc<D>) -> Self {
        Self {
            root: Node::Empty,
            root_hash: keccak(&rlp::NULL_RLP),

            cache: HashMap::new(),
            passing_keys: HashSet::new(),
            gen_keys: HashSet::new(),

            db,
        }
    }

    pub fn root(&self) -> Node {
        self.root.clone()
    }

    pub fn at_root(&self, root_hash: H256) -> Self {
        Self {
            root: Node::from_hash(root_hash),
            root_hash,

            cache: HashMap::new(),
            passing_keys: HashSet::new(),
            gen_keys: HashSet::new(),

            db: self.db.clone(),
        }
    }

    pub fn iter(&self) -> TrieIterator<D> {
        TrieIterator::new(self)
    }

    /// Returns the number of nodes stored in the backing database.
    pub fn len(&self) -> usize {
        self.db.len().unwrap_or_default()
    }

    /// Returns all values stored on the trie.
    pub fn values(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self.iter().collect())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a copy of the underlying backing database
    pub fn db(&self) -> Arc<D> {
        self.db.clone()
    }
}

impl<D> Trie<D> for InnerTrie<D>
where
    D: Database,
{
    /// Returns the value for key stored in the trie.
    fn get(&self, key: Key) -> Result<Option<Vec<u8>>> {
        let path = &Nibbles::from_raw(key, true);
        let result = self.get_at(&self.root, path, 0);

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            })
        } else {
            result
        }
    }

    /// Checks that the key is present in the trie
    fn contains(&self, key: Key) -> Result<bool> {
        let path = &Nibbles::from_raw(key, true);
        Ok(self.get_at(&self.root, path, 0)?.map_or(false, |_| true))
    }

    /// Inserts value into trie and modifies it if it exists
    fn insert(&mut self, key: Key, value: Value) -> Result<()> {
        // TODO: Consider not emptying nodes when providing empty values
        if value.is_empty() {
            return Err(TrieError::InvalidData(format!(
                "value provided for key {0:?} is empty",
                key,
            )));
        }

        let mut root = self.root.clone();
        let path = &Nibbles::from_raw(key, true);
        let result = self.insert_at(&mut root, path, 0, value.to_vec());

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            return Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            });
        }

        self.root = result?;

        self.commit()?;

        Ok(())
    }

    /// Removes any existing value for key from the trie.
    fn remove(&mut self, key: Key) -> Result<bool> {
        let path = &Nibbles::from_raw(key, true);

        let result = self.delete_at(&mut self.root.clone(), path, 0);

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            return Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            });
        }

        let (n, removed) = result?;
        self.root = n;

        self.commit()?;

        Ok(removed)
    }

    /// Saves all the nodes in the db, clears the cache data, recalculates the
    /// root. Returns the root hash of the trie.
    fn root_hash(&mut self) -> Result<H256> {
        self.commit()
    }

    /// Prove constructs a merkle proof for key. The result contains all encoded
    /// nodes on the path to the value at key. The value itself is also
    /// included in the last node and can be retrieved by verifying the
    /// proof.
    ///
    /// If the trie does not contain a value for key, the returned proof
    /// contains all nodes of the longest existing prefix of the key (at
    /// least the root node), ending with the node that proves the absence
    /// of the key.
    fn get_proof(&mut self, key: Key) -> Result<Vec<Vec<u8>>> {
        let key_path = &Nibbles::from_raw(key, true);
        let result = self.get_path_at(&self.root, key_path, 0);

        if let Err(TrieError::MissingTrieNode {
            node_hash,
            traversed,
            root_hash,
            err_key: _,
        }) = result
        {
            return Err(TrieError::MissingTrieNode {
                node_hash,
                traversed,
                root_hash,
                err_key: Some(key.to_vec()),
            });
        }

        let mut path = result?;
        match self.root {
            Node::Empty => {}
            _ => path.push(self.root.clone()),
        }

        Ok(path
            .into_iter()
            .rev()
            .map(|n| self.encode_raw(&n))
            .collect())
    }

    /// return value if key exists, None if key not exist, Error if proof is
    /// wrong
    ///
    /// Verifies whether a value exists for a key within the trie and returs its
    /// associated value if it exists, none if it doesn't or an error if the
    /// proof is invalid
    fn verify_proof(
        &self,
        root_hash: H256,
        key: &[u8],
        proof: Vec<Vec<u8>>,
    ) -> Result<Option<OwnedValue>> {
        let proof_db = Arc::new(MemoryDB::new(true));
        for node_encoded in proof.into_iter() {
            let hash = keccak(&node_encoded);

            if root_hash.eq(&hash) || node_encoded.len() >= HASHED_LENGTH {
                proof_db.insert(hash.as_bytes(), node_encoded).unwrap();
            }
        }

        // TODO: consider calling contains instead of get
        let trie = InnerTrie::new(proof_db).at_root(root_hash);
        trie.get(key).or(Err(TrieError::InvalidProof))
    }

    fn commit(&mut self) -> Result<H256> {
        let root_hash = match self.write_node(&self.root.clone()) {
            EncodedNode::Hash(hash) => hash,
            EncodedNode::Inline(encoded) => {
                let hash = keccak(&encoded);
                self.cache.insert(hash.as_bytes().to_vec(), encoded);
                hash
            }
        };

        let mut keys = Vec::with_capacity(self.cache.len());
        let mut values = Vec::with_capacity(self.cache.len());

        for (k, v) in self.cache.drain() {
            keys.push(k.to_vec());
            values.push(v);
        }

        self.db
            .insert_batch(keys, values)
            .map_err(|e| TrieError::Database(e.to_string()))?;

        let removed_keys: Vec<Vec<u8>> = self
            .passing_keys
            .iter()
            .filter(|h| !self.gen_keys.contains(&h.to_vec()))
            .map(|h| h.to_vec())
            .collect();

        self.db
            .remove_batch(&removed_keys)
            .map_err(|e| TrieError::Database(e.to_string()))?;

        self.root_hash = root_hash;
        self.gen_keys.clear();
        self.passing_keys.clear();
        self.root = self
            .recover_from_db(root_hash)?
            .expect("The root that was just created is missing");

        Ok(root_hash)
    }
}

/// InnerTrie iternals
impl<D> InnerTrie<D>
where
    D: Database,
{
    fn get_at(
        &self,
        source_node: &Node,
        path: &Nibbles,
        path_index: usize,
    ) -> Result<Option<Vec<u8>>> {
        let partial = &path.offset(path_index);
        match source_node {
            Node::Empty => Ok(None),
            Node::Leaf(leaf) => {
                if &leaf.key == partial {
                    Ok(Some(leaf.value.clone()))
                } else {
                    Ok(None)
                }
            }
            Node::Branch(branch) => {
                let borrow_branch = branch;

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(borrow_branch.value.clone())
                } else {
                    let index = partial.at(0);
                    self.get_at(&borrow_branch.children[index], path, path_index + 1)
                }
            }
            Node::Extension(extension) => self.get_extension_node(extension, path, path_index),
            Node::Hash(hash_node) => self.get_hash_node(hash_node, path, path_index),
        }
    }

    fn get_extension_node(
        &self,
        node: &ExtensionNode,
        path: &Nibbles,
        path_index: usize,
    ) -> Result<Option<Vec<u8>>> {
        let extension = node;

        let partial = &path.offset(path_index);

        let prefix = &extension.prefix;
        let match_len = partial.common_prefix(prefix);
        if match_len == prefix.len() {
            self.get_at(&extension.node, path, path_index + match_len)
        } else {
            Ok(None)
        }
    }

    fn get_hash_node(
        &self,
        node: &HashNode,
        path: &Nibbles,
        path_index: usize,
    ) -> Result<Option<Vec<u8>>> {
        let node_hash = node.hash;
        let node = self
            .recover_from_db(node_hash)?
            .ok_or_else(|| TrieError::MissingTrieNode {
                node_hash,
                traversed: Some(path.slice(0, path_index)),
                root_hash: Some(self.root_hash),
                err_key: None,
            })?;

        self.get_at(&node, path, path_index)
    }

    fn insert_at(
        &mut self,
        n: &mut Node,
        path: &Nibbles,
        path_index: usize,
        value: Vec<u8>,
    ) -> Result<Node> {
        let partial = path.offset(path_index);
        match n {
            Node::Empty => Ok(Node::from_leaf(partial, value)),
            Node::Leaf(leaf) => {
                let old_partial = &leaf.key;
                let match_index = partial.common_prefix(old_partial);
                if match_index == old_partial.len() {
                    return Ok(Node::from_leaf(leaf.key.clone(), value));
                }

                let mut branch = BranchNode {
                    children: Default::default(),
                    value: None,
                };

                let n = Node::from_leaf(old_partial.offset(match_index + 1), leaf.value.clone());
                branch.insert(old_partial.at(match_index), n)?;

                let n = Node::from_leaf(partial.offset(match_index + 1), value);
                branch.insert(partial.at(match_index), n)?;

                if match_index == 0 {
                    return Ok(Node::Branch(branch));
                }

                // if it includes a common prefix
                Ok(Node::from_extension(
                    partial.slice(0, match_index),
                    Node::Branch(branch),
                ))
            }
            Node::Branch(ref mut branch) => {
                let mut borrow_branch = branch.borrow_mut();

                if partial.at(0) == 0x10 {
                    borrow_branch.value = Some(value);
                    return Ok(Node::Branch(branch.clone()));
                }

                let mut child = borrow_branch.children[partial.at(0)].clone();
                let new_child = self.insert_at(&mut child, path, path_index + 1, value)?;
                *borrow_branch.children[partial.at(0)] = new_child;

                Ok(Node::Branch(branch.clone()))
            }
            Node::Extension(ext) => {
                let mut borrow_ext = ext.borrow_mut();

                let prefix = &borrow_ext.prefix;
                let mut sub_node = borrow_ext.node.clone();
                let match_index = partial.common_prefix(prefix);

                if match_index == 0 {
                    let mut branch = BranchNode {
                        children: Default::default(),
                        value: None,
                    };

                    branch.insert(
                        prefix.at(0),
                        if prefix.len() == 1 {
                            *sub_node
                        } else {
                            Node::from_extension(prefix.offset(1), *sub_node)
                        },
                    )?;

                    let mut node = Node::Branch(branch);

                    return self.insert_at(&mut node, path, path_index, value);
                }

                if match_index == prefix.len() {
                    let new_node =
                        self.insert_at(&mut sub_node, path, path_index + match_index, value)?;

                    return Ok(Node::from_extension(prefix.clone(), new_node));
                }

                let mut new_ext = Node::from_extension(prefix.offset(match_index), *sub_node);
                let new_node =
                    self.insert_at(&mut new_ext, path, path_index + match_index, value)?;

                borrow_ext.prefix = prefix.slice(0, match_index);
                *borrow_ext.node = new_node;

                Ok(Node::Extension(ext.clone()))
            }

            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                self.passing_keys.insert(node_hash.as_bytes().to_vec());
                let mut node =
                    self.recover_from_db(node_hash)?
                        .ok_or_else(|| TrieError::MissingTrieNode {
                            node_hash,
                            traversed: Some(path.slice(0, path_index)),
                            root_hash: Some(self.root_hash),
                            err_key: None,
                        })?;

                self.insert_at(&mut node, path, path_index, value)
            }
        }
    }

    fn delete_at(
        &mut self,
        old_node: &mut Node,
        path: &Nibbles,
        path_index: usize,
    ) -> Result<(Node, bool)> {
        let partial = &path.offset(path_index);
        let (new_node, deleted) = match old_node {
            Node::Empty => Ok((Node::Empty, false)),
            Node::Leaf(leaf) => {
                if &leaf.key == partial {
                    return Ok((Node::Empty, true));
                }
                Ok((Node::Leaf(leaf.clone()), false))
            }
            Node::Branch(branch) => {
                let mut borrow_branch = branch.borrow_mut();

                if partial.at(0) == 0x10 {
                    borrow_branch.value = None;
                    return Ok((Node::Branch(branch.clone()), true));
                }

                let index = partial.at(0);
                let child = &mut borrow_branch.children[index];

                let (new_child, deleted) = self.delete_at(child, path, path_index + 1)?;
                if deleted {
                    *borrow_branch.children[index] = new_child;
                }

                Ok((Node::Branch(branch.clone()), deleted))
            }
            Node::Extension(ext) => {
                let borrow_ext = ext.borrow_mut();

                let prefix = &borrow_ext.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    let (new_node, deleted) =
                        self.delete_at(&mut borrow_ext.node, path, path_index + match_len)?;

                    if deleted {
                        *borrow_ext.node = new_node;
                    }

                    Ok((Node::Extension(ext.clone()), deleted))
                } else {
                    Ok((Node::Extension(ext.clone()), false))
                }
            }
            Node::Hash(hash_node) => {
                let hash = hash_node.hash;
                self.passing_keys.insert(hash.as_bytes().to_vec());

                let mut node =
                    self.recover_from_db(hash)?
                        .ok_or_else(|| TrieError::MissingTrieNode {
                            node_hash: hash,
                            traversed: Some(path.slice(0, path_index)),
                            root_hash: Some(self.root_hash),
                            err_key: None,
                        })?;

                self.delete_at(&mut node, path, path_index)
            }
        }?;

        if deleted {
            Ok((self.degenerate(new_node)?, deleted))
        } else {
            Ok((new_node, deleted))
        }
    }

    // This refactors the trie after a node deletion, as necessary.
    // For example, if a deletion removes a child of a branch node, leaving only one
    // child left, it needs to be modified into an extension and maybe combined
    // with its parent and/or child node.
    fn degenerate(&mut self, n: Node) -> Result<Node> {
        match n {
            Node::Branch(ref branch) => {
                let borrow_branch = branch;

                let mut used_indexs = vec![];
                for (index, node) in borrow_branch.children.iter().enumerate() {
                    // TODO: cleanup this double deref
                    match **node {
                        Node::Empty => continue,
                        _ => used_indexs.push(index),
                    }
                }

                // if only a value node, transmute to leaf.
                if used_indexs.is_empty() && borrow_branch.value.is_some() {
                    let key = Nibbles::from_raw(&[], true);
                    let value = borrow_branch.value.clone().unwrap();
                    Ok(Node::from_leaf(key, value))
                // if only one node. make an extension.
                } else if used_indexs.len() == 1 && borrow_branch.value.is_none() {
                    let used_index = used_indexs[0];
                    let n = borrow_branch.children[used_index].clone();

                    let new_node = Node::from_extension(Nibbles::from_hex(&[used_index as u8]), *n);
                    self.degenerate(new_node)
                } else {
                    Ok(Node::Branch(branch.clone()))
                }
            }
            Node::Extension(ref ext) => {
                let borrow_ext = ext;

                let prefix = &borrow_ext.prefix;
                match *borrow_ext.node.clone() {
                    Node::Extension(sub_ext) => {
                        let borrow_sub_ext = sub_ext;

                        let new_prefix = prefix.join(&borrow_sub_ext.prefix);
                        let new_n = Node::from_extension(new_prefix, *borrow_sub_ext.node.clone());
                        self.degenerate(new_n)
                    }
                    Node::Leaf(leaf) => {
                        let new_prefix = prefix.join(&leaf.key);
                        Ok(Node::from_leaf(new_prefix, leaf.value.clone()))
                    }
                    // try again after recovering node from the db.
                    Node::Hash(hash_node) => {
                        let node_hash = hash_node.hash;
                        self.passing_keys.insert(node_hash.as_bytes().to_vec());

                        let new_node =
                            self.recover_from_db(node_hash)?
                                .ok_or(TrieError::MissingTrieNode {
                                    node_hash,
                                    traversed: None,
                                    root_hash: Some(self.root_hash),
                                    err_key: None,
                                })?;

                        let n = Node::from_extension(borrow_ext.prefix.clone(), new_node);
                        self.degenerate(n)
                    }
                    _ => Ok(Node::Extension(ext.clone())),
                }
            }
            _ => Ok(n),
        }
    }

    // Get nodes path along the key, only the nodes whose encode length is greater
    // than hash length are added.
    // For embedded nodes whose data are already contained in their parent node, we
    // don't need to add them in the path.
    // In the code below, we only add the nodes get by `get_node_from_hash`, because
    // they contains all data stored in db, including nodes whose encoded data
    // is less than hash length.
    fn get_path_at(
        &self,
        source_node: &Node,
        path: &Nibbles,
        path_index: usize,
    ) -> Result<Vec<Node>> {
        let partial = &path.offset(path_index);
        match source_node {
            Node::Empty | Node::Leaf(_) => Ok(vec![]),
            Node::Branch(branch) => {
                let borrow_branch = branch;

                if partial.is_empty() || partial.at(0) == 16 {
                    Ok(vec![])
                } else {
                    let node = &borrow_branch.children[partial.at(0)];
                    self.get_path_at(node, path, path_index + 1)
                }
            }
            Node::Extension(ext) => {
                let borrow_ext = ext;

                let prefix = &borrow_ext.prefix;
                let match_len = partial.common_prefix(prefix);

                if match_len == prefix.len() {
                    self.get_path_at(&borrow_ext.node, path, path_index + match_len)
                } else {
                    Ok(vec![])
                }
            }
            Node::Hash(hash_node) => {
                let node_hash = hash_node.hash;
                let n = self
                    .recover_from_db(node_hash)?
                    .ok_or(TrieError::MissingTrieNode {
                        node_hash,
                        traversed: None,
                        root_hash: Some(self.root_hash),
                        err_key: None,
                    })?;
                let mut rest = self.get_path_at(&n, path, path_index)?;
                rest.push(n);
                Ok(rest)
            }
        }
    }

    fn write_node(&mut self, to_encode: &Node) -> EncodedNode {
        // Returns the hash value directly to avoid double counting.
        if let Node::Hash(hash_node) = to_encode {
            return EncodedNode::Hash(hash_node.hash);
        }

        let data = self.encode_raw(to_encode);
        // Nodes smaller than 32 bytes are stored inside their parent,
        // Nodes equal to 32 bytes are returned directly
        if data.len() < HASHED_LENGTH {
            EncodedNode::Inline(data)
        } else {
            let hash = keccak(&data);
            self.cache.insert(hash.as_bytes().to_vec(), data);

            self.gen_keys.insert(hash.as_bytes().to_vec());
            EncodedNode::Hash(hash)
        }
    }

    fn encode_raw(&mut self, node: &Node) -> Vec<u8> {
        match node {
            Node::Empty => rlp::NULL_RLP.to_vec(),
            Node::Leaf(leaf) => {
                let mut stream = RlpStream::new_list(2);
                stream.append(&leaf.key.encode_compact());
                stream.append(&leaf.value);
                stream.out().to_vec()
            }
            Node::Branch(branch) => {
                let borrow_branch = branch;

                let mut stream = RlpStream::new_list(17);
                for i in 0..16 {
                    let n = &borrow_branch.children[i];
                    match self.write_node(n) {
                        EncodedNode::Hash(hash) => stream.append(&hash.as_bytes()),
                        EncodedNode::Inline(data) => stream.append_raw(&data, 1),
                    };
                }

                match &borrow_branch.value {
                    Some(v) => stream.append(v),
                    None => stream.append_empty_data(),
                };
                stream.out().to_vec()
            }
            Node::Extension(ext) => {
                let borrow_ext = ext;

                let mut stream = RlpStream::new_list(2);
                stream.append(&borrow_ext.prefix.encode_compact());
                match self.write_node(&borrow_ext.node) {
                    EncodedNode::Hash(hash) => stream.append(&hash.as_bytes()),
                    EncodedNode::Inline(data) => stream.append_raw(&data, 1),
                };
                stream.out().to_vec()
            }
            Node::Hash(_hash) => unreachable!(),
        }
    }

    fn decode_node(&self, data: &[u8]) -> Result<Node> {
        let r = Rlp::new(data);

        match r.prototype()? {
            Prototype::Data(0) => Ok(Node::Empty),
            Prototype::List(2) => {
                let key = r.at(0)?.data()?;
                let key = Nibbles::from_compact(key);

                if key.is_leaf() {
                    Ok(Node::from_leaf(key, r.at(1)?.data()?.to_vec()))
                } else {
                    let n = self.decode_node(r.at(1)?.as_raw())?;

                    Ok(Node::from_extension(key, n))
                }
            }
            Prototype::List(17) => {
                let mut nodes: [Box<Node>; 16] = Default::default();
                #[allow(clippy::needless_range_loop)]
                for i in 0..nodes.len() {
                    let rlp_data = r.at(i)?;
                    let n = self.decode_node(rlp_data.as_raw())?;
                    *nodes[i] = n;
                }

                // The last element is a value node.
                let value_rlp = r.at(16)?;
                let value = if value_rlp.is_empty() {
                    None
                } else {
                    Some(value_rlp.data()?.to_vec())
                };

                Ok(Node::from_branch(nodes, value))
            }
            _ => {
                if r.is_data() && r.size() == HASHED_LENGTH {
                    let hash = H256::from_slice(r.data()?);
                    Ok(Node::from_hash(hash))
                } else {
                    Err(TrieError::InvalidData(
                        "bytes cannot be decoded into a node".to_string(),
                    ))
                }
            }
        }
    }

    pub(crate) fn recover_from_db(&self, key: H256) -> Result<Option<Node>> {
        let node = match self
            .db
            .get(key.as_bytes())
            .map_err(|e| TrieError::Database(e.to_string()))?
        {
            Some(value) => Some(self.decode_node(&value)?),
            None => None,
        };
        Ok(node)
    }
}
