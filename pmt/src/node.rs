use serde::{Deserialize, Serialize};
use serde_hash::H256;
use thiserror::Error;

use crate::{common::BRANCHING_FACTOR, nibbles::Nibbles};

pub type Link = Box<Node>;

pub type Result<T> = std::result::Result<T, NodeError>;

fn serialize_bytes<S>(data: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(data))
}

fn deserialize_bytes<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let data = hex::decode(s).map_err(serde::de::Error::custom)?;
    Ok(data)
}

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum NodeError {
    #[error("failed to insert node: {0}")]
    InvalidNodeInsert(String),

    #[error("unknown error ocurred: {0}")]
    Other(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum Node {
    #[default]
    Empty,
    Leaf(LeafNode),
    Extension(ExtensionNode),
    Branch(BranchNode),
    Hash(HashNode),
}

impl Node {
    pub fn from_leaf(key: Nibbles, value: Vec<u8>) -> Self {
        let leaf = LeafNode { key, value };
        Node::Leaf(leaf)
    }

    pub fn from_branch(children: [Link; BRANCHING_FACTOR], value: Option<Vec<u8>>) -> Self {
        let branch = BranchNode { children, value };
        Node::Branch(branch)
    }

    pub fn from_extension(prefix: Nibbles, node: Node) -> Self {
        let ext = ExtensionNode {
            prefix,
            node: Box::new(node),
        };

        Node::Extension(ext)
    }

    pub fn from_hash(hash: H256) -> Self {
        let hash_node = HashNode { hash };
        Node::Hash(hash_node)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafNode {
    pub key: Nibbles,
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchNode {
    pub children: [Link; BRANCHING_FACTOR],
    pub value: Option<Vec<u8>>,
}

impl BranchNode {
    /// Insert child node at index `i`.
    /// If the given index is the maximum amount of children a branch node can have
    /// the node is inserted as the branch node's value instead of as a child.
    /// Only `Node::Leaf` can be inserted into `Node::Branch`.
    pub fn insert(&mut self, i: usize, node: Node) -> Result<()> {
        if i == BRANCHING_FACTOR {
            match node {
                Node::Leaf(leaf) => {
                    self.value = Some(leaf.value.clone());
                    Ok(())
                }
                _ => Err(NodeError::InvalidNodeInsert(
                    "node must be a leaf node".into(),
                )),
            }
        } else {
            *self.children[i] = node;
            Ok(())
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ExtensionNode {
    pub prefix: Nibbles,
    pub node: Link,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashNode {
    pub hash: H256,
}
