use rlp::DecoderError;
use serde_hash::H256;
use thiserror::Error;

use crate::{nibbles::Nibbles, node::NodeError};

#[derive(Error, Debug, Clone, Eq, PartialEq)]
pub enum TrieError {
    #[error("invalid data: {0}")]
    InvalidData(String),

    #[error("invalid proof")]
    InvalidProof,

    #[error("missing node {node_hash:?}, root: {root_hash:?}")]
    MissingTrieNode {
        node_hash: H256,
        traversed: Option<Nibbles>,
        root_hash: Option<H256>,
        err_key: Option<Vec<u8>>,
    },

    #[error("database error: {0}")]
    Database(String),

    #[error("decoder error: {0}")]
    Decoder(#[from] DecoderError),

    #[error("node error: {0}")]
    NodeError(#[from] NodeError),
}

#[derive(Error, Debug, Clone)]
pub enum MemDBError {}
