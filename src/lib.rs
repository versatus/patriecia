/// heavily inspired by https://github.com/carver/eth-trie.rs which is a fork of https://github.com/citahub/cita-trie
///
pub mod db;
pub mod error;
pub mod inner;
pub mod result;
pub mod trie;

pub mod common;
mod trie_iterator;
pub use trie_iterator::*;

pub(crate) mod nibbles;
pub(crate) mod node;

pub use keccak_hash::H256;
