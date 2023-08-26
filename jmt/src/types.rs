// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod nibble;
pub mod proof;

/// Specifies a particular version of the [`JellyfishMerkleTree`](crate::JellyfishMerkleTree) state.
#[derive(
    Default,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct Version(pub u64); // Height - also used for MVCC in StateDB
impl From<Version> for Vec<u8> {
    fn from(v: Version) -> Self {
        v.0.to_be_bytes().to_vec()
    }
}
impl From<Vec<u8>> for Version {
    fn from(v: Vec<u8>) -> Self {
        Version(u64::from_be_bytes(v.try_into().unwrap()))
    }
}

/// The version before the genesis state. This version should always be empty.
pub const PRE_GENESIS_VERSION: Version = Version(u64::max_value());
