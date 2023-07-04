//! An adaptation of the original `keccak` function and `H256` type
//! that handles the implementation of `serde`.

use fixed_hash::construct_fixed_hash;
use keccak_hash::write_keccak;
use serde::{Deserialize, Serialize};

construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 32 bytes (256 bits) size.
    ///
    /// This type is an adaptation of `keccak::H256` that accounts for the `serde` derive macros
    /// that are used within the `pmt` portion of the `patriecia` library.
    #[cfg_attr(feature = "scale-info", derive(TypeInfo))]
    #[derive(Serialize, Deserialize)]
    pub struct H256(32);
}

/// An adaptation of the `keccak_hash::keccak` function that returns
/// a [serde_hash::H256].
pub fn keccak<T: AsRef<[u8]>>(s: T) -> crate::serde_hash::H256 {
    let mut result = [0u8; 32];
    write_keccak(s, &mut result);
    crate::serde_hash::H256(result)
}
