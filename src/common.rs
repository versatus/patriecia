pub const BRANCHING_FACTOR: usize = 16;

#[cfg(feature = "bush-trees")]
pub const BRANCHING_FACTOR: usize = 256;

pub type Key<'a> = &'a [u8];
pub type Value<'a> = &'a [u8];
pub type OwnedValue = Vec<u8>;
pub type OwnedKey = Vec<u8>;
pub type Proof = Vec<u8>;
