mod kzg_commitment;
mod kzg_proof;

#[cfg(feature = "real_crypto")]
pub mod trusted_setup;

// Always export these (pure data types, no crypto needed)
pub use crate::{
    kzg_commitment::{KzgCommitment, VERSIONED_HASH_VERSION_KZG},
    kzg_proof::KzgProof,
};

// Constants (from EIP-4844 spec, independent of c-kzg)
pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;
pub const BYTES_PER_BLOB: usize = 131072; // 4096 * 32
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
// Constants from rust_eth_kzg
pub const BYTES_PER_CELL: usize = 2048;
pub const CELLS_PER_EXT_BLOB: usize = 128;

#[cfg(feature = "real_crypto")]
mod real_crypto;
#[cfg(feature = "real_crypto")]
pub use real_crypto::*;

#[cfg(feature = "real_crypto")]
pub use trusted_setup::TrustedSetup;

#[cfg(feature = "fake_crypto")]
mod fake_crypto;
#[cfg(feature = "fake_crypto")]
pub use fake_crypto::*;
