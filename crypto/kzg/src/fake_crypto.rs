//! Fake KZG implementation for C-compiler-free builds.
//!
//! All verification functions return success, all computation functions
//! return placeholder values.

use crate::{KzgCommitment, KzgProof, BYTES_PER_BLOB, BYTES_PER_CELL, CELLS_PER_EXT_BLOB};
use std::fmt::Debug;

pub type Blob = [u8; BYTES_PER_BLOB];
pub type Bytes32 = [u8; 32];
pub type Bytes48 = [u8; 48];
pub type Cell = [u8; BYTES_PER_CELL];
pub type CellRef<'a> = &'a Cell;
pub type CellIndex = u64;
pub type CellsAndKzgProofs = ([Cell; CELLS_PER_EXT_BLOB], [KzgProof; CELLS_PER_EXT_BLOB]);
pub type KzgBlobRef<'a> = &'a [u8; BYTES_PER_BLOB];

#[derive(Debug)]
pub enum Error {
    /// An error from initialising the trusted setup.
    TrustedSetupError(String),
    /// The kzg verification failed
    KzgVerificationFailed,
    /// Misc indexing error
    InconsistentArrayLength(String),
    /// Error reconstructing data columns.
    ReconstructFailed(String),
    /// Kzg was not initialized with PeerDAS enabled.
    DASContextUninitialized,
}

/// Fake Kzg context that does no real cryptographic operations.
#[derive(Debug, Clone)]
pub struct Kzg;

impl Kzg {
    pub fn new_from_trusted_setup(_trusted_setup: &[u8]) -> Result<Self, Error> {
        Ok(Self)
    }

    pub fn new_from_trusted_setup_no_precomp(_trusted_setup: &[u8]) -> Result<Self, Error> {
        Ok(Self)
    }

    /// Compute the kzg proof given a blob and its kzg commitment.
    pub fn compute_blob_kzg_proof(
        &self,
        _blob: &Blob,
        _kzg_commitment: KzgCommitment,
    ) -> Result<KzgProof, Error> {
        Ok(KzgProof([0u8; 48]))
    }

    /// Verify a kzg proof given the blob, kzg commitment and kzg proof.
    pub fn verify_blob_kzg_proof(
        &self,
        _blob: &Blob,
        _kzg_commitment: KzgCommitment,
        _kzg_proof: KzgProof,
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Verify a batch of blob commitment proof triplets.
    pub fn verify_blob_kzg_proof_batch(
        &self,
        _blobs: &[Blob],
        _kzg_commitments: &[KzgCommitment],
        _kzg_proofs: &[KzgProof],
    ) -> Result<(), Error> {
        Ok(())
    }

    /// Converts a blob to a kzg commitment.
    pub fn blob_to_kzg_commitment(&self, _blob: &Blob) -> Result<KzgCommitment, Error> {
        Ok(KzgCommitment([0u8; 48]))
    }

    /// Computes the kzg proof for a given `blob` and an evaluation point `z`
    pub fn compute_kzg_proof(
        &self,
        _blob: &Blob,
        _z: &Bytes32,
    ) -> Result<(KzgProof, Bytes32), Error> {
        Ok((KzgProof([0u8; 48]), [0u8; 32]))
    }

    /// Verifies a `kzg_proof` for a `kzg_commitment` that evaluating a polynomial at `z` results in `y`
    pub fn verify_kzg_proof(
        &self,
        _kzg_commitment: KzgCommitment,
        _z: &Bytes32,
        _y: &Bytes32,
        _kzg_proof: KzgProof,
    ) -> Result<bool, Error> {
        Ok(true)
    }

    /// Computes the cells and associated proofs for a given `blob`.
    pub fn compute_cells_and_proofs(
        &self,
        _blob: KzgBlobRef<'_>,
    ) -> Result<CellsAndKzgProofs, Error> {
        Ok((
            [[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB],
            [KzgProof([0u8; 48]); CELLS_PER_EXT_BLOB],
        ))
    }

    /// Computes the cells for a given `blob`.
    pub fn compute_cells(&self, _blob: KzgBlobRef<'_>) -> Result<[Cell; CELLS_PER_EXT_BLOB], Error> {
        Ok([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB])
    }

    /// Verifies a batch of cell-proof-commitment triplets.
    pub fn verify_cell_proof_batch(
        &self,
        cells: &[CellRef<'_>],
        kzg_proofs: &[Bytes48],
        indices: Vec<CellIndex>,
        kzg_commitments: &[Bytes48],
    ) -> Result<(), (Option<u64>, Error)> {
        let expected_len = cells.len();

        if kzg_proofs.len() != expected_len
            || indices.len() != expected_len
            || kzg_commitments.len() != expected_len
        {
            return Err((
                None,
                Error::InconsistentArrayLength("Invalid data column".to_string()),
            ));
        }

        Ok(())
    }

    pub fn recover_cells_and_compute_kzg_proofs(
        &self,
        _cell_ids: &[u64],
        _cells: &[CellRef<'_>],
    ) -> Result<CellsAndKzgProofs, Error> {
        Ok((
            [[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB],
            [KzgProof([0u8; 48]); CELLS_PER_EXT_BLOB],
        ))
    }
}
