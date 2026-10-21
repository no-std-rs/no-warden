//! Opt-in actor-private archive annotations for personal and readable shared ciphers.
//!
//! Native single and selected routes have distinct account-revision effects. Neither
//! changes the common encrypted document or cipher revision. Storage, timestamps,
//! response projection and current-reader enumeration remain adapter responsibilities.
//! Selected operations commit readable targets in an operation-owned permutation.
//! A later error retains earlier actor-private changes/revision advances; native
//! order varies even for identical IDs and input order. Per-step atomic rollback
//! and live checks are local guarantees, not native backend/concurrency parity.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherSharingMembership,
        CipherSharingSource, resolve_cipher_access,
    },
    service::require_owner,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherArchiveOperation {
    Archive,
    Unarchive,
}

/// SINGLE refreshes all current readers' account revisions; SELECTED refreshes
/// only the actor's, even when the selection contains exactly one cipher.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherArchiveRevisionEffect {
    CurrentReaders,
    ActorOnly,
}

/// One sealed admitted source. It carries no encrypted payload or mutation date.
#[derive(Clone, Copy)]
pub struct CipherArchiveTarget<'a> {
    actor: &'a str,
    cipher: &'a str,
    owner: Option<&'a str>,
    organization: Option<&'a str>,
    revision: &'a str,
}
impl<'a> CipherArchiveTarget<'a> {
    pub const fn cipher_id(&self) -> &'a str {
        self.cipher
    }
    pub const fn personal_owner_id(&self) -> Option<&'a str> {
        self.owner
    }
    pub const fn organization_id(&self) -> Option<&'a str> {
        self.organization
    }
    pub const fn source_revision(&self) -> &'a str {
        self.revision
    }

    /// Recheck exact source identity/canonical ownership/revision and current READ
    /// admission inside the provider's transaction, before any mutation. Association
    /// facts must be for this exact cipher/viewer, with the canonical outer scope.
    pub fn validate_live<I: AsRef<str>, A: CipherCollectionAccessData + ?Sized>(
        &self,
        source: &CipherSharingSource<I>,
        membership: Option<CipherSharingMembership<&str>>,
        access: &A,
    ) -> Result<(), ApiError> {
        validate_source(source, self.cipher)?;
        if source.owner_id.as_ref().map(AsRef::as_ref) != self.owner
            || source.organization_id.as_ref().map(AsRef::as_ref) != self.organization
            || source.revision.as_ref() != self.revision
        {
            return Err(invalid_snapshot());
        }
        authorize(self.actor, source, membership, access)
    }
}
impl core::fmt::Debug for CipherArchiveTarget<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CipherArchiveTarget([REDACTED])")
    }
}

enum Targets<'a, I> {
    Single(&'a CipherSharingSource<I>),
    SelectedOne(&'a CipherSharingSource<I>),
}

/// One sealed annotation-only commit. The selected variant is one durable step,
/// not a whole-selection transaction or a native processing-order guarantee.
pub struct ValidatedCipherArchive<'a, I> {
    actor: &'a str,
    operation: CipherArchiveOperation,
    targets: Targets<'a, I>,
}
impl<I: AsRef<str>> ValidatedCipherArchive<'_, I> {
    pub const fn actor(&self) -> &str {
        self.actor
    }
    pub const fn operation(&self) -> CipherArchiveOperation {
        self.operation
    }
    pub const fn revision_effect(&self) -> CipherArchiveRevisionEffect {
        match self.targets {
            Targets::Single(_) => CipherArchiveRevisionEffect::CurrentReaders,
            Targets::SelectedOne(_) => CipherArchiveRevisionEffect::ActorOnly,
        }
    }
    pub const fn len(&self) -> usize {
        1
    }
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn target(&self, index: usize) -> Option<CipherArchiveTarget<'_>> {
        let source = match self.targets {
            Targets::Single(source) | Targets::SelectedOne(source) => {
                (index == 0).then_some(source)
            }
        }?;
        Some(CipherArchiveTarget {
            actor: self.actor,
            cipher: source.id.as_ref(),
            owner: source.owner_id.as_ref().map(AsRef::as_ref),
            organization: source.organization_id.as_ref().map(AsRef::as_ref),
            revision: source.revision.as_ref(),
        })
    }
}
impl<I> core::fmt::Debug for ValidatedCipherArchive<'_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherArchive([REDACTED])")
    }
}

/// All observational snapshots own backing storage independent of later cache-
/// reusing provider calls. Hold a consistent lock across admission and commit.
///
/// Commit must load CURRENT source/membership/associated grants, validate its
/// sealed target with validate_live BEFORE any write, then atomically mutate only
/// the actor's archive annotation and the specified account revisions. Archive sets
/// a fresh adapter timestamp (including repeat); Unarchive clears it (including
/// repeat). SINGLE advances every current READ accessor's account revision;
/// SELECTED advances only the actor once PER admitted unique target, including
/// annotation no-ops. Each selected commit is durable before the next lookup.
/// Enumerate viewers and resolve READ under the same transaction; no-grant,
/// accepted and revoked canonical members are not current readers.
///
/// Preserve current common opaque document/keys, cipher revision, ownership,
/// collections, deletion state, favorite/folder, other viewers' archive/private
/// annotations and account keys. No empty selection is committed. Errors roll back
/// the failing STEP's annotation/revision changes, retaining earlier successful
/// selected steps. Notifications follow each successful commit. These local
/// rollback/live-check contracts do not claim native backend failure parity.
/// Groups, historical-grant archive variants and broader lifecycle remain unproven.
pub trait CipherArchiveStorage: Storage {
    type ArchiveId: AsRef<str>;
    type ArchiveAccess: CipherCollectionAccessData;
    /// Stable owned permutation; no borrow of a cache later lookups can reuse.
    type ArchiveOrder: AsRef<[usize]>;
    /// Observational operation order over the supplied sorted UNIQUE exact IDs.
    /// Return every index once. The service validates it before any target lookup
    /// or write. Native permutation/distribution is not prescribed by this API.
    fn cipher_archive_order(
        &mut self,
        actor: &str,
        operation: CipherArchiveOperation,
        sorted_unique_ids: &[&str],
    ) -> Result<Self::ArchiveOrder, Self::Error>;
    fn cipher_archive_source(
        &mut self,
        cipher: &str,
    ) -> Result<Option<CipherSharingSource<Self::ArchiveId>>, Self::Error>;
    fn cipher_archive_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::ArchiveId>>, Self::Error>;
    fn cipher_archive_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Self::ArchiveId>,
    ) -> Result<Self::ArchiveAccess, Self::Error>;
    fn commit_cipher_archive(
        &mut self,
        plan: &ValidatedCipherArchive<'_, Self::ArchiveId>,
    ) -> Result<(), Self::Error>;
}
impl<T: CipherArchiveStorage + ?Sized> CipherArchiveStorage for &mut T {
    type ArchiveId = T::ArchiveId;
    type ArchiveAccess = T::ArchiveAccess;
    type ArchiveOrder = T::ArchiveOrder;
    fn cipher_archive_order(
        &mut self,
        actor: &str,
        operation: CipherArchiveOperation,
        sorted_unique_ids: &[&str],
    ) -> Result<Self::ArchiveOrder, Self::Error> {
        (**self).cipher_archive_order(actor, operation, sorted_unique_ids)
    }
    fn cipher_archive_source(
        &mut self,
        cipher: &str,
    ) -> Result<Option<CipherSharingSource<Self::ArchiveId>>, Self::Error> {
        (**self).cipher_archive_source(cipher)
    }
    fn cipher_archive_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::ArchiveId>>, Self::Error> {
        (**self).cipher_archive_membership(actor, organization)
    }
    fn cipher_archive_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Self::ArchiveId>,
    ) -> Result<Self::ArchiveAccess, Self::Error> {
        (**self).cipher_archive_collections(actor, source)
    }
    fn commit_cipher_archive(
        &mut self,
        plan: &ValidatedCipherArchive<'_, Self::ArchiveId>,
    ) -> Result<(), Self::Error> {
        (**self).commit_cipher_archive(plan)
    }
}

impl<S: CipherArchiveStorage> VaultService<S> {
    pub fn archive_cipher(
        &mut self,
        actor: &str,
        cipher: &str,
        operation: CipherArchiveOperation,
    ) -> Result<(), ApiError> {
        require_owner(actor)?;
        let source = self.admit_archive(actor, cipher)?;
        self.storage_mut()
            .commit_cipher_archive(&ValidatedCipherArchive {
                actor,
                operation,
                targets: Targets::Single(&source),
            })
            .map_err(S::map_error)
    }

    /// Reuse the existing selected-ID body with caller-owned scratch. ID capacity
    /// covers RAW input including duplicates; bool capacity covers UNIQUE IDs.
    /// Exact strings are never normalized; the core has no intrinsic count cap.
    /// Copy/sort/dedup and validate the complete provider-owned permutation before
    /// any target admission/write. Scratch contents are unspecified on error.
    ///
    /// Each ordered target is freshly READ-admitted and committed as one sealed
    /// ActorOnly step, even for annotation no-ops. Later failures retain earlier
    /// successful steps. Empty input performs no provider calls. Returned-count
    /// ID slots contain sorted unique response-lookup IDs, not native order.
    pub fn archive_selected_ciphers<'ids>(
        &mut self,
        actor: &str,
        operation: CipherArchiveOperation,
        ids: impl IntoIterator<Item = &'ids str>,
        id_scratch: &mut [&'ids str],
        seen_scratch: &mut [bool],
    ) -> Result<usize, ApiError> {
        require_owner(actor)?;
        let mut count = 0;
        for id in ids {
            let slot = id_scratch.get_mut(count).ok_or_else(scratch_too_small)?;
            *slot = id;
            count += 1;
        }
        let selected = &mut id_scratch[..count];
        selected.sort_unstable();
        let mut unique = 0;
        for index in 0..selected.len() {
            if unique == 0 || selected[index] != selected[unique - 1] {
                selected[unique] = selected[index];
                unique += 1;
            }
        }
        if seen_scratch.len() < unique {
            return Err(scratch_too_small());
        }
        if unique == 0 {
            return Ok(0);
        }
        let selected = &selected[..unique];
        let order = self
            .storage_mut()
            .cipher_archive_order(actor, operation, selected)
            .map_err(S::map_error)?;
        let order = order.as_ref();
        let seen = &mut seen_scratch[..unique];
        seen.fill(false);
        if order.len() != unique {
            return Err(invalid_snapshot());
        }
        for &index in order {
            let slot = seen.get_mut(index).ok_or_else(invalid_snapshot)?;
            if *slot {
                return Err(invalid_snapshot());
            }
            *slot = true;
        }
        for &index in order {
            let source = self.admit_archive(actor, selected[index])?;
            self.storage_mut()
                .commit_cipher_archive(&ValidatedCipherArchive {
                    actor,
                    operation,
                    targets: Targets::SelectedOne(&source),
                })
                .map_err(S::map_error)?;
        }
        Ok(unique)
    }

    fn admit_archive(
        &mut self,
        actor: &str,
        cipher: &str,
    ) -> Result<CipherSharingSource<S::ArchiveId>, ApiError> {
        let source = self
            .storage_mut()
            .cipher_archive_source(cipher)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("cipher", "Cipher doesn't exist"))?;
        validate_source(&source, cipher)?;
        match source.organization_id.as_ref() {
            Some(organization) => {
                let member = self
                    .storage_mut()
                    .cipher_archive_membership(actor, organization.as_ref())
                    .map_err(S::map_error)?;
                let access = self
                    .storage_mut()
                    .cipher_archive_collections(actor, &source)
                    .map_err(S::map_error)?;
                authorize(
                    actor,
                    &source,
                    member.as_ref().map(CipherSharingMembership::view),
                    &access,
                )?;
            }
            None => {
                let empty: &[CipherCollectionAccessRecord<'_>] = &[];
                authorize(actor, &source, None, empty)?;
            }
        }
        Ok(source)
    }
}
fn validate_source<I: AsRef<str>>(
    source: &CipherSharingSource<I>,
    expected: &str,
) -> Result<(), ApiError> {
    if expected.is_empty() || source.id.as_ref() != expected || source.revision.as_ref().is_empty()
    {
        return Err(invalid_snapshot());
    }
    source.ownership()?;
    Ok(())
}
fn authorize<I: AsRef<str>, A: CipherCollectionAccessData + ?Sized>(
    actor: &str,
    source: &CipherSharingSource<I>,
    membership: Option<CipherSharingMembership<&str>>,
    access: &A,
) -> Result<(), ApiError> {
    if !resolve_cipher_access(actor, source.ownership()?, membership, access)?.readable() {
        return Err(ApiError::invalid("cipher", "Cipher is not read accessible"));
    }
    Ok(())
}
fn scratch_too_small() -> ApiError {
    ApiError::invalid("ids", "The archive selection buffer is too small.")
}
fn invalid_snapshot() -> ApiError {
    ApiError::new(ErrorKind::Storage, "Invalid cipher archive snapshot")
}

#[cfg(test)]
mod tests;
