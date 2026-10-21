//! Opt-in actor-private archive annotations for personal and readable shared ciphers.
//!
//! Native single and selected routes have distinct account-revision effects. Neither
//! changes the common encrypted document or cipher revision. Storage, timestamps,
//! response projection and current-reader enumeration remain adapter responsibilities.
//! Native evidence covers admission failures, not backend failure atomicity: the
//! provider's atomic commit/live rechecks below are explicit local guarantees.

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
    Selected(&'a [Option<CipherSharingSource<I>>]),
}

/// Sealed annotation-only commit. Sorted selection order is a local deterministic
/// representation, not an upstream ordering guarantee between successful targets.
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
            Targets::Selected(_) => CipherArchiveRevisionEffect::ActorOnly,
        }
    }
    pub const fn len(&self) -> usize {
        match self.targets {
            Targets::Single(_) => 1,
            Targets::Selected(rows) => rows.len(),
        }
    }
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn target(&self, index: usize) -> Option<CipherArchiveTarget<'_>> {
        let source = match self.targets {
            Targets::Single(source) => (index == 0).then_some(source),
            Targets::Selected(rows) => rows.get(index).and_then(Option::as_ref),
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
/// Commit must load CURRENT source/membership/associated grants, validate every
/// sealed target with validate_live BEFORE any write, then atomically mutate only
/// the actor's archive annotation and the specified account revisions. Archive sets
/// a fresh adapter timestamp (including repeat); Unarchive clears it (including
/// repeat). SINGLE advances every current READ accessor's account revision;
/// SELECTED advances only the actor, once for a nonempty deduplicated selection.
/// Enumerate viewers and resolve READ under the same transaction; no-grant,
/// accepted and revoked canonical members are not current readers.
///
/// Preserve current common opaque document/keys, cipher revision, ownership,
/// collections, deletion state, favorite/folder, other viewers' archive/private
/// annotations and account keys. No empty selection is committed. Errors roll back
/// ALL annotation/revision changes; notifications follow successful commit. These
/// local rollback/live-check contracts do not claim native backend failure parity.
/// Groups, historical-grant archive variants and broader lifecycle remain unproven.
pub trait CipherArchiveStorage: Storage {
    type ArchiveId: AsRef<str>;
    type ArchiveAccess: CipherCollectionAccessData;
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
    /// must cover RAW input including duplicates; source slots must cover UNIQUE
    /// IDs. Strings remain exact and unnormalized. No intrinsic count/ID cap.
    /// Insufficient scratch fails before provider writes. Scratch contents are
    /// unspecified on error (including retained owned snapshots), never storage.
    /// Returned-count ID slots contain sorted unique response-lookup IDs; native
    /// distinct-target response order is unmeasured. Whole selection admission
    /// precedes the single provider commit; empty input performs no lookups/writes.
    pub fn archive_selected_ciphers<'ids>(
        &mut self,
        actor: &str,
        operation: CipherArchiveOperation,
        ids: impl IntoIterator<Item = &'ids str>,
        id_scratch: &mut [&'ids str],
        source_scratch: &mut [Option<CipherSharingSource<S::ArchiveId>>],
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
        if source_scratch.len() < unique {
            return Err(scratch_too_small());
        }
        if unique == 0 {
            return Ok(0);
        }
        let sources = &mut source_scratch[..unique];
        for (id, slot) in selected[..unique].iter().zip(sources.iter_mut()) {
            *slot = Some(self.admit_archive(actor, id)?);
        }
        self.storage_mut()
            .commit_cipher_archive(&ValidatedCipherArchive {
                actor,
                operation,
                targets: Targets::Selected(sources),
            })
            .map_err(S::map_error)?;
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
