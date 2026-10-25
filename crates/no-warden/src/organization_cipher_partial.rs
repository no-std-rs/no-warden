//! Allocation-free private annotations for personal and readable shared ciphers.
//!
//! This opt-in operation changes only the actor's favorite/folder and account
//! revision. It never replaces encrypted data or advances the cipher revision.
//! The measured partial route admits read-only members, independently of GET's
//! edit flag. Schema, transport, response projection, clocks and storage stay in
//! adapters. Broader native concurrency and client compatibility are not claimed.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherOwnership,
        CipherSharingMembership, CipherSharingSource, resolve_cipher_access,
    },
    service::require_owner,
};

/// Fully decoded annotation fields. Omitted, null and empty folder clear it.
/// No encrypted document or request-provided ownership participates in authority.
#[derive(Clone, Copy)]
pub struct CipherPartialView<'a> {
    pub folder_id: Option<&'a str>,
    pub favorite: bool,
}
impl CipherPartialView<'_> {
    fn normalized(self) -> Self {
        Self {
            folder_id: self.folder_id.filter(|id| !id.is_empty()),
            favorite: self.favorite,
        }
    }
}
impl core::fmt::Debug for CipherPartialView<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CipherPartialView([REDACTED])")
    }
}

/// Owned, cache-independent folder identity and owner, not merely a user label
/// returned for an unspecified lookup. Handles require no Clone or Debug.
pub struct CipherPartialFolder<I> {
    pub id: I,
    pub owner_id: I,
}
impl<I: AsRef<str>> CipherPartialFolder<I> {
    pub fn view(&self) -> CipherPartialFolder<&str> {
        CipherPartialFolder {
            id: self.id.as_ref(),
            owner_id: self.owner_id.as_ref(),
        }
    }
}
impl<I> core::fmt::Debug for CipherPartialFolder<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CipherPartialFolder([REDACTED])")
    }
}

/// Sealed actor-only annotation mutation. Construction follows read admission
/// and folder checks; it grants no right to alter a common cipher document.
pub struct ValidatedCipherPartial<'a> {
    actor: &'a str,
    cipher: &'a str,
    personal_owner: Option<&'a str>,
    organization: Option<&'a str>,
    revision: &'a str,
    change: CipherPartialView<'a>,
}
impl<'a> ValidatedCipherPartial<'a> {
    pub const fn actor(&self) -> &'a str {
        self.actor
    }
    pub const fn cipher_id(&self) -> &'a str {
        self.cipher
    }
    pub const fn personal_owner_id(&self) -> Option<&'a str> {
        self.personal_owner
    }
    pub const fn organization_id(&self) -> Option<&'a str> {
        self.organization
    }
    pub const fn source_revision(&self) -> &'a str {
        self.revision
    }
    pub const fn folder_id(&self) -> Option<&'a str> {
        self.change.folder_id
    }
    pub const fn favorite(&self) -> bool {
        self.change.favorite
    }
    pub const fn view(&self) -> CipherPartialView<'a> {
        self.change
    }

    /// Recheck live facts inside the provider's atomic commit. Exact source
    /// identity, canonical ownership and observed revision must remain bound;
    /// current READ admission precedes folder validation. A requested folder must
    /// be reloaded by its exact ID. Clearing needs no folder lookup.
    pub fn validate_live<I: AsRef<str>, A: CipherCollectionAccessData + ?Sized>(
        &self,
        source: &CipherSharingSource<I>,
        membership: Option<CipherSharingMembership<&str>>,
        access: &A,
        folder: Option<CipherPartialFolder<&str>>,
    ) -> Result<(), ApiError> {
        validate_source(source, self.cipher)?;
        if source.owner_id.as_ref().map(AsRef::as_ref) != self.personal_owner
            || source.organization_id.as_ref().map(AsRef::as_ref) != self.organization
            || source.revision.as_ref() != self.revision
        {
            return Err(invalid_snapshot());
        }
        authorize(self.actor, source.ownership()?, membership, access)?;
        validate_folder(self.actor, self.change.folder_id, folder)
    }
}
impl core::fmt::Debug for ValidatedCipherPartial<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherPartial([REDACTED])")
    }
}

/// Opt-in provider for actor-private annotations. All lookup snapshots own their
/// backing storage independently of subsequent cache-reusing provider calls.
/// Hold a consistent operation lock across the service, and return only trusted
/// associations for the exact source/viewer. The existing pure READ resolver
/// requires confirmed canonical membership but can union historical associated
/// grants. Historical readonly partial admission has separate native evidence;
/// configured groups and broader effective-grant combinations remain unverified.
///
/// Lookups are observational. Commit must re-read source, membership, associated
/// grants and requested folder under its transaction and call validate_live.
/// Atomically change ONLY the actor's favorite/folder and account revision.
/// Preserve common opaque encrypted bytes, key, cipher revision, ownership,
/// association links, dates, every other viewer's annotations/account revision,
/// and account keys. Advance the actor account revision even when the requested
/// annotations already equal stored values, as separately measured. Failure
/// leaves all persistent state unchanged. Native concurrency is unmeasured; these live checks and
/// rollback obligations are local provider guarantees, not native parity claims.
pub trait CipherPartialStorage: Storage {
    type PartialId: AsRef<str>;
    type PartialAccess: CipherCollectionAccessData;
    fn cipher_partial_source(
        &mut self,
        cipher: &str,
    ) -> Result<Option<CipherSharingSource<Self::PartialId>>, Self::Error>;
    fn cipher_partial_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::PartialId>>, Self::Error>;
    fn cipher_partial_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Self::PartialId>,
    ) -> Result<Self::PartialAccess, Self::Error>;
    fn cipher_partial_folder(
        &mut self,
        folder: &str,
    ) -> Result<Option<CipherPartialFolder<Self::PartialId>>, Self::Error>;
    fn commit_cipher_partial(
        &mut self,
        plan: &ValidatedCipherPartial<'_>,
    ) -> Result<(), Self::Error>;
}
impl<T: CipherPartialStorage + ?Sized> CipherPartialStorage for &mut T {
    type PartialId = T::PartialId;
    type PartialAccess = T::PartialAccess;
    fn cipher_partial_source(
        &mut self,
        cipher: &str,
    ) -> Result<Option<CipherSharingSource<Self::PartialId>>, Self::Error> {
        (**self).cipher_partial_source(cipher)
    }
    fn cipher_partial_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::PartialId>>, Self::Error> {
        (**self).cipher_partial_membership(actor, organization)
    }
    fn cipher_partial_collections(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Self::PartialId>,
    ) -> Result<Self::PartialAccess, Self::Error> {
        (**self).cipher_partial_collections(actor, source)
    }
    fn cipher_partial_folder(
        &mut self,
        folder: &str,
    ) -> Result<Option<CipherPartialFolder<Self::PartialId>>, Self::Error> {
        (**self).cipher_partial_folder(folder)
    }
    fn commit_cipher_partial(
        &mut self,
        plan: &ValidatedCipherPartial<'_>,
    ) -> Result<(), Self::Error> {
        (**self).commit_cipher_partial(plan)
    }
}

impl<S: CipherPartialStorage> VaultService<S> {
    /// Update only private annotations. Read access, not edit/manage authority,
    /// admits the measured operation for both personal and organization ciphers.
    pub fn update_cipher_private_annotations(
        &mut self,
        actor: &str,
        cipher: &str,
        change: CipherPartialView<'_>,
    ) -> Result<(), ApiError> {
        require_owner(actor)?;
        let change = change.normalized();
        let source = self
            .storage_mut()
            .cipher_partial_source(cipher)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("cipher", "Cipher doesn't exist"))?;
        validate_source(&source, cipher)?;
        let ownership = source.ownership()?;
        match ownership {
            CipherOwnership::Personal { .. } => {
                let empty: &[CipherCollectionAccessRecord<'_>] = &[];
                authorize(actor, ownership, None, empty)?;
            }
            CipherOwnership::Organization { organization_id } => {
                let member = self
                    .storage_mut()
                    .cipher_partial_membership(actor, organization_id)
                    .map_err(S::map_error)?;
                let access = self
                    .storage_mut()
                    .cipher_partial_collections(actor, &source)
                    .map_err(S::map_error)?;
                authorize(
                    actor,
                    ownership,
                    member.as_ref().map(CipherSharingMembership::view),
                    &access,
                )?;
            }
        }
        let folder = match change.folder_id {
            Some(id) => self
                .storage_mut()
                .cipher_partial_folder(id)
                .map_err(S::map_error)?,
            None => None,
        };
        validate_folder(
            actor,
            change.folder_id,
            folder.as_ref().map(CipherPartialFolder::view),
        )?;
        self.storage_mut()
            .commit_cipher_partial(&ValidatedCipherPartial {
                actor,
                cipher,
                personal_owner: source.owner_id.as_ref().map(AsRef::as_ref),
                organization: source.organization_id.as_ref().map(AsRef::as_ref),
                revision: source.revision.as_ref(),
                change,
            })
            .map_err(S::map_error)
    }
}

fn validate_source<I: AsRef<str>>(
    source: &CipherSharingSource<I>,
    cipher: &str,
) -> Result<(), ApiError> {
    if source.id.as_ref() != cipher
        || source.id.as_ref().is_empty()
        || source.revision.as_ref().is_empty()
    {
        return Err(invalid_snapshot());
    }
    source.ownership()?;
    Ok(())
}
fn authorize<A: CipherCollectionAccessData + ?Sized>(
    actor: &str,
    ownership: CipherOwnership<'_>,
    member: Option<CipherSharingMembership<&str>>,
    access: &A,
) -> Result<(), ApiError> {
    if !resolve_cipher_access(actor, ownership, member, access)?.readable() {
        return Err(ApiError::invalid("cipher", "Cipher is not read accessible"));
    }
    Ok(())
}
fn validate_folder(
    actor: &str,
    requested: Option<&str>,
    folder: Option<CipherPartialFolder<&str>>,
) -> Result<(), ApiError> {
    if let Some(id) = requested {
        if !folder.is_some_and(|f| f.id == id && f.owner_id == actor) {
            return Err(ApiError::invalid("folderId", "Invalid folder"));
        }
    }
    Ok(())
}
fn invalid_snapshot() -> ApiError {
    ApiError::new(ErrorKind::Storage, "Invalid cipher partial snapshot")
}

#[cfg(test)]
mod tests;
