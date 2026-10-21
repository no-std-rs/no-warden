//! Allocation-free ordinary updates of an existing organization-owned cipher.
//!
//! The adapter decodes every required field before calling this opt-in service and
//! retains the complete opaque payload. Core decisions follow the measured order:
//! source write authority, optional older-revision rejection, canonical organization
//! match, actor-owned folder, then required nonnull secure-note data. One provider
//! commit owns all persistence effects.
//! Personal updates, GET edit flags, crypto, date parsing and clocks are unchanged.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    organization_cipher_bulk_sharing::resolve_bulk_cipher_source_write_access,
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherOwnership, CipherSharingMembership, CipherSharingSource,
    },
    service::require_owner,
};

/// Decision fields from a fully structurally decoded request. Missing/null folder
/// means clear the acting viewer's folder. Missing/null revision imposes no older-
/// revision check. The source path, not a nested request ID, controls identity.
#[derive(Clone, Copy)]
pub struct OrganizationCipherUpdateView<'a> {
    pub organization_id: Option<&'a str>,
    pub folder_id: Option<&'a str>,
    pub last_known_revision_date: Option<&'a str>,
    /// A nonnull secure-note value; shape/normalization remains adapter-owned.
    pub secure_note_present: bool,
}
impl core::fmt::Debug for OrganizationCipherUpdateView<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationCipherUpdateView([REDACTED])")
    }
}

/// Stable caller-owned input. Required schema/type/opaque payload validation must
/// finish before this service. The view and payload must remain unchanged through
/// commit, and the adapter must not serialize this narrow view as a full cipher.
pub trait OrganizationCipherUpdateData {
    fn update_view(&self) -> OrganizationCipherUpdateView<'_>;
}
impl<T: OrganizationCipherUpdateData + ?Sized> OrganizationCipherUpdateData for &T {
    fn update_view(&self) -> OrganizationCipherUpdateView<'_> {
        (**self).update_view()
    }
}

/// Operation-local authorization. All fields are private and construction follows
/// every guard. This is not durable authority: persistence must recheck live facts
/// atomically. The exact original request remains available without copying it.
pub struct ValidatedOrganizationCipherUpdate<'a, D: ?Sized> {
    owner: &'a str,
    cipher: &'a str,
    organization: &'a str,
    revision: &'a str,
    update: OrganizationCipherUpdateView<'a>,
    request: &'a D,
}
impl<'a, D: ?Sized> ValidatedOrganizationCipherUpdate<'a, D> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub const fn cipher_id(&self) -> &'a str {
        self.cipher
    }
    pub const fn organization_id(&self) -> &'a str {
        self.organization
    }
    pub const fn source_revision(&self) -> &'a str {
        self.revision
    }
    pub const fn folder_id(&self) -> Option<&'a str> {
        self.update.folder_id
    }
    pub const fn last_known_revision_date(&self) -> Option<&'a str> {
        self.update.last_known_revision_date
    }
    pub const fn view(&self) -> OrganizationCipherUpdateView<'a> {
        self.update
    }
    pub const fn request(&self) -> &'a D {
        self.request
    }
}
impl<D: ?Sized> core::fmt::Debug for ValidatedOrganizationCipherUpdate<'_, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationCipherUpdate([REDACTED])")
    }
}

/// Opt-in provider for the measured ordinary shared-update subset. Return source,
/// membership and access snapshots with owned backing storage independent of later
/// cache-reusing calls. Hold a consistent operation lock across the service call.
/// Indexed collection facts have no intrinsic count or identifier-size limit.
///
/// Source-write decisions reuse the bulk source predicate: confirmed canonical
/// membership plus full access, writable associated access, or an assigned manage
/// grant. In particular read_only+manage permits PUT while ordinary GET edit stays
/// false. This reuse does not establish historical-grant, group or policy parity.
///
/// All lookups/comparison are observational and must not mutate stored data. Date
/// parsing stays here: a parseable older request is rejected, while malformed and
/// future values are accepted in the measured subset. The comparison hook is called
/// only when the request supplies a nonnull string, never as an equality-CAS rule.
///
/// Commit must atomically recheck canonical organization ownership, source identity
/// and observed revision, current write authority, request organization, folder
/// ownership and the older-only condition. Apply the exact opaque original payload,
/// preserving identity, canonical organization, association links, creation/deletion
/// metadata, every other viewer's private annotations and account key material.
/// Missing/null favorite preserves the acting viewer's previous favorite; folder
/// omission/null clears only that viewer's folder. Advance the common cipher revision
/// and eligible accessor account revisions in the same transaction. A failed commit
/// must leave payload, annotations and every affected revision unchanged. Local live
/// checks/rollback do not prove upstream provider-failure or concurrency behavior.
pub trait OrganizationCipherUpdateStorage: Storage {
    type UpdateId: AsRef<str>;
    type UpdateAccess: CipherCollectionAccessData;
    fn organization_cipher_update_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::UpdateId>>, Self::Error>;
    fn organization_cipher_update_membership(
        &mut self,
        user: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::UpdateId>>, Self::Error>;
    fn organization_cipher_update_collections(
        &mut self,
        user: &str,
        source: &CipherSharingSource<Self::UpdateId>,
    ) -> Result<Self::UpdateAccess, Self::Error>;
    fn organization_cipher_update_revision_is_older(
        &mut self,
        source: &CipherSharingSource<Self::UpdateId>,
        requested: Option<&str>,
    ) -> Result<bool, Self::Error>;
    fn commit_organization_cipher_update<D: OrganizationCipherUpdateData + ?Sized>(
        &mut self,
        plan: &ValidatedOrganizationCipherUpdate<'_, D>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationCipherUpdateStorage + ?Sized> OrganizationCipherUpdateStorage for &mut T {
    type UpdateId = T::UpdateId;
    type UpdateAccess = T::UpdateAccess;
    fn organization_cipher_update_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::UpdateId>>, Self::Error> {
        (**self).organization_cipher_update_source(id)
    }
    fn organization_cipher_update_membership(
        &mut self,
        user: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::UpdateId>>, Self::Error> {
        (**self).organization_cipher_update_membership(user, organization)
    }
    fn organization_cipher_update_collections(
        &mut self,
        user: &str,
        source: &CipherSharingSource<Self::UpdateId>,
    ) -> Result<Self::UpdateAccess, Self::Error> {
        (**self).organization_cipher_update_collections(user, source)
    }
    fn organization_cipher_update_revision_is_older(
        &mut self,
        source: &CipherSharingSource<Self::UpdateId>,
        requested: Option<&str>,
    ) -> Result<bool, Self::Error> {
        (**self).organization_cipher_update_revision_is_older(source, requested)
    }
    fn commit_organization_cipher_update<D: OrganizationCipherUpdateData + ?Sized>(
        &mut self,
        plan: &ValidatedOrganizationCipherUpdate<'_, D>,
    ) -> Result<(), Self::Error> {
        (**self).commit_organization_cipher_update(plan)
    }
}

impl<S: OrganizationCipherUpdateStorage> VaultService<S> {
    /// Authorize an ordinary update of a shared source without adding/removing its
    /// collection links or changing ownership. Personal-only APIs remain separate.
    pub fn update_organization_cipher<D: OrganizationCipherUpdateData + ?Sized>(
        &mut self,
        owner: &str,
        cipher_id: &str,
        request: &D,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let update = request.update_view();
        let source = self
            .storage_mut()
            .organization_cipher_update_source(cipher_id)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("cipher", "Cipher doesn't exist"))?;
        if source.id.as_ref() != cipher_id || source.revision.as_ref().is_empty() {
            return Err(invalid_snapshot());
        }
        let ownership = source.ownership()?;
        let CipherOwnership::Organization { organization_id } = ownership else {
            return Err(denied());
        };
        let membership = self
            .storage_mut()
            .organization_cipher_update_membership(owner, organization_id)
            .map_err(S::map_error)?;
        let access = self
            .storage_mut()
            .organization_cipher_update_collections(owner, &source)
            .map_err(S::map_error)?;
        if !resolve_bulk_cipher_source_write_access(
            owner,
            ownership,
            membership.as_ref().map(CipherSharingMembership::view),
            &access,
        )? {
            return Err(denied());
        }
        if let Some(revision) = update.last_known_revision_date {
            if self
                .storage_mut()
                .organization_cipher_update_revision_is_older(&source, Some(revision))
                .map_err(S::map_error)?
            {
                return Err(ApiError::invalid(
                    "lastKnownRevisionDate",
                    "Cipher revision is older than the stored revision",
                ));
            }
        }
        if update.organization_id != Some(organization_id) {
            return Err(ApiError::invalid(
                "organizationId",
                "Organization mismatch. Please resync the client before updating the cipher",
            ));
        }
        if let Some(folder) = update.folder_id {
            if !self
                .storage_mut()
                .folder_metadata(folder)
                .map_err(S::map_error)?
                .is_some_and(|metadata| metadata.owner_id == owner)
            {
                return Err(ApiError::invalid("folderId", "Invalid folder"));
            }
        }
        if !update.secure_note_present {
            return Err(ApiError::invalid(
                "secureNote",
                "Secure note data is required",
            ));
        }
        self.storage_mut()
            .commit_organization_cipher_update(&ValidatedOrganizationCipherUpdate {
                owner,
                cipher: cipher_id,
                organization: organization_id,
                revision: source.revision.as_ref(),
                update,
                request,
            })
            .map_err(S::map_error)
    }
}
fn denied() -> ApiError {
    ApiError::invalid("cipher", "Cipher is not write accessible")
}
fn invalid_snapshot() -> ApiError {
    ApiError::new(
        ErrorKind::Storage,
        "Invalid organization cipher update snapshot",
    )
}

#[cfg(test)]
mod tests;
