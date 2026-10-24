//! Allocation-free bulk cipher sharing over caller-owned opaque payloads.
//!
//! The measured native endpoint processes ciphers backwards and collections forwards.
//! Successful association steps and complete earlier cipher updates survive later
//! errors. This is a separate service from strict personal and single sharing APIs:
//! required names are opaque strings, encryptedFor is ignored, and shared sources
//! can be updated. Transport, crypto, persistence and clocks remain adapters.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherOwnership, CipherSharingCollection,
        CipherSharingMembership, CipherSharingSource, resolve_cipher_access,
    },
    service::require_owner,
};

/// Structurally decoded item. Required type/name are represented without imposing
/// the personal API's encrypted-name validation. The full opaque item stays in D.
#[derive(Clone, Copy)]
pub struct CipherBulkShareItem<'a> {
    pub id: Option<&'a str>,
    pub cipher_type: i32,
    pub name: &'a str,
    pub organization_id: Option<&'a str>,
    pub folder_id: Option<&'a str>,
}
/// An embedding's typed item supplies only the fields the core needs for decisions.
pub trait CipherBulkShareItemData {
    fn bulk_share_item(&self) -> CipherBulkShareItem<'_>;
}
impl CipherBulkShareItemData for CipherBulkShareItem<'_> {
    fn bulk_share_item(&self) -> CipherBulkShareItem<'_> {
        *self
    }
}

/// Stable, fully decoded indexed input. Every index below either length must exist
/// throughout this operation. Repeated IDs are processed, not deduplicated. The
/// service imposes no transport/batch capacity; a decoder may choose its own bounds.
pub trait CipherBulkSharingData {
    fn ciphers_len(&self) -> usize;
    fn cipher(&self, index: usize) -> Option<CipherBulkShareItem<'_>>;
    fn collections_len(&self) -> usize;
    fn collection(&self, index: usize) -> Option<&str>;
}
impl<T: CipherBulkSharingData + ?Sized> CipherBulkSharingData for &T {
    fn ciphers_len(&self) -> usize {
        (**self).ciphers_len()
    }
    fn cipher(&self, index: usize) -> Option<CipherBulkShareItem<'_>> {
        (**self).cipher(index)
    }
    fn collections_len(&self) -> usize {
        (**self).collections_len()
    }
    fn collection(&self, index: usize) -> Option<&str> {
        (**self).collection(index)
    }
}

/// Bulk source-write authority differs from GET edit flags and collection-add
/// admission: an assigned manage grant permits updating an existing readable
/// source even when read_only is true. It never grants permission to select that
/// readonly collection as a new destination. All canonical membership/association
/// scope checks are delegated to the same pure resolver used by ordinary reads.
/// This snapshot cannot authorize later persistence without a live recheck.
pub fn resolve_bulk_cipher_source_write_access<D: CipherCollectionAccessData + ?Sized>(
    viewer: &str,
    ownership: CipherOwnership<'_>,
    membership: Option<CipherSharingMembership<&str>>,
    collections: &D,
) -> Result<bool, ApiError> {
    let access = resolve_cipher_access(viewer, ownership, membership, collections)?;
    if access.writable() {
        return Ok(true);
    }
    if !access.readable() {
        return Ok(false);
    }
    for index in 0..collections.len() {
        let row = collections
            .get(index)
            .ok_or_else(invalid_snapshot)?
            .collection;
        if row.assigned && row.manage {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A single authorized durable association. The opaque original request and item
/// index let adapters recheck exact destination admission and source authority.
pub struct ValidatedCipherBulkShareAssociation<'a, D: ?Sized> {
    owner: &'a str,
    source: &'a str,
    revision: &'a str,
    source_owner: Option<&'a str>,
    source_organization: Option<&'a str>,
    target: &'a str,
    collection: &'a str,
    index: usize,
    request: &'a D,
}
impl<'a, D: ?Sized> ValidatedCipherBulkShareAssociation<'a, D> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub const fn cipher_id(&self) -> &'a str {
        self.source
    }
    pub const fn source_revision(&self) -> &'a str {
        self.revision
    }
    pub const fn source_owner(&self) -> Option<&'a str> {
        self.source_owner
    }
    pub const fn source_organization(&self) -> Option<&'a str> {
        self.source_organization
    }
    pub const fn target_organization(&self) -> &'a str {
        self.target
    }
    pub const fn collection_id(&self) -> &'a str {
        self.collection
    }
    pub const fn index(&self) -> usize {
        self.index
    }
    pub const fn request(&self) -> &'a D {
        self.request
    }
}

/// Final opaque payload/ownership/acting-user annotation phase for one item.
/// A personal source with a null target skips all selection lookups; a shared
/// source requires its exact current canonical organization, including on retries.
pub struct ValidatedCipherBulkShare<'a, D: ?Sized> {
    owner: &'a str,
    source: &'a str,
    revision: &'a str,
    source_owner: Option<&'a str>,
    source_organization: Option<&'a str>,
    target: Option<&'a str>,
    index: usize,
    request: &'a D,
}
impl<'a, D: ?Sized> ValidatedCipherBulkShare<'a, D> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub const fn cipher_id(&self) -> &'a str {
        self.source
    }
    pub const fn source_revision(&self) -> &'a str {
        self.revision
    }
    pub const fn source_owner(&self) -> Option<&'a str> {
        self.source_owner
    }
    pub const fn source_organization(&self) -> Option<&'a str> {
        self.source_organization
    }
    pub const fn target_organization(&self) -> Option<&'a str> {
        self.target
    }
    pub const fn index(&self) -> usize {
        self.index
    }
    pub const fn request(&self) -> &'a D {
        self.request
    }
}

/// Opt-in bulk provider. Every returned ID and SourceAccess must own its backing
/// storage independently of subsequent provider calls; no borrowed cache handles.
/// Hold the operation lock across the whole service call. Each association is an
/// idempotent durable step, with observed account-revision fanout, preserving the
/// cipher payload/ownership/revision and private annotations. A rejected step must
/// not partially mutate itself or roll back earlier successful steps.
///
/// Final commit atomically applies the exact opaque indexed item, ownership and
/// caller's private annotations, preserving other viewers' annotations and opaque
/// extensions. Recheck live source identity/revision/ownership and bulk source
/// write authority, target confirmed membership, selected collection add permission
/// and folder scope under the persistence transaction. Source associations can be
/// historical: they require the canonical outer ownership proof, not equal inner
/// collection organizations. Do not promote historical IDs to canonical ownership.
///
/// Associations do not advance cipher revision, so the same source revision remains
/// valid through that item's phases. A repeated item must be loaded afresh after a
/// prior final commit. Provider failures preserve previously committed phases.
/// These local transaction/failure guarantees do not establish upstream concurrency,
/// group, policy, attachment or full API parity.
pub trait OrganizationCipherBulkSharingStorage: Storage {
    type BulkId: AsRef<str>;
    type SourceAccess: CipherCollectionAccessData;
    fn bulk_sharing_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::BulkId>>, Self::Error>;
    fn bulk_sharing_membership(
        &mut self,
        user: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::BulkId>>, Self::Error>;
    fn bulk_source_collections(
        &mut self,
        user: &str,
        source: &CipherSharingSource<Self::BulkId>,
    ) -> Result<Self::SourceAccess, Self::Error>;
    fn bulk_sharing_collection(
        &mut self,
        user: &str,
        organization: &str,
        collection: &str,
    ) -> Result<Option<CipherSharingCollection<Self::BulkId>>, Self::Error>;
    fn associate_bulk_sharing_collection<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherBulkShareAssociation<'_, D>,
    ) -> Result<(), Self::Error>;
    fn commit_cipher_bulk_share<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherBulkShare<'_, D>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationCipherBulkSharingStorage + ?Sized> OrganizationCipherBulkSharingStorage
    for &mut T
{
    type BulkId = T::BulkId;
    type SourceAccess = T::SourceAccess;
    fn bulk_sharing_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::BulkId>>, Self::Error> {
        (**self).bulk_sharing_source(id)
    }
    fn bulk_sharing_membership(
        &mut self,
        user: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::BulkId>>, Self::Error> {
        (**self).bulk_sharing_membership(user, organization)
    }
    fn bulk_source_collections(
        &mut self,
        user: &str,
        source: &CipherSharingSource<Self::BulkId>,
    ) -> Result<Self::SourceAccess, Self::Error> {
        (**self).bulk_source_collections(user, source)
    }
    fn bulk_sharing_collection(
        &mut self,
        user: &str,
        organization: &str,
        collection: &str,
    ) -> Result<Option<CipherSharingCollection<Self::BulkId>>, Self::Error> {
        (**self).bulk_sharing_collection(user, organization, collection)
    }
    fn associate_bulk_sharing_collection<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherBulkShareAssociation<'_, D>,
    ) -> Result<(), Self::Error> {
        (**self).associate_bulk_sharing_collection(plan)
    }
    fn commit_cipher_bulk_share<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherBulkShare<'_, D>,
    ) -> Result<(), Self::Error> {
        (**self).commit_cipher_bulk_share(plan)
    }
}

impl<S: OrganizationCipherBulkSharingStorage> VaultService<S> {
    /// Decode all item structures before calling. Presence preflight precedes every
    /// provider call; source existence/authority are deliberately checked only when
    /// that item is reached in reverse order. There is no global rollback.
    pub fn bulk_share_ciphers<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        owner: &str,
        request: &D,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        if request.ciphers_len() == 0 {
            return Err(ApiError::invalid(
                "ciphers",
                "You must select at least one cipher.",
            ));
        }
        if request.collections_len() == 0 {
            return Err(ApiError::invalid(
                "collectionIds",
                "You must select at least one collection.",
            ));
        }
        for index in 0..request.ciphers_len() {
            request
                .cipher(index)
                .ok_or_else(invalid_snapshot)?
                .id
                .ok_or_else(|| ApiError::invalid("ids", "Request missing ids field"))?;
        }
        for index in 0..request.collections_len() {
            request.collection(index).ok_or_else(invalid_snapshot)?;
        }
        for index in (0..request.ciphers_len()).rev() {
            let item = request.cipher(index).ok_or_else(invalid_snapshot)?;
            let id = item.id.ok_or_else(invalid_snapshot)?;
            let source = self
                .storage_mut()
                .bulk_sharing_source(id)
                .map_err(S::map_error)?
                .ok_or_else(|| ApiError::invalid("cipher", "Cipher doesn't exist"))?;
            if source.id.as_ref() != id || source.revision.as_ref().is_empty() {
                return Err(invalid_snapshot());
            }
            let ownership = source.ownership()?;
            let membership = if let CipherOwnership::Organization { organization_id } = ownership {
                self.storage_mut()
                    .bulk_sharing_membership(owner, organization_id)
                    .map_err(S::map_error)?
            } else {
                None
            };
            let access = self
                .storage_mut()
                .bulk_source_collections(owner, &source)
                .map_err(S::map_error)?;
            if !resolve_bulk_cipher_source_write_access(
                owner,
                ownership,
                membership.as_ref().map(CipherSharingMembership::view),
                &access,
            )? {
                return Err(ApiError::invalid(
                    "cipher",
                    "Cipher is not write accessible",
                ));
            }
            if let CipherOwnership::Organization { organization_id } = ownership {
                if item.organization_id != Some(organization_id) {
                    return Err(ApiError::invalid(
                        "organizationId",
                        "Organization mismatch. Please resync the client before updating the cipher",
                    ));
                }
            }
            if let Some(organization) = item.organization_id {
                let member = self
                    .storage_mut()
                    .bulk_sharing_membership(owner, organization)
                    .map_err(S::map_error)?
                    .ok_or_else(collection_denied)?;
                if member.user_id.as_ref() != owner
                    || member.organization_id.as_ref() != organization
                {
                    return Err(invalid_snapshot());
                }
                if member.status != 2 {
                    return Err(collection_denied());
                }
                for selected_index in 0..request.collections_len() {
                    let selected = request
                        .collection(selected_index)
                        .ok_or_else(invalid_snapshot)?;
                    let row = self
                        .storage_mut()
                        .bulk_sharing_collection(owner, organization, selected)
                        .map_err(S::map_error)?
                        .ok_or_else(|| {
                            ApiError::invalid("collectionIds", "Invalid collection ID provided")
                        })?;
                    if row.id.as_ref() != selected
                        || row.user_id.as_ref() != owner
                        || row.organization_id.as_ref() != organization
                    {
                        return Err(invalid_snapshot());
                    }
                    if !member.full_access() && (!row.assigned || row.read_only) {
                        return Err(collection_denied());
                    }
                    self.storage_mut()
                        .associate_bulk_sharing_collection(&ValidatedCipherBulkShareAssociation {
                            owner,
                            source: id,
                            revision: source.revision.as_ref(),
                            source_owner: source.owner_id.as_ref().map(AsRef::as_ref),
                            source_organization: source.organization_id.as_ref().map(AsRef::as_ref),
                            target: organization,
                            collection: selected,
                            index,
                            request,
                        })
                        .map_err(S::map_error)?;
                }
            }
            // Native folder rejection occurs after the association prefix, even
            // though the failed payload/ownership phase itself remains unapplied.
            if let Some(folder) = item.folder_id {
                if !self
                    .storage_mut()
                    .folder_metadata(folder)
                    .map_err(S::map_error)?
                    .is_some_and(|row| row.owner_id == owner)
                {
                    return Err(ApiError::invalid("folderId", "Invalid folder"));
                }
            }
            self.storage_mut()
                .commit_cipher_bulk_share(&ValidatedCipherBulkShare {
                    owner,
                    source: id,
                    revision: source.revision.as_ref(),
                    source_owner: source.owner_id.as_ref().map(AsRef::as_ref),
                    source_organization: source.organization_id.as_ref().map(AsRef::as_ref),
                    target: item.organization_id,
                    index,
                    request,
                })
                .map_err(S::map_error)?;
        }
        Ok(())
    }
}
fn collection_denied() -> ApiError {
    ApiError::invalid("collectionIds", "No rights to modify the collection")
}
fn invalid_snapshot() -> ApiError {
    ApiError::new(
        ErrorKind::Storage,
        "Invalid bulk cipher sharing provider snapshot.",
    )
}
impl core::fmt::Debug for CipherBulkShareItem<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CipherBulkShareItem([REDACTED])")
    }
}
impl<D: ?Sized> core::fmt::Debug for ValidatedCipherBulkShareAssociation<'_, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherBulkShareAssociation([REDACTED])")
    }
}
impl<D: ?Sized> core::fmt::Debug for ValidatedCipherBulkShare<'_, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherBulkShare([REDACTED])")
    }
}
#[cfg(test)]
mod tests;
