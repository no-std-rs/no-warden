//! Allocation-free single-cipher sharing and trusted per-viewer access decisions.
//!
//! Collection associations are deliberately sequential: a later rejected selection
//! leaves earlier successful associations and their account-revision effects intact.
//! The opaque payload/ownership phase runs only after every selection succeeds.
//! HTTP guards, persistence, clocks, key wrapping and route-specific collection-ID
//! projections remain adapters. The measured secure-note subset is not full parity.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    service::{require_owner, validate_encrypted_for},
    validation,
    wire::CipherRequest,
};

/// Stable, fully decoded selection. IDs are exact opaque strings, including repeats.
/// All indices below len must exist throughout the operation. The service has no
/// batch cap; an optional bounded transport decoder is caller policy.
pub trait CipherShareIdsData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<&str>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: CipherShareIdsData + ?Sized> CipherShareIdsData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        (**self).get(index)
    }
}
impl CipherShareIdsData for [&str] {
    fn len(&self) -> usize {
        <[&str]>::len(self)
    }
    fn get(&self, index: usize) -> Option<&str> {
        <[&str]>::get(self, index).copied()
    }
}

/// Canonical ownership, independent of any encrypted request document.
#[derive(Clone, Copy)]
pub enum CipherOwnership<'a> {
    Personal { user_id: &'a str },
    Organization { organization_id: &'a str },
}

/// Provider-owned source snapshot. Handles need no Clone/Debug/Serialize and must
/// not borrow an adapter cache that a subsequent provider call could replace.
/// Exactly one owner is present. Revision is an opaque, nonempty concurrency token.
pub struct CipherSharingSource<I> {
    pub id: I,
    pub owner_id: Option<I>,
    pub organization_id: Option<I>,
    pub revision: I,
}
impl<I: AsRef<str>> CipherSharingSource<I> {
    pub fn ownership(&self) -> Result<CipherOwnership<'_>, ApiError> {
        match (&self.owner_id, &self.organization_id) {
            (Some(user), None) if !user.as_ref().is_empty() => Ok(CipherOwnership::Personal {
                user_id: user.as_ref(),
            }),
            (None, Some(org)) if !org.as_ref().is_empty() => Ok(CipherOwnership::Organization {
                organization_id: org.as_ref(),
            }),
            _ => Err(invalid_snapshot()),
        }
    }
}

/// Trusted membership facts; raw role and status stay distinct from wire aliases.
pub struct CipherSharingMembership<I> {
    pub user_id: I,
    pub organization_id: I,
    pub role: i32,
    pub status: i32,
    pub access_all: bool,
}
impl<I: AsRef<str>> CipherSharingMembership<I> {
    pub fn view(&self) -> CipherSharingMembership<&str> {
        CipherSharingMembership {
            user_id: self.user_id.as_ref(),
            organization_id: self.organization_id.as_ref(),
            role: self.role,
            status: self.status,
            access_all: self.access_all,
        }
    }
    /// Full-access roles and the stored access-all bit are independent of a
    /// direct collection grant. Confirmation is required separately.
    pub fn full_access(&self) -> bool {
        matches!(self.role, 0 | 1) || self.access_all
    }
}

/// Scoped effective collection facts. The provider resolves supported direct/group
/// grants; it must not invent a grant for unsupported group administration.
/// manage does not bypass read_only when adding a cipher to a collection.
pub struct CipherSharingCollection<I> {
    pub id: I,
    pub user_id: I,
    pub organization_id: I,
    pub assigned: bool,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}
impl<I: AsRef<str>> CipherSharingCollection<I> {
    pub fn view(&self) -> CipherSharingCollection<&str> {
        CipherSharingCollection {
            id: self.id.as_ref(),
            user_id: self.user_id.as_ref(),
            organization_id: self.organization_id.as_ref(),
            assigned: self.assigned,
            read_only: self.read_only,
            hide_passwords: self.hide_passwords,
            manage: self.manage,
        }
    }
}

/// Trusted association facts for one cipher and viewer. The outer organization is
/// the cipher's canonical owner, not necessarily the collection's organization:
/// a failed share can retain a collection link before a later share changes owner.
/// The provider must prove that this exact collection is linked to the cipher and
/// resolve the viewer's actual grant without inventing cross-organization access.
pub struct CipherCollectionAccessRecord<'a> {
    pub cipher_organization_id: Option<&'a str>,
    pub collection: CipherSharingCollection<&'a str>,
}

/// Stable association facts already selected for this cipher. The caller holds its
/// lock or consistent snapshot through resolution and subsequent response projection.
pub trait CipherCollectionAccessData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: CipherCollectionAccessData + ?Sized> CipherCollectionAccessData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        (**self).get(index)
    }
}
impl CipherCollectionAccessData for [CipherCollectionAccessRecord<'_>] {
    fn len(&self) -> usize {
        <[CipherCollectionAccessRecord<'_>]>::len(self)
    }
    fn get(&self, index: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        <[CipherCollectionAccessRecord<'_>]>::get(self, index).map(|row| {
            CipherCollectionAccessRecord {
                cipher_organization_id: row.cipher_organization_id,
                collection: row.collection.view(),
            }
        })
    }
}

/// Sealed result of pure access resolution, not mutation authority. Flags describe
/// the current snapshot only; they cannot authorize a later write after ACL changes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CipherAccessSnapshot {
    readable: bool,
    writable: bool,
    view_password: bool,
}
impl CipherAccessSnapshot {
    pub const fn readable(self) -> bool {
        self.readable
    }
    pub const fn writable(self) -> bool {
        self.writable
    }
    pub const fn view_password(self) -> bool {
        self.view_password
    }
    pub const fn delete(self) -> bool {
        self.writable
    }
    pub const fn restore(self) -> bool {
        self.writable
    }
}

/// Resolve access without storage, allocation or clocks. Every admitted collection
/// association is validated against the viewer and cipher's canonical ownership.
/// Confirmed membership in that organization is mandatory; associated collection
/// grants can belong to an earlier organization retained after a failed share.
/// Read, write and password visibility union the effective associated grants.
/// Broader policy/multiple-grant/backend parity remains outside the measured subset.
///
/// Do not use one collection-ID projection for every route: the measured readonly
/// recipient's single GET has [], while list/sync include its associated collection.
/// Adapters select IDs from the same validated stable facts after this resolution.
pub fn resolve_cipher_access<D: CipherCollectionAccessData + ?Sized>(
    viewer: &str,
    ownership: CipherOwnership<'_>,
    membership: Option<CipherSharingMembership<&str>>,
    collections: &D,
) -> Result<CipherAccessSnapshot, ApiError> {
    require_owner(viewer)?;
    let denied = CipherAccessSnapshot {
        readable: false,
        writable: false,
        view_password: false,
    };
    let (organization, full) = match ownership {
        CipherOwnership::Personal { user_id } => {
            if user_id != viewer {
                return Ok(denied);
            }
            (None, true)
        }
        CipherOwnership::Organization { organization_id } => {
            if organization_id.is_empty() {
                return Err(invalid_snapshot());
            }
            let Some(member) = membership else {
                return Ok(denied);
            };
            validate_membership(viewer, organization_id, &member)?;
            if member.status != 2 {
                return Ok(denied);
            }
            (Some(organization_id), member.full_access())
        }
    };
    let mut access = if full {
        CipherAccessSnapshot {
            readable: true,
            writable: true,
            view_password: true,
        }
    } else {
        denied
    };
    for index in 0..collections.len() {
        let record = collections.get(index).ok_or_else(invalid_snapshot)?;
        let row = record.collection;
        if record.cipher_organization_id != organization
            || row.id.is_empty()
            || row.user_id != viewer
            || row.organization_id.is_empty()
        {
            return Err(invalid_snapshot());
        }
        if row.assigned {
            access.readable = true;
            access.writable |= !row.read_only;
            access.view_password |= !row.hide_passwords;
        }
    }
    Ok(access)
}

/// One authorized association step. Constructed only after source, membership and
/// this collection's scope and add permission were checked. Prior steps may exist.
pub struct ValidatedCipherShareAssociation<'a> {
    owner: &'a str,
    cipher_id: &'a str,
    source_revision: &'a str,
    target_organization: &'a str,
    collection_id: &'a str,
}
impl<'a> ValidatedCipherShareAssociation<'a> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub const fn cipher_id(&self) -> &'a str {
        self.cipher_id
    }
    pub const fn source_revision(&self) -> &'a str {
        self.source_revision
    }
    pub const fn target_organization(&self) -> &'a str {
        self.target_organization
    }
    pub const fn collection_id(&self) -> &'a str {
        self.collection_id
    }
}

/// Final payload/ownership phase, reached only after all selected associations.
/// A null target is the separately observed personal-payload update branch; it
/// performs no collection lookups/association steps even if IDs were supplied.
pub struct ValidatedCipherShare<'request, 'data> {
    owner: &'request str,
    cipher_id: &'request str,
    source_revision: &'request str,
    target_organization: Option<&'request str>,
    request: &'request CipherRequest<'data>,
}
impl<'request, 'data> ValidatedCipherShare<'request, 'data> {
    pub const fn owner(&self) -> &'request str {
        self.owner
    }
    pub const fn cipher_id(&self) -> &'request str {
        self.cipher_id
    }
    pub const fn source_revision(&self) -> &'request str {
        self.source_revision
    }
    pub const fn target_organization(&self) -> Option<&'request str> {
        self.target_organization
    }
    pub const fn request(&self) -> &'request CipherRequest<'data> {
        self.request
    }
}

/// Opt-in sharing provider with cache-independent owned identifiers.
///
/// Hold the operation lock across lookup, each association and the final payload.
/// Each association is its own durable step: insert idempotently and perform its
/// observed account-revision fanout without changing source ownership, ciphertext,
/// cipher revision or private annotations. A later lookup/permission/provider error
/// must not undo previously successful steps. One failed step must not leak a partial
/// mutation of that step. Notifications follow successful step commits.
///
/// The final phase atomically replaces the opaque payload/ownership and acting
/// user's annotations, preserving other users' private annotations and attachment
/// bytes. Its failure retains earlier associations, without applying part of the
/// payload. Preserve unknown encrypted extensions in the adapter's original input;
/// a narrow request DTO round-trip must not discard them. Recheck the sealed scope,
/// source revision and live authority under persistence transactions. These provider
/// failure/concurrency guarantees are local contracts, not complete upstream proof.
pub trait OrganizationCipherSharingStorage: Storage {
    type ShareId: AsRef<str>;
    fn sharing_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::ShareId>>, Self::Error>;
    fn sharing_membership(
        &mut self,
        user: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::ShareId>>, Self::Error>;
    fn sharing_collection(
        &mut self,
        user: &str,
        organization: &str,
        collection: &str,
    ) -> Result<Option<CipherSharingCollection<Self::ShareId>>, Self::Error>;
    fn associate_sharing_collection(
        &mut self,
        plan: &ValidatedCipherShareAssociation<'_>,
    ) -> Result<(), Self::Error>;
    /// Compare an optional client revision using the adapter's timestamp rules.
    /// Only a valid older revision is stale. The service calls this after all
    /// association steps; rejecting the payload must preserve their commits.
    fn sharing_revision_is_older(
        &mut self,
        source: &CipherSharingSource<Self::ShareId>,
        requested: &str,
    ) -> Result<bool, Self::Error>;
    fn commit_cipher_share(
        &mut self,
        plan: &ValidatedCipherShare<'_, '_>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationCipherSharingStorage + ?Sized> OrganizationCipherSharingStorage for &mut T {
    type ShareId = T::ShareId;
    fn sharing_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::ShareId>>, Self::Error> {
        (**self).sharing_source(id)
    }
    fn sharing_membership(
        &mut self,
        user: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::ShareId>>, Self::Error> {
        (**self).sharing_membership(user, organization)
    }
    fn sharing_collection(
        &mut self,
        user: &str,
        organization: &str,
        collection: &str,
    ) -> Result<Option<CipherSharingCollection<Self::ShareId>>, Self::Error> {
        (**self).sharing_collection(user, organization, collection)
    }
    fn associate_sharing_collection(
        &mut self,
        plan: &ValidatedCipherShareAssociation<'_>,
    ) -> Result<(), Self::Error> {
        (**self).associate_sharing_collection(plan)
    }
    fn commit_cipher_share(
        &mut self,
        plan: &ValidatedCipherShare<'_, '_>,
    ) -> Result<(), Self::Error> {
        (**self).commit_cipher_share(plan)
    }
    fn sharing_revision_is_older(
        &mut self,
        source: &CipherSharingSource<Self::ShareId>,
        requested: &str,
    ) -> Result<bool, Self::Error> {
        (**self).sharing_revision_is_older(source, requested)
    }
}

impl<S: OrganizationCipherSharingStorage> VaultService<S> {
    /// Share an owned personal cipher. Fully decode the transport body before this
    /// call. Structural view defects are rejected before any provider call; target
    /// lookups remain sequential so a late rejected ID preserves successful prefixes.
    pub fn share_cipher<D: CipherShareIdsData + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherRequest<'_>,
        collections: &D,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        for index in 0..collections.len() {
            collections.get(index).ok_or_else(invalid_snapshot)?;
        }
        let source = self
            .storage_mut()
            .sharing_source(id)
            .map_err(S::map_error)?
            .ok_or_else(source_denied)?;
        if source.id.as_ref() != id || source.revision.as_ref().is_empty() {
            return Err(invalid_snapshot());
        }
        if !matches!(source.ownership()?, CipherOwnership::Personal {user_id} if user_id == owner) {
            return Err(source_denied());
        }
        validation::validate_cipher_payload(request)?;
        validate_encrypted_for(owner, request)?;
        if let Some(folder) = request.folder_id {
            let owned = self
                .storage_mut()
                .folder_metadata(folder)
                .map_err(S::map_error)?
                .is_some_and(|metadata| metadata.owner_id == owner);
            if !owned {
                return Err(ApiError::invalid(
                    "folderId",
                    "Folder does not exist in this vault.",
                ));
            }
        }
        if let Some(organization) = request.organization_id {
            let member = self
                .storage_mut()
                .sharing_membership(owner, organization)
                .map_err(S::map_error)?
                .ok_or_else(collection_denied)?;
            validate_membership(owner, organization, &member)?;
            if member.status != 2 || (collections.is_empty() && !member.full_access()) {
                return Err(collection_denied());
            }
            for index in 0..collections.len() {
                let selected = collections.get(index).ok_or_else(invalid_snapshot)?;
                let row = self
                    .storage_mut()
                    .sharing_collection(owner, organization, selected)
                    .map_err(S::map_error)?
                    .ok_or_else(collection_denied)?;
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
                    .associate_sharing_collection(&ValidatedCipherShareAssociation {
                        owner,
                        cipher_id: id,
                        source_revision: source.revision.as_ref(),
                        target_organization: organization,
                        collection_id: selected,
                    })
                    .map_err(S::map_error)?;
            }
        }
        if let Some(revision) = request.last_known_revision_date {
            if self
                .storage_mut()
                .sharing_revision_is_older(&source, revision)
                .map_err(S::map_error)?
            {
                return Err(ApiError::invalid(
                    "lastKnownRevisionDate",
                    "Cipher revision is older than the stored revision",
                ));
            }
        }
        self.storage_mut()
            .commit_cipher_share(&ValidatedCipherShare {
                owner,
                cipher_id: id,
                source_revision: source.revision.as_ref(),
                target_organization: request.organization_id,
                request,
            })
            .map_err(S::map_error)
    }
}

fn validate_membership<I: AsRef<str>>(
    owner: &str,
    organization: &str,
    member: &CipherSharingMembership<I>,
) -> Result<(), ApiError> {
    if member.user_id.as_ref() != owner || member.organization_id.as_ref() != organization {
        Err(invalid_snapshot())
    } else {
        Ok(())
    }
}
fn source_denied() -> ApiError {
    ApiError::invalid("cipher", "Cipher is not owned by user")
}
fn collection_denied() -> ApiError {
    ApiError::invalid(
        "collectionIds",
        "Cannot add this cipher to the selected collection",
    )
}
fn invalid_snapshot() -> ApiError {
    ApiError::new(
        ErrorKind::Storage,
        "Invalid cipher sharing provider snapshot.",
    )
}

macro_rules! redacted {
    ($($name:ident $(<$($generic:ident),+>)?),+ $(,)?) => {$(
        impl$(<$($generic),+>)? core::fmt::Debug for $name$(<$($generic),+>)? {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )+};
}
redacted!(
    CipherSharingSource<I>,
    CipherSharingMembership<I>,
    CipherSharingCollection<I>,
    CipherAccessSnapshot
);
impl core::fmt::Debug for CipherOwnership<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CipherOwnership([REDACTED])")
    }
}
impl core::fmt::Debug for CipherCollectionAccessRecord<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CipherCollectionAccessRecord([REDACTED])")
    }
}
impl core::fmt::Debug for ValidatedCipherShareAssociation<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherShareAssociation([REDACTED])")
    }
}
impl core::fmt::Debug for ValidatedCipherShare<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherShare([REDACTED])")
    }
}

#[cfg(test)]
mod tests;
