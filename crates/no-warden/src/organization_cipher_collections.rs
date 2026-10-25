//! Allocation-free collection reassignment for the measured collections_v2 subset.
//!
//! Selection order belongs to the embedding's stable operation, not the request.
//! Native failed requests retain unordered partial additions: no input-prefix,
//! random-distribution or whole-request atomicity parity is claimed. Only links
//! and account revisions change; opaque payloads, cipher revisions and private
//! annotations remain untouched. HTTP, budgets, clocks and persistence are adapters.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    organization_cipher_bulk_sharing::resolve_bulk_cipher_source_write_access,
    organization_cipher_sharing::{
        CipherAccessSnapshot, CipherCollectionAccessData, CipherShareIdsData,
        CipherSharingCollection, CipherSharingMembership, CipherSharingSource,
        resolve_cipher_access,
    },
    service::require_owner,
};

/// Operation-owned representative indices, stable throughout the call. Every
/// distinct input ID occurs exactly once; the core validates this before writes.
/// A deterministic embedding order is local policy, not native permutation parity.
pub trait CipherCollectionSelectionOrder {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<usize>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl CipherCollectionSelectionOrder for [usize] {
    fn len(&self) -> usize {
        <[usize]>::len(self)
    }
    fn get(&self, index: usize) -> Option<usize> {
        <[usize]>::get(self, index).copied()
    }
}
impl<T: CipherCollectionSelectionOrder + ?Sized> CipherCollectionSelectionOrder for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<usize> {
        (**self).get(index)
    }
}

/// Fully validate stable input and a complete unique representative permutation.
/// Uses O(input*order + order^2) comparisons and no scratch allocation. The host
/// must budget this work before entry; the reusable service has no batch cap.
pub fn validate_collection_selection_order<
    D: CipherShareIdsData + ?Sized,
    O: CipherCollectionSelectionOrder + ?Sized,
>(
    request: &D,
    order: &O,
) -> Result<(), ApiError> {
    for index in 0..request.len() {
        request.get(index).ok_or_else(invalid_snapshot)?;
    }
    for position in 0..order.len() {
        let index = order.get(position).ok_or_else(invalid_snapshot)?;
        if index >= request.len() {
            return Err(invalid_snapshot());
        }
        let id = request.get(index).ok_or_else(invalid_snapshot)?;
        for previous in 0..position {
            let other = order
                .get(previous)
                .and_then(|i| request.get(i))
                .ok_or_else(invalid_snapshot)?;
            if other == id {
                return Err(invalid_snapshot());
            }
        }
    }
    for index in 0..request.len() {
        let id = request.get(index).ok_or_else(invalid_snapshot)?;
        let mut found = false;
        for position in 0..order.len() {
            let other = order
                .get(position)
                .and_then(|i| request.get(i))
                .ok_or_else(invalid_snapshot)?;
            found |= other == id;
        }
        if !found {
            return Err(invalid_snapshot());
        }
    }
    Ok(())
}

/// Sealed durable-add authority. A provider must invoke validate_live under its
/// transaction before the idempotent link insertion and account revision fanout.
pub struct ValidatedCipherCollectionAdd<'a> {
    actor: &'a str,
    cipher: &'a str,
    organization: &'a str,
    revision: &'a str,
    collection: &'a str,
}
impl<'a> ValidatedCipherCollectionAdd<'a> {
    pub const fn actor(&self) -> &'a str {
        self.actor
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
    pub const fn collection_id(&self) -> &'a str {
        self.collection
    }
    pub fn validate_live<I: AsRef<str>, A: CipherCollectionAccessData + ?Sized>(
        &self,
        source: &CipherSharingSource<I>,
        membership: Option<CipherSharingMembership<&str>>,
        associated: &A,
        target: CipherSharingCollection<&str>,
    ) -> Result<(), ApiError> {
        validate_binding(source, self.cipher, self.organization, self.revision)?;
        let full = authorize_source(self.actor, source, membership, associated)?;
        authorize_target(self.actor, self.organization, self.collection, full, target)
    }
}

/// Sealed final removal plan after all selections succeeded. Omitted readonly,
/// readonly/manage and unassigned links remain protected for restricted actors.
/// Only core-selected removal IDs may be deleted. Even no-op Finish advances the
/// adapter's eligible account revisions; it never writes the cipher row.
pub struct ValidatedCipherCollectionsFinish<'a, D: ?Sized, A: ?Sized> {
    actor: &'a str,
    cipher: &'a str,
    organization: &'a str,
    revision: &'a str,
    full: bool,
    request: &'a D,
    associated: &'a A,
}
impl<'a, D: CipherShareIdsData + ?Sized, A: CipherCollectionAccessData + ?Sized>
    ValidatedCipherCollectionsFinish<'a, D, A>
{
    pub const fn actor(&self) -> &'a str {
        self.actor
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
    pub fn associated_len(&self) -> usize {
        self.associated.len()
    }
    pub fn removal(&self, index: usize) -> Result<Option<&str>, ApiError> {
        let row = self
            .associated
            .get(index)
            .ok_or_else(invalid_snapshot)?
            .collection;
        if !self.full && (!row.assigned || row.read_only) {
            return Ok(None);
        }
        for index in 0..self.request.len() {
            if self.request.get(index).ok_or_else(invalid_snapshot)? == row.id {
                return Ok(None);
            }
        }
        Ok(Some(row.id))
    }
    /// Live source, authority and old-link permissions must still match under
    /// the final transaction. The operation lock prevents our own earlier adds
    /// from racing this snapshot. Changed facts fail rather than delete old links.
    pub fn validate_live<I: AsRef<str>, B: CipherCollectionAccessData + ?Sized>(
        &self,
        source: &CipherSharingSource<I>,
        membership: Option<CipherSharingMembership<&str>>,
        associated: &B,
    ) -> Result<(), ApiError> {
        validate_binding(source, self.cipher, self.organization, self.revision)?;
        let full = authorize_source(self.actor, source, membership, associated)?;
        if full != self.full || associated.len() != self.associated.len() {
            return Err(invalid_snapshot());
        }
        for i in 0..self.associated.len() {
            let old = self.associated.get(i).ok_or_else(invalid_snapshot)?;
            let mut found = false;
            for j in 0..associated.len() {
                let now = associated.get(j).ok_or_else(invalid_snapshot)?;
                if old.collection.id == now.collection.id {
                    found = old.cipher_organization_id == now.cipher_organization_id
                        && same_collection(old.collection, now.collection);
                    break;
                }
            }
            if !found {
                return Err(invalid_snapshot());
            }
        }
        Ok(())
    }
}

/// One successful-operation projection scope, independent of subsequent readable
/// status. The adapter may load this exact source under its operation lock and
/// render the v2 cipher even when final ordinary GET/list/sync access is lost.
/// This is not persistent read authority or a full encrypted response DTO.
pub struct CipherCollectionsResponseScope<'a, I> {
    actor: &'a str,
    source: CipherSharingSource<I>,
}
impl<I: AsRef<str>> CipherCollectionsResponseScope<'_, I> {
    pub fn actor(&self) -> &str {
        self.actor
    }
    pub fn cipher_id(&self) -> &str {
        self.source.id.as_ref()
    }
    pub fn organization_id(&self) -> &str {
        self.source
            .organization_id
            .as_ref()
            .map(AsRef::as_ref)
            .unwrap_or("")
    }
    pub fn source_revision(&self) -> &str {
        self.source.revision.as_ref()
    }
    pub fn validate_source<J: AsRef<str>>(
        &self,
        live: &CipherSharingSource<J>,
    ) -> Result<(), ApiError> {
        validate_binding(
            live,
            self.cipher_id(),
            self.organization_id(),
            self.source_revision(),
        )
    }
    /// Returns current flags including readable=false; do not turn that legitimate
    /// successful-operation response into a missing/null cipher or another error.
    pub fn response_access<A: CipherCollectionAccessData + ?Sized>(
        &self,
        membership: Option<CipherSharingMembership<&str>>,
        associated: &A,
    ) -> Result<CipherAccessSnapshot, ApiError> {
        resolve_cipher_access(self.actor, self.source.ownership()?, membership, associated)
    }
}

/// Opt-in persistence boundary. All IDs/source/associated snapshots own storage
/// independently of later provider calls, without Clone/Debug/Serialize bounds.
/// Hold one operation lock through service and immediate response projection.
/// Recheck each sealed plan with validate_live under its transaction. Add commits
/// its link+account fanout durably; an error does not mutate its own step or undo
/// earlier additions. Finish removes only plan.removal IDs and bumps eligible
/// account revisions atomically even for no-op. Never change cipher revision,
/// payload/key/common metadata or any viewer's private annotations. Include the
/// acting account in observed fanout after it loses access; broader membership/
/// group/failure/concurrency fanout is not native parity established by this API.
pub trait OrganizationCipherCollectionsStorage: Storage {
    type CollectionId: AsRef<str>;
    type CollectionAccess: CipherCollectionAccessData;
    fn collection_reassignment_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::CollectionId>>, Self::Error>;
    fn collection_reassignment_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::CollectionId>>, Self::Error>;
    fn collection_reassignment_associations(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Self::CollectionId>,
    ) -> Result<Self::CollectionAccess, Self::Error>;
    fn collection_reassignment_target(
        &mut self,
        actor: &str,
        organization: &str,
        collection: &str,
    ) -> Result<Option<CipherSharingCollection<Self::CollectionId>>, Self::Error>;
    fn add_cipher_collection(
        &mut self,
        plan: &ValidatedCipherCollectionAdd<'_>,
    ) -> Result<(), Self::Error>;
    fn finish_cipher_collections<D: CipherShareIdsData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherCollectionsFinish<'_, D, Self::CollectionAccess>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationCipherCollectionsStorage + ?Sized> OrganizationCipherCollectionsStorage
    for &mut T
{
    type CollectionId = T::CollectionId;
    type CollectionAccess = T::CollectionAccess;
    fn collection_reassignment_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::CollectionId>>, Self::Error> {
        (**self).collection_reassignment_source(id)
    }
    fn collection_reassignment_membership(
        &mut self,
        actor: &str,
        organization: &str,
    ) -> Result<Option<CipherSharingMembership<Self::CollectionId>>, Self::Error> {
        (**self).collection_reassignment_membership(actor, organization)
    }
    fn collection_reassignment_associations(
        &mut self,
        actor: &str,
        source: &CipherSharingSource<Self::CollectionId>,
    ) -> Result<Self::CollectionAccess, Self::Error> {
        (**self).collection_reassignment_associations(actor, source)
    }
    fn collection_reassignment_target(
        &mut self,
        actor: &str,
        organization: &str,
        collection: &str,
    ) -> Result<Option<CipherSharingCollection<Self::CollectionId>>, Self::Error> {
        (**self).collection_reassignment_target(actor, organization, collection)
    }
    fn add_cipher_collection(
        &mut self,
        plan: &ValidatedCipherCollectionAdd<'_>,
    ) -> Result<(), Self::Error> {
        (**self).add_cipher_collection(plan)
    }
    fn finish_cipher_collections<D: CipherShareIdsData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherCollectionsFinish<'_, D, Self::CollectionAccess>,
    ) -> Result<(), Self::Error> {
        (**self).finish_cipher_collections(plan)
    }
}

impl<S: OrganizationCipherCollectionsStorage> VaultService<S> {
    /// Only collections_v2 semantics are provided; this neither registers aliases
    /// nor serializes their different response families. Decode the entire native
    /// request before calling. No source/target mutation precedes order preflight.
    pub fn reassign_cipher_collections<
        'a,
        D: CipherShareIdsData + ?Sized,
        O: CipherCollectionSelectionOrder + ?Sized,
    >(
        &mut self,
        actor: &'a str,
        cipher: &str,
        request: &D,
        order: &O,
    ) -> Result<CipherCollectionsResponseScope<'a, S::CollectionId>, ApiError> {
        require_owner(actor)?;
        if cipher.is_empty() {
            return Err(source_denied());
        }
        validate_collection_selection_order(request, order)?;
        let source = self
            .storage_mut()
            .collection_reassignment_source(cipher)
            .map_err(S::map_error)?
            .ok_or_else(source_denied)?;
        if source.id.as_ref() != cipher || source.revision.as_ref().is_empty() {
            return Err(invalid_snapshot());
        }
        let organization = source
            .organization_id
            .as_ref()
            .map(AsRef::as_ref)
            .ok_or_else(source_denied)?;
        // Initial authority also applies to an empty selection.
        let member = self
            .storage_mut()
            .collection_reassignment_membership(actor, organization)
            .map_err(S::map_error)?;
        let access = self
            .storage_mut()
            .collection_reassignment_associations(actor, &source)
            .map_err(S::map_error)?;
        authorize_source(
            actor,
            &source,
            member.as_ref().map(CipherSharingMembership::view),
            &access,
        )?;
        for position in 0..order.len() {
            let collection = order
                .get(position)
                .and_then(|index| request.get(index))
                .ok_or_else(invalid_snapshot)?;
            let live = self
                .storage_mut()
                .collection_reassignment_source(cipher)
                .map_err(S::map_error)?
                .ok_or_else(source_denied)?;
            let member = self
                .storage_mut()
                .collection_reassignment_membership(actor, organization)
                .map_err(S::map_error)?;
            let access = self
                .storage_mut()
                .collection_reassignment_associations(actor, &live)
                .map_err(S::map_error)?;
            validate_binding(&live, cipher, organization, source.revision.as_ref())?;
            authorize_source(
                actor,
                &live,
                member.as_ref().map(CipherSharingMembership::view),
                &access,
            )?;
            let target = self
                .storage_mut()
                .collection_reassignment_target(actor, organization, collection)
                .map_err(S::map_error)?
                .ok_or_else(target_denied)?;
            let plan = ValidatedCipherCollectionAdd {
                actor,
                cipher,
                organization,
                revision: source.revision.as_ref(),
                collection,
            };
            plan.validate_live(
                &live,
                member.as_ref().map(CipherSharingMembership::view),
                &access,
                target.view(),
            )?;
            self.storage_mut()
                .add_cipher_collection(&plan)
                .map_err(S::map_error)?;
        }
        let live = self
            .storage_mut()
            .collection_reassignment_source(cipher)
            .map_err(S::map_error)?
            .ok_or_else(source_denied)?;
        validate_binding(&live, cipher, organization, source.revision.as_ref())?;
        let member = self
            .storage_mut()
            .collection_reassignment_membership(actor, organization)
            .map_err(S::map_error)?;
        let access = self
            .storage_mut()
            .collection_reassignment_associations(actor, &live)
            .map_err(S::map_error)?;
        let full = authorize_source(
            actor,
            &live,
            member.as_ref().map(CipherSharingMembership::view),
            &access,
        )?;
        let plan = ValidatedCipherCollectionsFinish {
            actor,
            cipher,
            organization,
            revision: source.revision.as_ref(),
            full,
            request,
            associated: &access,
        };
        self.storage_mut()
            .finish_cipher_collections(&plan)
            .map_err(S::map_error)?;
        Ok(CipherCollectionsResponseScope { actor, source })
    }
}
fn validate_binding<I: AsRef<str>>(
    source: &CipherSharingSource<I>,
    cipher: &str,
    organization: &str,
    revision: &str,
) -> Result<(), ApiError> {
    if source.id.as_ref() != cipher
        || source.owner_id.is_some()
        || source.organization_id.as_ref().map(AsRef::as_ref) != Some(organization)
        || source.revision.as_ref() != revision
        || revision.is_empty()
    {
        return Err(invalid_snapshot());
    }
    Ok(())
}
fn authorize_source<I: AsRef<str>, A: CipherCollectionAccessData + ?Sized>(
    actor: &str,
    source: &CipherSharingSource<I>,
    membership: Option<CipherSharingMembership<&str>>,
    associated: &A,
) -> Result<bool, ApiError> {
    if source.owner_id.is_some() || source.organization_id.is_none() {
        return Err(source_denied());
    }
    let full = membership
        .as_ref()
        .is_some_and(CipherSharingMembership::full_access);
    if !resolve_bulk_cipher_source_write_access(actor, source.ownership()?, membership, associated)?
    {
        return Err(source_denied());
    }
    // Effective per-collection rows must be complete and unique; permission union
    // belongs to the adapter's supported direct/group fact provider.
    for i in 0..associated.len() {
        let row = associated.get(i).ok_or_else(invalid_snapshot)?;
        for j in 0..i {
            if associated
                .get(j)
                .ok_or_else(invalid_snapshot)?
                .collection
                .id
                == row.collection.id
            {
                return Err(invalid_snapshot());
            }
        }
    }
    Ok(full)
}
fn authorize_target(
    actor: &str,
    organization: &str,
    collection: &str,
    full: bool,
    target: CipherSharingCollection<&str>,
) -> Result<(), ApiError> {
    if target.id.is_empty()
        || target.id != collection
        || target.user_id != actor
        || target.organization_id != organization
    {
        return Err(invalid_snapshot());
    }
    if !full && (!target.assigned || target.read_only) {
        return Err(target_denied());
    }
    Ok(())
}
fn same_collection(a: CipherSharingCollection<&str>, b: CipherSharingCollection<&str>) -> bool {
    a.id == b.id
        && a.user_id == b.user_id
        && a.organization_id == b.organization_id
        && a.assigned == b.assigned
        && a.read_only == b.read_only
        && a.hide_passwords == b.hide_passwords
        && a.manage == b.manage
}
fn source_denied() -> ApiError {
    ApiError::invalid("cipher", "Cipher is not write accessible")
}
fn target_denied() -> ApiError {
    ApiError::invalid("collectionIds", "Invalid or inaccessible collection")
}
fn invalid_snapshot() -> ApiError {
    ApiError::new(
        ErrorKind::Storage,
        "Invalid cipher collection reassignment snapshot.",
    )
}
impl core::fmt::Debug for ValidatedCipherCollectionAdd<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherCollectionAdd([REDACTED])")
    }
}
impl<D: ?Sized, A: ?Sized> core::fmt::Debug for ValidatedCipherCollectionsFinish<'_, D, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedCipherCollectionsFinish([REDACTED])")
    }
}
impl<I> core::fmt::Debug for CipherCollectionsResponseScope<'_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CipherCollectionsResponseScope([REDACTED])")
    }
}
#[cfg(test)]
mod tests;
