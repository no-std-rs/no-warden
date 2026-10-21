//! Allocation-free authorization and scoped views for three web organization reads.
//! Encrypted cipher documents, HTTP queries and configured group administration
//! remain adapters. Empty groups require an explicit provider proof.
use crate::{
    ApiError, ErrorKind, VaultService,
    organization_collections::{CollectionAccessData, OrganizationCollectionStorage},
    wire::CollectionAccessDetailsResponse,
};

/// Canonical cipher ownership metadata; encrypted payloads never enter this view.
#[derive(Clone, Copy)]
pub struct OrganizationCipherReadRecord<'a> {
    pub id: &'a str,
    pub organization_id: &'a str,
}
impl core::fmt::Debug for OrganizationCipherReadRecord<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationCipherReadRecord([REDACTED])")
    }
}
/// Stable, complete, provider-owned ordering with no intrinsic batch limit.
pub trait OrganizationCipherReadData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<OrganizationCipherReadRecord<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: OrganizationCipherReadData + ?Sized> OrganizationCipherReadData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<OrganizationCipherReadRecord<'_>> {
        (**self).get(index)
    }
}
impl OrganizationCipherReadData for [OrganizationCipherReadRecord<'_>] {
    fn len(&self) -> usize {
        <[OrganizationCipherReadRecord<'_>]>::len(self)
    }
    fn get(&self, index: usize) -> Option<OrganizationCipherReadRecord<'_>> {
        <[OrganizationCipherReadRecord<'_>]>::get(self, index).copied()
    }
}
/// Stable collection access rows. Aggregate rows may include implicit full-access
/// memberships; individual collection details retain their separate direct view.
pub trait OrganizationCollectionDetailsData {
    type Details<'a>: CollectionAccessData
    where
        Self: 'a;
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<Self::Details<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: OrganizationCollectionDetailsData + ?Sized> OrganizationCollectionDetailsData for &T {
    type Details<'a>
        = T::Details<'a>
    where
        Self: 'a;
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<Self::Details<'_>> {
        (**self).get(index)
    }
}
/// Distinguish the measured empty branch from unsupported configured groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationGroupPresence {
    NoCreatedGroups,
    ConfiguredOrUnknown,
}
/// Opt-in read-only provider. Keep the authenticated operation locked/snapshotted
/// through scope validation and serialization. Rows must belong to the requested
/// organization, and collection memberships to the exact actor. Resolve effective
/// flags and implicit full-access users before returning stable borrowed views.
/// Reads and failures preserve persisted data, revisions and session authority.
pub trait OrganizationWebReadsStorage: OrganizationCollectionStorage {
    type CipherReads<'a>: OrganizationCipherReadData
    where
        Self: 'a;
    type CollectionDetails<'a>: OrganizationCollectionDetailsData
    where
        Self: 'a;
    fn organization_cipher_reads(
        &mut self,
        organization: &str,
    ) -> Result<Self::CipherReads<'_>, Self::Error>;
    fn organization_collection_details(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<Self::CollectionDetails<'_>, Self::Error>;
    fn organization_group_presence(
        &mut self,
        organization: &str,
    ) -> Result<OrganizationGroupPresence, Self::Error>;
}
impl<T: OrganizationWebReadsStorage + ?Sized> OrganizationWebReadsStorage for &mut T {
    type CipherReads<'a>
        = T::CipherReads<'a>
    where
        Self: 'a;
    type CollectionDetails<'a>
        = T::CollectionDetails<'a>
    where
        Self: 'a;
    fn organization_cipher_reads(
        &mut self,
        organization: &str,
    ) -> Result<Self::CipherReads<'_>, Self::Error> {
        (**self).organization_cipher_reads(organization)
    }
    fn organization_collection_details(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<Self::CollectionDetails<'_>, Self::Error> {
        (**self).organization_collection_details(owner, organization)
    }
    fn organization_group_presence(
        &mut self,
        organization: &str,
    ) -> Result<OrganizationGroupPresence, Self::Error> {
        (**self).organization_group_presence(organization)
    }
}
/// Sealed scope-checked IDs. Adapters project opaque documents under the same lock;
/// this snapshot cannot authorize a later mutation or a different organization.
pub struct OrganizationCipherListGrant<L> {
    records: L,
}
impl<L> core::fmt::Debug for OrganizationCipherListGrant<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationCipherListGrant([REDACTED])")
    }
}
impl<L: OrganizationCipherReadData> OrganizationCipherListGrant<L> {
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<OrganizationCipherReadRecord<'_>> {
        self.records.get(index)
    }
}
pub struct OrganizationCollectionDetailsResponse<L> {
    records: L,
}
impl<L> core::fmt::Debug for OrganizationCollectionDetailsResponse<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationCollectionDetailsResponse([REDACTED])")
    }
}
impl<L: OrganizationCollectionDetailsData> serde::Serialize
    for OrganizationCollectionDetailsResponse<L>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        struct Rows<'a, L>(&'a L);
        impl<L: OrganizationCollectionDetailsData> serde::Serialize for Rows<'_, L> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
                for index in 0..self.0.len() {
                    let row = self.0.get(index).ok_or_else(|| {
                        serde::ser::Error::custom("Incomplete collection details list")
                    })?;
                    rows.serialize_element(&CollectionAccessDetailsResponse::for_list(row))?;
                }
                rows.end()
            }
        }
        let mut response = serializer.serialize_map(Some(3))?;
        response.serialize_entry("data", &Rows(&self.records))?;
        response.serialize_entry("object", "list")?;
        response.serialize_entry("continuationToken", &Option::<&str>::None)?;
        response.end()
    }
}
/// No group row model is invented: only the provider-proved empty list is exposed.
#[derive(Clone, Copy, Debug)]
pub struct OrganizationEmptyGroupsResponse {
    _sealed: (),
}
impl serde::Serialize for OrganizationEmptyGroupsResponse {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut response = serializer.serialize_map(Some(3))?;
        response.serialize_entry("data", &[] as &[()])?;
        response.serialize_entry("object", "list")?;
        response.serialize_entry("continuationToken", &Option::<&str>::None)?;
        response.end()
    }
}
fn invalid_view() -> ApiError {
    ApiError::new(
        ErrorKind::Storage,
        "Invalid organization read provider view",
    )
}
impl<S: OrganizationWebReadsStorage> VaultService<S> {
    fn authorize_org_web_admin(&mut self, owner: &str, organization: &str) -> Result<(), ApiError> {
        let actor = self.authorize_org_collection_manager(owner, organization)?;
        if !matches!(actor.role(), 0 | 1) && !actor.access_all() {
            return Err(ApiError::new(ErrorKind::NotFound, "Resource not found."));
        }
        Ok(())
    }
    pub fn authorize_org_cipher_list(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<OrganizationCipherListGrant<S::CipherReads<'_>>, ApiError> {
        self.authorize_org_web_admin(owner, organization)?;
        let records = self
            .storage_mut()
            .organization_cipher_reads(organization)
            .map_err(S::map_error)?;
        for index in 0..records.len() {
            let row = records.get(index).ok_or_else(invalid_view)?;
            if row.organization_id != organization || row.id.is_empty() {
                return Err(invalid_view());
            }
        }
        Ok(OrganizationCipherListGrant { records })
    }
    pub fn list_org_collection_details(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<OrganizationCollectionDetailsResponse<S::CollectionDetails<'_>>, ApiError> {
        self.authorize_org_collection_manager(owner, organization)?;
        let records = self
            .storage_mut()
            .organization_collection_details(owner, organization)
            .map_err(S::map_error)?;
        for index in 0..records.len() {
            let details = records.get(index).ok_or_else(invalid_view)?;
            let row = details.collection();
            if row.collection.organization_id != organization
                || row.collection.id.is_empty()
                || row.membership.organization_id != organization
                || row.membership.user_id != owner
                || row.membership.status != 2
                || !row.readable
            {
                return Err(invalid_view());
            }
            for index in 0..details.users_len() {
                let user = details.user(index).ok_or_else(invalid_view)?;
                if user.organization_id != organization || user.id.is_empty() {
                    return Err(invalid_view());
                }
            }
            if details.groups_enabled() {
                for index in 0..details.groups_len() {
                    let group = details.group(index).ok_or_else(invalid_view)?;
                    if group.organization_id != organization || group.id.is_empty() {
                        return Err(invalid_view());
                    }
                }
            }
        }
        Ok(OrganizationCollectionDetailsResponse { records })
    }
    pub fn list_empty_org_groups(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<OrganizationEmptyGroupsResponse, ApiError> {
        self.authorize_org_web_admin(owner, organization)?;
        match self
            .storage_mut()
            .organization_group_presence(organization)
            .map_err(S::map_error)?
        {
            OrganizationGroupPresence::NoCreatedGroups => {
                Ok(OrganizationEmptyGroupsResponse { _sealed: () })
            }
            OrganizationGroupPresence::ConfiguredOrUnknown => Err(ApiError::new(
                ErrorKind::Forbidden,
                "Configured organization groups are unsupported",
            )),
        }
    }
}

#[cfg(test)]
mod tests;
