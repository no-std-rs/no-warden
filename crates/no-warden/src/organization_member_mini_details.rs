//! Minimal organization-member discovery without allocation or account key reads.
use crate::{
    ApiError, ErrorKind, VaultService, organization_collections::OrganizationCollectionStorage,
};

/// Minimal trusted member/account join. Name is the account name even for invited
/// or revoked memberships; this projection does not inherit the full-list name
/// eligibility filter. Organization ID is an internal association, never emitted.
#[derive(Clone, Copy)]
pub struct OrganizationMemberMiniRecord<'a> {
    pub membership_id: &'a str,
    pub organization_id: &'a str,
    pub user_id: &'a str,
    pub email: &'a str,
    pub name: &'a str,
    pub role: i32,
    pub status: i32,
}
impl core::fmt::Debug for OrganizationMemberMiniRecord<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberMiniRecord([REDACTED])")
    }
}

/// Stable complete caller/provider-owned view, without an intrinsic member limit.
/// Keep exact provider order and every membership state. Every index below len
/// must remain present and unchanged through validation and serialization.
pub trait OrganizationMemberMiniData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<OrganizationMemberMiniRecord<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: OrganizationMemberMiniData + ?Sized> OrganizationMemberMiniData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<OrganizationMemberMiniRecord<'_>> {
        (**self).get(index)
    }
}
impl OrganizationMemberMiniData for [OrganizationMemberMiniRecord<'_>] {
    fn len(&self) -> usize {
        <[OrganizationMemberMiniRecord<'_>]>::len(self)
    }
    fn get(&self, index: usize) -> Option<OrganizationMemberMiniRecord<'_>> {
        <[OrganizationMemberMiniRecord<'_>]>::get(self, index).copied()
    }
}

/// Opt-in read-only provider. Return trusted minimal account/membership joins
/// scoped to the requested organization. Do not require full access or filter
/// targets by role, status, direct/group grants or actor identity. Keep the
/// operation's authenticated lock/snapshot through response construction and
/// serialization. Never load keys or private account documents into these views.
/// Reads/errors preserve all persisted state and account/session authority.
pub trait OrganizationMemberMiniStorage: OrganizationCollectionStorage {
    type MiniMembers<'a>: OrganizationMemberMiniData
    where
        Self: 'a;
    fn organization_member_mini_details(
        &mut self,
        organization: &str,
    ) -> Result<Self::MiniMembers<'_>, Self::Error>;
}
impl<T: OrganizationMemberMiniStorage + ?Sized> OrganizationMemberMiniStorage for &mut T {
    type MiniMembers<'a>
        = T::MiniMembers<'a>
    where
        Self: 'a;
    fn organization_member_mini_details(
        &mut self,
        organization: &str,
    ) -> Result<Self::MiniMembers<'_>, Self::Error> {
        (**self).organization_member_mini_details(organization)
    }
}

/// Sealed list of exact seven-field mini rows, independent of the richer member
/// projection. No request/query flags or key-bearing data enter serialization.
pub struct OrganizationMemberMiniDetailsResponse<L> {
    records: L,
}
impl<L> core::fmt::Debug for OrganizationMemberMiniDetailsResponse<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberMiniDetailsResponse([REDACTED])")
    }
}
struct Row<'a>(OrganizationMemberMiniRecord<'a>);
impl serde::Serialize for Row<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let row = self.0;
        let mut result = serializer.serialize_map(Some(7))?;
        result.serialize_entry("id", row.membership_id)?;
        result.serialize_entry("userId", row.user_id)?;
        result.serialize_entry("email", row.email)?;
        result.serialize_entry("name", row.name)?;
        result.serialize_entry("type", &if row.role == 3 { 4 } else { row.role })?;
        result.serialize_entry("status", &row.status.max(-1))?;
        result.serialize_entry("object", "organizationUserUserMiniDetails")?;
        result.end()
    }
}
impl<L: OrganizationMemberMiniData> serde::Serialize for OrganizationMemberMiniDetailsResponse<L> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        struct Rows<'a, L>(&'a L);
        impl<L: OrganizationMemberMiniData> serde::Serialize for Rows<'_, L> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
                for index in 0..self.0.len() {
                    let record = self.0.get(index).ok_or_else(|| {
                        serde::ser::Error::custom("Incomplete organization mini-member view")
                    })?;
                    rows.serialize_element(&Row(record))?;
                }
                rows.end()
            }
        }
        let mut result = serializer.serialize_map(Some(3))?;
        result.serialize_entry("data", &Rows(&self.records))?;
        result.serialize_entry("object", "list")?;
        result.serialize_entry("continuationToken", &Option::<&str>::None)?;
        result.end()
    }
}
impl<S: OrganizationMemberMiniStorage> VaultService<S> {
    /// Confirmed Owner/Admin/Manager admission is independent of access_all.
    /// Invited, Accepted and Revoked targets remain visible, in provider order.
    pub fn list_org_member_mini_details(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<OrganizationMemberMiniDetailsResponse<S::MiniMembers<'_>>, ApiError> {
        self.authorize_org_collection_manager(owner, organization)?;
        let records = self
            .storage_mut()
            .organization_member_mini_details(organization)
            .map_err(S::map_error)?;
        for index in 0..records.len() {
            let row = records.get(index).ok_or_else(|| {
                ApiError::new(
                    ErrorKind::Storage,
                    "Organization mini-member view is incomplete",
                )
            })?;
            if row.organization_id != organization {
                return Err(ApiError::new(
                    ErrorKind::Unauthorized,
                    "Organization mini-member view belongs to another organization",
                ));
            }
        }
        Ok(OrganizationMemberMiniDetailsResponse { records })
    }
}

#[cfg(test)]
mod tests;
