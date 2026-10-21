//! Scoped organization-member public-key discovery without allocation.
//!
//! Providers own joined snapshots; callers own request and result storage. This
//! read never loads private keys or changes memberships, revisions or sessions.

use crate::{
    ApiError, ErrorKind, VaultService, organization_collections::OrganizationCollectionStorage,
};

/// Completely decoded, stable opaque membership IDs, including duplicates.
/// All reported indices must remain present throughout the service invocation.
/// A host may implement this over an uncapped owned list instead of a bounded DTO.
pub trait OrganizationMemberPublicKeysData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<&str>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: OrganizationMemberPublicKeysData + ?Sized> OrganizationMemberPublicKeysData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        (**self).get(index)
    }
}
impl OrganizationMemberPublicKeysData for [&str] {
    fn len(&self) -> usize {
        <[&str]>::len(self)
    }
    fn get(&self, index: usize) -> Option<&str> {
        <[&str]>::get(self, index).copied()
    }
}
impl<const N: usize> OrganizationMemberPublicKeysData
    for crate::wire::OrganizationMemberPublicKeysRequest<'_, N>
{
    fn len(&self) -> usize {
        self.ids.len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.ids.get(index).copied()
    }
}

/// Owned joined metadata. An existing account with no public key is a present
/// record with public_key=None; this differs from a missing membership/account.
/// Handles need not be Clone, Debug or Serialize. Public keys remain opaque,
/// including empty strings and future formats, and are never inspected here.
pub struct OrganizationMemberPublicKeyRecord<I, K> {
    pub membership_id: I,
    pub organization_id: I,
    pub user_id: I,
    pub public_key: Option<K>,
}
impl<I, K> core::fmt::Debug for OrganizationMemberPublicKeyRecord<I, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberPublicKeyRecord([REDACTED])")
    }
}

/// Scoped join outcome: absent membership/account, present nullable-key record,
/// or a provider error. Keeping these three outcomes distinct is required.
pub type OrganizationMemberPublicKeyLookup<I, K, E> =
    Result<Option<OrganizationMemberPublicKeyRecord<I, K>>, E>;

/// Opt-in scoped read provider. Run authorize_org_member_admin before HTTP UUID
/// and body guards, then hold the authenticated lock/snapshot for the operation.
/// Lookup must join BOTH organization and membership IDs to an existing account.
/// Return None for a missing scoped membership or missing account, but Some with
/// public_key=None when that existing account has no public key. Do not filter
/// targets by status, role, confirmation eligibility, grants or actor identity.
/// Do not normalize any identifier or load unrelated secret account fields.
///
/// Reads and errors must preserve memberships, account revisions, credentials,
/// key material, organization state, grants, sessions/devices and vault payloads.
/// Safely mapped provider failures abort the response. Backend diagnostic/absence
/// behavior remains distinct from upstream finders that may collapse failures.
pub trait OrganizationMemberPublicKeyStorage: OrganizationCollectionStorage {
    type Id: AsRef<str>;
    type PublicKey: AsRef<str>;
    fn member_public_key(
        &mut self,
        organization: &str,
        membership: &str,
    ) -> OrganizationMemberPublicKeyLookup<Self::Id, Self::PublicKey, Self::Error>;
}
impl<T: OrganizationMemberPublicKeyStorage + ?Sized> OrganizationMemberPublicKeyStorage for &mut T {
    type Id = T::Id;
    type PublicKey = T::PublicKey;
    fn member_public_key(
        &mut self,
        organization: &str,
        membership: &str,
    ) -> OrganizationMemberPublicKeyLookup<Self::Id, Self::PublicKey, Self::Error> {
        (**self).member_public_key(organization, membership)
    }
}

/// Explicit, exact four-field public row, borrowing an authorized owned snapshot.
pub struct OrganizationMemberPublicKeyResponse<'a, I, K> {
    record: &'a OrganizationMemberPublicKeyRecord<I, K>,
}
impl<'a, I: AsRef<str>, K: AsRef<str>> OrganizationMemberPublicKeyResponse<'a, I, K> {
    pub fn membership_id(&self) -> &'a str {
        self.record.membership_id.as_ref()
    }
    pub fn user_id(&self) -> &'a str {
        self.record.user_id.as_ref()
    }
    pub fn public_key(&self) -> Option<&'a str> {
        self.record.public_key.as_ref().map(AsRef::as_ref)
    }
}
impl<I, K> core::fmt::Debug for OrganizationMemberPublicKeyResponse<'_, I, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberPublicKeyResponse([REDACTED])")
    }
}
impl<I: AsRef<str>, K: AsRef<str>> serde::Serialize
    for OrganizationMemberPublicKeyResponse<'_, I, K>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut row = serializer.serialize_map(Some(4))?;
        row.serialize_entry("object", "organizationUserPublicKeyResponseModel")?;
        row.serialize_entry("id", self.membership_id())?;
        row.serialize_entry("userId", self.user_id())?;
        row.serialize_entry("key", &self.public_key())?;
        row.end()
    }
}

/// Ordered complete response; missing records consume no slot. Output snapshots
/// remain owned by the caller and no storage access happens during serialization.
pub struct OrganizationMemberPublicKeysResponse<'out, I, K> {
    records: &'out [Option<OrganizationMemberPublicKeyRecord<I, K>>],
}
impl<I: AsRef<str>, K: AsRef<str>> OrganizationMemberPublicKeysResponse<'_, I, K> {
    pub const fn len(&self) -> usize {
        self.records.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<OrganizationMemberPublicKeyResponse<'_, I, K>> {
        Some(OrganizationMemberPublicKeyResponse {
            record: self.records.get(index)?.as_ref()?,
        })
    }
}
impl<I, K> core::fmt::Debug for OrganizationMemberPublicKeysResponse<'_, I, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationMemberPublicKeysResponse([REDACTED])")
    }
}
impl<I: AsRef<str>, K: AsRef<str>> serde::Serialize
    for OrganizationMemberPublicKeysResponse<'_, I, K>
{
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        struct Rows<'a, I, K>(&'a [Option<OrganizationMemberPublicKeyRecord<I, K>>]);
        impl<I: AsRef<str>, K: AsRef<str>> serde::Serialize for Rows<'_, I, K> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut rows = serializer.serialize_seq(Some(self.0.len()))?;
                for slot in self.0 {
                    let record = slot.as_ref().ok_or_else(|| {
                        serde::ser::Error::custom("Incomplete organization public-key output")
                    })?;
                    rows.serialize_element(&OrganizationMemberPublicKeyResponse { record })?;
                }
                rows.end()
            }
        }
        let mut result = serializer.serialize_map(Some(3))?;
        result.serialize_entry("data", &Rows(self.records))?;
        result.serialize_entry("object", "list")?;
        result.serialize_entry("continuationToken", &Option::<&str>::None)?;
        result.end()
    }
}

fn invalid_view(message: &'static str) -> ApiError {
    ApiError::new(ErrorKind::Storage, message)
}
impl<S: OrganizationMemberPublicKeyStorage> VaultService<S> {
    /// Authorize, validate complete caller input/output capacity, then join exact
    /// scoped IDs in input order. Duplicates survive and absent records are omitted.
    /// Scratch must fit the input count even if some records will be absent. This
    /// local embedding capacity is not an intrinsic HTTP batch limit. On lookup or
    /// association error, clear partial output and return no partial response.
    pub fn get_org_member_public_keys<'out, D: OrganizationMemberPublicKeysData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        request: &D,
        scratch: &'out mut [Option<OrganizationMemberPublicKeyRecord<S::Id, S::PublicKey>>],
    ) -> Result<OrganizationMemberPublicKeysResponse<'out, S::Id, S::PublicKey>, ApiError> {
        self.authorize_org_member_admin(owner, organization)?;
        let count = request.len();
        if scratch.len() < count {
            return Err(invalid_view(
                "Organization public-key output capacity is insufficient",
            ));
        }
        for index in 0..count {
            if request.get(index).is_none() {
                return Err(invalid_view(
                    "Organization public-key input view is incomplete",
                ));
            }
        }
        for slot in &mut scratch[..count] {
            *slot = None;
        }
        let result = (|| {
            let mut rows = 0;
            for index in 0..count {
                let id = request.get(index).ok_or_else(|| {
                    invalid_view("Organization public-key input view is incomplete")
                })?;
                if let Some(record) = self
                    .storage_mut()
                    .member_public_key(organization, id)
                    .map_err(S::map_error)?
                {
                    if record.organization_id.as_ref() != organization
                        || record.membership_id.as_ref() != id
                    {
                        return Err(invalid_view(
                            "Organization public-key provider association is invalid",
                        ));
                    }
                    scratch[rows] = Some(record);
                    rows += 1;
                }
            }
            Ok(rows)
        })();
        match result {
            Ok(rows) => Ok(OrganizationMemberPublicKeysResponse {
                records: &scratch[..rows],
            }),
            Err(error) => {
                for slot in &mut scratch[..count] {
                    *slot = None;
                }
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests;
