//! Ordered, independently committed organization-member revoke/restore batches.
//!
//! Input and result storage belong to the caller. The core has no allocator or
//! intrinsic batch limit, and reuses the sealed single-member status write plan.

use crate::{
    ApiError, ErrorKind, VaultService,
    organization_member_status::{
        OrganizationMemberStatusOperation, OrganizationMemberStatusStorage,
    },
};

/// Fully decoded, stable opaque IDs, preserving bytes, order and duplicates.
/// Adapters must finish decoding the whole body before invoking a batch. A host
/// can implement this over owned strings instead of the optional bounded DTOs.
pub trait OrganizationBulkMemberStatusData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<&str>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: OrganizationBulkMemberStatusData + ?Sized> OrganizationBulkMemberStatusData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        (**self).get(index)
    }
}
impl OrganizationBulkMemberStatusData for [&str] {
    fn len(&self) -> usize {
        <[&str]>::len(self)
    }
    fn get(&self, index: usize) -> Option<&str> {
        <[&str]>::get(self, index).copied()
    }
}
impl<const N: usize> OrganizationBulkMemberStatusData
    for crate::wire::OrganizationBulkMemberRevokeRequest<'_, N>
{
    fn len(&self) -> usize {
        self.ids.as_ref().map_or(0, |ids| ids.len())
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.ids.as_ref()?.get(index).copied()
    }
}
impl<const N: usize> OrganizationBulkMemberStatusData
    for crate::wire::OrganizationBulkMemberRestoreRequest<'_, N>
{
    fn len(&self) -> usize {
        self.ids.len()
    }
    fn get(&self, index: usize) -> Option<&str> {
        self.ids.get(index).copied()
    }
}

/// One exact input ID and its safely mapped public error, or success.
/// Provider diagnostics and internal Debug output are never serialized.
#[derive(Clone, Copy)]
pub struct OrganizationBulkMemberStatusResult<'a> {
    id: &'a str,
    error: Option<ApiError>,
}
impl<'a> OrganizationBulkMemberStatusResult<'a> {
    pub const fn id(&self) -> &'a str {
        self.id
    }
    pub const fn error(&self) -> Option<ApiError> {
        self.error
    }
}
impl core::fmt::Debug for OrganizationBulkMemberStatusResult<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationBulkMemberStatusResult([REDACTED])")
    }
}
impl serde::Serialize for OrganizationBulkMemberStatusResult<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut row = serializer.serialize_map(Some(3))?;
        row.serialize_entry("object", "OrganizationUserBulkResponseModel")?;
        row.serialize_entry("id", self.id)?;
        row.serialize_entry("error", self.error.map_or("", |error| error.message))?;
        row.end()
    }
}

/// Complete response borrowing caller-owned IDs and output slots.
pub struct OrganizationBulkMemberStatusResponse<'out, 'data> {
    results: &'out [Option<OrganizationBulkMemberStatusResult<'data>>],
}
impl<'data> OrganizationBulkMemberStatusResponse<'_, 'data> {
    pub const fn len(&self) -> usize {
        self.results.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
    pub fn get(&self, index: usize) -> Option<&OrganizationBulkMemberStatusResult<'data>> {
        self.results.get(index)?.as_ref()
    }
}
impl core::fmt::Debug for OrganizationBulkMemberStatusResponse<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationBulkMemberStatusResponse([REDACTED])")
    }
}
impl serde::Serialize for OrganizationBulkMemberStatusResponse<'_, '_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{SerializeMap, SerializeSeq};
        struct Rows<'a, 'b>(&'a [Option<OrganizationBulkMemberStatusResult<'b>>]);
        impl serde::Serialize for Rows<'_, '_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
                for slot in self.0 {
                    sequence.serialize_element(slot.as_ref().ok_or_else(|| {
                        serde::ser::Error::custom("Incomplete bulk member status output")
                    })?)?;
                }
                sequence.end()
            }
        }
        let mut response = serializer.serialize_map(Some(3))?;
        response.serialize_entry("data", &Rows(self.results))?;
        response.serialize_entry("object", "list")?;
        response.serialize_entry("continuationToken", &Option::<&str>::None)?;
        response.end()
    }
}

impl<S: OrganizationMemberStatusStorage> VaultService<S> {
    /// Authorize once, then revoke each member independently in input order.
    /// Missing/null revoke IDs decode to an empty view. Item errors do not abort
    /// later rows or undo an earlier success. Commit rechecks live authority and
    /// target state with the existing single-status provider contract.
    pub fn bulk_revoke_org_members<'data, 'out, D: OrganizationBulkMemberStatusData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        request: &'data D,
        scratch: &'out mut [Option<OrganizationBulkMemberStatusResult<'data>>],
    ) -> Result<OrganizationBulkMemberStatusResponse<'out, 'data>, ApiError> {
        self.bulk_change_org_member_status(
            owner,
            organization,
            request,
            scratch,
            OrganizationMemberStatusOperation::Revoke,
        )
    }
    /// Restore each member using the same ordered per-item status/policy rules.
    /// Restore's required IDs are enforced by the DTO/adapter before any writes.
    pub fn bulk_restore_org_members<'data, 'out, D: OrganizationBulkMemberStatusData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        request: &'data D,
        scratch: &'out mut [Option<OrganizationBulkMemberStatusResult<'data>>],
    ) -> Result<OrganizationBulkMemberStatusResponse<'out, 'data>, ApiError> {
        self.bulk_change_org_member_status(
            owner,
            organization,
            request,
            scratch,
            OrganizationMemberStatusOperation::Restore,
        )
    }
    fn bulk_change_org_member_status<'data, 'out, D: OrganizationBulkMemberStatusData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        request: &'data D,
        scratch: &'out mut [Option<OrganizationBulkMemberStatusResult<'data>>],
        operation: OrganizationMemberStatusOperation,
    ) -> Result<OrganizationBulkMemberStatusResponse<'out, 'data>, ApiError> {
        let actor_role = self.org_member_admin_role(owner, organization)?;
        let count = request.len();
        if scratch.len() < count {
            return Err(ApiError::new(
                ErrorKind::Storage,
                "Bulk member status output capacity is insufficient",
            ));
        }
        for index in 0..count {
            if request.get(index).is_none() {
                return Err(ApiError::new(
                    ErrorKind::Storage,
                    "Bulk member status input view is incomplete",
                ));
            }
        }
        scratch[..count].fill(None);
        for (index, slot) in scratch[..count].iter_mut().enumerate() {
            let member = request.get(index).ok_or_else(|| {
                ApiError::new(
                    ErrorKind::Storage,
                    "Bulk member status input view is incomplete",
                )
            })?;
            let result = self.change_org_member_status_with_role(
                owner,
                organization,
                member,
                operation,
                actor_role,
            );
            *slot = Some(OrganizationBulkMemberStatusResult {
                id: member,
                error: result.err(),
            });
        }
        Ok(OrganizationBulkMemberStatusResponse {
            results: &scratch[..count],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{OrganizationBulkMemberRestoreRequest, OrganizationBulkMemberRevokeRequest};
    use std::format;

    #[test]
    fn bulk_status_dtos_distinguish_optional_revoke_and_required_restore_ids() {
        for input in ["{}", r#"{"ids":null}"#, "[null]"] {
            let revoke: OrganizationBulkMemberRevokeRequest<'_, 3> =
                serde_json::from_str(input).unwrap();
            assert!(revoke.is_empty());
            assert!(revoke.get(0).is_none());
            assert!(
                serde_json::from_str::<OrganizationBulkMemberRestoreRequest<'_, 3>>(input).is_err()
            );
        }
        for input in [r#"{"ids":[]}"#, "[[]]"] {
            let revoke: OrganizationBulkMemberRevokeRequest<'_, 0> =
                serde_json::from_str(input).unwrap();
            let restore: OrganizationBulkMemberRestoreRequest<'_, 0> =
                serde_json::from_str(input).unwrap();
            assert!(revoke.is_empty());
            assert!(restore.is_empty());
        }
        for input in [
            "[]",
            "null",
            "true",
            "0",
            r#"{"ids":"member"}"#,
            r#"{"ids":["member",null]}"#,
            r#"{"ids":[1]}"#,
            r#"{"ids":[],"ids":[]}"#,
        ] {
            assert!(
                serde_json::from_str::<OrganizationBulkMemberRevokeRequest<'_, 3>>(input).is_err(),
                "{input}"
            );
            assert!(
                serde_json::from_str::<OrganizationBulkMemberRestoreRequest<'_, 3>>(input).is_err(),
                "{input}"
            );
        }
    }

    #[test]
    fn bulk_status_dtos_borrow_opaque_ids_allow_unknown_fields_and_use_only_caller_capacity() {
        let input = r#"{"ids":["bad.id","","bad.id"],"unknown":true}"#;
        let revoke: OrganizationBulkMemberRevokeRequest<'_, 3> =
            serde_json::from_str(input).unwrap();
        let restore: OrganizationBulkMemberRestoreRequest<'_, 3> =
            serde_json::from_str(input).unwrap();
        assert_eq!(revoke.len(), 3);
        assert_eq!(restore.len(), 3);
        for (index, id) in ["bad.id", "", "bad.id"].iter().enumerate() {
            assert_eq!(revoke.get(index), Some(*id));
            assert_eq!(restore.get(index), Some(*id));
        }
        assert!(serde_json::from_str::<OrganizationBulkMemberRevokeRequest<'_, 2>>(input).is_err());
        assert!(
            serde_json::from_str::<OrganizationBulkMemberRestoreRequest<'_, 2>>(input).is_err()
        );
        assert_eq!(
            format!("{revoke:?}"),
            "OrganizationBulkMemberRevokeRequest([REDACTED])"
        );
        assert_eq!(
            format!("{restore:?}"),
            "OrganizationBulkMemberRestoreRequest([REDACTED])"
        );
        let forwarded = &restore;
        assert_eq!(
            OrganizationBulkMemberStatusData::get(&forwarded, 0),
            Some("bad.id")
        );
    }

    #[test]
    fn bulk_status_result_and_response_debug_redact_identifiers_and_errors() {
        let slots = [Some(OrganizationBulkMemberStatusResult {
            id: "private-member-id",
            error: Some(ApiError::invalid("private-field", "private diagnostic")),
        })];
        let response = OrganizationBulkMemberStatusResponse { results: &slots };
        assert_eq!(
            format!("{:?}", slots[0].unwrap()),
            "OrganizationBulkMemberStatusResult([REDACTED])"
        );
        assert_eq!(
            format!("{response:?}"),
            "OrganizationBulkMemberStatusResponse([REDACTED])"
        );
    }
}
