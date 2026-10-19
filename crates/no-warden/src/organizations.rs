//! Organization owner creation/discovery over allocation-free persistence providers.
//!
//! Identifier generation, Unicode lowercase, email validation, clocks, membership/ACL
//! queries and transactions belong to adapters. These APIs do not implement invitations,
//! organization administration, shared cipher writes, or organization policy management.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    service::require_owner,
    wire::{
        OrganizationCreateRequest, OrganizationProfileListResponse, OrganizationResponse,
        UserCollectionListResponse,
    },
};

/// Trusted service configuration for the wire projection, never client input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OrganizationFeatures {
    pub events: bool,
    pub groups: bool,
    pub mail: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrganizationCreationPolicy {
    pub allowed: bool,
    pub single_org_blocked: bool,
    pub billing_email_valid: bool,
}

/// Public organization metadata, deliberately excluding all organization key material.
#[derive(Clone, Copy)]
pub struct OrganizationRecord<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub billing_email: &'a str,
    pub has_public_and_private_keys: bool,
    pub features: OrganizationFeatures,
}

/// Internal membership metadata used for ownership and collection authorization.
#[derive(Clone, Copy)]
pub struct OrganizationMembership<'a> {
    pub user_id: &'a str,
    pub organization_id: &'a str,
    pub role: i32,
    pub status: i32,
}

/// Joined profile metadata for the authenticated member. Only the explicit response
/// serializer exposes the wrapped organization key; raw records are not serializable.
#[derive(Clone, Copy)]
pub struct OrganizationProfileRecord<'a> {
    pub organization: OrganizationRecord<'a>,
    pub membership: OrganizationMembership<'a>,
    pub membership_id: &'a str,
    pub key: &'a str,
    pub access_all: bool,
    pub reset_password_enrolled: bool,
}

#[derive(Clone, Copy)]
pub struct CollectionRecord<'a> {
    pub id: &'a str,
    pub organization_id: &'a str,
    pub name: &'a str,
    pub external_id: Option<&'a str>,
}

/// The provider resolves direct/group access and supplies trusted per-user flags.
/// The service independently checks the user, joined organization, confirmed status
/// and readable decision before any record reaches serialization.
#[derive(Clone, Copy)]
pub struct UserCollectionRecord<'a> {
    pub collection: CollectionRecord<'a>,
    pub membership: OrganizationMembership<'a>,
    pub readable: bool,
    pub read_only: bool,
    pub hide_passwords: bool,
    pub manage: bool,
}

macro_rules! redacted {
    ($($name:ident),+ $(,)?) => {$(
        impl core::fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )+};
}
redacted!(
    OrganizationRecord,
    OrganizationMembership,
    OrganizationProfileRecord,
    CollectionRecord,
    UserCollectionRecord
);

/// Caller-owned stable view: every index below len exists through serialization.
pub trait UserCollectionListData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<UserCollectionRecord<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: UserCollectionListData + ?Sized> UserCollectionListData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<UserCollectionRecord<'_>> {
        (**self).get(index)
    }
}
impl UserCollectionListData for [UserCollectionRecord<'_>] {
    fn len(&self) -> usize {
        <[UserCollectionRecord<'_>]>::len(self)
    }
    fn get(&self, index: usize) -> Option<UserCollectionRecord<'_>> {
        <[UserCollectionRecord<'_>]>::get(self, index).copied()
    }
}

/// Caller-owned profile memberships, including statuses needed for profile discovery.
pub trait OrganizationProfileListData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<OrganizationProfileRecord<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: OrganizationProfileListData + ?Sized> OrganizationProfileListData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<OrganizationProfileRecord<'_>> {
        (**self).get(index)
    }
}
impl OrganizationProfileListData for [OrganizationProfileRecord<'_>] {
    fn len(&self) -> usize {
        <[OrganizationProfileRecord<'_>]>::len(self)
    }
    fn get(&self, index: usize) -> Option<OrganizationProfileRecord<'_>> {
        <[OrganizationProfileRecord<'_>]>::get(self, index).copied()
    }
}

/// A creation request admitted after trusted policy and billing-email checks.
pub struct ValidatedOrganizationCreate<'a, 'r> {
    request: &'r OrganizationCreateRequest<'a>,
}
impl<'a, 'r> ValidatedOrganizationCreate<'a, 'r> {
    pub const fn request(&self) -> &'r OrganizationCreateRequest<'a> {
        self.request
    }
    pub const fn membership_role(&self) -> i32 {
        0
    }
    pub const fn membership_status(&self) -> i32 {
        2
    }
    pub const fn access_all(&self) -> bool {
        true
    }
}
impl core::fmt::Debug for ValidatedOrganizationCreate<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationCreate([REDACTED])")
    }
}

/// Opt-in organization persistence. Owner arguments come from verified sessions.
/// Hold the embedding operation's storage lock/context through validation and projection.
///
/// Resolve configured creation permission and SingleOrg policy before billing validation.
/// Billing email is Unicode-lowercased WITHOUT trimming; validate that normalized address
/// using the adapter's source-compatible email parser. Other request strings are opaque,
/// including empty strings and key strings; plan_type is required but ignored.
///
/// Creation generates fresh organization, membership and collection IDs, and commits the
/// organization (including optional key pair), confirmed Owner role 0/status 2/access_all
/// membership and opaque wrapped key, initial collection, and authenticated account
/// revision together. This is stronger than upstream's sequential saves. An error must
/// leave all prior state unchanged. Preserve credentials, keys, sessions, personal vaults
/// and foreign state. Prepare the returned borrowed record in provider-owned memory so
/// no fallible post-commit lookup is required. Recheck mutable policy within the write
/// transaction as needed. No notifications or organization management are implied.
///
/// Reads must use exact identifiers and stable complete views. Collection providers resolve
/// direct/group grants and permissions and select only readable confirmed memberships.
/// Profile providers join each membership to its actual organization and preserve status.
/// Never log raw records or expose stored private organization keys through these views.
/// Organization-aware account deletion must enforce its last-confirmed-owner restriction;
/// creation must not permit subsequent account cleanup to orphan the organization.
pub trait OrganizationStorage: Storage {
    type Collections<'a>: UserCollectionListData
    where
        Self: 'a;
    type Profiles<'a>: OrganizationProfileListData
    where
        Self: 'a;
    fn creation_policy(
        &mut self,
        owner: &str,
        billing_email: &str,
    ) -> Result<OrganizationCreationPolicy, Self::Error>;
    fn create_organization(
        &mut self,
        owner: &str,
        plan: &ValidatedOrganizationCreate<'_, '_>,
    ) -> Result<OrganizationRecord<'_>, Self::Error>;
    fn organization_membership(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<Option<OrganizationMembership<'_>>, Self::Error>;
    fn organization(
        &mut self,
        organization: &str,
    ) -> Result<Option<OrganizationRecord<'_>>, Self::Error>;
    fn user_collections(&mut self, owner: &str) -> Result<Self::Collections<'_>, Self::Error>;
    fn profile_organizations(&mut self, owner: &str) -> Result<Self::Profiles<'_>, Self::Error>;
}

impl<T: OrganizationStorage + ?Sized> OrganizationStorage for &mut T {
    type Collections<'a>
        = T::Collections<'a>
    where
        Self: 'a;
    type Profiles<'a>
        = T::Profiles<'a>
    where
        Self: 'a;
    fn creation_policy(
        &mut self,
        owner: &str,
        email: &str,
    ) -> Result<OrganizationCreationPolicy, Self::Error> {
        (**self).creation_policy(owner, email)
    }
    fn create_organization(
        &mut self,
        owner: &str,
        plan: &ValidatedOrganizationCreate<'_, '_>,
    ) -> Result<OrganizationRecord<'_>, Self::Error> {
        (**self).create_organization(owner, plan)
    }
    fn organization_membership(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<Option<OrganizationMembership<'_>>, Self::Error> {
        (**self).organization_membership(owner, organization)
    }
    fn organization(
        &mut self,
        organization: &str,
    ) -> Result<Option<OrganizationRecord<'_>>, Self::Error> {
        (**self).organization(organization)
    }
    fn user_collections(&mut self, owner: &str) -> Result<Self::Collections<'_>, Self::Error> {
        (**self).user_collections(owner)
    }
    fn profile_organizations(&mut self, owner: &str) -> Result<Self::Profiles<'_>, Self::Error> {
        (**self).profile_organizations(owner)
    }
}

fn not_member() -> ApiError {
    ApiError::new(
        ErrorKind::Unauthorized,
        "The current user isn't member of the organization",
    )
}

impl<S: OrganizationStorage> VaultService<S> {
    pub fn create_organization(
        &mut self,
        owner: &str,
        request: &OrganizationCreateRequest<'_>,
    ) -> Result<OrganizationResponse<'_>, ApiError> {
        require_owner(owner)?;
        let policy = self
            .storage_mut()
            .creation_policy(owner, request.billing_email)
            .map_err(S::map_error)?;
        if !policy.allowed {
            return Err(ApiError::invalid(
                "organization",
                "User not allowed to create organizations",
            ));
        }
        if policy.single_org_blocked {
            return Err(ApiError::invalid(
                "organization",
                "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization.",
            ));
        }
        if !policy.billing_email_valid {
            // HTTP adapters can render the source's escaped address using this marker.
            return Err(ApiError::invalid(
                "billingEmail",
                "BillingEmail is not a valid email address",
            ));
        }
        let plan = ValidatedOrganizationCreate { request };
        let record = self
            .storage_mut()
            .create_organization(owner, &plan)
            .map_err(S::map_error)?;
        Ok(OrganizationResponse::new(record))
    }

    pub fn get_organization(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<OrganizationResponse<'_>, ApiError> {
        require_owner(owner)?;
        let member = self
            .storage_mut()
            .organization_membership(owner, organization)
            .map_err(S::map_error)?
            .ok_or_else(not_member)?;
        if member.user_id != owner || member.organization_id != organization {
            return Err(not_member());
        }
        if member.role != 0 || member.status != 2 {
            return Err(ApiError::new(
                ErrorKind::Unauthorized,
                "You need to be Owner to call this endpoint",
            ));
        }
        let record = self
            .storage_mut()
            .organization(organization)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("organization", "Can't find organization details"))?;
        if record.id != organization {
            return Err(ApiError::invalid("organization", "Organization not found"));
        }
        Ok(OrganizationResponse::new(record))
    }

    pub fn list_user_collections(
        &mut self,
        owner: &str,
    ) -> Result<UserCollectionListResponse<S::Collections<'_>>, ApiError> {
        require_owner(owner)?;
        let records = self
            .storage_mut()
            .user_collections(owner)
            .map_err(S::map_error)?;
        for index in 0..records.len() {
            let row = records.get(index).ok_or_else(|| {
                ApiError::new(ErrorKind::Storage, "Collection view is incomplete")
            })?;
            if row.membership.user_id != owner
                || row.membership.organization_id != row.collection.organization_id
                || row.membership.status != 2
                || !row.readable
            {
                return Err(not_member());
            }
        }
        Ok(UserCollectionListResponse::new(records))
    }

    pub fn profile_organizations(
        &mut self,
        owner: &str,
    ) -> Result<OrganizationProfileListResponse<S::Profiles<'_>>, ApiError> {
        require_owner(owner)?;
        let records = self
            .storage_mut()
            .profile_organizations(owner)
            .map_err(S::map_error)?;
        for index in 0..records.len() {
            let row = records.get(index).ok_or_else(|| {
                ApiError::new(
                    ErrorKind::Storage,
                    "Organization profile view is incomplete",
                )
            })?;
            if row.membership.user_id != owner
                || row.membership.organization_id != row.organization.id
            {
                return Err(not_member());
            }
        }
        Ok(OrganizationProfileListResponse::new(records))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::Secret,
        service::ItemMetadata,
        wire::{AccountKeys, CipherRequest, FolderRequest, OrganizationPlanType, RegisterRequest},
    };
    use serde::Deserialize;
    use serde_json::json;
    use std::{
        string::{String, ToString},
        vec::Vec,
    };

    fn organization() -> OrganizationRecord<'static> {
        OrganizationRecord {
            id: "org",
            name: "opaque organization",
            billing_email: "billing@example.test",
            has_public_and_private_keys: false,
            features: OrganizationFeatures::default(),
        }
    }
    fn membership() -> OrganizationMembership<'static> {
        OrganizationMembership {
            user_id: "owner",
            organization_id: "org",
            role: 0,
            status: 2,
        }
    }
    fn profile() -> OrganizationProfileRecord<'static> {
        OrganizationProfileRecord {
            organization: organization(),
            membership: membership(),
            membership_id: "member",
            key: "opaque-member-key",
            access_all: true,
            reset_password_enrolled: false,
        }
    }
    fn collection() -> UserCollectionRecord<'static> {
        UserCollectionRecord {
            collection: CollectionRecord {
                id: "collection",
                organization_id: "org",
                name: "opaque collection",
                external_id: None,
            },
            membership: membership(),
            readable: true,
            read_only: false,
            hide_passwords: false,
            manage: true,
        }
    }
    #[derive(Clone, PartialEq, Eq)]
    struct State {
        present: bool,
        name: String,
        email: String,
        collection: String,
        key: String,
        keys: Option<(String, String)>,
        revision: u64,
        foreign: [u64; 4],
    }
    struct Memory {
        state: State,
        policy: OrganizationCreationPolicy,
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        member: Option<OrganizationMembership<'static>>,
        collections: [UserCollectionRecord<'static>; 2],
        profiles: [OrganizationProfileRecord<'static>; 4],
        count: usize,
        profile_count: usize,
    }
    impl Memory {
        fn new() -> Self {
            Self {
                state: State {
                    present: true,
                    name: "opaque organization".into(),
                    email: "billing@example.test".into(),
                    collection: "opaque collection".into(),
                    key: "opaque-member-key".into(),
                    keys: None,
                    revision: 3,
                    foreign: [2, 3, 5, 7],
                },
                policy: OrganizationCreationPolicy {
                    allowed: true,
                    single_org_blocked: false,
                    billing_email_valid: true,
                },
                calls: Vec::new(),
                fail: None,
                member: Some(membership()),
                collections: [collection(); 2],
                profiles: [profile(); 4],
                count: 1,
                profile_count: 1,
            }
        }
        fn check(&mut self, call: &'static str) -> Result<(), ()> {
            self.calls.push(call);
            if self.fail == Some(call) {
                Err(())
            } else {
                Ok(())
            }
        }
        fn record(&self) -> OrganizationRecord<'_> {
            OrganizationRecord {
                name: &self.state.name,
                billing_email: &self.state.email,
                has_public_and_private_keys: self.state.keys.is_some(),
                ..organization()
            }
        }
    }
    impl Storage for Memory {
        type Error = ();
        fn map_error(_: ()) -> ApiError {
            ApiError::new(ErrorKind::Storage, "Organization provider failed")
        }
        fn account_exists(&mut self, _: &str) -> Result<bool, ()> {
            unreachable!()
        }
        fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), ()> {
            unreachable!()
        }
        fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
            unreachable!()
        }
        fn save_folder(&mut self, _: &str, _: &str, _: &FolderRequest<'_>) -> Result<(), ()> {
            unreachable!()
        }
        fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), ()> {
            unreachable!()
        }
        fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
            unreachable!()
        }
        fn save_cipher(&mut self, _: &str, _: &str, _: &CipherRequest<'_>) -> Result<(), ()> {
            unreachable!()
        }
        fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), ()> {
            unreachable!()
        }
        fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), ()> {
            unreachable!()
        }
    }
    impl OrganizationStorage for Memory {
        type Collections<'a> = &'a [UserCollectionRecord<'static>];
        type Profiles<'a> = &'a [OrganizationProfileRecord<'static>];
        fn creation_policy(&mut self, _: &str, _: &str) -> Result<OrganizationCreationPolicy, ()> {
            self.check("policy")?;
            Ok(self.policy)
        }
        fn create_organization(
            &mut self,
            owner: &str,
            plan: &ValidatedOrganizationCreate<'_, '_>,
        ) -> Result<OrganizationRecord<'_>, ()> {
            self.check("create")?;
            assert_eq!(owner, "owner");
            assert_eq!(
                (
                    plan.membership_role(),
                    plan.membership_status(),
                    plan.access_all()
                ),
                (0, 2, true)
            );
            let request = plan.request();
            let mut next = self.state.clone();
            next.present = true;
            next.name = request.name.to_string();
            next.email = request.billing_email.to_lowercase();
            next.collection = request.collection_name.to_string();
            next.key = request.key.expose_secret().to_string();
            next.keys = request.keys.as_ref().map(|keys| {
                (
                    keys.encrypted_private_key.to_string(),
                    keys.public_key.to_string(),
                )
            });
            next.revision += 1;
            self.state = next;
            Ok(self.record())
        }
        fn organization_membership(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<OrganizationMembership<'_>>, ()> {
            self.check("member")?;
            Ok(self.member)
        }
        fn organization(&mut self, _: &str) -> Result<Option<OrganizationRecord<'_>>, ()> {
            self.check("org")?;
            Ok(self.state.present.then(|| self.record()))
        }
        fn user_collections(&mut self, _: &str) -> Result<Self::Collections<'_>, ()> {
            self.check("collections")?;
            Ok(&self.collections[..self.count])
        }
        fn profile_organizations(&mut self, _: &str) -> Result<Self::Profiles<'_>, ()> {
            self.check("profiles")?;
            Ok(&self.profiles[..self.profile_count])
        }
    }
    fn request() -> OrganizationCreateRequest<'static> {
        OrganizationCreateRequest {
            billing_email: "Billing@EXAMPLE.TEST",
            collection_name: "",
            key: Secret::new("opaque\0wrapped"),
            name: "",
            keys: None,
            plan_type: OrganizationPlanType::String("ignored arbitrary plan"),
        }
    }

    #[test]
    fn organization_services_require_authenticated_owner_before_any_provider() {
        let mut store = Memory::new();
        let mut service = VaultService::new(&mut store);
        assert_eq!(
            service
                .create_organization("", &request())
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            service
                .get_organization("", "org")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            service.list_user_collections("").unwrap_err().status_code(),
            401
        );
        assert_eq!(
            service.profile_organizations("").unwrap_err().status_code(),
            401
        );
        assert!(store.calls.is_empty());
    }

    #[test]
    fn organization_creation_policies_precede_billing_and_never_mutate_on_rejection() {
        let mut store = Memory::new();
        let before = store.state.clone();
        store.policy = OrganizationCreationPolicy {
            allowed: false,
            single_org_blocked: true,
            billing_email_valid: false,
        };
        let error = VaultService::new(&mut store)
            .create_organization("owner", &request())
            .unwrap_err();
        assert_eq!(error.message, "User not allowed to create organizations");
        store.policy.allowed = true;
        let error = VaultService::new(&mut store)
            .create_organization("owner", &request())
            .unwrap_err();
        assert!(
            error
                .message
                .starts_with("You may not create an organization.")
        );
        store.policy.single_org_blocked = false;
        let error = VaultService::new(&mut store)
            .create_organization("owner", &request())
            .unwrap_err();
        assert_eq!(error.field, Some("billingEmail"));
        assert!(store.calls.iter().all(|call| *call == "policy") && store.state == before);
    }

    #[test]
    fn organization_creation_preserves_opaque_strings_and_commits_fixed_owner_membership() {
        let name = "未来\0".repeat(1024);
        let mut input = request();
        input.name = &name;
        input.keys = Some(AccountKeys {
            encrypted_private_key: "",
            public_key: "",
        });
        input.plan_type = OrganizationPlanType::Integer(i64::MIN);
        let mut store = Memory::new();
        let mut service = VaultService::new(&mut store);
        let response = service.create_organization("owner", &input).unwrap();
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["name"], name);
        assert_eq!(value["billingEmail"], "billing@example.test");
        assert_eq!(value["hasPublicAndPrivateKeys"], true);
        assert_eq!(value["planType"], 6);
        assert!(store.state.collection.is_empty() && store.state.key == "opaque\0wrapped");
        assert_eq!(store.state.revision, 4);
        assert_eq!(store.state.foreign, [2, 3, 5, 7]);
        assert_eq!(store.calls, ["policy", "create"]);
    }

    #[test]
    fn organization_provider_failures_map_without_fallback_or_partial_mutations() {
        for call in ["policy", "create"] {
            let mut store = Memory::new();
            store.fail = Some(call);
            let before = store.state.clone();
            let error = VaultService::new(&mut store)
                .create_organization("owner", &request())
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Storage);
            assert!(store.state == before);
            if call == "policy" {
                assert_eq!(store.calls, ["policy"]);
            }
            store.fail = None;
            VaultService::new(&mut store)
                .create_organization("owner", &request())
                .unwrap();
        }
    }

    #[test]
    fn organization_owner_read_checks_exact_user_org_role_and_confirmed_status_first() {
        for member in [
            None,
            Some(OrganizationMembership {
                user_id: "foreign",
                ..membership()
            }),
            Some(OrganizationMembership {
                organization_id: "foreign-org",
                ..membership()
            }),
            Some(OrganizationMembership {
                role: 1,
                ..membership()
            }),
            Some(OrganizationMembership {
                status: 1,
                ..membership()
            }),
            Some(OrganizationMembership {
                status: -1,
                ..membership()
            }),
        ] {
            let mut store = Memory::new();
            store.member = member;
            assert_eq!(
                VaultService::new(&mut store)
                    .get_organization("owner", "org")
                    .unwrap_err()
                    .status_code(),
                401
            );
            assert_eq!(store.calls, ["member"]);
        }
        let mut store = Memory::new();
        store.state.present = false;
        assert_eq!(
            VaultService::new(&mut store)
                .get_organization("owner", "org")
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(store.calls, ["member", "org"]);
    }

    #[test]
    fn organization_ordinary_and_profile_projections_keep_distinct_flags_and_private_boundary() {
        let mut store = Memory::new();
        let value = serde_json::to_value(
            VaultService::new(&mut store)
                .get_organization("owner", "org")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 47);
        assert_eq!(value["limitCollectionCreation"], true);
        assert!(value["seats"].is_null());
        for key in [
            "key",
            "privateKey",
            "publicKey",
            "organizationUserId",
            "userId",
        ] {
            assert!(value.get(key).is_none());
        }
        let profiles = serde_json::to_value(
            VaultService::new(&mut store)
                .profile_organizations("owner")
                .unwrap(),
        )
        .unwrap();
        let value = &profiles[0];
        assert_eq!(value.as_object().unwrap().len(), 59);
        assert_eq!(value["limitCollectionCreation"], false);
        assert_eq!(value["seats"], 20);
        assert_eq!(value["key"], "opaque-member-key");
        assert_eq!(value["organizationUserId"], "member");
        assert_eq!(value["permissions"].as_object().unwrap().len(), 12);
        assert!(
            value["permissions"]
                .as_object()
                .unwrap()
                .values()
                .all(|value| value == &json!(false))
        );
    }

    #[test]
    fn organization_profile_arrays_filter_status_and_reject_cross_user_joins() {
        let mut store = Memory::new();
        store.profile_count = 4;
        for (row, status) in store.profiles.iter_mut().zip([2, 1, 0, -1]) {
            row.membership.status = status;
        }
        let mut service = VaultService::new(&mut store);
        let profiles = service.profile_organizations("owner").unwrap();
        assert_eq!(
            serde_json::to_value(profiles.confirmed())
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            serde_json::to_value(profiles.accepted_and_confirmed())
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            2
        );
        store.profiles[3].membership.user_id = "foreign";
        assert_eq!(
            VaultService::new(&mut store)
                .profile_organizations("owner")
                .unwrap_err()
                .status_code(),
            401
        );
    }

    #[test]
    fn organization_collection_views_use_basic_list_and_authorized_sync_details() {
        let mut store = Memory::new();
        let mut service = VaultService::new(&mut store);
        let collections = service.list_user_collections("owner").unwrap();
        let value = serde_json::to_value(&collections).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 3);
        assert_eq!(value["object"], "list");
        assert!(value["continuationToken"].is_null());
        assert_eq!(value["data"][0].as_object().unwrap().len(), 7);
        let details = serde_json::to_value(collections.details()).unwrap();
        assert_eq!(details[0].as_object().unwrap().len(), 10);
        assert_eq!(details[0]["manage"], true);
        assert_eq!(details[0]["readOnly"], false);
        for case in 0..4 {
            let mut store = Memory::new();
            match case {
                0 => store.collections[0].membership.user_id = "foreign",
                1 => store.collections[0].membership.status = 1,
                2 => store.collections[0].readable = false,
                _ => store.collections[0].collection.organization_id = "foreign-org",
            }
            assert_eq!(
                VaultService::new(&mut store)
                    .list_user_collections("owner")
                    .unwrap_err()
                    .status_code(),
                401
            );
        }
    }

    #[test]
    fn organization_borrowed_provider_forwarding_and_empty_views_remain_allocation_independent() {
        let mut store = Memory::new();
        store.count = 0;
        store.profile_count = 0;
        let mut borrowed = &mut store;
        let mut service = VaultService::new(&mut borrowed);
        assert_eq!(
            serde_json::to_value(service.list_user_collections("owner").unwrap()).unwrap(),
            json!({"data":[],"object":"list","continuationToken":null})
        );
        assert_eq!(
            serde_json::to_value(service.profile_organizations("owner").unwrap()).unwrap(),
            json!([])
        );
    }

    #[test]
    fn organization_borrowed_request_preserves_schema_number_string_plan_and_redaction() {
        for plan in [
            json!(i64::MIN),
            json!(i64::MAX),
            json!(""),
            json!("arbitrary future plan"),
        ] {
            let value = json!({"billingEmail":"","collectionName":"雪\0","key":"private-key-value","name":"","keys":{"encryptedPrivateKey":"private-value","publicKey":""},"planType":plan});
            let request = OrganizationCreateRequest::deserialize(&value).unwrap();
            assert_eq!(request.collection_name, "雪\0");
            assert_eq!(
                std::format!("{request:?}"),
                "OrganizationCreateRequest([REDACTED])"
            );
        }
        for plan in [json!(null), json!(true), json!(1.5), json!(u64::MAX)] {
            let value =
                json!({"billingEmail":"","collectionName":"","key":"","name":"","planType":plan});
            assert!(OrganizationCreateRequest::deserialize(&value).is_err());
        }
        let value = json!([
            "billing@example.test",
            "collection",
            "wrapped",
            "name",
            ["private", "public"],
            "ignored"
        ]);
        let request = OrganizationCreateRequest::deserialize(&value).unwrap();
        assert_eq!(request.keys.unwrap().encrypted_private_key, "private");
        let missing = json!({"billingEmail":"","collectionName":"","key":"","name":""});
        assert!(OrganizationCreateRequest::deserialize(&missing).is_err());
    }

    #[test]
    fn organization_features_and_custom_manager_profile_flags_are_provider_driven() {
        let features = OrganizationFeatures {
            events: true,
            groups: true,
            mail: true,
        };
        let ordinary = serde_json::to_value(OrganizationResponse::new(OrganizationRecord {
            features,
            ..organization()
        }))
        .unwrap();
        let mut store = Memory::new();
        store.profiles[0].organization.features = features;
        store.profiles[0].membership.role = 3;
        let profiles = serde_json::to_value(
            VaultService::new(&mut store)
                .profile_organizations("owner")
                .unwrap(),
        )
        .unwrap();
        for field in ["useEvents", "useGroups", "useResetPassword"] {
            assert_eq!(ordinary[field], true);
            assert_eq!(profiles[0][field], true);
        }
        assert_eq!(profiles[0]["type"], 4);
        assert_eq!(profiles[0]["limitCollectionCreation"], false);
        for field in [
            "createNewCollections",
            "editAnyCollection",
            "deleteAnyCollection",
        ] {
            assert_eq!(profiles[0]["permissions"][field], true);
        }
        assert_eq!(profiles[0]["permissions"]["manageUsers"], false);
    }
}
