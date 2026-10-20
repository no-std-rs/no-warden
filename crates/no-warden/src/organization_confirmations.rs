//! Single-member organization confirmation over allocation-free providers.
//!
//! The core checks actor authority, target association, role and accepted state.
//! HTTP/path decoding, crypto, clocks, persistence, SMTP and notifications stay external.

use crate::{
    ApiError, ErrorKind, VaultService, identity::Secret,
    organization_collections::OrganizationCollectionStorage, wire::OrganizationConfirmRequest,
};

/// Owned provider metadata, independent of a mutable storage borrow. Identifiers may
/// use owned strings or caller-bounded handles. No key/account-private data is needed.
pub struct OrganizationConfirmationRecord<I> {
    pub membership_id: I,
    pub organization_id: I,
    pub user_id: I,
    pub role: i32,
    pub status: i32,
}
impl<I> core::fmt::Debug for OrganizationConfirmationRecord<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OrganizationConfirmationRecord([REDACTED])")
    }
}

/// Trusted policy decision for the proposed confirmed membership. Richer adapters
/// resolve applicable roles, 2FA/enrollment and SingleOrg rules in source order.
/// The standalone no-policy adapter uses Allowed; these are not enabled policies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationConfirmationPolicy {
    Allowed,
    TwoFactorRequired,
    OtherOrganizationPolicy,
    SingleOrganizationPolicy,
}
impl OrganizationConfirmationPolicy {
    /// Static policy markers. HTTP adapters may append their escaped membership ID
    /// to reproduce dynamic source messages; this core error never contains an ID/key.
    pub const fn error(self) -> Option<ApiError> {
        let message = match self {
            Self::Allowed => return None,
            Self::TwoFactorRequired => "Cannot confirm because 2FA is required",
            Self::OtherOrganizationPolicy => {
                "Cannot confirm because another organization policy forbids it"
            }
            Self::SingleOrganizationPolicy => {
                "Cannot confirm because the organization policy forbids being part of other organization"
            }
        };
        Some(ApiError::invalid("confirmationPolicy", message))
    }
}

/// Sealed transition, borrowing an owned target and caller-owned key. The policy hook
/// observes the proposed status 2; only after it allows the transition is commit called.
/// Never serialize/log the plan or expose an unwrapped organization key here.
pub struct ValidatedOrganizationConfirmation<'a, I> {
    owner: &'a str,
    target: &'a OrganizationConfirmationRecord<I>,
    key: &'a Secret<'a>,
}
impl<'a, I: AsRef<str>> ValidatedOrganizationConfirmation<'a, I> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub fn organization(&self) -> &str {
        self.target.organization_id.as_ref()
    }
    pub fn membership_id(&self) -> &str {
        self.target.membership_id.as_ref()
    }
    pub fn user_id(&self) -> &str {
        self.target.user_id.as_ref()
    }
    pub const fn role(&self) -> i32 {
        self.target.role
    }
    pub const fn previous_status(&self) -> i32 {
        self.target.status
    }
    pub const fn status(&self) -> i32 {
        2
    }
    pub const fn key(&self) -> &Secret<'a> {
        self.key
    }
}
impl<I> core::fmt::Debug for ValidatedOrganizationConfirmation<'_, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ValidatedOrganizationConfirmation([REDACTED])")
    }
}

/// Opt-in single-member confirmation; existing organization providers are unchanged.
/// The adapter runs authorize_org_member_admin before HTTP UUID/body guards and holds
/// the operation context through this service. Target lookup must scope BOTH org and
/// membership ID, returning an owned snapshot. Missing and foreign targets are identical.
/// Policy evaluation inspects the proposed confirmed status and must not commit the
/// membership transition. Owner/Admin targets are policy-exempt; for applicable targets
/// resolve 2FA (including configured fallback), other-organization SingleOrg policy, then
/// this organization's SingleOrg policy in that order. Resolve configured side effects
/// (such as 2FA enrollment)
/// explicitly; the service does not pretend to implement SMTP, policy tables or events.
///
/// Commit must recheck confirmed Admin/Owner actor, target identity/org/role/accepted
/// status and applicable policy within its transaction, then atomically store status 2,
/// the exact nonempty opaque wrapped key, and the target account revision. Preserve
/// membership role, access_all, grants, inviter, enrollment and all other memberships;
/// preserve credentials, sessions, devices, personal ciphertext and foreign state. An
/// error leaves prior persistence unchanged. This transactional write guarantee is
/// stronger than upstream's sequential policy/event/mail/save effects; notification
/// delivery and upstream's save-failure notification timing remain adapter concerns.
pub trait OrganizationConfirmationStorage: OrganizationCollectionStorage {
    type Id: AsRef<str>;
    fn confirmation_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> Result<Option<OrganizationConfirmationRecord<Self::Id>>, Self::Error>;
    fn confirmation_policy(
        &mut self,
        plan: &ValidatedOrganizationConfirmation<'_, Self::Id>,
    ) -> Result<OrganizationConfirmationPolicy, Self::Error>;
    fn confirm_organization_member(
        &mut self,
        plan: &ValidatedOrganizationConfirmation<'_, Self::Id>,
    ) -> Result<(), Self::Error>;
}
impl<T: OrganizationConfirmationStorage + ?Sized> OrganizationConfirmationStorage for &mut T {
    type Id = T::Id;
    fn confirmation_member(
        &mut self,
        organization: &str,
        member: &str,
    ) -> Result<Option<OrganizationConfirmationRecord<Self::Id>>, Self::Error> {
        (**self).confirmation_member(organization, member)
    }
    fn confirmation_policy(
        &mut self,
        plan: &ValidatedOrganizationConfirmation<'_, Self::Id>,
    ) -> Result<OrganizationConfirmationPolicy, Self::Error> {
        (**self).confirmation_policy(plan)
    }
    fn confirm_organization_member(
        &mut self,
        plan: &ValidatedOrganizationConfirmation<'_, Self::Id>,
    ) -> Result<(), Self::Error> {
        (**self).confirm_organization_member(plan)
    }
}
fn invalid(message: &'static str) -> ApiError {
    ApiError::new(ErrorKind::InvalidRequest, message)
}
fn missing_member() -> ApiError {
    invalid("The specified user isn't a member of the organization")
}

impl<S: OrganizationConfirmationStorage> VaultService<S> {
    /// Confirm exactly one accepted member. The optional body ID is intentionally
    /// ignored; only the authenticated path context selects a target. Key strings are
    /// opaque: whitespace/NUL/future formats are valid, and only empty/missing rejects.
    pub fn confirm_org_member(
        &mut self,
        owner: &str,
        organization: &str,
        member: &str,
        request: &OrganizationConfirmRequest<'_>,
    ) -> Result<(), ApiError> {
        let actor_role = self.org_member_admin_role(owner, organization)?;
        let key = request
            .key
            .as_ref()
            .filter(|key| !key.expose_secret().is_empty())
            .filter(|_| !member.is_empty())
            .ok_or_else(|| invalid("Key or UserId is not set, unable to process request"))?;
        let target = self
            .storage_mut()
            .confirmation_member(organization, member)
            .map_err(S::map_error)?
            .ok_or_else(missing_member)?;
        if target.membership_id.as_ref() != member
            || target.organization_id.as_ref() != organization
        {
            return Err(missing_member());
        }
        if target.role != 2 && actor_role != 0 {
            return Err(invalid(
                "Only Owners can confirm Managers, Admins or Owners",
            ));
        }
        if target.status != 1 {
            return Err(invalid("User in invalid state"));
        }
        let plan = ValidatedOrganizationConfirmation {
            owner,
            target: &target,
            key,
        };
        if let Some(error) = self
            .storage_mut()
            .confirmation_policy(&plan)
            .map_err(S::map_error)?
            .error()
        {
            return Err(error);
        }
        self.storage_mut()
            .confirm_organization_member(&plan)
            .map_err(S::map_error)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::{
        Storage,
        organization_collections::{
            CollectionAccessData, CollectionAccessEntry, CollectionCreateData,
            OrganizationCollectionMembership, ValidatedCollectionCreate,
        },
        organizations::{
            CollectionRecord, OrganizationCreationPolicy, OrganizationMembership,
            OrganizationProfileRecord, OrganizationRecord, OrganizationStorage,
            UserCollectionRecord, ValidatedOrganizationCreate,
        },
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    // An owned handle need not implement Debug, Serialize, Clone or equality.
    struct Id(String);
    impl AsRef<str> for Id {
        fn as_ref(&self) -> &str {
            &self.0
        }
    }
    #[derive(Clone, Copy)]
    struct Target {
        member: &'static str,
        org: &'static str,
        user: &'static str,
        role: i32,
        status: i32,
    }
    struct Memory {
        actor: Option<OrganizationCollectionMembership<'static>>,
        target: Option<Target>,
        key: String,
        policy: OrganizationConfirmationPolicy,
        fail: Option<&'static str>,
        stale: bool,
        calls: Vec<&'static str>,
        revision: u64,
        preserved: [u64; 8],
    }
    impl Memory {
        fn new() -> Self {
            Self {
                actor: Some(OrganizationCollectionMembership {
                    membership: OrganizationMembership {
                        user_id: "actor",
                        organization_id: "org",
                        role: 0,
                        status: 2,
                    },
                    access_all: true,
                }),
                target: Some(Target {
                    member: "member",
                    org: "org",
                    user: "recipient",
                    role: 2,
                    status: 1,
                }),
                key: "prior-key".to_string(),
                policy: OrganizationConfirmationPolicy::Allowed,
                fail: None,
                stale: false,
                calls: Vec::new(),
                revision: 7,
                preserved: [11, 22, 33, 44, 55, 66, 77, 88],
            }
        }
        fn step(&mut self, name: &'static str) -> Result<(), ()> {
            self.calls.push(name);
            if self.fail == Some(name) {
                Err(())
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Memory {
        type Error = ();
        fn map_error(_: ()) -> ApiError {
            ApiError::new(ErrorKind::Conflict, "Confirmation provider conflict")
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
            unreachable!()
        }
        fn create_organization(
            &mut self,
            _: &str,
            _: &ValidatedOrganizationCreate<'_, '_>,
        ) -> Result<OrganizationRecord<'_>, ()> {
            unreachable!()
        }
        fn organization_membership(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<OrganizationMembership<'_>>, ()> {
            unreachable!()
        }
        fn organization(&mut self, _: &str) -> Result<Option<OrganizationRecord<'_>>, ()> {
            unreachable!()
        }
        fn user_collections(&mut self, _: &str) -> Result<Self::Collections<'_>, ()> {
            unreachable!()
        }
        fn profile_organizations(&mut self, _: &str) -> Result<Self::Profiles<'_>, ()> {
            unreachable!()
        }
    }
    struct Unused;
    impl CollectionAccessData for Unused {
        fn collection(&self) -> UserCollectionRecord<'_> {
            unreachable!()
        }
        fn assigned(&self) -> bool {
            unreachable!()
        }
        fn users_len(&self) -> usize {
            unreachable!()
        }
        fn user(&self, _: usize) -> Option<CollectionAccessEntry<'_>> {
            unreachable!()
        }
        fn groups_enabled(&self) -> bool {
            unreachable!()
        }
        fn groups_len(&self) -> usize {
            unreachable!()
        }
        fn group(&self, _: usize) -> Option<CollectionAccessEntry<'_>> {
            unreachable!()
        }
    }
    impl OrganizationCollectionStorage for Memory {
        type OrgCollections<'a> = &'a [CollectionRecord<'static>];
        type AccessDetails<'a> = Unused;
        fn collection_membership(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<OrganizationCollectionMembership<'_>>, ()> {
            self.step("actor")?;
            Ok(self.actor)
        }
        fn org_collections(&mut self, _: &str) -> Result<Self::OrgCollections<'_>, ()> {
            unreachable!()
        }
        fn can_manage_collection(&mut self, _: &str, _: &str) -> Result<bool, ()> {
            unreachable!()
        }
        fn collection_access_details(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<Self::AccessDetails<'_>>, ()> {
            unreachable!()
        }
        fn collection_group_exists(&mut self, _: &str, _: &str) -> Result<bool, ()> {
            unreachable!()
        }
        fn collection_member_exists(&mut self, _: &str, _: &str) -> Result<bool, ()> {
            unreachable!()
        }
        fn create_collection<D: CollectionCreateData + ?Sized>(
            &mut self,
            _: &str,
            _: &str,
            _: &ValidatedCollectionCreate<'_, D>,
        ) -> Result<UserCollectionRecord<'_>, ()> {
            unreachable!()
        }
    }

    impl OrganizationConfirmationStorage for Memory {
        type Id = Id;
        fn confirmation_member(
            &mut self,
            org: &str,
            member: &str,
        ) -> Result<Option<OrganizationConfirmationRecord<Id>>, ()> {
            assert_eq!((org, member), ("org", "member"));
            self.step("target")?;
            Ok(self.target.map(|row| OrganizationConfirmationRecord {
                membership_id: Id(row.member.to_string()),
                organization_id: Id(row.org.to_string()),
                user_id: Id(row.user.to_string()),
                role: row.role,
                status: row.status,
            }))
        }
        fn confirmation_policy(
            &mut self,
            plan: &ValidatedOrganizationConfirmation<'_, Id>,
        ) -> Result<OrganizationConfirmationPolicy, ()> {
            self.step("policy")?;
            assert_eq!(
                (
                    plan.owner(),
                    plan.organization(),
                    plan.membership_id(),
                    plan.user_id()
                ),
                ("actor", "org", "member", "recipient")
            );
            assert_eq!((plan.previous_status(), plan.status()), (1, 2));
            Ok(self.policy)
        }
        fn confirm_organization_member(
            &mut self,
            plan: &ValidatedOrganizationConfirmation<'_, Id>,
        ) -> Result<(), ()> {
            self.step("commit")?;
            if self.stale {
                return Err(());
            }
            let target = self.target.as_mut().unwrap();
            if target.status != plan.previous_status()
                || target.role != plan.role()
                || target.user != plan.user_id()
            {
                return Err(());
            }
            target.status = plan.status();
            self.key = plan.key().expose_secret().to_string();
            self.revision += 1;
            Ok(())
        }
    }
    fn input(key: &str) -> OrganizationConfirmRequest<'_> {
        OrganizationConfirmRequest {
            id: None,
            key: Some(Secret::new(key)),
        }
    }
    fn confirm(
        memory: &mut Memory,
        request: &OrganizationConfirmRequest<'_>,
    ) -> Result<(), ApiError> {
        VaultService::new(memory).confirm_org_member("actor", "org", "member", request)
    }

    #[test]
    fn confirmation_authentication_checks_actor_identity_confirmed_status_and_admin_role_before_key()
     {
        let request = input("");
        let mut memory = Memory::new();
        assert_eq!(
            VaultService::new(&mut memory)
                .confirm_org_member("", "org", "member", &request)
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(memory.calls.is_empty());
        for (user, org, role, status) in [
            ("other", "org", 0, 2),
            ("actor", "foreign", 0, 2),
            ("actor", "org", 0, 1),
            ("actor", "org", 2, 2),
            ("actor", "org", 3, 2),
            ("actor", "org", 4, 2),
        ] {
            let mut memory = Memory::new();
            memory.actor.as_mut().unwrap().membership = OrganizationMembership {
                user_id: user,
                organization_id: org,
                role,
                status,
            };
            assert_eq!(
                confirm(&mut memory, &request).unwrap_err().status_code(),
                401
            );
            assert_eq!(memory.calls, ["actor"]);
        }
        let mut memory = Memory::new();
        memory.actor = None;
        assert_eq!(
            confirm(&mut memory, &input("opaque"))
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(memory.calls, ["actor"]);
    }

    #[test]
    fn confirmation_empty_or_absent_key_and_empty_path_member_fail_before_target_lookup() {
        for request in [
            OrganizationConfirmRequest {
                id: None,
                key: None,
            },
            input(""),
        ] {
            let mut memory = Memory::new();
            memory.target = None;
            assert_eq!(
                confirm(&mut memory, &request).unwrap_err().message,
                "Key or UserId is not set, unable to process request"
            );
            assert_eq!(memory.calls, ["actor"]);
        }
        let mut memory = Memory::new();
        assert_eq!(
            VaultService::new(&mut memory)
                .confirm_org_member("actor", "org", "", &input("opaque"))
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(memory.calls, ["actor"]);
    }

    #[test]
    fn confirmation_missing_foreign_and_mismatched_provider_memberships_are_indistinguishable() {
        for variant in 0..3 {
            let mut memory = Memory::new();
            match variant {
                0 => memory.target = None,
                1 => memory.target.as_mut().unwrap().org = "foreign",
                _ => memory.target.as_mut().unwrap().member = "other",
            }
            assert_eq!(
                confirm(&mut memory, &input("opaque")).unwrap_err().message,
                "The specified user isn't a member of the organization"
            );
            assert_eq!(memory.calls, ["actor", "target"]);
            assert_eq!(memory.key, "prior-key");
        }
    }

    #[test]
    fn confirmation_owner_hierarchy_precedes_target_state_and_admin_needs_no_access_all() {
        for role in [0, 1, 3] {
            let mut memory = Memory::new();
            memory.actor.as_mut().unwrap().membership.role = 1;
            memory.actor.as_mut().unwrap().access_all = false;
            let target = memory.target.as_mut().unwrap();
            target.role = role;
            target.status = 0;
            assert_eq!(
                confirm(&mut memory, &input("opaque")).unwrap_err().message,
                "Only Owners can confirm Managers, Admins or Owners"
            );
            assert_eq!(memory.calls, ["actor", "target"]);
        }
        let mut memory = Memory::new();
        memory.actor.as_mut().unwrap().membership.role = 1;
        memory.actor.as_mut().unwrap().access_all = false;
        confirm(&mut memory, &input("opaque")).unwrap();
        assert_eq!(memory.target.unwrap().status, 2);
        for role in [0, 1, 2, 3] {
            let mut memory = Memory::new();
            memory.target.as_mut().unwrap().role = role;
            confirm(&mut memory, &input("opaque")).unwrap();
            assert_eq!(memory.target.unwrap().role, role);
        }
    }

    #[test]
    fn confirmation_accepts_only_accepted_state_and_repeated_confirmation_preserves_original_key() {
        for status in [-128, -127, -126, -1, 0, 2, 99] {
            let mut memory = Memory::new();
            memory.target.as_mut().unwrap().status = status;
            assert_eq!(
                confirm(&mut memory, &input("opaque")).unwrap_err().message,
                "User in invalid state"
            );
            assert_eq!(memory.calls, ["actor", "target"]);
        }
        let mut memory = Memory::new();
        confirm(&mut memory, &input("first-key")).unwrap();
        assert_eq!(
            confirm(&mut memory, &input("replacement"))
                .unwrap_err()
                .message,
            "User in invalid state"
        );
        assert_eq!(memory.key, "first-key");
        assert_eq!(memory.revision, 8);
    }

    #[test]
    fn confirmation_applies_policy_to_proposed_confirmed_state_before_commit() {
        for (policy, message) in [
            (
                OrganizationConfirmationPolicy::TwoFactorRequired,
                "Cannot confirm because 2FA is required",
            ),
            (
                OrganizationConfirmationPolicy::OtherOrganizationPolicy,
                "Cannot confirm because another organization policy forbids it",
            ),
            (
                OrganizationConfirmationPolicy::SingleOrganizationPolicy,
                "Cannot confirm because the organization policy forbids being part of other organization",
            ),
        ] {
            let mut memory = Memory::new();
            memory.policy = policy;
            let error = confirm(&mut memory, &input("opaque")).unwrap_err();
            assert_eq!(error.message, message);
            assert_eq!(error.status_code(), 400);
            assert_eq!(error.field, Some("confirmationPolicy"));
            assert_eq!(memory.calls, ["actor", "target", "policy"]);
            assert_eq!(memory.target.unwrap().status, 1);
            assert_eq!(memory.revision, 7);
        }
    }

    #[test]
    fn confirmation_exact_opaque_key_and_ignored_body_id_change_only_target_state_key_revision() {
        for key in [" ", "future:\u{1f511}", "opaque\0wrapped\nkey"] {
            let mut memory = Memory::new();
            let request = OrganizationConfirmRequest {
                id: Some("unrelated-body-id"),
                key: Some(Secret::new(key)),
            };
            confirm(&mut memory, &request).unwrap();
            let row = memory.target.unwrap();
            assert_eq!(
                (row.status, row.role, row.user, row.member, row.org),
                (2, 2, "recipient", "member", "org")
            );
            assert_eq!(memory.key, key);
            assert_eq!(memory.revision, 8);
            assert_eq!(memory.preserved, [11, 22, 33, 44, 55, 66, 77, 88]);
            assert_eq!(memory.calls, ["actor", "target", "policy", "commit"]);
        }
        let key = "future Ω".repeat(4096);
        let mut memory = Memory::new();
        confirm(&mut memory, &input(&key)).unwrap();
        assert_eq!(memory.key, key);
    }

    #[test]
    fn confirmation_provider_errors_and_stale_plan_rejection_leave_state_unchanged() {
        for fail in ["actor", "target", "policy", "commit"] {
            let mut memory = Memory::new();
            memory.fail = Some(fail);
            let error = confirm(&mut memory, &input("opaque")).unwrap_err();
            assert_eq!(error.kind, ErrorKind::Conflict);
            assert_eq!(error.message, "Confirmation provider conflict");
            assert_eq!(memory.key, "prior-key");
            assert_eq!(memory.target.unwrap().status, 1);
            assert_eq!(memory.revision, 7);
            assert_eq!(memory.preserved, [11, 22, 33, 44, 55, 66, 77, 88]);
        }
        let mut memory = Memory::new();
        memory.stale = true;
        assert!(confirm(&mut memory, &input("opaque")).is_err());
        assert_eq!(memory.revision, 7);
        assert_eq!(memory.key, "prior-key");
    }

    #[test]
    fn confirmation_forwarding_owned_handles_and_redaction_do_not_require_secret_serialization() {
        let mut memory = Memory::new();
        let mut forwarded = &mut memory;
        VaultService::new(&mut forwarded)
            .confirm_org_member("actor", "org", "member", &input("secret-key"))
            .unwrap();
        let target = OrganizationConfirmationRecord {
            membership_id: Id("sensitive-member".to_string()),
            organization_id: Id("sensitive-org".to_string()),
            user_id: Id("sensitive-user".to_string()),
            role: 2,
            status: 1,
        };
        let request = input("secret-key");
        let plan = ValidatedOrganizationConfirmation {
            owner: "sensitive-owner",
            target: &target,
            key: request.key.as_ref().unwrap(),
        };
        for debug in [
            format!("{target:?}"),
            format!("{request:?}"),
            format!("{plan:?}"),
        ] {
            assert!(debug.contains("REDACTED"));
            assert!(!debug.contains("sensitive"));
            assert!(!debug.contains("secret-key"));
        }
    }

    #[test]
    fn confirmation_wire_option_slots_body_id_schema_and_borrowed_key_match_source() {
        for body in [r#"{}"#, r#"{"id":null,"key":null}"#, r#"[null,null]"#] {
            let input: OrganizationConfirmRequest<'_> = serde_json::from_str(body).unwrap();
            assert!(input.id.is_none() && input.key.is_none());
        }
        for body in [
            r#"{"key":"future Ω","id":"ignored"}"#,
            r#"["ignored","future Ω"]"#,
        ] {
            let input: OrganizationConfirmRequest<'_> = serde_json::from_str(body).unwrap();
            assert_eq!(input.id, Some("ignored"));
            let value = input.key.as_ref().unwrap().expose_secret();
            assert_eq!(value, "future Ω");
            assert!(
                (body.as_ptr() as usize..body.as_ptr() as usize + body.len())
                    .contains(&(value.as_ptr() as usize))
            );
        }
        for body in [
            r#"[]"#,
            r#"[null]"#,
            r#"[null,"x",null]"#,
            r#"{"id":123,"key":"x"}"#,
            r#"{"key":false}"#,
            r#"{"key":"x","key":"y"}"#,
        ] {
            assert!(
                serde_json::from_str::<OrganizationConfirmRequest<'_>>(body).is_err(),
                "{body}"
            );
        }
        let input: OrganizationConfirmRequest<'_> =
            serde_json::from_str(r#"{"ID":1,"Key":1,"unknown":[],"key":"x"}"#).unwrap();
        assert!(input.id.is_none());
        assert_eq!(input.key.unwrap().expose_secret(), "x");
    }
}
