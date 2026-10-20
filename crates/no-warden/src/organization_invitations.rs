//! Sequential organization invitations over caller-owned, uncapped input views.
//!
//! Authentication, email normalization/validation, UUID generation, clocks, storage,
//! mail, event delivery and invitation-token signing remain adapter responsibilities.

use core::fmt;

pub use crate::wire::{
    OrganizationInviteCollection, OrganizationInvitePermissions, OrganizationInviteRole,
};

use crate::{
    ApiError, ErrorKind, VaultService, organization_collections::OrganizationCollectionStorage,
};

/// Stable indexed request view. Every reported index must exist for the operation.
/// Preserve input order, duplicate addresses and opaque strings; email normalization
/// belongs to the provider. A bounded decoder is caller policy, not a protocol limit.
pub trait OrganizationInviteData {
    fn emails_len(&self) -> usize;
    fn email(&self, index: usize) -> Option<&str>;
    fn groups_len(&self) -> usize;
    fn group(&self, index: usize) -> Option<&str>;
    fn collections_len(&self) -> usize;
    fn collection(&self, index: usize) -> Option<OrganizationInviteCollection<'_>>;
    fn role(&self) -> OrganizationInviteRole<'_>;
    fn permissions(&self) -> OrganizationInvitePermissions;
}
impl<T: OrganizationInviteData + ?Sized> OrganizationInviteData for &T {
    fn emails_len(&self) -> usize {
        (**self).emails_len()
    }
    fn email(&self, index: usize) -> Option<&str> {
        (**self).email(index)
    }
    fn groups_len(&self) -> usize {
        (**self).groups_len()
    }
    fn group(&self, index: usize) -> Option<&str> {
        (**self).group(index)
    }
    fn collections_len(&self) -> usize {
        (**self).collections_len()
    }
    fn collection(&self, index: usize) -> Option<OrganizationInviteCollection<'_>> {
        (**self).collection(index)
    }
    fn role(&self) -> OrganizationInviteRole<'_> {
        (**self).role()
    }
    fn permissions(&self) -> OrganizationInvitePermissions {
        (**self).permissions()
    }
}

impl<const E: usize, const G: usize, const C: usize> OrganizationInviteData
    for crate::wire::OrganizationInviteRequest<'_, E, G, C>
{
    fn emails_len(&self) -> usize {
        self.emails.len()
    }
    fn email(&self, index: usize) -> Option<&str> {
        self.emails.get(index).copied()
    }
    fn groups_len(&self) -> usize {
        self.groups.len()
    }
    fn group(&self, index: usize) -> Option<&str> {
        self.groups.get(index).copied()
    }
    fn collections_len(&self) -> usize {
        self.collections.as_ref().map_or(0, |v| v.len())
    }
    fn collection(&self, index: usize) -> Option<OrganizationInviteCollection<'_>> {
        self.collections.as_ref()?.get(index).copied()
    }
    fn role(&self) -> OrganizationInviteRole<'_> {
        self.role
    }
    fn permissions(&self) -> OrganizationInvitePermissions {
        self.permissions
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationPolicy {
    pub mail_enabled: bool,
    pub invitations_allowed: bool,
}

/// Trusted result of Unicode-lowercase-without-trim email lookup. Do not treat an
/// existing passwordless account as an ordinary registered account. Existing members
/// of any status are duplicates. Missing-user domain and email policies are independent.
pub enum InvitationTarget<I> {
    Existing {
        account_id: I,
        has_master_password: bool,
        already_member: bool,
    },
    Missing {
        domain_allowed: bool,
        email_valid: bool,
    },
}
impl<I> fmt::Debug for InvitationTarget<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InvitationTarget([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteCommit {
    Created,
    AlreadyMember,
}

/// One email's authorized write plan. A provider cannot construct it from raw input.
/// The whole input has passed reference/role checks, and this target has passed policy.
pub struct ValidatedOrganizationInvite<'a, D: ?Sized, I> {
    request: &'a D,
    email: &'a str,
    index: usize,
    target: &'a InvitationTarget<I>,
    role: i32,
    access_all: bool,
    mail_enabled: bool,
}
impl<'a, D: ?Sized, I: AsRef<str>> ValidatedOrganizationInvite<'a, D, I> {
    pub const fn request(&self) -> &'a D {
        self.request
    }
    pub const fn email(&self) -> &'a str {
        self.email
    }
    pub const fn index(&self) -> usize {
        self.index
    }
    pub fn account_id(&self) -> Option<&str> {
        match self.target {
            InvitationTarget::Existing { account_id, .. } => Some(account_id.as_ref()),
            _ => None,
        }
    }
    pub const fn creates_account(&self) -> bool {
        matches!(self.target, InvitationTarget::Missing { .. })
    }
    pub const fn requires_invitation(&self) -> bool {
        !self.mail_enabled
            && !matches!(
                self.target,
                InvitationTarget::Existing {
                    has_master_password: true,
                    ..
                }
            )
    }
    pub const fn membership_status(&self) -> i32 {
        if !self.mail_enabled
            && matches!(
                self.target,
                InvitationTarget::Existing {
                    has_master_password: true,
                    ..
                }
            )
        {
            1
        } else {
            0
        }
    }
    pub const fn role(&self) -> i32 {
        self.role
    }
    pub const fn access_all(&self) -> bool {
        self.access_all
    }
    pub const fn mail_enabled(&self) -> bool {
        self.mail_enabled
    }
    pub const fn key(&self) -> &'static str {
        ""
    }
}
impl<D: ?Sized, I> fmt::Debug for ValidatedOrganizationInvite<'_, D, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedOrganizationInvite([REDACTED])")
    }
}

/// Opt-in invitation persistence; existing organization providers remain unchanged.
/// Hold the verified actor's context/lock throughout an operation. Resolve each email
/// once using Unicode lowercase without trimming, and expose only owned account handles.
/// Policies apply to missing users only; existing users bypass invitation/domain policy.
///
/// Each commit must atomically recheck membership/references/actor policy and persist a
/// fresh membership with empty key, requested role/status/access_all, trusted inviter
/// identity, groups and non-access_all direct collection grants, plus affected revisions.
/// Groups must be validated/persisted even if group *projection* is disabled. For missing
/// users initialize a fresh enabled passwordless account. If requires_invitation() is
/// true, persist a pending invitation marker; normal registration must be able to finish
/// that placeholder, preserve its identity, consume the marker and accept its invited
/// memberships. Never confirm a membership in this operation.
///
/// AlreadyMember changes nothing, and Err rolls back this email's entire write. Earlier
/// successful email commits MUST remain: no batch rollback or deduplication. Per-email
/// atomicity is stronger than upstream's inner sequential saves. Do not mutate unrelated
/// accounts, personal vault data, keys, sessions or foreign organization state. Prepare
/// any owned cache before commit. SMTP delivery/failure compensation, events and policy
/// settings are adapter responsibilities, not a claim of complete invitation parity.
pub trait OrganizationInvitationStorage: OrganizationCollectionStorage {
    type AccountId: AsRef<str>;
    fn invitation_policy(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<InvitationPolicy, Self::Error>;
    fn invitation_collection_exists(
        &mut self,
        organization: &str,
        collection: &str,
    ) -> Result<bool, Self::Error>;
    fn invitation_target(
        &mut self,
        organization: &str,
        raw_email: &str,
    ) -> Result<InvitationTarget<Self::AccountId>, Self::Error>;
    fn commit_organization_invitation<D: OrganizationInviteData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        plan: &ValidatedOrganizationInvite<'_, D, Self::AccountId>,
    ) -> Result<InviteCommit, Self::Error>;
}
impl<T: OrganizationInvitationStorage + ?Sized> OrganizationInvitationStorage for &mut T {
    type AccountId = T::AccountId;
    fn invitation_policy(
        &mut self,
        owner: &str,
        org: &str,
    ) -> Result<InvitationPolicy, Self::Error> {
        (**self).invitation_policy(owner, org)
    }
    fn invitation_collection_exists(&mut self, org: &str, col: &str) -> Result<bool, Self::Error> {
        (**self).invitation_collection_exists(org, col)
    }
    fn invitation_target(
        &mut self,
        org: &str,
        email: &str,
    ) -> Result<InvitationTarget<Self::AccountId>, Self::Error> {
        (**self).invitation_target(org, email)
    }
    fn commit_organization_invitation<D: OrganizationInviteData + ?Sized>(
        &mut self,
        owner: &str,
        org: &str,
        plan: &ValidatedOrganizationInvite<'_, D, Self::AccountId>,
    ) -> Result<InviteCommit, Self::Error> {
        (**self).commit_organization_invitation(owner, org, plan)
    }
}

/// Dynamic public-message categories. Display/Debug never print an email address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrganizationInviteErrorKind {
    Api,
    UserDoesNotExist,
    AlreadyMember,
    InvalidEmail,
    InvalidInvitationEmail,
}
#[derive(Clone, Copy)]
pub struct OrganizationInviteError<'a> {
    cause: ApiError,
    kind: OrganizationInviteErrorKind,
    index: Option<usize>,
    completed: usize,
    email: Option<&'a str>,
}
impl<'a> OrganizationInviteError<'a> {
    pub const fn cause(&self) -> ApiError {
        self.cause
    }
    pub const fn kind(&self) -> OrganizationInviteErrorKind {
        self.kind
    }
    pub const fn index(&self) -> Option<usize> {
        self.index
    }
    pub const fn completed(&self) -> usize {
        self.completed
    }
    pub const fn email(&self) -> Option<&'a str> {
        self.email
    }
    /// Explicitly stream a public message. Pass the original input for duplicate/missing
    /// errors, and the provider's normalized email for email-validation failures. This
    /// method performs no Unicode normalization and never writes backend diagnostics.
    pub fn write_message<W: fmt::Write + ?Sized>(
        &self,
        out: &mut W,
        display_email: Option<&str>,
    ) -> fmt::Result {
        let email = display_email.or(self.email).unwrap_or_default();
        match self.kind {
            OrganizationInviteErrorKind::Api => out.write_str(self.cause.message),
            OrganizationInviteErrorKind::AlreadyMember => write!(
                out,
                "User already in organization: {}",
                email.escape_debug()
            ),
            OrganizationInviteErrorKind::UserDoesNotExist => {
                write!(out, "User does not exist: {}", email.escape_debug())
            }
            OrganizationInviteErrorKind::InvalidEmail => write!(
                out,
                "User email {} is not a valid email address",
                email.escape_debug()
            ),
            OrganizationInviteErrorKind::InvalidInvitationEmail => write!(
                out,
                "Invitation email {} is not a valid email address",
                email.escape_debug()
            ),
        }
    }
}
impl fmt::Debug for OrganizationInviteError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OrganizationInviteError([REDACTED])")
    }
}
impl fmt::Display for OrganizationInviteError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.cause.message)
    }
}
impl core::error::Error for OrganizationInviteError<'_> {}

fn invalid(message: &'static str) -> ApiError {
    ApiError::new(ErrorKind::InvalidRequest, message)
}
fn incomplete() -> ApiError {
    ApiError::new(ErrorKind::Storage, "Invitation view is incomplete")
}
fn failure<'a>(
    cause: ApiError,
    index: Option<usize>,
    completed: usize,
    email: Option<&'a str>,
) -> OrganizationInviteError<'a> {
    OrganizationInviteError {
        cause,
        kind: OrganizationInviteErrorKind::Api,
        index,
        completed,
        email,
    }
}
fn dynamic<'a>(
    kind: OrganizationInviteErrorKind,
    index: usize,
    email: &'a str,
) -> OrganizationInviteError<'a> {
    let message = match kind {
        OrganizationInviteErrorKind::UserDoesNotExist => "User does not exist",
        OrganizationInviteErrorKind::AlreadyMember => "User already in organization",
        OrganizationInviteErrorKind::InvalidEmail => "Email is not a valid email address",
        OrganizationInviteErrorKind::InvalidInvitationEmail => {
            "Invitation email is not a valid email address"
        }
        OrganizationInviteErrorKind::Api => "Invalid invitation",
    };
    OrganizationInviteError {
        cause: invalid(message),
        kind,
        index: Some(index),
        completed: index,
        email: Some(email),
    }
}
fn role(value: OrganizationInviteRole<'_>) -> Option<(i32, bool)> {
    use crate::wire::OrganizationPlanType::{Integer, String};
    Some(match value {
        Integer(0) | String("0" | "Owner") => (0, false),
        Integer(1) | String("1" | "Admin") => (1, false),
        Integer(2) | String("2" | "User") => (2, false),
        Integer(3) | String("3" | "Manager" | "Custom") => (3, false),
        Integer(4) | String("4") => (3, true),
        _ => return None,
    })
}

impl<S: OrganizationInvitationStorage> VaultService<S> {
    /// Invite in input order, returning the committed prefix length. Authentication and
    /// whole-request reference/role checks precede target lookups, even for an empty batch.
    pub fn invite_org_members<'a, D: OrganizationInviteData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        request: &'a D,
    ) -> Result<usize, OrganizationInviteError<'a>> {
        let actor_role = self
            .org_member_admin_role(owner, organization)
            .map_err(|e| failure(e, None, 0, None))?;
        for i in 0..request.collections_len() {
            let selection = request
                .collection(i)
                .ok_or_else(|| failure(incomplete(), None, 0, None))?;
            if !self
                .storage_mut()
                .invitation_collection_exists(organization, selection.id)
                .map_err(|e| failure(S::map_error(e), None, 0, None))?
            {
                return Err(failure(invalid("Invalid collection"), None, 0, None));
            }
        }
        for i in 0..request.groups_len() {
            let group = request
                .group(i)
                .ok_or_else(|| failure(incomplete(), None, 0, None))?;
            if !self
                .storage_mut()
                .collection_group_exists(organization, group)
                .map_err(|e| failure(S::map_error(e), None, 0, None))?
            {
                return Err(failure(invalid("Invalid group"), None, 0, None));
            }
        }
        let (role, raw_custom) =
            role(request.role()).ok_or_else(|| failure(invalid("Invalid type"), None, 0, None))?;
        if role != 2 && actor_role != 0 {
            return Err(failure(
                invalid("Only Owners can invite Managers, Admins or Owners"),
                None,
                0,
                None,
            ));
        }
        let permissions = request.permissions();
        let access_all = matches!(role, 0 | 1)
            || (raw_custom
                && permissions.create_new_collections
                && permissions.edit_any_collection
                && permissions.delete_any_collection);
        let policy = self
            .storage_mut()
            .invitation_policy(owner, organization)
            .map_err(|e| failure(S::map_error(e), None, 0, None))?;
        for index in 0..request.emails_len() {
            let email = request
                .email(index)
                .ok_or_else(|| failure(incomplete(), Some(index), index, None))?;
            let target = self
                .storage_mut()
                .invitation_target(organization, email)
                .map_err(|e| failure(S::map_error(e), Some(index), index, Some(email)))?;
            match &target {
                InvitationTarget::Existing {
                    already_member: true,
                    ..
                } => {
                    return Err(dynamic(
                        OrganizationInviteErrorKind::AlreadyMember,
                        index,
                        email,
                    ));
                }
                InvitationTarget::Missing { .. } if !policy.invitations_allowed => {
                    return Err(dynamic(
                        OrganizationInviteErrorKind::UserDoesNotExist,
                        index,
                        email,
                    ));
                }
                InvitationTarget::Missing {
                    domain_allowed: false,
                    ..
                } => {
                    return Err(failure(
                        invalid("Email domain not eligible for invitations"),
                        Some(index),
                        index,
                        Some(email),
                    ));
                }
                InvitationTarget::Missing {
                    email_valid: false, ..
                } => {
                    return Err(dynamic(
                        if policy.mail_enabled {
                            OrganizationInviteErrorKind::InvalidEmail
                        } else {
                            OrganizationInviteErrorKind::InvalidInvitationEmail
                        },
                        index,
                        email,
                    ));
                }
                _ => {}
            }
            let plan = ValidatedOrganizationInvite {
                request,
                email,
                index,
                target: &target,
                role,
                access_all,
                mail_enabled: policy.mail_enabled,
            };
            if self
                .storage_mut()
                .commit_organization_invitation(owner, organization, &plan)
                .map_err(|e| failure(S::map_error(e), Some(index), index, Some(email)))?
                == InviteCommit::AlreadyMember
            {
                return Err(dynamic(
                    OrganizationInviteErrorKind::AlreadyMember,
                    index,
                    email,
                ));
            }
        }
        Ok(request.emails_len())
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
        wire::{CipherRequest, FolderRequest, OrganizationInviteRequest, RegisterRequest},
    };
    use std::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    // No Debug implementation: the production API must not demand one for owned IDs.
    struct AccountId(String);
    impl AsRef<str> for AccountId {
        fn as_ref(&self) -> &str {
            &self.0
        }
    }
    #[derive(Debug, PartialEq)]
    struct Saved {
        email: String,
        status: i32,
        role: i32,
        access_all: bool,
        stub: bool,
        invitation: bool,
        groups: usize,
        collections: usize,
    }
    struct Memory {
        actor: Option<OrganizationCollectionMembership<'static>>,
        policy: InvitationPolicy,
        collections_exist: bool,
        groups_exist: bool,
        domain_allowed: bool,
        email_valid: bool,
        fail: Option<&'static str>,
        fail_commit: Option<usize>,
        race: Option<usize>,
        calls: Vec<&'static str>,
        saved: Vec<Saved>,
        revision: usize,
        foreign_revision: usize,
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
                policy: InvitationPolicy {
                    mail_enabled: false,
                    invitations_allowed: true,
                },
                collections_exist: true,
                groups_exist: true,
                domain_allowed: true,
                email_valid: true,
                fail: None,
                fail_commit: None,
                race: None,
                calls: Vec::new(),
                saved: Vec::new(),
                revision: 40,
                foreign_revision: 90,
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
            ApiError::new(ErrorKind::Conflict, "Invitation provider conflict")
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
        fn collection_group_exists(&mut self, org: &str, _: &str) -> Result<bool, ()> {
            assert_eq!(org, "org");
            self.step("group")?;
            Ok(self.groups_exist)
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
    impl OrganizationInvitationStorage for Memory {
        type AccountId = AccountId;
        fn invitation_policy(&mut self, owner: &str, org: &str) -> Result<InvitationPolicy, ()> {
            assert_eq!((owner, org), ("actor", "org"));
            self.step("policy")?;
            Ok(self.policy)
        }
        fn invitation_collection_exists(&mut self, org: &str, _: &str) -> Result<bool, ()> {
            assert_eq!(org, "org");
            self.step("collection")?;
            Ok(self.collections_exist)
        }
        fn invitation_target(
            &mut self,
            org: &str,
            email: &str,
        ) -> Result<InvitationTarget<AccountId>, ()> {
            assert_eq!(org, "org");
            self.step("target")?;
            let normalized = email.to_lowercase();
            if self.saved.iter().any(|s| s.email == normalized)
                || normalized.starts_with("known")
                || normalized.starts_with("passwordless")
            {
                Ok(InvitationTarget::Existing {
                    account_id: AccountId(normalized.clone()),
                    has_master_password: !normalized.starts_with("passwordless"),
                    already_member: self.saved.iter().any(|s| s.email == normalized),
                })
            } else {
                Ok(InvitationTarget::Missing {
                    domain_allowed: self.domain_allowed,
                    email_valid: self.email_valid,
                })
            }
        }
        fn commit_organization_invitation<D: OrganizationInviteData + ?Sized>(
            &mut self,
            owner: &str,
            org: &str,
            plan: &ValidatedOrganizationInvite<'_, D, AccountId>,
        ) -> Result<InviteCommit, ()> {
            assert_eq!((owner, org), ("actor", "org"));
            self.step("commit")?;
            if self.fail_commit == Some(plan.index()) {
                return Err(());
            }
            if self.race == Some(plan.index()) {
                return Ok(InviteCommit::AlreadyMember);
            }
            assert_eq!(plan.key(), "");
            assert_eq!(plan.account_id().is_none(), plan.creates_account());
            self.saved.push(Saved {
                email: plan.email().to_lowercase(),
                status: plan.membership_status(),
                role: plan.role(),
                access_all: plan.access_all(),
                stub: plan.creates_account(),
                invitation: plan.requires_invitation(),
                groups: plan.request().groups_len(),
                collections: if plan.access_all() {
                    0
                } else {
                    plan.request().collections_len()
                },
            });
            self.revision += 1;
            Ok(InviteCommit::Created)
        }
    }
    fn request(json: &str) -> OrganizationInviteRequest<'_, 8, 4, 4> {
        serde_json::from_str(json).unwrap()
    }
    fn invite<'a>(
        memory: &mut Memory,
        input: &'a impl OrganizationInviteData,
    ) -> Result<usize, OrganizationInviteError<'a>> {
        VaultService::new(memory).invite_org_members("actor", "org", input)
    }

    #[test]
    fn invitations_authentication_binds_owner_org_status_and_admin_role_before_provider_work() {
        let input = request(r#"{"emails":["known"],"groups":[],"type":2}"#);
        let mut memory = Memory::new();
        assert_eq!(
            VaultService::new(&mut memory)
                .invite_org_members("", "org", &input)
                .unwrap_err()
                .cause()
                .status_code(),
            401
        );
        assert!(memory.calls.is_empty());
        for actor in [
            None,
            Some(OrganizationCollectionMembership {
                membership: OrganizationMembership {
                    user_id: "other",
                    organization_id: "org",
                    role: 0,
                    status: 2,
                },
                access_all: true,
            }),
            Some(OrganizationCollectionMembership {
                membership: OrganizationMembership {
                    user_id: "actor",
                    organization_id: "foreign",
                    role: 0,
                    status: 2,
                },
                access_all: true,
            }),
        ] {
            let mut memory = Memory::new();
            memory.actor = actor;
            assert_eq!(
                invite(&mut memory, &input)
                    .unwrap_err()
                    .cause()
                    .status_code(),
                401
            );
            assert_eq!(memory.calls, ["actor"]);
        }
        for (role, status) in [(2, 2), (3, 2), (4, 2), (0, 1), (1, -126)] {
            let mut memory = Memory::new();
            let member = &mut memory.actor.as_mut().unwrap().membership;
            member.role = role;
            member.status = status;
            assert_eq!(
                invite(&mut memory, &input)
                    .unwrap_err()
                    .cause()
                    .status_code(),
                401
            );
            assert!(memory.saved.is_empty());
        }
    }

    #[test]
    fn invitations_validate_all_collections_then_groups_then_role_even_for_empty_batch() {
        let input = request(
            r#"{"emails":[],"groups":["g","g"],"type":"bogus","collections":[["c",false,true,false],["c",true,false,true]]}"#,
        );
        let mut memory = Memory::new();
        memory.collections_exist = false;
        assert_eq!(
            invite(&mut memory, &input).unwrap_err().cause().message,
            "Invalid collection"
        );
        assert_eq!(memory.calls, ["actor", "collection"]);
        let mut memory = Memory::new();
        memory.groups_exist = false;
        assert_eq!(
            invite(&mut memory, &input).unwrap_err().cause().message,
            "Invalid group"
        );
        assert_eq!(memory.calls, ["actor", "collection", "collection", "group"]);
        let mut memory = Memory::new();
        assert_eq!(
            invite(&mut memory, &input).unwrap_err().cause().message,
            "Invalid type"
        );
        assert_eq!(
            memory.calls,
            ["actor", "collection", "collection", "group", "group"]
        );
        let input = request(r#"{"emails":[],"groups":[],"type":"User"}"#);
        assert_eq!(invite(&mut memory, &input).unwrap(), 0);
        assert_eq!(memory.revision, 40);
    }

    #[test]
    fn invitations_raw_custom_role_provenance_and_owner_escalation_are_preserved() {
        for (value, role, access_all) in [
            ("0", 0, true),
            ("1", 1, true),
            ("2", 2, false),
            ("3", 3, false),
            ("4", 3, true),
            (r#""4""#, 3, true),
            (r#""Custom""#, 3, false),
            (r#""Manager""#, 3, false),
        ] {
            let json = format!(
                r#"{{"emails":["known"],"groups":[],"type":{value},"permissions":{{"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true}}}}"#
            );
            let input = request(&json);
            let mut memory = Memory::new();
            invite(&mut memory, &input).unwrap();
            assert_eq!(
                (memory.saved[0].role, memory.saved[0].access_all),
                (role, access_all)
            );
        }
        for value in ["0", "1", "3", "4"] {
            let json = format!(r#"{{"emails":[],"groups":[],"type":{value}}}"#);
            let input = request(&json);
            let mut memory = Memory::new();
            memory.actor.as_mut().unwrap().membership.role = 1;
            let error = invite(&mut memory, &input).unwrap_err();
            assert_eq!(
                error.cause().message,
                "Only Owners can invite Managers, Admins or Owners"
            );
            assert_eq!(memory.calls, ["actor"]);
        }
        let input = request(r#"{"emails":["known"],"groups":[],"type":2}"#);
        let mut memory = Memory::new();
        memory.actor.as_mut().unwrap().membership.role = 1;
        assert_eq!(invite(&mut memory, &input).unwrap(), 1);
    }

    #[test]
    fn invitations_no_smtp_lifecycle_and_disabled_group_projection_do_not_drop_assignments() {
        let input = request(
            r#"{"emails":["Known","passwordless","missing"],"groups":["g","g"],"type":2,"collections":[["c",true,false,true]]}"#,
        );
        let mut memory = Memory::new();
        assert_eq!(invite(&mut memory, &input).unwrap(), 3);
        assert_eq!(
            memory
                .saved
                .iter()
                .map(|s| (s.status, s.stub, s.invitation, s.groups, s.collections))
                .collect::<Vec<_>>(),
            [
                (1, false, false, 2, 1),
                (0, false, true, 2, 1),
                (0, true, true, 2, 1)
            ]
        );
        assert_eq!(memory.revision, 43);
        assert_eq!(memory.foreign_revision, 90);
        let mut memory = Memory::new();
        memory.policy.mail_enabled = true;
        invite(&mut memory, &input).unwrap();
        assert!(memory.saved.iter().all(|s| s.status == 0 && !s.invitation));
    }

    #[test]
    fn invitations_missing_user_policies_do_not_restrict_existing_registered_or_passwordless_users()
    {
        let input =
            request(r#"{"emails":["known","passwordless","missing"],"groups":[],"type":2}"#);
        let mut memory = Memory::new();
        memory.policy.invitations_allowed = false;
        memory.domain_allowed = false;
        memory.email_valid = false;
        let error = invite(&mut memory, &input).unwrap_err();
        assert_eq!(error.kind(), OrganizationInviteErrorKind::UserDoesNotExist);
        assert_eq!(error.completed(), 2);
        assert_eq!(memory.saved.len(), 2);
        let input = request(r#"{"emails":["missing"],"groups":[],"type":2}"#);
        let mut memory = Memory::new();
        memory.domain_allowed = false;
        memory.email_valid = false;
        assert_eq!(
            invite(&mut memory, &input).unwrap_err().cause().message,
            "Email domain not eligible for invitations"
        );
        let mut memory = Memory::new();
        memory.email_valid = false;
        assert_eq!(
            invite(&mut memory, &input).unwrap_err().kind(),
            OrganizationInviteErrorKind::InvalidInvitationEmail
        );
        memory.policy.mail_enabled = true;
        assert_eq!(
            invite(&mut memory, &input).unwrap_err().kind(),
            OrganizationInviteErrorKind::InvalidEmail
        );
    }

    #[test]
    fn invitations_duplicate_normalized_emails_retain_successful_prefix_without_deduplication() {
        let input = request(r#"{"emails":["Known","KNOWN","missing"],"groups":[],"type":2}"#);
        let mut memory = Memory::new();
        let error = invite(&mut memory, &input).unwrap_err();
        assert_eq!(
            (error.index(), error.completed(), error.email()),
            (Some(1), 1, Some("KNOWN"))
        );
        assert_eq!(error.kind(), OrganizationInviteErrorKind::AlreadyMember);
        assert_eq!(memory.saved.len(), 1);
        assert_eq!(memory.revision, 41);
        assert_eq!(
            memory.calls,
            ["actor", "policy", "target", "commit", "target"]
        );
    }

    #[test]
    fn invitations_per_email_failure_and_racing_duplicate_preserve_earlier_commits() {
        let input = request(r#"{"emails":["first","second","third"],"groups":[],"type":2}"#);
        for race in [false, true] {
            let mut memory = Memory::new();
            if race {
                memory.race = Some(1);
            } else {
                memory.fail_commit = Some(1);
            }
            let error = invite(&mut memory, &input).unwrap_err();
            assert_eq!(
                (
                    error.completed(),
                    error.index(),
                    memory.saved.len(),
                    memory.revision
                ),
                (1, Some(1), 1, 41)
            );
            assert_eq!(
                error.cause().kind,
                if race {
                    ErrorKind::InvalidRequest
                } else {
                    ErrorKind::Conflict
                }
            );
            assert_eq!(memory.foreign_revision, 90);
        }
    }

    #[test]
    fn invitations_provider_error_mapping_and_incomplete_views_fail_before_affected_write() {
        let input = request(
            r#"{"emails":["known"],"groups":["g"],"type":2,"collections":[["c",false,false,false]]}"#,
        );
        for fail in ["actor", "collection", "group", "policy", "target", "commit"] {
            let mut memory = Memory::new();
            memory.fail = Some(fail);
            let error = invite(&mut memory, &input).unwrap_err();
            assert_eq!(error.cause().kind, ErrorKind::Conflict);
            assert!(memory.saved.is_empty());
            assert_eq!(memory.revision, 40);
        }
        struct Hole;
        impl OrganizationInviteData for Hole {
            fn emails_len(&self) -> usize {
                1
            }
            fn email(&self, _: usize) -> Option<&str> {
                None
            }
            fn groups_len(&self) -> usize {
                0
            }
            fn group(&self, _: usize) -> Option<&str> {
                None
            }
            fn collections_len(&self) -> usize {
                0
            }
            fn collection(&self, _: usize) -> Option<OrganizationInviteCollection<'_>> {
                None
            }
            fn role(&self) -> OrganizationInviteRole<'_> {
                OrganizationInviteRole::Integer(2)
            }
            fn permissions(&self) -> OrganizationInvitePermissions {
                OrganizationInvitePermissions::default()
            }
        }
        let mut memory = Memory::new();
        let error = invite(&mut memory, &Hole).unwrap_err();
        assert_eq!(error.cause().kind, ErrorKind::Storage);
        assert!(!memory.calls.contains(&"target"));
    }

    #[test]
    fn invitations_forwarding_and_uncapped_opaque_borrowed_views_preserve_input() {
        struct Input<'a>(&'a str);
        impl OrganizationInviteData for Input<'_> {
            fn emails_len(&self) -> usize {
                1
            }
            fn email(&self, i: usize) -> Option<&str> {
                (i == 0).then_some(self.0)
            }
            fn groups_len(&self) -> usize {
                0
            }
            fn group(&self, _: usize) -> Option<&str> {
                None
            }
            fn collections_len(&self) -> usize {
                0
            }
            fn collection(&self, _: usize) -> Option<OrganizationInviteCollection<'_>> {
                None
            }
            fn role(&self) -> OrganizationInviteRole<'_> {
                OrganizationInviteRole::String("User")
            }
            fn permissions(&self) -> OrganizationInvitePermissions {
                OrganizationInvitePermissions::default()
            }
        }
        let text = " Ω\0 ".repeat(2048);
        let input = Input(&text);
        let view: &dyn OrganizationInviteData = &input;
        let mut memory = Memory::new();
        let mut forwarded = &mut memory;
        assert_eq!(
            VaultService::new(&mut forwarded)
                .invite_org_members("actor", "org", &view)
                .unwrap(),
            1
        );
        assert_eq!(memory.saved[0].email, text.to_lowercase());
    }

    #[test]
    fn invitations_dynamic_messages_are_explicitly_streamed_and_debug_never_exposes_addresses() {
        let raw = "MiXeD\n\0@invalid";
        let normalized = "mixed\n\0@invalid";
        for (kind, prefix) in [
            (
                OrganizationInviteErrorKind::AlreadyMember,
                "User already in organization: ",
            ),
            (
                OrganizationInviteErrorKind::UserDoesNotExist,
                "User does not exist: ",
            ),
            (OrganizationInviteErrorKind::InvalidEmail, "User email "),
            (
                OrganizationInviteErrorKind::InvalidInvitationEmail,
                "Invitation email ",
            ),
        ] {
            let error = dynamic(kind, 2, raw);
            let mut message = String::new();
            error.write_message(&mut message, Some(normalized)).unwrap();
            let suffix = if matches!(
                kind,
                OrganizationInviteErrorKind::InvalidEmail
                    | OrganizationInviteErrorKind::InvalidInvitationEmail
            ) {
                " is not a valid email address"
            } else {
                ""
            };
            assert_eq!(
                message,
                format!("{prefix}{}{suffix}", normalized.escape_debug())
            );
            assert!(!format!("{error:?} {error}").contains("MiXeD"));
        }
        let target = InvitationTarget::Existing {
            account_id: AccountId(raw.to_string()),
            has_master_password: true,
            already_member: false,
        };
        let input = request(r#"{"emails":[],"groups":[],"type":2}"#);
        let plan = ValidatedOrganizationInvite {
            request: &input,
            email: raw,
            index: 0,
            target: &target,
            role: 2,
            access_all: false,
            mail_enabled: false,
        };
        for value in [
            format!("{input:?}"),
            format!("{target:?}"),
            format!("{plan:?}"),
        ] {
            assert!(value.contains("REDACTED"));
            assert!(!value.contains("MiXeD"));
        }
        let mut message = String::new();
        failure(
            ApiError::new(ErrorKind::Conflict, "safe conflict"),
            None,
            0,
            None,
        )
        .write_message(&mut message, None)
        .unwrap();
        assert_eq!(message, "safe conflict");
    }

    #[test]
    fn invitations_wire_required_slots_permission_map_and_caller_capacity_match_semantic_view() {
        type Request<'a> = OrganizationInviteRequest<'a, 2, 1, 1>;
        for body in [
            r#"{"emails":[],"groups":[],"type":2}"#,
            r#"{"emails":[],"groups":[],"type":"User","collections":null}"#,
            r#"[[],[],2,null]"#,
        ] {
            let decoded: Request<'_> = serde_json::from_str(body).unwrap();
            assert_eq!(decoded.collections_len(), 0);
            assert_eq!(
                decoded.permissions,
                OrganizationInvitePermissions::default()
            );
        }
        for body in [
            r#"[[],[],2]"#,
            r#"[[],[],2,null,{},0]"#,
            r#"{"emails":[],"groups":[],"type":2,"permissions":null}"#,
            r#"{"emails":[],"groups":[],"type":2,"collections":[{"id":"c","readOnly":false,"hidePasswords":false}]}"#,
            r#"{"emails":["a","b","c"],"groups":[],"type":2}"#,
            r#"{"emails":[],"groups":[],"type":2.5}"#,
        ] {
            assert!(serde_json::from_str::<Request<'_>>(body).is_err(), "{body}");
        }
        let decoded:Request<'_>=serde_json::from_str(r#"[["a"],["g"],"4",[["c",true,false,true]],{"createNewCollections":true,"editAnyCollection":true,"editAnyCollection":{"nested":[true]},"deleteAnyCollection":"true","unknown":[null]}]"#).unwrap();
        assert_eq!(decoded.collection(0).unwrap().id, "c");
        assert!(decoded.collection(0).unwrap().read_only);
        assert!(!decoded.collection(0).unwrap().hide_passwords);
        assert!(decoded.collection(0).unwrap().manage);
        assert_eq!(
            decoded.permissions,
            OrganizationInvitePermissions {
                create_new_collections: true,
                edit_any_collection: false,
                delete_any_collection: false
            }
        );
        let value = serde_json::to_value(decoded.collection(0).unwrap()).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"id":"c","readOnly":true,"hidePasswords":false,"manage":true})
        );
        assert!(format!("{decoded:?}").contains("REDACTED"));
    }
}
