//! Link a real bare-metal executable without a global allocator.
#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::{hint::black_box, panic::PanicInfo};
use no_warden::{
    Storage, VaultService,
    account_deletion::AccountDeletionStorage,
    account_key_id::{AccountKeyIdStorage, ValidatedUserKeyId},
    auth_login::{AuthRequestLoginContext, AuthRequestLoginDevice, AuthRequestLoginRecord},
    auth_requests::{AuthRequestContext, AuthRequestRecord},
    cipher_reads::CipherReadStorage,
    devices::{DeviceRecord, PendingDeviceAuthRequest},
    domains::{DomainProjection, DomainSettingsView, GlobalDomain},
    identity::Secret,
    organization_cipher_bulk_sharing::{
        CipherBulkSharingData, OrganizationCipherBulkSharingStorage, ValidatedCipherBulkShare,
        ValidatedCipherBulkShareAssociation, resolve_bulk_cipher_source_write_access,
    },
    organization_cipher_sharing::{
        CipherCollectionAccessData, CipherCollectionAccessRecord, CipherOwnership,
        CipherSharingCollection, CipherSharingMembership, CipherSharingSource,
        OrganizationCipherSharingStorage, ValidatedCipherShare, ValidatedCipherShareAssociation,
        resolve_cipher_access,
    },
    organization_collection_mutations::{
        OrganizationCollectionMutationStorage, ValidatedCollectionDelete, ValidatedCollectionUpdate,
    },
    organization_collections::{
        CollectionAccessData, CollectionAccessEntry, CollectionCreateData, CollectionListData,
        OrganizationCollectionMembership, OrganizationCollectionStorage, ValidatedCollectionCreate,
    },
    organization_confirmations::{
        OrganizationConfirmationPolicy, OrganizationConfirmationRecord,
        OrganizationConfirmationStorage, ValidatedOrganizationConfirmation,
    },
    organization_invitations::{
        InvitationPolicy, InvitationTarget, InviteCommit, OrganizationInvitationStorage,
        OrganizationInviteData, ValidatedOrganizationInvite,
    },
    organization_member_mini_details::{
        OrganizationMemberMiniData, OrganizationMemberMiniRecord, OrganizationMemberMiniStorage,
    },
    organization_member_public_keys::{
        OrganizationMemberPublicKeyLookup, OrganizationMemberPublicKeyRecord,
        OrganizationMemberPublicKeyStorage,
    },
    organization_member_removal::{
        OrganizationBulkMemberRemovalStorage, OrganizationMemberRemovalBatchAuthority,
        OrganizationMemberRemovalRecord, OrganizationMemberRemovalStorage,
        ValidatedOrganizationBulkMemberRemoval, ValidatedOrganizationMemberRemoval,
    },
    organization_member_status::{
        OrganizationMemberRestorationPolicy, OrganizationMemberStatusOperation,
        OrganizationMemberStatusRecord, OrganizationMemberStatusStorage,
        ValidatedOrganizationMemberStatus,
    },
    organization_members::{
        OrganizationMemberCollection, OrganizationMemberDetailQuery,
        OrganizationMemberDetailStorage, OrganizationMemberGroup, OrganizationMemberListData,
        OrganizationMemberQuery, OrganizationMemberRecord, OrganizationMemberStorage,
    },
    organization_web_reads::{
        OrganizationCipherReadData, OrganizationCipherReadRecord,
        OrganizationCollectionDetailsData, OrganizationGroupPresence, OrganizationWebReadsStorage,
    },
    organizations::{
        CollectionRecord, OrganizationCreationPolicy, OrganizationFeatures, OrganizationMembership,
        OrganizationProfileListData, OrganizationProfileRecord, OrganizationRecord,
        OrganizationStorage, UserCollectionListData, UserCollectionRecord,
        ValidatedOrganizationCreate,
    },
    password_login::{PasswordLoginAccount, PasswordLoginDevice, PasswordLoginStorage},
    prelogin::{PreloginLookup, PreloginStorage, UnknownKdfIndex},
    purge::VaultPurgeStorage,
    refresh::{RefreshIdentity, RefreshMethod, RefreshStorage},
    registration::RegistrationEmail,
    route::{Method, classify},
    sends::{
        AuthorizedSendFileDownload, FileSendStorage, SendContext, SendFileMetadata, SendFileQuota,
        SendFileUpload, SendListData, SendLookup, SendNumber, SendPayload, SendPolicy, SendRecord,
        SendState, SendStorage, ValidatedFileSend, ValidatedSendAccess, ValidatedSendFileUpload,
        ValidatedTextSend,
    },
    service::{ImportData, ItemMetadata},
    wire::{
        AccountKdfRequest, AccountKeys, AccountKeysResponse, AccountPasswordRequest,
        ApiKeyResponse, AttachmentRequest, AttachmentResponse, AttachmentUploadResponse,
        AuthRequestCreateRequest, AuthRequestListResponse, AuthRequestLoginRequest,
        AuthRequestResponse, AuthRequestUpdateRequest, AvatarUpdateRequest,
        CipherBulkShareItemRequest, CipherBulkShareRequest, CipherIdsRequest, CipherRequest,
        CipherShareRequest, ClientCredentialsRequest, DeviceListResponse, DevicePushTokenRequest,
        DeviceResponse, DomainSettingsRequest, DomainSettingsResponse,
        DomainSettingsUpdateResponse, FileSendRequest, FolderRequest, ImportRequest,
        InitializedAccountKeysResponse, KnownDeviceRequest, KnownDeviceResponse,
        MasterPasswordPolicy, MasterPasswordPolicyResponse, OrganizationBulkConfirmRequest,
        OrganizationBulkMemberRemovalRequest, OrganizationBulkMemberRestoreRequest,
        OrganizationBulkMemberRevokeRequest, OrganizationCollectionCreateRequest,
        OrganizationConfirmRequest, OrganizationCreateRequest, OrganizationInviteCollection,
        OrganizationInvitePermissions, OrganizationInviteRequest,
        OrganizationMemberPublicKeysRequest, OrganizationPlanType, PasswordLoginRequest,
        PasswordOrOtpRequest, PreloginKdfSettings, PreloginRequest, PreloginResponse,
        ProfileUpdateRequest, RefreshTokenRequest, RegisterRequest, RegistrationAuthentication,
        RegistrationCredentials, RegistrationFinishRequest, RegistrationFinishResponse,
        RegistrationUnlock, RegistrationVerificationRequest, RegistrationVerificationToken,
        SecretVerificationRequest, SendAccessTokenRequest, SendFileData, TextSendRequest,
        UserKeyIdRequest, UserPublicKeyResponse, WebAuthnCredentialsResponse,
    },
};

// Compile/link probe only: the trusted flag stands in for an external verifier.
// Its caller-owned fixed buffers prove the business-logic call needs no allocator.
struct PurgeProbe {
    verified: bool,
    account_present: bool,
    personal_items: [bool; 2],
    revision: u64,
    send_present: bool,
    send_count: i32,
    send_maximum: Option<i32>,
    send_kind: i32,
    file_uploaded: bool,
    user_key_id: [u8; 32],
    user_key_id_len: Option<usize>,
    organization_present: bool,
    organization_name: [u8; 64],
    organization_name_len: usize,
    organization_key: [u8; 32],
    organization_key_len: usize,
    collection_name: [u8; 64],
    collection_name_len: usize,
    organization_keys: bool,
    added_collection: bool,
    added_collection_name: [u8; 64],
    added_collection_name_len: usize,
    added_external: [u8; 64],
    added_external_len: Option<usize>,
    invited: [bool; 2],
    confirmed: bool,
    confirmed_key: [u8; 96],
    confirmed_key_len: usize,
    member_removed: bool,
    member_status: i32,
    sharing_associations: usize,
    shared_cipher: bool,
    bulk_associations: usize,
    bulk_commits: usize,
}
impl PurgeProbe {
    fn organization_record(&self) -> OrganizationRecord<'_> {
        OrganizationRecord {
            id: "embedded-org",
            name: core::str::from_utf8(&self.organization_name[..self.organization_name_len])
                .unwrap_or_default(),
            billing_email: "owner@example.com",
            has_public_and_private_keys: self.organization_keys,
            features: OrganizationFeatures::default(),
        }
    }
    fn membership(&self) -> OrganizationMembership<'static> {
        OrganizationMembership {
            user_id: "embedded-owner",
            organization_id: "embedded-org",
            role: 0,
            status: 2,
        }
    }
    fn send_record(&self) -> SendRecord<'_, Option<&'static str>> {
        SendRecord {
            id: "embedded-send",
            owner_id: "embedded-owner",
            access_id: "embedded-access",
            name: "opaque-name",
            notes: None,
            text: None,
            key: "opaque-key",
            max_access_count: self.send_maximum,
            access_count: self.send_count,
            password_hash: None,
            disabled: false,
            hide_email: None,
            revision_date: "1970-01-01T00:00:00.000Z",
            expiration_date: None,
            deletion_date: "1970-01-01T00:00:00.000001Z",
            creator_identifier: Some("bare-metal@example.com"),
        }
    }
}
struct SendProbeRecords<'a>(&'a PurgeProbe);
impl<'a> SendListData<'a> for SendProbeRecords<'a> {
    type Payload = Option<&'static str>;
    fn len(&self) -> usize {
        usize::from(self.0.send_present)
    }
    fn get(&self, index: usize) -> Option<SendRecord<'a, Self::Payload>> {
        (index == 0 && self.0.send_present).then(|| self.0.send_record())
    }
    fn kind(&self, index: usize) -> Option<i32> {
        (index == 0 && self.0.send_present).then_some(self.0.send_kind)
    }
}
impl Storage for PurgeProbe {
    type Error = ();
    fn user_key_id(&mut self, owner: &str) -> Result<Option<&str>, ()> {
        if owner != "embedded-owner" {
            return Err(());
        }
        self.user_key_id_len
            .map(|length| core::str::from_utf8(&self.user_key_id[..length]).map_err(|_| ()))
            .transpose()
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
    fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
        Ok(
            (id == "embedded-cipher" && self.personal_items[0]).then_some(ItemMetadata {
                owner_id: "embedded-owner",
                deleted: false,
            }),
        )
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
impl CipherReadStorage for PurgeProbe {}
impl OrganizationCipherSharingStorage for PurgeProbe {
    type ShareId = &'static str;
    fn sharing_revision_is_older(
        &mut self,
        source: &CipherSharingSource<Self::ShareId>,
        requested: &str,
    ) -> Result<bool, ()> {
        Ok(source.revision == "embedded-source-revision" && requested == "embedded-old-revision")
    }
    fn sharing_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::ShareId>>, ()> {
        Ok(
            (id == "embedded-share-source" && !self.shared_cipher).then_some(CipherSharingSource {
                id: "embedded-share-source",
                owner_id: Some("embedded-owner"),
                organization_id: None,
                revision: "embedded-source-revision",
            }),
        )
    }
    fn sharing_membership(
        &mut self,
        user: &str,
        org: &str,
    ) -> Result<Option<CipherSharingMembership<Self::ShareId>>, ()> {
        Ok(
            (user == "embedded-owner" && org == "embedded-org").then_some(
                CipherSharingMembership {
                    user_id: "embedded-owner",
                    organization_id: "embedded-org",
                    role: 0,
                    status: 2,
                    access_all: true,
                },
            ),
        )
    }
    fn sharing_collection(
        &mut self,
        user: &str,
        org: &str,
        collection: &str,
    ) -> Result<Option<CipherSharingCollection<Self::ShareId>>, ()> {
        Ok((user == "embedded-owner"
            && org == "embedded-org"
            && collection == "embedded-share-collection")
            .then_some(CipherSharingCollection {
                id: "embedded-share-collection",
                user_id: "embedded-owner",
                organization_id: "embedded-org",
                assigned: true,
                read_only: false,
                hide_passwords: false,
                manage: false,
            }))
    }
    fn associate_sharing_collection(
        &mut self,
        plan: &ValidatedCipherShareAssociation<'_>,
    ) -> Result<(), ()> {
        if plan.owner() != "embedded-owner"
            || plan.cipher_id() != "embedded-share-source"
            || plan.source_revision() != "embedded-source-revision"
            || plan.target_organization() != "embedded-org"
            || plan.collection_id() != "embedded-share-collection"
        {
            return Err(());
        }
        self.sharing_associations += 1;
        Ok(())
    }
    fn commit_cipher_share(&mut self, plan: &ValidatedCipherShare<'_, '_>) -> Result<(), ()> {
        if plan.owner() != "embedded-owner"
            || plan.cipher_id() != "embedded-share-source"
            || plan.source_revision() != "embedded-source-revision"
            || plan.target_organization() != Some("embedded-org")
            || plan.request().kind != 2
        {
            return Err(());
        }
        self.shared_cipher = true;
        Ok(())
    }
}
struct BulkAccess;
impl CipherCollectionAccessData for BulkAccess {
    fn len(&self) -> usize {
        0
    }
    fn get(&self, _: usize) -> Option<CipherCollectionAccessRecord<'_>> {
        None
    }
}
impl OrganizationCipherBulkSharingStorage for PurgeProbe {
    type BulkId = &'static str;
    type SourceAccess = BulkAccess;
    fn bulk_sharing_source(
        &mut self,
        id: &str,
    ) -> Result<Option<CipherSharingSource<Self::BulkId>>, ()> {
        Ok((id == "bulk-source").then_some(CipherSharingSource {
            id: "bulk-source",
            owner_id: Some("embedded-owner"),
            organization_id: None,
            revision: "bulk-revision",
        }))
    }
    fn bulk_sharing_membership(
        &mut self,
        user: &str,
        org: &str,
    ) -> Result<Option<CipherSharingMembership<Self::BulkId>>, ()> {
        self.sharing_membership(user, org)
    }
    fn bulk_source_collections(
        &mut self,
        _: &str,
        _: &CipherSharingSource<Self::BulkId>,
    ) -> Result<Self::SourceAccess, ()> {
        Ok(BulkAccess)
    }
    fn bulk_sharing_collection(
        &mut self,
        user: &str,
        org: &str,
        collection: &str,
    ) -> Result<Option<CipherSharingCollection<Self::BulkId>>, ()> {
        self.sharing_collection(user, org, collection)
    }
    fn associate_bulk_sharing_collection<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherBulkShareAssociation<'_, D>,
    ) -> Result<(), ()> {
        if plan.owner() != "embedded-owner"
            || plan.cipher_id() != "bulk-source"
            || plan.source_revision() != "bulk-revision"
            || plan.source_owner() != Some("embedded-owner")
            || plan.source_organization().is_some()
            || plan.target_organization() != "embedded-org"
            || plan.collection_id() != "embedded-share-collection"
            || plan.request().cipher(plan.index()).and_then(|v| v.id) != Some("bulk-source")
        {
            return Err(());
        }
        self.bulk_associations += 1;
        Ok(())
    }
    fn commit_cipher_bulk_share<D: CipherBulkSharingData + ?Sized>(
        &mut self,
        plan: &ValidatedCipherBulkShare<'_, D>,
    ) -> Result<(), ()> {
        if plan.owner() != "embedded-owner"
            || plan.cipher_id() != "bulk-source"
            || plan.source_revision() != "bulk-revision"
            || plan.source_owner() != Some("embedded-owner")
            || plan.source_organization().is_some()
            || plan.target_organization() != Some("embedded-org")
            || plan.request().cipher(plan.index()).map(|v| v.cipher_type) != Some(2)
        {
            return Err(());
        }
        self.bulk_commits += 1;
        Ok(())
    }
}
struct OrganizationProbeProfiles<'a>(&'a PurgeProbe);
impl OrganizationProfileListData for OrganizationProbeProfiles<'_> {
    fn len(&self) -> usize {
        usize::from(self.0.organization_present)
    }
    fn get(&self, index: usize) -> Option<OrganizationProfileRecord<'_>> {
        (index == 0 && self.0.organization_present).then(|| OrganizationProfileRecord {
            organization: self.0.organization_record(),
            membership: self.0.membership(),
            membership_id: "embedded-member",
            key: core::str::from_utf8(&self.0.organization_key[..self.0.organization_key_len])
                .unwrap_or_default(),
            access_all: true,
            reset_password_enrolled: false,
        })
    }
}
struct OrganizationProbeCollections<'a>(&'a PurgeProbe);
impl UserCollectionListData for OrganizationProbeCollections<'_> {
    fn len(&self) -> usize {
        usize::from(self.0.organization_present)
    }
    fn get(&self, index: usize) -> Option<UserCollectionRecord<'_>> {
        (index == 0 && self.0.organization_present).then(|| self.0.initial_collection_row())
    }
}
impl OrganizationStorage for PurgeProbe {
    type Collections<'a> = OrganizationProbeCollections<'a>;
    type Profiles<'a> = OrganizationProbeProfiles<'a>;
    fn creation_policy(&mut self, _: &str, email: &str) -> Result<OrganizationCreationPolicy, ()> {
        Ok(OrganizationCreationPolicy {
            allowed: self.account_present,
            single_org_blocked: false,
            billing_email_valid: email == "owner@example.com",
        })
    }
    fn create_organization(
        &mut self,
        owner: &str,
        plan: &ValidatedOrganizationCreate<'_, '_>,
    ) -> Result<OrganizationRecord<'_>, ()> {
        let request = plan.request();
        let key = request.key.expose_secret().as_bytes();
        if owner != "embedded-owner"
            || request.name.len() > self.organization_name.len()
            || request.collection_name.len() > self.collection_name.len()
            || key.len() > self.organization_key.len()
        {
            return Err(());
        }
        self.organization_name[..request.name.len()].copy_from_slice(request.name.as_bytes());
        self.organization_name_len = request.name.len();
        self.collection_name[..request.collection_name.len()]
            .copy_from_slice(request.collection_name.as_bytes());
        self.collection_name_len = request.collection_name.len();
        self.organization_key[..key.len()].copy_from_slice(key);
        self.organization_key_len = key.len();
        self.organization_keys = request.keys.is_some();
        self.organization_present = true;
        self.revision += 1;
        black_box((
            plan.membership_role(),
            plan.membership_status(),
            plan.access_all(),
        ));
        Ok(self.organization_record())
    }
    fn organization_membership(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<Option<OrganizationMembership<'_>>, ()> {
        Ok((self.organization_present
            && owner == "embedded-owner"
            && organization == "embedded-org")
            .then(|| self.membership()))
    }
    fn organization(&mut self, organization: &str) -> Result<Option<OrganizationRecord<'_>>, ()> {
        Ok(
            (self.organization_present && organization == "embedded-org")
                .then(|| self.organization_record()),
        )
    }
    fn user_collections(&mut self, _: &str) -> Result<Self::Collections<'_>, ()> {
        Ok(OrganizationProbeCollections(self))
    }
    fn profile_organizations(&mut self, _: &str) -> Result<Self::Profiles<'_>, ()> {
        Ok(OrganizationProbeProfiles(self))
    }
}

struct OrgCollectionProbe<'a>(&'a PurgeProbe);
impl CollectionListData for OrgCollectionProbe<'_> {
    fn len(&self) -> usize {
        usize::from(self.0.organization_present) + usize::from(self.0.added_collection)
    }
    fn get(&self, index: usize) -> Option<CollectionRecord<'_>> {
        match index {
            0 if self.0.organization_present => Some(self.0.initial_collection_row().collection),
            1 if self.0.added_collection => Some(self.0.added_collection_record()),
            _ => None,
        }
    }
}
struct OrgCollectionDetailsProbe<'a> {
    provider: &'a PurgeProbe,
    added: bool,
}
impl CollectionAccessData for OrgCollectionDetailsProbe<'_> {
    fn collection(&self) -> UserCollectionRecord<'_> {
        if self.added {
            self.provider.added_collection_row()
        } else {
            self.provider.initial_collection_row()
        }
    }
    fn assigned(&self) -> bool {
        true
    }
    fn users_len(&self) -> usize {
        0
    }
    fn user(&self, _: usize) -> Option<CollectionAccessEntry<'_>> {
        None
    }
    fn groups_enabled(&self) -> bool {
        false
    }
    fn groups_len(&self) -> usize {
        0
    }
    fn group(&self, _: usize) -> Option<CollectionAccessEntry<'_>> {
        None
    }
}
impl PurgeProbe {
    fn initial_collection_row(&self) -> UserCollectionRecord<'_> {
        UserCollectionRecord {
            collection: CollectionRecord {
                id: "embedded-collection",
                organization_id: "embedded-org",
                name: core::str::from_utf8(&self.collection_name[..self.collection_name_len])
                    .unwrap_or_default(),
                external_id: None,
            },
            membership: self.membership(),
            readable: true,
            read_only: false,
            hide_passwords: false,
            manage: true,
        }
    }
    fn added_collection_record(&self) -> CollectionRecord<'_> {
        CollectionRecord {
            id: "embedded-added-collection",
            organization_id: "embedded-org",
            name: core::str::from_utf8(
                &self.added_collection_name[..self.added_collection_name_len],
            )
            .unwrap_or_default(),
            external_id: self
                .added_external_len
                .map(|len| core::str::from_utf8(&self.added_external[..len]).unwrap_or_default()),
        }
    }
    fn added_collection_row(&self) -> UserCollectionRecord<'_> {
        UserCollectionRecord {
            collection: self.added_collection_record(),
            membership: self.membership(),
            readable: true,
            read_only: false,
            hide_passwords: false,
            manage: true,
        }
    }
}
struct WebCipherProbe<'a>(&'a PurgeProbe);
impl OrganizationCipherReadData for WebCipherProbe<'_> {
    fn len(&self) -> usize {
        usize::from(self.0.organization_present)
    }
    fn get(&self, index: usize) -> Option<OrganizationCipherReadRecord<'_>> {
        (index == 0 && self.0.organization_present).then_some(OrganizationCipherReadRecord {
            id: "embedded-shared-cipher",
            organization_id: "embedded-org",
        })
    }
}
struct WebDetailsProbe<'a>(&'a PurgeProbe);
impl OrganizationCollectionDetailsData for WebDetailsProbe<'_> {
    type Details<'a>
        = OrgCollectionDetailsProbe<'a>
    where
        Self: 'a;
    fn len(&self) -> usize {
        usize::from(self.0.organization_present) + usize::from(self.0.added_collection)
    }
    fn get(&self, index: usize) -> Option<Self::Details<'_>> {
        match index {
            0 if self.0.organization_present => Some(OrgCollectionDetailsProbe {
                provider: self.0,
                added: false,
            }),
            1 if self.0.added_collection => Some(OrgCollectionDetailsProbe {
                provider: self.0,
                added: true,
            }),
            _ => None,
        }
    }
}
impl OrganizationWebReadsStorage for PurgeProbe {
    type CipherReads<'a> = WebCipherProbe<'a>;
    type CollectionDetails<'a> = WebDetailsProbe<'a>;
    fn organization_cipher_reads(&mut self, org: &str) -> Result<Self::CipherReads<'_>, ()> {
        if org != "embedded-org" {
            return Err(());
        }
        Ok(WebCipherProbe(self))
    }
    fn organization_collection_details(
        &mut self,
        owner: &str,
        org: &str,
    ) -> Result<Self::CollectionDetails<'_>, ()> {
        if owner != "embedded-owner" || org != "embedded-org" {
            return Err(());
        }
        Ok(WebDetailsProbe(self))
    }
    fn organization_group_presence(&mut self, org: &str) -> Result<OrganizationGroupPresence, ()> {
        if org != "embedded-org" {
            return Err(());
        }
        Ok(OrganizationGroupPresence::NoCreatedGroups)
    }
}
impl OrganizationCollectionStorage for PurgeProbe {
    type OrgCollections<'a> = OrgCollectionProbe<'a>;
    type AccessDetails<'a> = OrgCollectionDetailsProbe<'a>;
    fn collection_membership(
        &mut self,
        owner: &str,
        organization: &str,
    ) -> Result<Option<OrganizationCollectionMembership<'_>>, ()> {
        Ok((self.organization_present
            && owner == "embedded-owner"
            && organization == "embedded-org")
            .then(|| OrganizationCollectionMembership {
                membership: self.membership(),
                access_all: true,
            }))
    }
    fn org_collections(&mut self, _: &str) -> Result<Self::OrgCollections<'_>, ()> {
        Ok(OrgCollectionProbe(self))
    }
    fn can_manage_collection(&mut self, owner: &str, collection: &str) -> Result<bool, ()> {
        Ok(owner == "embedded-owner"
            && ((collection == "embedded-collection" && self.organization_present)
                || (collection == "embedded-added-collection" && self.added_collection)))
    }
    fn collection_access_details(
        &mut self,
        _: &str,
        collection: &str,
    ) -> Result<Option<Self::AccessDetails<'_>>, ()> {
        Ok(match collection {
            "embedded-collection" if self.organization_present => Some(OrgCollectionDetailsProbe {
                provider: self,
                added: false,
            }),
            "embedded-added-collection" if self.added_collection => {
                Some(OrgCollectionDetailsProbe {
                    provider: self,
                    added: true,
                })
            }
            _ => None,
        })
    }
    fn collection_group_exists(&mut self, _: &str, _: &str) -> Result<bool, ()> {
        Ok(false)
    }
    fn collection_member_exists(&mut self, organization: &str, member: &str) -> Result<bool, ()> {
        Ok(organization == "embedded-org" && member == "embedded-member")
    }
    fn create_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        organization: &str,
        plan: &ValidatedCollectionCreate<'_, D>,
    ) -> Result<UserCollectionRecord<'_>, ()> {
        let name = plan.request().name().as_bytes();
        let external = plan.external_id().map(str::as_bytes);
        if owner != "embedded-owner"
            || organization != "embedded-org"
            || name.len() > self.added_collection_name.len()
            || external.is_some_and(|value| value.len() > self.added_external.len())
        {
            return Err(());
        }
        self.added_collection_name[..name.len()].copy_from_slice(name);
        self.added_collection_name_len = name.len();
        self.added_external_len = external.map(|value| {
            self.added_external[..value.len()].copy_from_slice(value);
            value.len()
        });
        // This compile probe's only valid member is access_all, so no direct link is written.
        self.added_collection = true;
        self.revision += 1;
        Ok(self.added_collection_row())
    }
}
// Caller-owned storage proves sequential invitation service/error formatting links
// without a heap. These fixed capacities belong only to this compile probe.
struct InvitationMessageBuffer {
    bytes: [u8; 192],
    len: usize,
}
impl core::fmt::Write for InvitationMessageBuffer {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?;
        destination.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}
// This probe's only removable target is a different User, so its stack-owned
// batch context never authorizes a missing actor or a self-removal transition.
struct RemovalBatchProbe {
    role: i32,
}
impl OrganizationBulkMemberRemovalStorage for PurgeProbe {
    type Batch = RemovalBatchProbe;
    fn begin_member_removal_batch(
        &mut self,
        authority: &OrganizationMemberRemovalBatchAuthority<'_>,
    ) -> Result<Self::Batch, ()> {
        if !self.organization_present
            || authority.owner() != "embedded-owner"
            || authority.organization() != "embedded-org"
            || authority.actor_role() != 0
        {
            return Err(());
        }
        Ok(RemovalBatchProbe {
            role: authority.actor_role(),
        })
    }
    fn remove_organization_member_in_batch(
        &mut self,
        batch: &mut Self::Batch,
        plan: &ValidatedOrganizationBulkMemberRemoval<'_, Self::Id>,
    ) -> Result<(), ()> {
        if !self.organization_present
            || plan.actor_role() != batch.role
            || plan.actor_removed_by_batch()
            || plan.removes_actor()
        {
            return Err(());
        }
        self.remove_organization_member(plan.removal())
    }
}
impl OrganizationMemberStatusStorage for PurgeProbe {
    type Id = &'static str;
    fn status_member(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberStatusRecord<Self::Id>>, ()> {
        Ok((org == "embedded-org"
            && member == "embedded-invited-member"
            && self.invited[0]
            && !self.member_removed)
            .then_some(OrganizationMemberStatusRecord {
                membership_id: "embedded-invited-member",
                organization_id: "embedded-org",
                user_id: "existing-account",
                role: 2,
                status: self.member_status,
            }))
    }
    fn status_confirmed_owner_count(&mut self, _: &str) -> Result<u64, ()> {
        Ok(1)
    }
    fn restoration_policy(
        &mut self,
        _: &ValidatedOrganizationMemberStatus<'_, Self::Id>,
    ) -> Result<OrganizationMemberRestorationPolicy, ()> {
        Ok(OrganizationMemberRestorationPolicy::Allowed)
    }
    fn set_organization_member_status(
        &mut self,
        plan: &ValidatedOrganizationMemberStatus<'_, Self::Id>,
    ) -> Result<(), ()> {
        let status = match plan.operation() {
            OrganizationMemberStatusOperation::Revoke if self.member_status >= 0 => {
                self.member_status - 128
            }
            OrganizationMemberStatusOperation::Restore if self.member_status < 0 => {
                self.member_status + 128
            }
            OrganizationMemberStatusOperation::Restore if self.member_status == 0 => 0,
            _ => return Err(()),
        };
        if !self.organization_present
            || !self.invited[0]
            || self.member_removed
            || plan.owner() != "embedded-owner"
            || plan.organization() != "embedded-org"
            || plan.membership_id() != "embedded-invited-member"
            || plan.user_id() != "existing-account"
            || plan.role() != 2
            || plan.previous_status() != self.member_status
            || plan.status() != status
        {
            return Err(());
        }
        self.member_status = status;
        self.confirmed = status == 2;
        self.revision += 1;
        Ok(())
    }
}
impl OrganizationMemberPublicKeyStorage for PurgeProbe {
    type Id = &'static str;
    type PublicKey = &'static str;
    fn member_public_key(
        &mut self,
        organization: &str,
        membership: &str,
    ) -> OrganizationMemberPublicKeyLookup<Self::Id, Self::PublicKey, ()> {
        Ok((organization == "embedded-org"
            && membership == "embedded-invited-member"
            && self.invited[0]
            && !self.member_removed)
            .then_some(OrganizationMemberPublicKeyRecord {
                membership_id: "embedded-invited-member",
                organization_id: "embedded-org",
                user_id: "existing-account",
                public_key: Some("embedded-public-key"),
            }))
    }
}
impl OrganizationMemberRemovalStorage for PurgeProbe {
    type Id = &'static str;
    fn removal_member(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<OrganizationMemberRemovalRecord<Self::Id>>, ()> {
        Ok((org == "embedded-org"
            && member == "embedded-invited-member"
            && self.invited[0]
            && !self.member_removed)
            .then_some(OrganizationMemberRemovalRecord {
                membership_id: "embedded-invited-member",
                organization_id: "embedded-org",
                user_id: "existing-account",
                role: 2,
                status: if self.confirmed { 2 } else { 1 },
                mail_enabled: false,
                user_exists: true,
                other_invited_memberships: false,
            }))
    }
    fn confirmed_owner_count(&mut self, _: &str) -> Result<u64, ()> {
        Ok(1)
    }
    fn remove_organization_member(
        &mut self,
        plan: &ValidatedOrganizationMemberRemoval<'_, Self::Id>,
    ) -> Result<(), ()> {
        if !self.invited[0]
            || self.member_removed
            || plan.owner() != "embedded-owner"
            || plan.organization() != "embedded-org"
            || plan.membership_id() != "embedded-invited-member"
            || plan.user_id() != "existing-account"
            || plan.role() != 2
            || plan.status() != if self.confirmed { 2 } else { 1 }
            || !plan.remove_invitation()
        {
            return Err(());
        }
        self.invited[0] = false;
        self.confirmed = false;
        self.confirmed_key_len = 0;
        self.member_removed = true;
        self.revision += 1;
        Ok(())
    }
}
impl OrganizationConfirmationStorage for PurgeProbe {
    type Id = &'static str;
    fn confirmation_member(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<OrganizationConfirmationRecord<Self::Id>>, ()> {
        Ok(
            (org == "embedded-org" && member == "embedded-invited-member" && self.invited[0])
                .then_some(OrganizationConfirmationRecord {
                    membership_id: "embedded-invited-member",
                    organization_id: "embedded-org",
                    user_id: "existing-account",
                    role: 2,
                    status: if self.confirmed { 2 } else { 1 },
                }),
        )
    }
    fn confirmation_policy(
        &mut self,
        plan: &ValidatedOrganizationConfirmation<'_, Self::Id>,
    ) -> Result<OrganizationConfirmationPolicy, ()> {
        if plan.status() != 2 || plan.previous_status() != 1 {
            return Err(());
        }
        Ok(OrganizationConfirmationPolicy::Allowed)
    }
    fn confirm_organization_member(
        &mut self,
        plan: &ValidatedOrganizationConfirmation<'_, Self::Id>,
    ) -> Result<(), ()> {
        let key = plan.key().expose_secret().as_bytes();
        if self.confirmed
            || !self.invited[0]
            || plan.owner() != "embedded-owner"
            || plan.organization() != "embedded-org"
            || plan.membership_id() != "embedded-invited-member"
            || plan.user_id() != "existing-account"
            || key.len() > self.confirmed_key.len()
        {
            return Err(());
        }
        self.confirmed_key[..key.len()].copy_from_slice(key);
        self.confirmed_key_len = key.len();
        self.confirmed = true;
        self.member_status = 2;
        self.revision += 1;
        Ok(())
    }
}
impl OrganizationInvitationStorage for PurgeProbe {
    type AccountId = &'static str;
    fn invitation_policy(&mut self, _: &str, _: &str) -> Result<InvitationPolicy, ()> {
        Ok(InvitationPolicy {
            mail_enabled: false,
            invitations_allowed: true,
        })
    }
    fn invitation_collection_exists(&mut self, org: &str, col: &str) -> Result<bool, ()> {
        Ok(org == "embedded-org" && col == "embedded-collection" && self.organization_present)
    }
    fn invitation_target(
        &mut self,
        _: &str,
        email: &str,
    ) -> Result<InvitationTarget<Self::AccountId>, ()> {
        match email {
            "existing@example.com" => Ok(InvitationTarget::Existing {
                account_id: "existing-account",
                has_master_password: true,
                already_member: self.invited[0],
            }),
            "new@example.com" if self.invited[1] => Ok(InvitationTarget::Existing {
                account_id: "new-account",
                has_master_password: false,
                already_member: true,
            }),
            "new@example.com" => Ok(InvitationTarget::Missing {
                domain_allowed: true,
                email_valid: true,
            }),
            _ => Err(()),
        }
    }
    fn commit_organization_invitation<D: OrganizationInviteData + ?Sized>(
        &mut self,
        owner: &str,
        org: &str,
        plan: &ValidatedOrganizationInvite<'_, D, Self::AccountId>,
    ) -> Result<InviteCommit, ()> {
        let index = match plan.email() {
            "existing@example.com" => 0,
            "new@example.com" => 1,
            _ => return Err(()),
        };
        if owner != "embedded-owner"
            || org != "embedded-org"
            || plan.role() != 2
            || plan.access_all()
            || plan.key() != ""
        {
            return Err(());
        }
        if self.invited[index] {
            return Ok(InviteCommit::AlreadyMember);
        }
        if plan.membership_status() != if index == 0 { 1 } else { 0 }
            || plan.requires_invitation() != (index == 1)
        {
            return Err(());
        }
        self.invited[index] = true;
        self.revision += 1;
        Ok(InviteCommit::Created)
    }
}
impl OrganizationCollectionMutationStorage for PurgeProbe {
    fn mutation_collection(
        &mut self,
        org: &str,
        col: &str,
    ) -> Result<Option<CollectionRecord<'_>>, ()> {
        Ok(if org != "embedded-org" {
            None
        } else if col == "embedded-added-collection" && self.added_collection {
            Some(self.added_collection_record())
        } else if col == "embedded-collection" && self.organization_present {
            Some(self.initial_collection_row().collection)
        } else {
            None
        })
    }
    fn update_collection<D: CollectionCreateData + ?Sized>(
        &mut self,
        owner: &str,
        org: &str,
        col: &str,
        plan: &ValidatedCollectionUpdate<'_, D>,
    ) -> Result<UserCollectionRecord<'_>, ()> {
        let name = plan.request().name().as_bytes();
        let external = plan.external_id().map(str::as_bytes);
        if owner != "embedded-owner"
            || org != "embedded-org"
            || col != "embedded-added-collection"
            || !self.added_collection
            || name.len() > self.added_collection_name.len()
            || external.is_some_and(|value| value.len() > self.added_external.len())
        {
            return Err(());
        }
        self.added_collection_name[..name.len()].copy_from_slice(name);
        self.added_collection_name_len = name.len();
        self.added_external_len = external.map(|value| {
            self.added_external[..value.len()].copy_from_slice(value);
            value.len()
        });
        self.revision += 1;
        Ok(self.added_collection_row())
    }
    fn delete_collection(&mut self, plan: &ValidatedCollectionDelete<'_>) -> Result<(), ()> {
        if plan.owner() != "embedded-owner"
            || plan.organization() != "embedded-org"
            || plan.collection() != "embedded-added-collection"
            || !self.added_collection
        {
            return Err(());
        }
        self.added_collection = false;
        self.revision += 1;
        Ok(())
    }
}
struct OrganizationMembersProbe<'a>(&'a PurgeProbe, Option<usize>);
impl OrganizationMemberListData for OrganizationMembersProbe<'_> {
    fn len(&self) -> usize {
        if self.0.organization_present {
            if self.1.is_some() { 1 } else { 2 }
        } else {
            0
        }
    }
    fn get(&self, index: usize) -> Option<OrganizationMemberRecord<'_>> {
        if index >= OrganizationMemberListData::len(self) {
            return None;
        }
        let index = self.1.unwrap_or(index);
        Some(OrganizationMemberRecord {
            membership_id: if index == 0 {
                "embedded-member"
            } else {
                "embedded-guest-member"
            },
            user_id: if index == 0 {
                "embedded-owner"
            } else {
                "embedded-guest"
            },
            organization_id: "embedded-org",
            name: Some("public embedded account"),
            email: "account@example.com",
            external_id: None,
            avatar_color: None,
            status: 2,
            role: if index == 0 { 0 } else { 3 },
            access_all: index == 0,
            two_factor_enabled: false,
            reset_password_enrolled: false,
            has_master_password: true,
            full_access_group: false,
        })
    }
    fn groups_enabled(&self) -> bool {
        true
    }
    fn groups_len(&self, _: usize) -> usize {
        1
    }
    fn group(&self, _: usize, index: usize) -> Option<OrganizationMemberGroup<'_>> {
        (index == 0).then_some(OrganizationMemberGroup {
            id: "embedded-group",
            organization_id: "embedded-org",
        })
    }
    fn collections_len(&self, _: usize) -> usize {
        1
    }
    fn collection(&self, _: usize, index: usize) -> Option<OrganizationMemberCollection<'_>> {
        (index == 0).then_some(OrganizationMemberCollection {
            id: "embedded-collection",
            organization_id: "embedded-org",
            read_only: false,
            hide_passwords: false,
            manage: false,
        })
    }
}
impl OrganizationMemberStorage for PurgeProbe {
    type Members<'a> = OrganizationMembersProbe<'a>;
    fn organization_members(&mut self, org: &str) -> Result<Self::Members<'_>, ()> {
        if org != "embedded-org" {
            return Err(());
        }
        Ok(OrganizationMembersProbe(self, None))
    }
}
impl OrganizationMemberMiniData for OrganizationMembersProbe<'_> {
    fn len(&self) -> usize {
        OrganizationMemberListData::len(self)
    }
    fn get(&self, index: usize) -> Option<OrganizationMemberMiniRecord<'_>> {
        let row = OrganizationMemberListData::get(self, index)?;
        Some(OrganizationMemberMiniRecord {
            membership_id: row.membership_id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            email: row.email,
            name: row.name.unwrap_or(""),
            role: row.role,
            status: row.status,
        })
    }
}
impl OrganizationMemberMiniStorage for PurgeProbe {
    type MiniMembers<'a> = OrganizationMembersProbe<'a>;
    fn organization_member_mini_details(&mut self, org: &str) -> Result<Self::MiniMembers<'_>, ()> {
        if org != "embedded-org" {
            return Err(());
        }
        Ok(OrganizationMembersProbe(self, None))
    }
}
impl OrganizationMemberDetailStorage for PurgeProbe {
    fn organization_member(
        &mut self,
        org: &str,
        member: &str,
    ) -> Result<Option<Self::Members<'_>>, ()> {
        if org != "embedded-org" || !self.organization_present {
            return Ok(None);
        }
        let index = match member {
            "embedded-member" => 0,
            "embedded-guest-member" => 1,
            _ => return Ok(None),
        };
        Ok(Some(OrganizationMembersProbe(self, Some(index))))
    }
}
impl PreloginStorage for PurgeProbe {
    fn prelogin(&mut self, raw_email: &str) -> Result<PreloginLookup, ()> {
        if raw_email == "bare-metal@example.com" {
            Ok(PreloginLookup::Known(PreloginKdfSettings {
                iterations: i32::MIN,
                kdf_type: -7,
                memory: Some(-8),
                parallelism: Some(i32::MAX),
            }))
        } else {
            // Compile/link probe only; a production provider supplies normalized
            // lookup and secret-dependent cryptographic selection externally.
            let index = UnknownKdfIndex::new(black_box(4)).ok_or(())?;
            Ok(PreloginLookup::Unknown(index))
        }
    }
}
impl AccountKeyIdStorage for PurgeProbe {
    fn set_user_key_id_if_absent(
        &mut self,
        owner: &str,
        update: &ValidatedUserKeyId<'_>,
    ) -> Result<bool, ()> {
        if owner != "embedded-owner" || !self.account_present {
            return Err(());
        }
        if self.user_key_id_len.is_some() {
            return Ok(false);
        }
        let bytes = update.user_key_id().as_bytes();
        if bytes.len() > self.user_key_id.len() {
            return Err(());
        }
        self.user_key_id[..bytes.len()].copy_from_slice(bytes);
        self.user_key_id_len = Some(bytes.len());
        self.revision += 1;
        Ok(true)
    }
}
impl SendStorage for PurgeProbe {
    type SendId = &'static str;
    type Payload<'a> = Option<&'static str>;
    type Sends<'a> = SendProbeRecords<'a>;
    fn send_policy(&mut self, _: &str) -> Result<SendPolicy, ()> {
        Ok(SendPolicy {
            can_modify: self.account_present,
            can_hide_email: true,
        })
    }
    fn send_state(&mut self, id: &str) -> SendLookup<SendState<'_>, ()> {
        Ok(
            (id == "embedded-send" && self.send_present).then_some(SendState {
                id: "embedded-send",
                owner_id: "embedded-owner",
                kind: self.send_kind,
                disabled: false,
                max_access_count: self.send_maximum,
                access_count: self.send_count,
                expiration_ns: None,
                deletion_ns: 1000,
                password_protected: false,
            }),
        )
    }
    fn send(&mut self, id: &str) -> SendLookup<SendRecord<'_, Self::Payload<'_>>, ()> {
        Ok((id == "embedded-send" && self.send_present).then(|| self.send_record()))
    }
    fn sends(&mut self, _: &str) -> Result<Self::Sends<'_>, ()> {
        Ok(SendProbeRecords(self))
    }
    fn create_text_send<P: SendPayload + ?Sized>(
        &mut self,
        _: &str,
        plan: &ValidatedTextSend<'_, '_, P>,
    ) -> Result<Self::SendId, ()> {
        let mut buffer = [0; 256];
        let _ = black_box(serde_json_core::to_slice(
            plan.request().text.unwrap(),
            &mut buffer,
        ));
        black_box((buffer, plan.password_change()));
        self.send_present = true;
        self.send_kind = 0;
        self.send_count = 0;
        self.send_maximum = plan.max_access_count();
        Ok("embedded-send")
    }
    fn update_text_send<P: SendPayload + ?Sized>(
        &mut self,
        _: &str,
        _: &str,
        plan: &ValidatedTextSend<'_, '_, P>,
    ) -> Result<(), ()> {
        black_box(plan);
        self.send_maximum = plan.max_access_count();
        Ok(())
    }
    fn delete_send(&mut self, _: &str, _: &str) -> Result<(), ()> {
        self.send_present = false;
        Ok(())
    }
    fn remove_send_password(&mut self, _: &str, _: &str) -> Result<(), ()> {
        Ok(())
    }
    fn resolve_send_access_id(&mut self, id: &str) -> Result<Option<Self::SendId>, ()> {
        Ok((id == "embedded-access").then_some("embedded-send"))
    }
    fn verify_send_password(&mut self, _: &str, password: &Secret<'_>) -> Result<bool, ()> {
        black_box(password);
        Ok(self.verified)
    }
    fn verify_send_access_token(&mut self, token: &Secret<'_>) -> Result<Option<Self::SendId>, ()> {
        black_box(token);
        Ok(self.verified.then_some("embedded-send"))
    }
    fn register_send_access(&mut self, plan: &ValidatedSendAccess<'_>) -> Result<bool, ()> {
        black_box((plan.id(), plan.now_unix_nanos()));
        self.revision += 1;
        if self
            .send_maximum
            .is_some_and(|maximum| self.send_count >= maximum)
        {
            return Ok(false);
        }
        self.send_count += 1;
        Ok(true)
    }
}
impl FileSendStorage for PurgeProbe {
    type Url = &'static str;
    fn file_send_quota(&mut self, _: &str) -> Result<SendFileQuota, ()> {
        Ok(SendFileQuota::default())
    }
    fn create_file_send<P: SendPayload + ?Sized>(
        &mut self,
        _: &str,
        plan: &ValidatedFileSend<'_, '_, P>,
    ) -> Result<Self::SendId, ()> {
        let mut output = [0; 256];
        let _ = black_box(serde_json_core::to_slice(
            plan.request().file.unwrap(),
            &mut output,
        ));
        black_box((plan.common(), plan.file_length(), plan.password_change()));
        self.send_present = true;
        self.send_kind = 1;
        self.send_count = 0;
        self.send_maximum = plan.max_access_count();
        Ok("embedded-send")
    }
    fn update_file_send<P: SendPayload + ?Sized>(
        &mut self,
        _: &str,
        _: &str,
        plan: &ValidatedFileSend<'_, '_, P>,
    ) -> Result<(), ()> {
        black_box(plan);
        Ok(())
    }
    fn send_file_metadata(&mut self, _: &str) -> SendLookup<SendFileMetadata<'_>, ()> {
        Ok(Some(SendFileMetadata {
            file_id: "embedded-file",
            file_name: "opaque-file",
            file_size: 4,
        }))
    }
    fn commit_send_file_upload(
        &mut self,
        _: &str,
        plan: &ValidatedSendFileUpload<'_>,
    ) -> Result<bool, ()> {
        black_box((plan.id(), plan.file_id(), plan.file_size()));
        if self.file_uploaded {
            return Ok(false);
        }
        self.file_uploaded = true;
        self.revision += 1;
        Ok(true)
    }
    fn touch_file_send_access(&mut self, _: &ValidatedSendAccess<'_>) -> Result<(), ()> {
        self.revision += 1;
        Ok(())
    }
    fn send_file_upload_url(&mut self, _: &str) -> Result<Self::Url, ()> {
        Ok("/sends/embedded-send/file/embedded-file")
    }
    fn send_file_download_url(
        &mut self,
        grant: &AuthorizedSendFileDownload<'_>,
    ) -> Result<Self::Url, ()> {
        black_box((grant.id(), grant.file_id(), grant.expires_in()));
        Ok("/api/sends/embedded-send/embedded-file?t=opaque")
    }
    fn verify_send_file_download(
        &mut self,
        _: &str,
        _: &str,
        proof: &Secret<'_>,
    ) -> Result<bool, ()> {
        black_box(proof);
        Ok(self.verified)
    }
}
impl PasswordLoginStorage for PurgeProbe {
    type OwnerId = &'static str;

    fn verify_password_login(
        &mut self,
        username: &str,
        password: &Secret<'_>,
    ) -> Result<Option<PasswordLoginAccount<Self::OwnerId>>, ()> {
        // Compile/link probe only: an external verifier supplies this trusted flag.
        black_box(password);
        Ok(
            (self.verified && self.account_present && username == "bare-metal@example.com")
                .then_some(PasswordLoginAccount {
                    owner: "embedded-owner",
                    enabled: true,
                }),
        )
    }

    fn prepare_password_login(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
        device: PasswordLoginDevice<'_>,
    ) -> Result<(), ()> {
        black_box((owner, password, device));
        Ok(())
    }
}
impl RefreshStorage for PurgeProbe {
    type OwnerId = &'static str;
    type DeviceId = &'static str;

    fn verify_refresh_token(
        &mut self,
        refresh_token: &Secret<'_>,
    ) -> Result<Option<RefreshIdentity<Self::OwnerId, Self::DeviceId>>, ()> {
        // Compile/link probe only: trusted verification/time/device binding is external.
        black_box(refresh_token);
        Ok(
            (self.verified && self.account_present).then_some(RefreshIdentity {
                owner: "embedded-owner",
                device_identifier: "",
                method: RefreshMethod::Password,
            }),
        )
    }

    fn prepare_password_refresh(&mut self, owner: &str, device_identifier: &str) -> Result<(), ()> {
        black_box((owner, device_identifier));
        Ok(())
    }
}
impl VaultPurgeStorage for PurgeProbe {
    fn verify_vault_purge_proof(
        &mut self,
        owner: &str,
        proof: no_warden::identity::ReauthenticationProof<'_>,
    ) -> Result<bool, ()> {
        black_box(proof);
        Ok(owner == "embedded-owner" && self.verified)
    }
    fn purge_personal_vault(&mut self, _: &str) -> Result<(), ()> {
        self.personal_items.fill(false);
        self.revision += 1;
        Ok(())
    }
}

impl AccountDeletionStorage for PurgeProbe {
    fn account_deletion_blocked_by_last_owner(&mut self, _: &str) -> Result<bool, ()> {
        Ok(self.organization_present)
    }
    fn verify_account_deletion_proof(
        &mut self,
        owner: &str,
        proof: no_warden::identity::ReauthenticationProof<'_>,
    ) -> Result<bool, ()> {
        black_box(proof);
        Ok(owner == "embedded-owner" && self.verified && self.account_present)
    }
    fn delete_account(&mut self, _: &str) -> Result<(), ()> {
        self.personal_items.fill(false);
        self.account_present = false;
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let input = black_box(br#"{"email":"bare-metal@example.com"}"#);
    let request = serde_json_core::from_slice::<PreloginRequest<'_>>(input);
    let _ = black_box(request);
    let registration = serde_json_core::from_slice::<RegistrationVerificationRequest<'_>>(input);
    let _ = black_box(registration);
    let authentication = serde_json_core::from_slice::<RegistrationAuthentication<'_>>(black_box(
        br#"{"kdf":{"kdf":0,"kdfIterations":100000},"salt":"bare-metal@example.com","hash":"opaque-proof"}"#,
    ));
    let unlock = serde_json_core::from_slice::<RegistrationUnlock<'_>>(black_box(
        br#"{"kdf":{"kdf":0,"kdfIterations":100000},"salt":"bare-metal@example.com","key":"opaque-wrapped-key"}"#,
    ));
    if let (Ok((authentication, _)), Ok((unlock, _))) = (authentication, unlock) {
        black_box(RegistrationFinishRequest {
            email: "bare-metal@example.com",
            credentials: RegistrationCredentials::Nested {
                authentication,
                unlock,
            },
            email_verification_token: Some(Secret::new("opaque-verification-token")),
            keys: None,
            master_password_hint: None,
        });
    }
    black_box(RegistrationEmail {
        storage_email: "bare-metal@example.com",
        salt_email: "bare-metal@example.com",
    });
    let mut registration_output = [0u8; 128];
    let _ = black_box(serde_json_core::to_slice(
        &RegistrationVerificationToken::new(black_box("opaque-verification-token")),
        &mut registration_output,
    ));
    let _ = black_box(serde_json_core::to_slice(
        &RegistrationFinishResponse,
        &mut registration_output,
    ));
    black_box(registration_output);
    black_box(classify(
        Method::Post,
        black_box("/identity/accounts/register/finish"),
    ));
    black_box(classify(
        Method::Get,
        black_box("/api/sync?excludeDomains=true"),
    ));
    let mut output = [0u8; 256];
    let _ = black_box(serde_json_core::to_slice(
        &PreloginResponse::default(),
        &mut output,
    ));
    black_box(output);
    let cipher = serde_json_core::from_slice::<CipherRequest<'_>>(black_box(
        br#"{"type":1,"data":"opaque sealed blob"}"#,
    ));
    if let Ok((cipher, _)) = cipher {
        let _ = black_box(no_warden::validation::validate_cipher(&cipher));
        let mut encoded = [0u8; 2048];
        let _ = black_box(serde_json_core::to_slice(&cipher, &mut encoded));
        black_box(encoded);
    }
    let import = serde_json_core::from_slice::<ImportRequest<'_, 1, 1, 1>>(black_box(
        br#"{"folders":[{"name":"encrypted folder"}],"ciphers":[{"type":1,"data":"opaque sealed blob","encryptedByKeyId":"opaque:key/id"}],"folderRelationships":[{"key":0,"value":0}]}"#,
    ));
    if let Ok((import, _)) = import {
        black_box(import.folder_count());
        black_box(import.cipher(0));
        let mut encoded = [0u8; 2048];
        let _ = black_box(serde_json_core::to_slice(&import, &mut encoded));
        black_box(encoded);
    }
    let ids = serde_json_core::from_slice::<CipherIdsRequest<'_, 3>>(black_box(
        br#"{"ids":["opaque:One/id","opaque:One/id","opaque:one/id"]}"#,
    ));
    if let Ok((ids, _)) = ids {
        black_box(ids.ids.len());
        let mut encoded = [0u8; 256];
        let _ = black_box(serde_json_core::to_slice(&ids, &mut encoded));
        black_box(encoded);
    }
    let proof = serde_json_core::from_slice::<PasswordOrOtpRequest<'_>>(black_box(
        br#"{"masterPasswordHash":"test-only-authorization-hash"}"#,
    ));
    if let Ok((proof, _)) = proof {
        let _ = black_box(proof.proof());
        let mut provider = PurgeProbe {
            verified: black_box(true),
            account_present: black_box(true),
            personal_items: black_box([true, true]),
            revision: black_box(0),
            send_present: black_box(false),
            send_count: black_box(0),
            send_maximum: None,
            send_kind: 0,
            file_uploaded: false,
            user_key_id: [0; 32],
            user_key_id_len: None,
            organization_present: false,
            organization_name: [0; 64],
            organization_name_len: 0,
            organization_key: [0; 32],
            organization_key_len: 0,
            collection_name: [0; 64],
            collection_name_len: 0,
            organization_keys: false,
            added_collection: false,
            added_collection_name: [0; 64],
            added_collection_name_len: 0,
            added_external: [0; 64],
            added_external_len: None,
            invited: [false; 2],
            confirmed: false,
            confirmed_key: [0; 96],
            confirmed_key_len: 0,
            member_removed: false,
            member_status: 1,
            sharing_associations: 0,
            shared_cipher: false,
            bulk_associations: 0,
            bulk_commits: 0,
        };
        let organization = OrganizationCreateRequest {
            billing_email: "owner@example.com",
            collection_name: "opaque collection",
            key: Secret::new("opaque org key"),
            name: "opaque org",
            keys: None,
            plan_type: OrganizationPlanType::String("ignored"),
        };
        let mut organization_output = [0; 8192];
        let mut organization_service = VaultService::new(&mut provider);
        // The real sharing service retains an association prefix after a later
        // missing selection, then reaches the sealed payload phase on success.
        let share = serde_json_core::from_slice::<CipherShareRequest<'_, 2>>(black_box(
            br#"{"collectionIds":["embedded-share-collection","missing"],"cipher":{"type":2,"organizationId":"embedded-org","encryptedFor":"embedded-owner","name":"2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","notes":"2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","secureNote":{"type":0},"key":null,"lastKnownRevisionDate":"embedded-old-revision"}}"#,
        ));
        if let Ok((request, _)) = share {
            let _ = black_box(organization_service.share_cipher(
                "embedded-owner",
                "embedded-share-source",
                &request.cipher,
                &request,
            ));
            black_box((
                organization_service.storage().sharing_associations,
                organization_service.storage().shared_cipher,
            ));
            let mut stale = request.cipher.clone();
            stale.last_known_revision_date = Some(black_box("embedded-old-revision"));
            let _ = black_box(organization_service.share_cipher(
                "embedded-owner",
                "embedded-share-source",
                &stale,
                ["embedded-share-collection"].as_slice(),
            ));
            black_box((
                organization_service.storage().sharing_associations,
                organization_service.storage().shared_cipher,
            ));
            let mut current = request.cipher.clone();
            current.last_known_revision_date = None;
            let _ = black_box(organization_service.share_cipher(
                "embedded-owner",
                "embedded-share-source",
                &current,
                ["embedded-share-collection"].as_slice(),
            ));
            black_box((
                organization_service.storage().sharing_associations,
                organization_service.storage().shared_cipher,
            ));
        }
        let bulk = serde_json_core::from_slice::<CipherBulkShareRequest<'_, CipherBulkShareItemRequest<'_>, 2, 2>>(black_box(
            br#"{"ciphers":[{"id":"bulk-source","type":2,"name":"","encryptedFor":"ignored wire value","organizationId":"embedded-org"}],"collectionIds":["embedded-share-collection","missing"]}"#,
        ));
        if let Ok((mut request, _)) = bulk {
            // Prefix error retains one association; the next call succeeds with
            // the caller-bounded borrowed DTO through the generic core service.
            let _ = black_box(organization_service.bulk_share_ciphers("embedded-owner", &request));
            black_box((
                organization_service.storage().bulk_associations,
                organization_service.storage().bulk_commits,
            ));
            let mut ids = no_warden::bounded::BoundedList::new();
            let _ = ids.push("embedded-share-collection");
            request.collection_ids = ids;
            let _ = black_box(organization_service.bulk_share_ciphers("embedded-owner", &request));
            black_box((
                organization_service.storage().bulk_associations,
                organization_service.storage().bulk_commits,
            ));
        }
        let readonly = [CipherCollectionAccessRecord {
            cipher_organization_id: Some("embedded-org"),
            collection: CipherSharingCollection {
                id: "embedded-share-collection",
                user_id: "embedded-reader",
                organization_id: "embedded-historical-org",
                assigned: true,
                read_only: true,
                hide_passwords: false,
                manage: true,
            },
        }];
        if let Ok(access) = resolve_cipher_access(
            "embedded-reader",
            CipherOwnership::Organization {
                organization_id: "embedded-org",
            },
            Some(CipherSharingMembership {
                user_id: "embedded-reader",
                organization_id: "embedded-org",
                role: 2,
                status: 2,
                access_all: false,
            }),
            readonly.as_slice(),
        ) {
            black_box((
                access.readable(),
                access.writable(),
                access.view_password(),
                access.delete(),
                access.restore(),
            ));
        }
        let _ = black_box(resolve_bulk_cipher_source_write_access(
            "embedded-reader",
            CipherOwnership::Organization {
                organization_id: "embedded-org",
            },
            Some(CipherSharingMembership {
                user_id: "embedded-reader",
                organization_id: "embedded-org",
                role: 2,
                status: 2,
                access_all: false,
            }),
            readonly.as_slice(),
        ));
        if let Ok(response) =
            organization_service.create_organization("embedded-owner", &organization)
        {
            let _ = black_box(serde_json_core::to_slice(
                &response,
                &mut organization_output,
            ));
        }
        if let Ok(response) =
            organization_service.get_organization("embedded-owner", "embedded-org")
        {
            let _ = black_box(serde_json_core::to_slice(
                &response,
                &mut organization_output,
            ));
        }
        if let Ok(response) = organization_service.list_user_collections("embedded-owner") {
            let _ = black_box(serde_json_core::to_slice(
                &response,
                &mut organization_output,
            ));
            let _ = black_box(serde_json_core::to_slice(
                &response.details(),
                &mut organization_output,
            ));
        }
        if let Ok(response) = organization_service.profile_organizations("embedded-owner") {
            let _ = black_box(serde_json_core::to_slice(
                &response.confirmed(),
                &mut organization_output,
            ));
            let _ = black_box(serde_json_core::to_slice(
                &response.accepted_and_confirmed(),
                &mut organization_output,
            ));
        }
        if let Ok((request, _)) = serde_json_core::from_slice::<OrganizationCollectionCreateRequest<'_, 1, 1>>(black_box(br#"{"name":"opaque collection","groups":[],"users":[{"hidePasswords":false,"id":"embedded-member","readOnly":true,"manage":false}],"externalId":" "}"#)) {
            let _ = black_box(serde_json_core::to_slice(&request, &mut organization_output));
            if let Ok(response) = organization_service.create_org_collection("embedded-owner", "embedded-org", &request) {
                let _ = black_box(serde_json_core::to_slice(&response, &mut organization_output));
            }
            if let Ok(response) = organization_service.list_org_collections("embedded-owner", "embedded-org") {
                let _ = black_box(serde_json_core::to_slice(&response, &mut organization_output));
            }
            if let Ok(response) = organization_service.get_org_collection_details("embedded-owner", "embedded-org", "embedded-added-collection") {
                let _ = black_box(serde_json_core::to_slice(&response, &mut organization_output));
            }
        }
        if let Ok((mut update, _)) =
            serde_json_core::from_slice::<OrganizationCollectionCreateRequest<'_, 1, 1>>(black_box(
                br#"["renamed opaque collection",[],[],null]"#,
            ))
        {
            update.external_id = Some("\u{2003}\u{a0} ");
            if let Ok(response) = organization_service.update_org_collection(
                "embedded-owner",
                "embedded-org",
                "embedded-added-collection",
                &update,
            ) {
                let _ = black_box(serde_json_core::to_slice(
                    &response,
                    &mut organization_output,
                ));
            }
            let _ = black_box(organization_service.delete_org_collection(
                "embedded-owner",
                "embedded-org",
                "embedded-added-collection",
            ));
        }
        if let Ok(grant) =
            organization_service.authorize_org_cipher_list("embedded-owner", "embedded-org")
        {
            black_box(grant.len());
            black_box(grant.get(0));
        }
        if let Ok(response) =
            organization_service.list_org_collection_details("embedded-owner", "embedded-org")
        {
            let _ = black_box(serde_json_core::to_slice(
                &response,
                &mut organization_output,
            ));
        }
        if let Ok(response) =
            organization_service.list_empty_org_groups("embedded-owner", "embedded-org")
        {
            let _ = black_box(serde_json_core::to_slice(
                &response,
                &mut organization_output,
            ));
        }
        for uri in [
            "/api/ciphers/organization-details?organizationId=embedded-org",
            "/api/organizations/embedded-org/collections/details",
            "/api/organizations/embedded-org/groups",
        ] {
            black_box(classify(Method::Get, uri));
        }
        // The mini view has its own provider/serializer and never traverses ACLs.
        if let Ok(response) =
            organization_service.list_org_member_mini_details("embedded-owner", "embedded-org")
        {
            let _ = black_box(serde_json_core::to_slice(
                &response,
                &mut organization_output,
            ));
        }
        black_box(classify(
            Method::Get,
            "/api/organizations/embedded-org/users/mini-details",
        ));
        for query in [
            OrganizationMemberQuery::default(),
            OrganizationMemberQuery {
                include_groups: true,
                include_collections: true,
            },
        ] {
            if let Ok(response) =
                organization_service.list_org_members("embedded-owner", "embedded-org", &query)
            {
                let _ = black_box(serde_json_core::to_slice(
                    &response,
                    &mut organization_output,
                ));
            }
        }
        for query in [
            OrganizationMemberDetailQuery::default(),
            OrganizationMemberDetailQuery {
                include_groups: Some(true),
                include_collections: None,
            },
            OrganizationMemberDetailQuery {
                include_groups: Some(true),
                include_collections: Some(false),
            },
        ] {
            if let Ok(response) = organization_service.get_org_member(
                "embedded-owner",
                "embedded-org",
                "embedded-guest-member",
                &query,
            ) {
                let _ = black_box(serde_json_core::to_slice(
                    &response,
                    &mut organization_output,
                ));
            }
        }
        black_box(classify(
            Method::Get,
            "/api/organizations/embedded-org/users/embedded-guest-member?includeGroups=true",
        ));
        let selected = serde_json_core::from_slice::<OrganizationInviteCollection<'_>>(black_box(
            br#"{"id":"embedded-collection","readOnly":true,"hidePasswords":false,"manage":false}"#,
        ));
        if let Ok((selected, _)) = selected {
            let mut emails = no_warden::bounded::BoundedList::<_, 2>::new();
            let _ = emails.push(black_box("existing@example.com"));
            let _ = emails.push(black_box("new@example.com"));
            let mut collections = no_warden::bounded::BoundedList::<_, 1>::new();
            let _ = collections.push(selected);
            let request = OrganizationInviteRequest {
                emails,
                groups: no_warden::bounded::BoundedList::<&str, 0>::new(),
                role: OrganizationPlanType::String("User"),
                collections: Some(collections),
                permissions: OrganizationInvitePermissions::default(),
            };
            let _ = black_box(serde_json_core::to_slice(
                &selected,
                &mut organization_output,
            ));
            let _ = black_box(organization_service.invite_org_members(
                "embedded-owner",
                "embedded-org",
                &request,
            ));
            if let Err(error) =
                organization_service.invite_org_members("embedded-owner", "embedded-org", &request)
            {
                let mut output = InvitationMessageBuffer {
                    bytes: [0; 192],
                    len: 0,
                };
                let _ = black_box(error.write_message(&mut output, error.email()));
                black_box((
                    error.cause(),
                    error.completed(),
                    error.index(),
                    output.bytes,
                ));
            }
        }
        black_box(classify(
            Method::Post,
            "/api/organizations/embedded-org/users/invite",
        ));
        // The adapter/caller chooses both decoder and output capacities. This real
        // service call preserves order, commits one target, then reports its duplicate.
        let bulk = serde_json_core::from_slice::<OrganizationBulkConfirmRequest<'_, 3>>(black_box(
            br#"{"keys":[{"id":"","key":"ignored"},{"id":"embedded-invited-member","key":"opaque-bulk-key"},{"id":"embedded-invited-member","key":"repeat"}]}"#,
        ));
        if let Ok((request, _)) = bulk {
            let mut slots = [None; 3];
            match organization_service.bulk_confirm_org_members(
                "embedded-owner",
                "embedded-org",
                &request,
                &mut slots,
            ) {
                Ok(response) => {
                    let _ = black_box(serde_json_core::to_slice(
                        &response,
                        &mut organization_output,
                    ));
                    black_box((
                        response.len(),
                        response.get(0).and_then(|row| row.error()),
                        response.get(1).map(|row| row.id()),
                    ));
                }
                Err(error) => {
                    black_box((error.cause(), error.processed(), error.index()));
                }
            }
        }
        // A missing item ID aborts after the processed prefix, without serializing
        // a partial response. No borrowed key is retained in output scratch.
        let bulk = serde_json_core::from_slice::<OrganizationBulkConfirmRequest<'_, 2>>(black_box(
            br#"{"keys":[{"id":"","key":null},{"key":"missing-id"}]}"#,
        ));
        if let Ok((request, _)) = bulk {
            let mut slots = [None; 2];
            if let Err(error) = organization_service.bulk_confirm_org_members(
                "embedded-owner",
                "embedded-org",
                &request,
                &mut slots,
            ) {
                black_box((error.cause(), error.processed(), error.index()));
            }
        }
        black_box(classify(
            Method::Post,
            "/api/organizations/embedded-org/users/confirm",
        ));
        let confirmation = serde_json_core::from_slice::<OrganizationConfirmRequest<'_>>(
            black_box(br#"{"id":"ignored-body-id","key":"opaque-wrapped-org-key"}"#),
        );
        if let Ok((request, _)) = confirmation {
            let _ = black_box(organization_service.confirm_org_member(
                "embedded-owner",
                "embedded-org",
                "embedded-invited-member",
                &request,
            ));
            let _ = black_box(organization_service.confirm_org_member(
                "embedded-owner",
                "embedded-org",
                "embedded-invited-member",
                &request,
            ));
            let state = organization_service.storage_mut();
            black_box((
                state.confirmed,
                state.confirmed_key_len,
                state.confirmed_key,
            ));
        }
        black_box(classify(
            Method::Post,
            "/api/organizations/embedded-org/users/embedded-invited-member/confirm",
        ));
        // Owned provider snapshots, ordered duplicates and the explicit nullable
        // projection all compile and link without a global allocator.
        let public_keys =
            serde_json_core::from_slice::<OrganizationMemberPublicKeysRequest<'_, 3>>(black_box(
                br#"{"ids":["missing","embedded-invited-member","embedded-invited-member"]}"#,
            ));
        if let Ok((request, _)) = public_keys {
            let mut snapshots = core::array::from_fn::<_, 3, _>(|_| None);
            if let Ok(response) = organization_service.get_org_member_public_keys(
                "embedded-owner",
                "embedded-org",
                &request,
                &mut snapshots,
            ) {
                let _ = black_box(serde_json_core::to_slice(
                    &response,
                    &mut organization_output,
                ));
                black_box((
                    response.len(),
                    response.get(1).map(|row| row.public_key().map(str::len)),
                ));
            }
        }
        black_box(classify(
            Method::Post,
            "/api/organizations/embedded-org/users/public-keys",
        ));
        // Status-only operations keep the existing opaque wrapped key and personal
        // authority in stack-owned storage while revoking/restoring the same member.
        let _ = black_box(organization_service.revoke_org_member(
            "embedded-owner",
            "embedded-org",
            "embedded-invited-member",
        ));
        let _ = black_box(organization_service.restore_org_member(
            "embedded-owner",
            "embedded-org",
            "embedded-invited-member",
        ));
        // Both bulk status DTOs and streamed ordered results are used by this
        // bare-metal link probe, with no allocator supplied by the adapter.
        let revoke = serde_json_core::from_slice::<OrganizationBulkMemberRevokeRequest<'_, 3>>(
            black_box(br#"{"ids":["bad.id","embedded-invited-member","embedded-invited-member"]}"#),
        );
        if let Ok((request, _)) = revoke {
            let mut slots = [None; 3];
            if let Ok(response) = organization_service.bulk_revoke_org_members(
                "embedded-owner",
                "embedded-org",
                &request,
                &mut slots,
            ) {
                let _ = black_box(serde_json_core::to_slice(
                    &response,
                    &mut organization_output,
                ));
                black_box((response.len(), response.get(2).and_then(|row| row.error())));
            }
        }
        let restore = serde_json_core::from_slice::<OrganizationBulkMemberRestoreRequest<'_, 2>>(
            black_box(br#"{"ids":["embedded-invited-member","embedded-invited-member"]}"#),
        );
        if let Ok((request, _)) = restore {
            let mut slots = [None; 2];
            if let Ok(response) = organization_service.bulk_restore_org_members(
                "embedded-owner",
                "embedded-org",
                &request,
                &mut slots,
            ) {
                let _ = black_box(serde_json_core::to_slice(
                    &response,
                    &mut organization_output,
                ));
                black_box((response.is_empty(), response.get(0).map(|row| row.id())));
            }
        }
        for path in [
            "/api/organizations/embedded-org/users/revoke",
            "/api/organizations/embedded-org/users/restore",
        ] {
            black_box(classify(Method::Put, path));
        }
        let state = organization_service.storage_mut();
        black_box((
            state.member_status,
            state.confirmed_key_len,
            state.account_present,
            state.personal_items,
        ));
        for suffix in [
            "/api/organizations/embedded-org/users/embedded-invited-member/revoke",
            "/api/organizations/embedded-org/users/embedded-invited-member/restore",
            "/api/organizations/embedded-org/users/embedded-invited-member/restore/vnext",
        ] {
            black_box(classify(Method::Put, suffix));
        }
        // Caller-bounded decoding and output storage exercise the real bulk service:
        // an opaque missing ID, successful recipient removal and duplicate row error.
        let bulk_removal = serde_json_core::from_slice::<OrganizationBulkMemberRemovalRequest<'_, 3>>(
            black_box(br#"{"ids":["bad.id","embedded-invited-member","embedded-invited-member"]}"#),
        );
        if let Ok((request, _)) = bulk_removal {
            let mut slots = [None; 3];
            if let Ok(response) = organization_service.bulk_remove_org_members(
                "embedded-owner",
                "embedded-org",
                &request,
                &mut slots,
            ) {
                let _ = black_box(serde_json_core::to_slice(
                    &response,
                    &mut organization_output,
                ));
                black_box((
                    response.len(),
                    response.get(1).map(|row| row.id()),
                    response.get(2).and_then(|row| row.error()),
                ));
            }
        }
        black_box(classify(
            Method::Delete,
            "/api/organizations/embedded-org/users",
        ));
        // Single-member removal uses the same stack-owned provider. Personal
        // account and vault state survive; only the selected membership is removed.
        let _ = black_box(organization_service.remove_org_member(
            "embedded-owner",
            "embedded-org",
            "embedded-invited-member",
        ));
        let _ = black_box(organization_service.remove_org_member(
            "embedded-owner",
            "embedded-org",
            "embedded-invited-member",
        ));
        let state = organization_service.storage_mut();
        black_box((
            state.member_removed,
            state.account_present,
            state.personal_items,
            state.invited,
            state.revision,
        ));
        black_box(classify(
            Method::Delete,
            "/api/organizations/embedded-org/users/embedded-invited-member",
        ));
        black_box(organization_output);
        for email in black_box(["bare-metal@example.com", ""]) {
            let mut discovery = VaultService::new(&mut provider);
            if let Ok(response) = discovery.prelogin(&PreloginRequest { email }) {
                let mut encoded = [0; 384];
                let _ = black_box(serde_json_core::to_slice(&response, &mut encoded));
                black_box((response.settings(), encoded));
            }
        }
        let user_key_id = serde_json_core::from_slice::<UserKeyIdRequest<'_>>(black_box(
            br#"{"userKeyId":"opaque-id"}"#,
        ));
        if let Ok((request, _)) = user_key_id {
            let mut output = [0; 64];
            black_box(serde_json_core::to_slice(&request, &mut output)).ok();
            black_box(output);
            let mut migration = VaultService::new(&mut provider);
            black_box(migration.set_user_key_id("embedded-owner", &request)).ok();
            let _ = black_box(migration.storage_mut().user_key_id("embedded-owner"));
            let _ = black_box(migration.set_user_key_id("embedded-owner", &request));
        }
        let payload = black_box("opaque-text");
        let send = TextSendRequest {
            kind: 0,
            key: "opaque-key",
            password: None,
            max_access_count: Some(SendNumber::String("1")),
            expiration_ns: None,
            deletion_ns: 1000,
            disabled: false,
            hide_email: None,
            emails: None,
            name: "opaque-name",
            notes: None,
            text: Some(&payload),
        };
        let context = SendContext {
            now_unix_nanos: black_box(0),
        };
        let mut send_output = [0; 2048];
        let mut service = VaultService::new(&mut provider);
        if let Ok(response) = service.create_text_send("embedded-owner", &send, &context) {
            let _ = black_box(serde_json_core::to_slice(&response, &mut send_output));
        }
        let access = serde_json_core::from_slice::<SendAccessTokenRequest<'_>>(black_box(
            br#"{"grant_type":"send_access","client_id":"","send_id":"embedded-access"}"#,
        ));
        if let Ok((access, _)) = access {
            let _ = black_box(service.authenticate_send_access(&access, &context));
        }
        if let Ok(response) = service.access_text_send(
            &Secret::new(black_box("external-recipient-proof")),
            &context,
        ) {
            let _ = black_box(serde_json_core::to_slice(&response, &mut send_output));
        }
        let _ = black_box(service.access_text_send(
            &Secret::new(black_box("external-recipient-proof")),
            &context,
        ));
        if let Ok(response) = service.list_sends("embedded-owner") {
            let _ = black_box(serde_json_core::to_slice(&response, &mut send_output));
        }
        let file = serde_json_core::from_slice::<SendFileData<'_>>(black_box(
            br#"{"fileName":"opaque-file"}"#,
        ));
        if let Ok((file, _)) = file {
            let request = FileSendRequest {
                common: TextSendRequest {
                    kind: 1,
                    key: "opaque-key",
                    password: None,
                    max_access_count: Some(SendNumber::Integer(1)),
                    expiration_ns: None,
                    deletion_ns: 1000,
                    disabled: false,
                    hide_email: None,
                    emails: None,
                    name: "opaque-name",
                    notes: None,
                    text: None,
                },
                file: Some(&file),
                file_length: Some(SendNumber::Integer(4)),
            };
            if let Ok(response) = service.reserve_file_send("embedded-owner", &request, &context) {
                let _ = black_box(serde_json_core::to_slice(&response, &mut send_output));
            }
            let _ = black_box(service.upload_send_file(
                "embedded-owner",
                "embedded-send",
                "embedded-file",
                &SendFileUpload {
                    file_name: Some("opaque-file"),
                    file_size: 4,
                    allow_legacy_filename_suffix: false,
                },
            ));
            if let Ok(response) =
                service.access_send(&Secret::new("external-recipient-proof"), &context)
            {
                let _ = black_box(serde_json_core::to_slice(&response, &mut send_output));
            }
            if let Ok(response) = service.access_send_file(
                &Secret::new("external-recipient-proof"),
                "embedded-file",
                &context,
            ) {
                let _ = black_box(serde_json_core::to_slice(&response, &mut send_output));
            }
            let _ = black_box(service.authorize_send_file_download(
                "embedded-send",
                "embedded-file",
                &Secret::new("external-file-proof"),
            ));
            if let Ok(response) =
                service.update_file_send("embedded-owner", "embedded-send", &request, &context)
            {
                let _ = black_box(serde_json_core::to_slice(&response, &mut send_output));
            }
            if let Ok(response) = service.list_sends("embedded-owner") {
                let _ = black_box(serde_json_core::to_slice(&response, &mut send_output));
            }
        }
        black_box(send_output);
        let password_login = serde_json_core::from_slice::<PasswordLoginRequest<'_>>(black_box(
            br#"{"grant_type":"password","client_id":"cli","password":"test-only-proof","scope":"api offline_access","username":" bare-metal@example.com ","deviceIdentifier":"","deviceName":"","deviceType":""}"#,
        ));
        let grant = password_login.ok().and_then(|(request, _)| {
            VaultService::new(&mut provider)
                .authenticate_password(&request)
                .ok()
        });
        if let Some(grant) = grant {
            black_box((
                grant.user_id(),
                grant.client_id(),
                grant.device(),
                grant.scope(),
                grant.expires_in(),
                grant.allows_refresh(),
            ));
        }
        let refresh = serde_json_core::from_slice::<RefreshTokenRequest<'_>>(black_box(
            br#"{"grant_type":"refresh_token","refresh_token":"test-only-refresh-proof","client_id":""}"#,
        ));
        if let Ok((refresh, _)) = refresh {
            for _ in 0..2 {
                let grant = VaultService::new(&mut provider).authenticate_refresh(&refresh);
                if let Ok(grant) = grant {
                    black_box((
                        grant.user_id(),
                        grant.device_identifier(),
                        grant.client_id(),
                        grant.scope(),
                        grant.expires_in(),
                        grant.allows_refresh(),
                    ));
                }
            }
        }
        if let Ok(grant) = VaultService::new(&mut provider)
            .authorize_cipher_read(black_box("embedded-owner"), black_box("embedded-cipher"))
        {
            black_box((grant.owner(), grant.id()));
        }
        let _ = black_box(
            VaultService::new(&mut provider)
                .purge_personal_vault(black_box("embedded-owner"), &proof),
        );
        let _ = black_box(
            VaultService::new(&mut provider).delete_account(black_box("embedded-owner"), &proof),
        );
        black_box((
            provider.personal_items,
            provider.revision,
            provider.account_present,
        ));
    }
    black_box(classify(Method::Post, black_box("/api/ciphers/purge")));
    black_box(classify(Method::Post, black_box("/api/sends/file/v2")));
    black_box(classify(
        Method::Post,
        black_box("/api/sends/send/file/file-id"),
    ));
    black_box(classify(
        Method::Post,
        black_box("/api/sends/access/file/file-id"),
    ));
    black_box(classify(
        Method::Get,
        black_box("/api/sends/send/file-id?t=opaque"),
    ));
    black_box(classify(Method::Delete, black_box("/api/accounts")));
    black_box(classify(Method::Post, black_box("/api/accounts/delete")));
    black_box(classify(
        Method::Get,
        black_box("/api/ciphers/embedded-cipher/details"),
    ));
    black_box(classify(
        Method::Get,
        black_box("/api/ciphers/embedded-cipher/admin"),
    ));
    let verification = serde_json_core::from_slice::<SecretVerificationRequest<'_>>(black_box(
        br#"{"masterPasswordHash":"test-only-authorization-hash"}"#,
    ));
    let _ = black_box(verification);
    let mut policy_output = [0_u8; 512];
    for policy in [
        None,
        Some(MasterPasswordPolicy {
            min_complexity: Some(3),
            min_length: Some(12),
            require_lower: true,
            require_upper: true,
            require_numbers: true,
            require_special: false,
            enforce_on_login: true,
        }),
    ] {
        let _ = black_box(serde_json_core::to_slice(
            &MasterPasswordPolicyResponse { policy },
            &mut policy_output,
        ));
    }
    black_box(policy_output);
    black_box(classify(
        Method::Post,
        black_box("/api/accounts/security-stamp"),
    ));
    let kdf = serde_json_core::from_slice::<AccountKdfRequest<'_>>(black_box(
        br#"{"authenticationData":{"salt":"bare-metal@example.com","kdf":{"kdf":0,"kdfIterations":700000},"masterPasswordAuthenticationHash":"new-opaque-proof"},"unlockData":{"salt":"bare-metal@example.com","kdf":{"kdf":0,"kdfIterations":700000},"masterKeyWrappedUserKey":"opaque-rewrapped-key"},"masterPasswordHash":"old-opaque-proof"}"#,
    ));
    let _ = black_box(kdf);
    black_box(classify(Method::Post, black_box("/api/accounts/kdf")));
    let password = serde_json_core::from_slice::<AccountPasswordRequest<'_>>(black_box(
        br#"{"masterPasswordHash":"old-opaque-proof","newMasterPasswordHash":"new-opaque-proof","key":"opaque-rewrapped-key"}"#,
    ));
    let _ = black_box(password);
    black_box(classify(Method::Post, black_box("/api/accounts/password")));
    let policy = no_warden::account_password::PasswordChangeStampPolicy;
    black_box(policy.expires_at(black_box(1_800_000_000)));
    black_box(policy.authorize_previous_stamp(
        black_box(1_800_000_120),
        black_box(1_800_000_120),
        black_box("get_public_keys"),
        black_box(true),
    ));
    let credentials = serde_json_core::from_slice::<ClientCredentialsRequest<'_>>(black_box(
        br#"{"grant_type":"client_credentials","client_id":"user.opaque:ID","client_secret":"test-only-key","scope":"api","deviceIdentifier":"device","deviceName":"bare metal","deviceType":"iOS"}"#,
    ));
    let _ = black_box(credentials);
    let mut encoded = [0u8; 256];
    let _ = black_box(serde_json_core::to_slice(
        &ApiKeyResponse {
            api_key: Secret::new(black_box("test-only-key")),
            revision_date: "2026-01-01T00:00:00Z",
        },
        &mut encoded,
    ));
    black_box(encoded);
    // This decoder lacks deserialize_any for the numeric-or-string size union.
    // Hosts can construct the borrowed request; encoding and core rules remain no_alloc.
    let attachment = AttachmentRequest {
        key: "opaque-wrapped-key",
        file_name: "opaque-filename",
        file_size: 17,
        admin_request: None,
    };
    let mut attachment_output = [0u8; 1024];
    let _ = black_box(serde_json_core::to_slice(
        &attachment,
        &mut attachment_output,
    ));
    let response = AttachmentResponse {
        id: "attachment",
        url: Secret::new("scoped-download-url"),
        file_name: "opaque-filename",
        size: "17",
        size_name: "17 B",
        key: Some("opaque-wrapped-key"),
    };
    let _ = black_box(serde_json_core::to_slice(&response, &mut attachment_output));
    let upload = AttachmentUploadResponse::direct(
        "attachment",
        Secret::new("relative-upload-url"),
        0_u8,
        false,
    );
    let _ = black_box(serde_json_core::to_slice(&upload, &mut attachment_output));
    black_box(attachment_output);
    let pair = serde_json_core::from_slice::<AccountKeys<'_>>(black_box(
        br#"{"encryptedPrivateKey":"opaque-private-key","publicKey":"opaque-public-key"}"#,
    ));
    if let Ok((pair, _)) = pair {
        let mut key_output = [0u8; 1024];
        let own_keys = AccountKeysResponse {
            key: Some(Secret::new("opaque-symmetric-key")),
            public_key: pair.public_key,
            private_key: Secret::new(pair.encrypted_private_key),
        };
        let _ = black_box(serde_json_core::to_slice(&own_keys, &mut key_output));
        let initialized = InitializedAccountKeysResponse {
            public_key: pair.public_key,
            private_key: Secret::new(pair.encrypted_private_key),
        };
        let _ = black_box(serde_json_core::to_slice(&initialized, &mut key_output));
        let public_key = UserPublicKeyResponse {
            user_id: "requested-user",
            public_key: pair.public_key,
        };
        let _ = black_box(serde_json_core::to_slice(&public_key, &mut key_output));
        black_box(key_output);
    }
    let mut credential_output = [0_u8; 64];
    let _ = black_box(serde_json_core::to_slice(
        &WebAuthnCredentialsResponse,
        &mut credential_output,
    ));
    black_box(credential_output);
    black_box(classify(
        Method::Get,
        black_box("/api/webauthn/?ignored=true"),
    ));
    let profile = serde_json_core::from_slice::<ProfileUpdateRequest<'_>>(black_box(
        br#"{"name":"bare-metal profile"}"#,
    ));
    if let Ok((profile, _)) = profile {
        let mut output = [0u8; 128];
        let _ = black_box(serde_json_core::to_slice(&profile, &mut output));
        black_box(output);
    }
    let avatar = serde_json_core::from_slice::<AvatarUpdateRequest<'_>>(black_box(
        br##"{"avatarColor":"#abc123"}"##,
    ));
    if let Ok((avatar, _)) = avatar {
        let mut output = [0u8; 128];
        let _ = black_box(serde_json_core::to_slice(&avatar, &mut output));
        black_box(output);
    }
    let domains = serde_json_core::from_slice::<DomainSettingsRequest<'_, 2, 2, 2>>(black_box(
        br#"{"excludedGlobalEquivalentDomains":[1],"equivalentDomains":[["example.test","example.org"]]}"#,
    ));
    if let Ok((domains, _)) = domains {
        let mut output = [0u8; 256];
        let _ = black_box(serde_json_core::to_slice(&domains, &mut output));
        black_box(output);
    }
    let groups: &[&[&str]] = &[&["embedded.test", "embedded.example"]];
    let catalog = [
        GlobalDomain {
            kind: 1,
            domains: &["example.org"],
        },
        GlobalDomain {
            kind: 2,
            domains: &["example.net"],
        },
    ];
    for projection in [DomainProjection::All, DomainProjection::Sync] {
        let settings = DomainSettingsView {
            excluded_globals: black_box(&[1]),
            equivalent_domains: black_box(groups),
        };
        let response = DomainSettingsResponse::new(settings, black_box(&catalog[..]), projection);
        let mut output = [0u8; 512];
        let _ = black_box(serde_json_core::to_slice(&response, &mut output));
        black_box(output);
    }
    let mut output = [0u8; 8];
    let _ = black_box(serde_json_core::to_slice(
        &DomainSettingsUpdateResponse {},
        &mut output,
    ));
    black_box(output);
    let auth = serde_json_core::from_slice::<AuthRequestCreateRequest<'_>>(black_box(
        br#"{"accessCode":"caller-supplied-test-code","deviceIdentifier":"embedded-device","email":"bare-metal@example.com","publicKey":"caller-supplied-public-key"}"#,
    ));
    let mut auth_output = [0_u8; 2048];
    if let Ok((auth, _)) = auth {
        let _ = black_box(serde_json_core::to_slice(&auth, &mut auth_output));
    }
    let approval = serde_json_core::from_slice::<AuthRequestUpdateRequest<'_>>(black_box(
        br#"{"deviceIdentifier":"embedded-response-device","key":"opaque-wrapped-key","masterPasswordHash":null,"requestApproved":true}"#,
    ));
    if let Ok((approval, _)) = approval {
        let _ = black_box(serde_json_core::to_slice(&approval, &mut auth_output));
    }
    let poll_code = Secret::new(black_box("caller-supplied-test-code"));
    black_box(poll_code.expose_secret());
    black_box(classify(
        Method::Put,
        black_box("/api/auth-requests/request-id"),
    ));
    black_box(classify(
        Method::Get,
        black_box("/api/auth-requests/request-id/response?code=caller-supplied-test-code"),
    ));
    let request_login = serde_json_core::from_slice::<AuthRequestLoginRequest<'_>>(black_box(
        br#"{"grant_type":"password","username":"bare-metal@example.com","password":"caller-supplied-test-code","authRequest":"authentication-request","scope":"api offline_access","client_id":"embedded","deviceIdentifier":"new-device","deviceName":"caller-name","deviceType":"25"}"#,
    ));
    let _ = black_box(request_login);
    black_box(AuthRequestLoginContext {
        request_ip: "127.0.0.1",
        now_unix_nanos: 1_800_000_000_000_000_000,
    });
    black_box(AuthRequestLoginRecord {
        id: "authentication-request",
        owner_id: "private-owner",
        request_ip: "127.0.0.1",
        approved: Some(true),
        used: false,
        created_at_unix_nanos: 1_800_000_000_000_000_000,
        account_enabled: true,
    });
    black_box(AuthRequestLoginDevice {
        identifier: "new-device",
        name: "caller-name",
        device_type: "25",
    });
    let auth_context = AuthRequestContext {
        device_type: 25,
        request_ip: "127.0.0.1",
        origin: "https://example.test",
    };
    black_box(auth_context);
    let auth_record = AuthRequestRecord {
        id: "authentication-request",
        owner_id: "private-owner",
        request_device_identifier: "embedded-device",
        device_type: 25,
        request_ip: "127.0.0.1",
        access_code: "caller-supplied-test-code",
        public_key: "caller-supplied-public-key",
        key: None,
        master_password_hash: None,
        approved: None,
        creation_date: "2026-01-01T00:00:00Z",
        response_date: None,
    };
    for state in [
        AuthRequestRecord {
            key: Some("opaque-wrapped-key"),
            master_password_hash: Some("opaque-master-password-hash"),
            approved: Some(true),
            response_date: Some("2026-01-01T00:01:00Z"),
            ..auth_record
        },
        AuthRequestRecord {
            response_date: Some("2026-01-01T00:01:00Z"),
            ..auth_record
        },
    ] {
        let _ = black_box(serde_json_core::to_slice(
            &AuthRequestResponse::stored(black_box(state), auth_context.origin),
            &mut auth_output,
        ));
    }
    let _ = black_box(serde_json_core::to_slice(
        &AuthRequestResponse::created(black_box(auth_record), auth_context.origin),
        &mut auth_output,
    ));
    let _ = black_box(serde_json_core::to_slice(
        &AuthRequestResponse::stored(black_box(auth_record), auth_context.origin),
        &mut auth_output,
    ));
    let auth_records = [
        auth_record,
        AuthRequestRecord {
            approved: Some(true),
            ..auth_record
        },
    ];
    let _ = black_box(serde_json_core::to_slice(
        &AuthRequestListResponse::new(black_box(&auth_records[..]), auth_context.origin),
        &mut auth_output,
    ));
    black_box(auth_output);
    black_box(classify(
        Method::Get,
        black_box("/api/auth-requests/pending"),
    ));
    let push = serde_json_core::from_slice::<DevicePushTokenRequest<'_>>(black_box(
        br#"{"pushToken":"caller-supplied-test-value"}"#,
    ));
    if let Ok((push, _)) = push {
        let mut encoded = [0_u8; 256];
        let _ = black_box(serde_json_core::to_slice(&push, &mut encoded));
        black_box(encoded);
    }
    black_box(classify(
        Method::Put,
        black_box("/api/devices/identifier/device/token"),
    ));
    black_box(KnownDeviceRequest {
        email: "embedded@example.test",
        identifier: "embedded-device",
    });
    let mut known_output = [0u8; 8];
    let _ = black_box(serde_json_core::to_slice(
        &KnownDeviceResponse(true),
        &mut known_output,
    ));
    black_box(known_output);
    let device = DeviceRecord {
        owner_id: "embedded-owner",
        identifier: "embedded-device",
        name: "embedded client",
        device_type: 8,
        creation_date: "2026-10-18T00:00:00.000000Z",
        pending_auth_request: Some(PendingDeviceAuthRequest {
            id: "pending-request",
            creation_date: "2026-10-18T00:00:00.000000Z",
        }),
    };
    let mut device_output = [0u8; 1024];
    let _ = black_box(serde_json_core::to_slice(
        &DeviceResponse::new(black_box(device)),
        &mut device_output,
    ));
    black_box(device_output);
    let records = [device];
    let response = DeviceListResponse::new(black_box(&records[..]));
    let mut list_output = [0u8; 1024];
    let _ = black_box(serde_json_core::to_slice(&response, &mut list_output));
    black_box(list_output);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
