use std::{ffi::OsStr, fmt::Display};

#[derive(Clone, Copy, PartialEq)]
enum Suite {
    All,
    Personal,
    Folders,
    AccountKeys,
    Profile,
    Domains,
    Devices,
    DeviceTokens,
    AuthRequests,
    AuthResponses,
    AuthLogin,
    Registration,
    AccountSecurity,
    AccountKdf,
    AccountKdfCli,
    AccountPassword,
    AccountPasswordCli,
    WebauthnCredentials,
    PersonalVaultPurge,
    AccountDeletion,
    CipherReads,
    PasswordGrants,
    RefreshGrants,
    TextSends,
    TextSendsCli,
    FileSends,
    FileSendsCli,
    UserKeyId,
    UserKeyIdCli,
    Prelogin,
    PreloginCli,
    OrganizationOwner,
    OrganizationOwnerCli,
    OrganizationCipherCollections,
    OrganizationCipherCollectionsCli,
    OrganizationCipherPartial,
    OrganizationCipherPartialCli,
    OrganizationCipherBulkSharing,
    OrganizationCipherBulkSharingCli,
    OrganizationCipherSharing,
    OrganizationWebReads,
    OrganizationWebReadsCli,
    OrganizationCipherSharingCli,
    OrganizationCollections,
    OrganizationCollectionsCli,
    OrganizationCollectionMutations,
    OrganizationCollectionMutationsCli,
    OrganizationBulkMemberRemoval,
    OrganizationBulkMemberRemovalCli,
    OrganizationMemberRemoval,
    OrganizationMemberRemovalCli,
    OrganizationBulkMemberStatus,
    OrganizationBulkMemberStatusCli,
    OrganizationMemberStatus,
    OrganizationMemberStatusCli,
    OrganizationMemberPublicKeys,
    OrganizationMemberPublicKeysCli,
    OrganizationMemberMiniDetails,
    OrganizationMemberMiniDetailsCli,
    OrganizationMembers,
    OrganizationMembersCli,
    OrganizationBulkConfirmations,
    OrganizationBulkConfirmationsCli,
    OrganizationConfirmations,
    OrganizationConfirmationsCli,
    OrganizationInvites,
    OrganizationInvitesCli,
}

impl Suite {
    fn parse(value: &OsStr) -> Option<Self> {
        Some(match value.to_str()? {
            "all" => Self::All,
            "personal" => Self::Personal,
            "folders" => Self::Folders,
            "account-keys" => Self::AccountKeys,
            "profile" => Self::Profile,
            "domains" => Self::Domains,
            "devices" => Self::Devices,
            "device-tokens" => Self::DeviceTokens,
            "auth-requests" => Self::AuthRequests,
            "auth-responses" => Self::AuthResponses,
            "auth-login" => Self::AuthLogin,
            "registration" => Self::Registration,
            "account-security" => Self::AccountSecurity,
            "account-kdf" => Self::AccountKdf,
            "account-kdf-cli" => Self::AccountKdfCli,
            "account-password" => Self::AccountPassword,
            "account-password-cli" => Self::AccountPasswordCli,
            "webauthn-credentials" => Self::WebauthnCredentials,
            "personal-vault-purge" => Self::PersonalVaultPurge,
            "account-deletion" => Self::AccountDeletion,
            "cipher-reads" => Self::CipherReads,
            "password-grants" => Self::PasswordGrants,
            "refresh-grants" => Self::RefreshGrants,
            "text-sends" => Self::TextSends,
            "text-sends-cli" => Self::TextSendsCli,
            "file-sends" => Self::FileSends,
            "file-sends-cli" => Self::FileSendsCli,
            "user-key-id" => Self::UserKeyId,
            "user-key-id-cli" => Self::UserKeyIdCli,
            "prelogin" => Self::Prelogin,
            "prelogin-cli" => Self::PreloginCli,
            "organization-owner" => Self::OrganizationOwner,
            "organization-owner-cli" => Self::OrganizationOwnerCli,
            "organization-cipher-collections" => Self::OrganizationCipherCollections,
            "organization-cipher-collections-cli" => Self::OrganizationCipherCollectionsCli,
            "organization-cipher-partial" => Self::OrganizationCipherPartial,
            "organization-cipher-partial-cli" => Self::OrganizationCipherPartialCli,
            "organization-cipher-bulk-sharing" => Self::OrganizationCipherBulkSharing,
            "organization-cipher-bulk-sharing-cli" => Self::OrganizationCipherBulkSharingCli,
            "organization-cipher-sharing" => Self::OrganizationCipherSharing,
            "web-organization-reads" => Self::OrganizationWebReads,
            "web-organization-reads-cli" => Self::OrganizationWebReadsCli,
            "organization-cipher-sharing-cli" => Self::OrganizationCipherSharingCli,
            "organization-collections" => Self::OrganizationCollections,
            "organization-collections-cli" => Self::OrganizationCollectionsCli,
            "organization-collection-mutations" => Self::OrganizationCollectionMutations,
            "organization-collection-mutations-cli" => Self::OrganizationCollectionMutationsCli,
            "organization-bulk-member-removal" => Self::OrganizationBulkMemberRemoval,
            "organization-bulk-member-removal-cli" => Self::OrganizationBulkMemberRemovalCli,
            "organization-member-removal" => Self::OrganizationMemberRemoval,
            "organization-member-removal-cli" => Self::OrganizationMemberRemovalCli,
            "organization-bulk-member-status" => Self::OrganizationBulkMemberStatus,
            "organization-bulk-member-status-cli" => Self::OrganizationBulkMemberStatusCli,
            "organization-member-status" => Self::OrganizationMemberStatus,
            "organization-member-status-cli" => Self::OrganizationMemberStatusCli,
            "organization-member-public-keys-cli" => Self::OrganizationMemberPublicKeysCli,
            "organization-member-public-keys" => Self::OrganizationMemberPublicKeys,
            "organization-member-mini-details-cli" => Self::OrganizationMemberMiniDetailsCli,
            "organization-member-mini-details" => Self::OrganizationMemberMiniDetails,
            "organization-members" => Self::OrganizationMembers,
            "organization-members-cli" => Self::OrganizationMembersCli,
            "organization-bulk-confirmation" => Self::OrganizationBulkConfirmations,
            "organization-bulk-confirmation-cli" => Self::OrganizationBulkConfirmationsCli,
            "organization-confirmation" => Self::OrganizationConfirmations,
            "organization-confirmation-cli" => Self::OrganizationConfirmationsCli,
            "organization-invites" => Self::OrganizationInvites,
            "organization-invites-cli" => Self::OrganizationInvitesCli,
            _ => return None,
        })
    }

    fn includes(self, group: Self) -> bool {
        self == Self::All
            || self == group
            || (self == Self::Personal
                && matches!(
                    group,
                    Self::Folders | Self::AccountKeys | Self::Profile | Self::Domains
                ))
    }
}

fn check<E: Display>(result: Result<(), E>) {
    if let Err(error) = result {
        eprintln!("HTTP conformance failed: {error}");
        std::process::exit(1);
    }
}

fn usage() {
    eprintln!(
        "Usage: no-warden-http-conformance [--suite all|personal|folders|account-keys|profile|domains|devices|device-tokens|auth-requests|auth-responses|auth-login|registration|account-security|account-kdf|account-kdf-cli|account-password|account-password-cli|webauthn-credentials|personal-vault-purge|account-deletion|cipher-reads|password-grants|refresh-grants|text-sends|text-sends-cli|file-sends|file-sends-cli|user-key-id|user-key-id-cli|prelogin|prelogin-cli|organization-owner|organization-owner-cli|organization-collections|organization-collections-cli|organization-collection-mutations|organization-collection-mutations-cli|organization-members|organization-members-cli|organization-invites|organization-invites-cli|organization-confirmation|organization-confirmation-cli|organization-bulk-confirmation|organization-bulk-confirmation-cli|organization-member-removal|organization-member-removal-cli|organization-bulk-member-removal|organization-bulk-member-removal-cli|organization-member-status|organization-member-status-cli|organization-bulk-member-status|organization-bulk-member-status-cli|organization-member-public-keys|organization-member-public-keys-cli|organization-member-mini-details|organization-member-mini-details-cli|organization-cipher-sharing|organization-cipher-sharing-cli|organization-cipher-bulk-sharing|organization-cipher-bulk-sharing-cli|web-organization-reads|web-organization-reads-cli|organization-cipher-collections|organization-cipher-collections-cli|organization-cipher-partial|organization-cipher-partial-cli]"
    );
}

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let suite = match (arguments.next(), arguments.next(), arguments.next()) {
        (None, None, None) => Some(Suite::All),
        (Some(flag), None, None) if flag == "--help" => {
            usage();
            return;
        }
        (Some(flag), Some(value), None) if flag == "--suite" => Suite::parse(&value),
        _ => None,
    };
    let Some(suite) = suite else {
        usage();
        std::process::exit(2);
    };
    if suite.includes(Suite::Folders) {
        check(no_warden_conformance::folders::run());
    }
    if suite.includes(Suite::AccountKeys) {
        check(no_warden_conformance::account_keys::run());
    }
    if suite.includes(Suite::Profile) {
        check(no_warden_conformance::account_profile::run());
    }
    if suite.includes(Suite::Domains) {
        check(no_warden_conformance::domains::run());
    }
    if suite.includes(Suite::Devices) {
        check(no_warden_conformance::devices::run());
    }
    if suite.includes(Suite::DeviceTokens) {
        check(no_warden_conformance::device_tokens::run());
    }
    if suite.includes(Suite::AuthRequests) {
        check(no_warden_conformance::auth_requests::run());
    }
    if suite.includes(Suite::AuthResponses) {
        check(no_warden_conformance::auth_responses::run());
    }
    if suite.includes(Suite::AuthLogin) {
        check(no_warden_conformance::auth_login::run());
    }
    if suite.includes(Suite::Registration) {
        check(no_warden_conformance::registration::run());
    }
    if suite.includes(Suite::AccountSecurity) {
        check(no_warden_conformance::account_security::run());
    }
    if suite.includes(Suite::AccountKdf) {
        check(no_warden_conformance::account_kdf::run());
    }
    if suite.includes(Suite::AccountPassword) {
        check(no_warden_conformance::account_password::run());
    }
    // Explicit opt-in: the default HTTP selection needs no installed CLI.
    if suite == Suite::AccountKdfCli {
        check(no_warden_conformance::account_kdf::run_cli());
    }
    if suite == Suite::AccountPasswordCli {
        check(no_warden_conformance::account_password::run_cli());
    }
    // Explicit opt-in: this independent comparison includes its own expiry wait.
    if suite == Suite::WebauthnCredentials {
        check(no_warden_conformance::webauthn_credentials::run());
    }
    // Destructive disposable fixtures are an explicit independent selection.
    if suite == Suite::PersonalVaultPurge {
        check(no_warden_conformance::purge::run());
    }
    if suite == Suite::AccountDeletion {
        check(no_warden_conformance::account_deletion::run());
    }
    if suite == Suite::CipherReads {
        check(no_warden_conformance::cipher_reads::run());
    }
    if suite == Suite::PasswordGrants {
        check(no_warden_conformance::password_login::run());
    }
    if suite == Suite::RefreshGrants {
        check(no_warden_conformance::refresh_grants::run());
    }
    if suite == Suite::TextSends {
        check(no_warden_conformance::text_sends::run());
    }
    if suite == Suite::TextSendsCli {
        check(no_warden_conformance::text_sends_cli::run());
    }
    if suite == Suite::FileSends {
        check(no_warden_conformance::file_sends::run());
    }
    if suite == Suite::FileSendsCli {
        check(no_warden_conformance::file_sends_cli::run());
    }
    if suite == Suite::UserKeyId {
        check(no_warden_conformance::user_key_id::run());
    }
    if suite == Suite::UserKeyIdCli {
        check(no_warden_conformance::user_key_id_cli::run());
    }
    if suite == Suite::Prelogin {
        check(no_warden_conformance::prelogin::run());
    }
    if suite == Suite::PreloginCli {
        check(no_warden_conformance::prelogin_cli::run());
    }
    if suite == Suite::OrganizationOwner {
        check(no_warden_conformance::organization_owner::run());
    }
    if suite == Suite::OrganizationWebReadsCli {
        check(no_warden_conformance::organization_web_reads_cli::run());
    }
    if suite == Suite::OrganizationWebReads {
        check(no_warden_conformance::organization_web_reads::run());
    }
    if suite == Suite::OrganizationCipherBulkSharing {
        check(no_warden_conformance::organization_cipher_bulk_sharing::run());
    }
    if suite == Suite::OrganizationCipherBulkSharingCli {
        check(no_warden_conformance::organization_cipher_bulk_sharing_cli::run());
    }
    if suite == Suite::OrganizationCipherPartial {
        check(no_warden_conformance::organization_cipher_partial::run());
    }
    if suite == Suite::OrganizationCipherPartialCli {
        check(no_warden_conformance::organization_cipher_partial_cli::run());
    }
    if suite == Suite::OrganizationCipherCollections {
        check(no_warden_conformance::organization_cipher_collections::run());
    }
    if suite == Suite::OrganizationCipherCollectionsCli {
        check(no_warden_conformance::organization_cipher_collections_cli::run());
    }
    if suite == Suite::OrganizationCipherSharing {
        check(no_warden_conformance::organization_cipher_sharing::run());
    }
    if suite == Suite::OrganizationCipherSharingCli {
        check(no_warden_conformance::organization_cipher_sharing_cli::run());
    }
    if suite == Suite::OrganizationCollections {
        check(no_warden_conformance::organization_collections::run());
    }
    if suite == Suite::OrganizationCollectionMutations {
        check(no_warden_conformance::organization_collection_mutations::run());
    }
    if suite == Suite::OrganizationBulkMemberRemoval {
        check(no_warden_conformance::organization_bulk_member_removal::run());
    }
    if suite == Suite::OrganizationBulkMemberRemovalCli {
        check(no_warden_conformance::organization_bulk_member_removal_cli::run());
    }
    if suite == Suite::OrganizationMemberRemoval {
        check(no_warden_conformance::organization_member_removal::run());
    }
    if suite == Suite::OrganizationMemberRemovalCli {
        check(no_warden_conformance::organization_member_removal_cli::run());
    }
    if suite == Suite::OrganizationBulkMemberStatus {
        check(no_warden_conformance::organization_bulk_member_status::run());
    }
    if suite == Suite::OrganizationBulkMemberStatusCli {
        check(no_warden_conformance::organization_bulk_member_status_cli::run());
    }
    if suite == Suite::OrganizationMemberStatus {
        check(no_warden_conformance::organization_member_status::run());
    }
    if suite == Suite::OrganizationMemberStatusCli {
        check(no_warden_conformance::organization_member_status_cli::run());
    }
    if suite == Suite::OrganizationMemberPublicKeysCli {
        check(no_warden_conformance::organization_member_public_keys_cli::run());
    }
    if suite == Suite::OrganizationMemberPublicKeys {
        check(no_warden_conformance::organization_member_public_keys::run());
    }
    if suite == Suite::OrganizationMemberMiniDetailsCli {
        check(no_warden_conformance::organization_member_mini_details_cli::run());
    }
    if suite == Suite::OrganizationMemberMiniDetails {
        check(no_warden_conformance::organization_member_mini_details::run());
    }
    if suite == Suite::OrganizationMembers {
        check(no_warden_conformance::organization_members::run());
    }
    if suite == Suite::OrganizationBulkConfirmations {
        check(no_warden_conformance::organization_bulk_confirmations::run());
    }
    if suite == Suite::OrganizationBulkConfirmationsCli {
        check(no_warden_conformance::organization_bulk_confirmations_cli::run());
    }
    if suite == Suite::OrganizationConfirmations {
        check(no_warden_conformance::organization_confirmations::run());
    }
    if suite == Suite::OrganizationConfirmationsCli {
        check(no_warden_conformance::organization_confirmations_cli::run());
    }
    if suite == Suite::OrganizationInvites {
        check(no_warden_conformance::organization_invites::run());
    }
    if suite == Suite::OrganizationInvitesCli {
        check(no_warden_conformance::organization_invites_cli::run());
    }
    if suite == Suite::OrganizationMembersCli {
        check(no_warden_conformance::organization_members_cli::run());
    }
    if suite == Suite::OrganizationCollectionMutationsCli {
        check(no_warden_conformance::organization_collection_mutations_cli::run());
    }
    if suite == Suite::OrganizationCollectionsCli {
        check(no_warden_conformance::organization_collections_cli::run());
    }
    if suite == Suite::OrganizationOwnerCli {
        check(no_warden_conformance::organization_owner_cli::run());
    }
}
