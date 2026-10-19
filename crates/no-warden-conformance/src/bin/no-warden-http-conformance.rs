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
        "Usage: no-warden-http-conformance [--suite all|personal|folders|account-keys|profile|domains|devices|device-tokens|auth-requests|auth-responses|auth-login|registration|account-security|account-kdf|account-kdf-cli|account-password|account-password-cli|webauthn-credentials|personal-vault-purge|account-deletion|cipher-reads|password-grants|refresh-grants|text-sends|text-sends-cli|file-sends|file-sends-cli|user-key-id|user-key-id-cli|prelogin|prelogin-cli|organization-owner|organization-owner-cli]"
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
    if suite == Suite::OrganizationOwnerCli {
        check(no_warden_conformance::organization_owner_cli::run());
    }
}
