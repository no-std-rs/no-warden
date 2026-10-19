//! Ordinary password-grant authorization with provider-owned credential and account policy.
//!
//! Form parsing, Unicode email lowercase, password verification, server verifier upgrades,
//! mail/2FA policy, device registration, clocks, rate limits and token issuance belong to
//! adapters. A password proof is an opaque client-generated server-authorization hash,
//! not a plaintext master password or a vault unlock key.

use crate::{ApiError, Storage, VaultService, identity::Secret, wire::PasswordLoginRequest};

/// Authoritative account state returned only after the supplied proof was verified.
/// An owned handle can use caller-owned fixed storage; no allocation or Debug bound is
/// imposed on it. The enabled flag must come from trusted provider state.
pub struct PasswordLoginAccount<O: AsRef<str>> {
    pub owner: O,
    pub enabled: bool,
}
impl<O: AsRef<str>> core::fmt::Debug for PasswordLoginAccount<O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordLoginAccount")
            .finish_non_exhaustive()
    }
}

/// Raw new-login device fields, including blank identifiers/names and nonnumeric types.
/// The adapter applies the upstream device-type parsing policy after authorization.
#[derive(Clone, Copy)]
pub struct PasswordLoginDevice<'a> {
    pub identifier: &'a str,
    pub name: &'a str,
    pub device_type: &'a str,
}
impl core::fmt::Debug for PasswordLoginDevice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordLoginDevice")
            .finish_non_exhaustive()
    }
}

/// Password-method authority after proof, enabled-state and provider policy checks.
///
/// Its owned account handle releases provider borrows before device/session issuance.
/// It deliberately has no public constructor, Serialize, Clone or Copy implementation.
/// The host must retain its operation lock through issuance, preserve the grant's exact
/// client ID and device fields, and issue access plus refresh authority as appropriate.
pub struct AuthorizedPasswordGrant<'a, O: AsRef<str>> {
    owner: O,
    client_id: &'a str,
    device: PasswordLoginDevice<'a>,
}
impl<O: AsRef<str>> core::fmt::Debug for AuthorizedPasswordGrant<'_, O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizedPasswordGrant")
            .finish_non_exhaustive()
    }
}
impl<'a, O: AsRef<str>> AuthorizedPasswordGrant<'a, O> {
    pub fn user_id(&self) -> &str {
        self.owner.as_ref()
    }
    pub const fn client_id(&self) -> &'a str {
        self.client_id
    }
    pub const fn device(&self) -> PasswordLoginDevice<'a> {
        self.device
    }
    pub const fn scope(&self) -> &'static str {
        "api offline_access"
    }
    pub const fn expires_in(&self) -> u32 {
        7200
    }
    pub const fn allows_refresh(&self) -> bool {
        true
    }
}

/// Opt-in ordinary-password login without adding obligations to existing Storage adapters.
///
/// Hold the application's operation lock across verification, preparation and subsequent
/// device/token issuance so authoritative account state remains stable. The HTTP adapter
/// dispatches other grant methods and any present authRequest before ordinary login, and
/// handles request guards, global SSO-only policy and source-ordered rate limiting.
///
/// verify_password_login receives username.trim(); apply Unicode lowercase for account
/// lookup without further trimming. Verify the exact opaque proof with an appropriate
/// cryptographic verifier and return None for both unknown accounts and wrong proofs.
/// Do not log/serialize the proof, reveal account existence, or mutate state in this hook.
/// Return authoritative enabled state only after successful verification.
///
/// prepare_password_login runs only for a verified, enabled account. Complete required
/// server-verifier upgrades and mail/device/2FA policy in source order, or fail closed.
/// Internal verifier cost is distinct from the client's KDF. A supported upgrade must
/// preserve client KDF, encrypted keys, security stamp and unrelated vault/account state;
/// an upstream upgrade may advance account revision. Prior successful upgrade work may
/// survive a later policy error: this service does not promise whole-login rollback.
/// Providers choose transactional boundaries, including source-compatible best-effort
/// upgrade-save handling. Supporting this trait alone implements neither those policies
/// nor rate controls, notifications, device registration or token issuance.
pub trait PasswordLoginStorage: Storage {
    type OwnerId: AsRef<str>;

    fn verify_password_login(
        &mut self,
        username: &str,
        password: &Secret<'_>,
    ) -> Result<Option<PasswordLoginAccount<Self::OwnerId>>, Self::Error>;

    fn prepare_password_login(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
        device: PasswordLoginDevice<'_>,
    ) -> Result<(), Self::Error>;
}
impl<T: PasswordLoginStorage + ?Sized> PasswordLoginStorage for &mut T {
    type OwnerId = T::OwnerId;

    fn verify_password_login(
        &mut self,
        username: &str,
        password: &Secret<'_>,
    ) -> Result<Option<PasswordLoginAccount<Self::OwnerId>>, Self::Error> {
        (**self).verify_password_login(username, password)
    }
    fn prepare_password_login(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
        device: PasswordLoginDevice<'_>,
    ) -> Result<(), Self::Error> {
        (**self).prepare_password_login(owner, password, device)
    }
}

fn unavailable() -> ApiError {
    ApiError::invalid("password", "Username or password is incorrect. Try again")
}

impl<S: PasswordLoginStorage> VaultService<S> {
    /// Authorize only ordinary password login. A present authRequest, including an empty
    /// one, is rejected before provider work; it must never fall back to password proof.
    pub fn authenticate_password<'a>(
        &mut self,
        request: &PasswordLoginRequest<'a>,
    ) -> Result<AuthorizedPasswordGrant<'a, S::OwnerId>, ApiError> {
        if request.grant_type != Some("password") {
            return Err(ApiError::invalid("grant_type", "Unsupported grant type."));
        }
        let client_id = request
            .client_id
            .ok_or_else(|| ApiError::invalid("client_id", "client_id cannot be blank"))?;
        let password = request
            .password
            .as_ref()
            .ok_or_else(|| ApiError::invalid("password", "password cannot be blank"))?;
        let scope = request
            .scope
            .ok_or_else(|| ApiError::invalid("scope", "scope cannot be blank"))?;
        let username = request
            .username
            .ok_or_else(|| ApiError::invalid("username", "username cannot be blank"))?;
        let device = PasswordLoginDevice {
            identifier: request.device_identifier.ok_or_else(|| {
                ApiError::invalid("device_identifier", "device_identifier cannot be blank")
            })?,
            name: request
                .device_name
                .ok_or_else(|| ApiError::invalid("device_name", "device_name cannot be blank"))?,
            device_type: request
                .device_type
                .ok_or_else(|| ApiError::invalid("device_type", "device_type cannot be blank"))?,
        };
        if scope != "api offline_access" {
            // The source includes escaped caller data in its message. Keep the core's
            // static error allocation-free; a transport may render that dynamic detail.
            return Err(ApiError::invalid("scope", "Scope not supported"));
        }
        if request.auth_request.is_some() {
            return Err(ApiError::invalid(
                "authRequest",
                "Authentication requests require access-code login.",
            ));
        }
        let account = self
            .storage_mut()
            .verify_password_login(username.trim(), password)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        if account.owner.as_ref().is_empty() {
            return Err(unavailable());
        }
        if !account.enabled {
            return Err(ApiError::invalid("username", "This user has been disabled"));
        }
        self.storage_mut()
            .prepare_password_login(account.owner.as_ref(), password, device)
            .map_err(S::map_error)?;
        Ok(AuthorizedPasswordGrant {
            owner: account.owner,
            client_id,
            device,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind,
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{format, string::String, vec, vec::Vec};

    const OWNER: &str = "private-owner";
    const PROOF: &str = " private-proof\0雪\r\n ";

    // Owned, bounded handle deliberately lacks Debug, Clone and Copy.
    struct Owner(&'static str);
    impl AsRef<str> for Owner {
        fn as_ref(&self) -> &str {
            self.0
        }
    }
    #[derive(Clone, Copy, PartialEq)]
    enum Fail {
        Verify,
        Prepare,
    }
    struct Mock {
        email: &'static str,
        proof: &'static str,
        owner: &'static str,
        enabled: bool,
        calls: Vec<&'static str>,
        username: String,
        prepared: Option<(String, String, String, String)>,
        fail: Option<Fail>,
        failure: ErrorKind,
        upgraded: bool,
        unrelated: [u8; 8],
    }
    impl Mock {
        fn new() -> Self {
            Self {
                email: "älice@example.test",
                proof: PROOF,
                owner: OWNER,
                enabled: true,
                calls: vec![],
                username: String::new(),
                prepared: None,
                fail: None,
                failure: ErrorKind::Storage,
                upgraded: false,
                unrelated: [7; 8],
            }
        }
    }
    impl Storage for Mock {
        type Error = ErrorKind;
        fn map_error(error: Self::Error) -> ApiError {
            ApiError::new(error, "Static provider failure")
        }
        fn account_exists(&mut self, _: &str) -> Result<bool, Self::Error> {
            unreachable!()
        }
        fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
            unreachable!()
        }
        fn save_folder(
            &mut self,
            _: &str,
            _: &str,
            _: &FolderRequest<'_>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
            unreachable!()
        }
        fn save_cipher(
            &mut self,
            _: &str,
            _: &str,
            _: &CipherRequest<'_>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), Self::Error> {
            unreachable!()
        }
        fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), Self::Error> {
            unreachable!()
        }
    }
    impl PasswordLoginStorage for Mock {
        type OwnerId = Owner;
        fn verify_password_login(
            &mut self,
            username: &str,
            password: &Secret<'_>,
        ) -> Result<Option<PasswordLoginAccount<Self::OwnerId>>, Self::Error> {
            self.calls.push("verify");
            self.username = username.into();
            if self.fail == Some(Fail::Verify) {
                return Err(self.failure);
            }
            // Explicit test double only; production providers use a cryptographic verifier.
            Ok(
                (username.to_lowercase() == self.email && password.expose_secret() == self.proof)
                    .then_some(PasswordLoginAccount {
                        owner: Owner(self.owner),
                        enabled: self.enabled,
                    }),
            )
        }
        fn prepare_password_login(
            &mut self,
            owner: &str,
            password: &Secret<'_>,
            device: PasswordLoginDevice<'_>,
        ) -> Result<(), Self::Error> {
            self.calls.push("prepare");
            assert_eq!(owner, self.owner);
            assert_eq!(password.expose_secret(), self.proof);
            self.prepared = Some((
                owner.into(),
                device.identifier.into(),
                device.name.into(),
                device.device_type.into(),
            ));
            // A successful internal-verifier upgrade may precede a later mail/2FA error.
            self.upgraded = true;
            if self.fail == Some(Fail::Prepare) {
                return Err(self.failure);
            }
            Ok(())
        }
    }
    fn request() -> PasswordLoginRequest<'static> {
        PasswordLoginRequest {
            grant_type: Some("password"),
            client_id: Some("private-client"),
            password: Some(Secret::new(PROOF)),
            scope: Some("api offline_access"),
            username: Some(" \tÄLICE@EXAMPLE.TEST\u{2003}"),
            device_identifier: Some("private-device\0雪"),
            device_name: Some("  private-name\r\n"),
            device_type: Some("not-a-number"),
            auth_request: None,
        }
    }
    fn error(mock: &mut Mock, request: &PasswordLoginRequest<'_>) -> ApiError {
        VaultService::new(mock)
            .authenticate_password(request)
            .unwrap_err()
    }

    #[test]
    fn password_login_required_presence_order_precedes_scope_and_provider() {
        let fields = [
            "client_id",
            "password",
            "scope",
            "username",
            "device_identifier",
            "device_name",
            "device_type",
        ];
        for (present, field) in fields.iter().enumerate() {
            let mut mock = Mock::new();
            let mut input = request();
            // Fill only the leading required fields; a bad present scope must not mask
            // a later missing required field. Upstream checks all presence first.
            input.client_id = (present > 0).then_some("");
            input.password = (present > 1).then_some(Secret::new(""));
            input.scope = (present > 2).then_some("wrong-scope");
            input.username = (present > 3).then_some("");
            input.device_identifier = (present > 4).then_some("");
            input.device_name = (present > 5).then_some("");
            input.device_type = None;
            let failure = error(&mut mock, &input);
            assert_eq!(failure.field, Some(*field));
            assert_eq!(failure.message, format!("{field} cannot be blank"));
            assert_eq!(failure.status_code(), 400);
            assert!(mock.calls.is_empty());
            assert!(!mock.upgraded);
        }
    }

    #[test]
    fn password_login_grant_and_exact_scope_fail_without_provider() {
        for grant_type in [None, Some(""), Some("Password"), Some("refresh_token")] {
            let mut mock = Mock::new();
            let mut input = request();
            input.grant_type = grant_type;
            input.client_id = None;
            assert_eq!(error(&mut mock, &input).field, Some("grant_type"));
            assert!(mock.calls.is_empty());
        }
        for scope in [
            "",
            "api",
            "offline_access api",
            "api  offline_access",
            "api offline_access ",
            "api offline_access\n",
        ] {
            let mut mock = Mock::new();
            let mut input = request();
            input.scope = Some(scope);
            let failure = error(&mut mock, &input);
            assert_eq!(failure.field, Some("scope"));
            assert_eq!(failure.message, "Scope not supported");
            assert!(!format!("{failure:?}").contains(scope) || scope.is_empty());
            assert!(mock.calls.is_empty());
        }
    }

    #[test]
    fn password_login_auth_request_presence_never_falls_back_to_password() {
        for auth_request in ["", "opaque-request", "\0雪"] {
            let mut mock = Mock::new();
            let mut input = request();
            input.auth_request = Some(auth_request);
            assert_eq!(error(&mut mock, &input).field, Some("authRequest"));
            assert!(mock.calls.is_empty());
            assert!(!mock.upgraded);
        }
    }

    #[test]
    fn password_login_trims_username_preserves_opaque_fields_and_prepares_before_grant() {
        let mut mock = Mock::new();
        let input = request();
        let grant = VaultService::new(&mut mock)
            .authenticate_password(&input)
            .unwrap();
        assert_eq!(grant.user_id(), OWNER);
        assert_eq!(grant.client_id(), input.client_id.unwrap());
        assert_eq!(grant.device().identifier, input.device_identifier.unwrap());
        assert_eq!(grant.device().name, input.device_name.unwrap());
        assert_eq!(grant.device().device_type, input.device_type.unwrap());
        assert_eq!(grant.scope(), "api offline_access");
        assert_eq!(grant.expires_in(), 7200);
        assert!(grant.allows_refresh());
        assert_eq!(mock.username, "ÄLICE@EXAMPLE.TEST");
        assert_eq!(mock.calls, ["verify", "prepare"]);
        assert!(mock.upgraded);
        assert_eq!(mock.unrelated, [7; 8]);
        // No provider borrow remains in the owned grant.
        mock.email = "another@example.test";
        assert_eq!(grant.user_id(), OWNER);
    }

    #[test]
    fn password_login_present_empty_values_are_not_missing_or_normalized() {
        let mut mock = Mock::new();
        mock.email = "";
        mock.proof = "";
        let mut input = request();
        input.client_id = Some("");
        input.password = Some(Secret::new(""));
        input.username = Some(" \u{2003}\t");
        input.device_identifier = Some("");
        input.device_name = Some("");
        input.device_type = Some("");
        let grant = VaultService::new(&mut mock)
            .authenticate_password(&input)
            .unwrap();
        assert_eq!(grant.client_id(), "");
        assert_eq!(grant.device().identifier, "");
        assert_eq!(grant.device().name, "");
        assert_eq!(grant.device().device_type, "");
        assert_eq!(mock.username, "");
        assert_eq!(mock.calls, ["verify", "prepare"]);
    }

    #[test]
    fn password_login_wrong_proof_and_unknown_account_share_error_without_prepare() {
        let mut failures = vec![];
        for unknown in [false, true] {
            let mut mock = Mock::new();
            mock.enabled = false;
            let mut input = request();
            if unknown {
                input.username = Some("unknown@example.test");
            } else {
                // Proof normalization would make this equal; the service must not trim.
                input.password = Some(Secret::new(PROOF.trim()));
            }
            failures.push(error(&mut mock, &input));
            assert_eq!(mock.calls, ["verify"]);
            assert!(mock.prepared.is_none());
            assert!(!mock.upgraded);
            assert_eq!(mock.unrelated, [7; 8]);
        }
        assert_eq!(failures[0], failures[1]);
        assert_eq!(
            failures[0].message,
            "Username or password is incorrect. Try again"
        );
        assert_eq!(failures[0].status_code(), 400);
    }

    #[test]
    fn password_login_disabled_and_empty_provider_owner_fail_closed_before_prepare() {
        let mut mock = Mock::new();
        mock.enabled = false;
        let failure = error(&mut mock, &request());
        assert_eq!(failure.message, "This user has been disabled");
        assert_eq!(failure.status_code(), 400);
        assert_eq!(mock.calls, ["verify"]);
        assert!(!mock.upgraded);

        let mut mock = Mock::new();
        mock.owner = "";
        assert_eq!(error(&mut mock, &request()), unavailable());
        assert_eq!(mock.calls, ["verify"]);
        assert!(!mock.upgraded);
    }

    #[test]
    fn password_login_provider_errors_keep_typed_mapping_and_never_grant() {
        for fail in [Fail::Verify, Fail::Prepare] {
            for kind in [
                ErrorKind::Storage,
                ErrorKind::Conflict,
                ErrorKind::Forbidden,
            ] {
                let mut mock = Mock::new();
                mock.fail = Some(fail);
                mock.failure = kind;
                let failure = error(&mut mock, &request());
                assert_eq!(failure.kind, kind);
                assert_eq!(failure.message, "Static provider failure");
                assert_eq!(
                    mock.calls,
                    if fail == Fail::Verify {
                        vec!["verify"]
                    } else {
                        vec!["verify", "prepare"]
                    }
                );
                assert_eq!(mock.upgraded, fail == Fail::Prepare);
                assert_eq!(mock.unrelated, [7; 8]);
            }
        }
    }

    #[test]
    fn password_login_borrowed_adapter_forwards_both_hooks() {
        let mut mock = Mock::new();
        let mut borrowed = &mut mock;
        let grant = VaultService::new(&mut borrowed)
            .authenticate_password(&request())
            .unwrap();
        assert_eq!(grant.user_id(), OWNER);
        assert_eq!(mock.calls, ["verify", "prepare"]);
    }

    #[test]
    fn password_login_wire_borrows_proof_and_aliases_without_exposing_debug() {
        let json = r#"{"grant_type":"password","client_id":"private-client","password":"private-proof","scope":"api offline_access","username":"private-email","device_identifier":"private-device","deviceName":"private-name","device_type":"private-type","authRequest":null}"#;
        let input: PasswordLoginRequest<'_> = serde_json::from_str(json).unwrap();
        assert_eq!(input.device_identifier, Some("private-device"));
        assert_eq!(input.device_name, Some("private-name"));
        assert_eq!(input.device_type, Some("private-type"));
        assert!(input.auth_request.is_none());
        let password = input.password.as_ref().unwrap().expose_secret();
        assert_eq!(password, "private-proof");
        let source_range = json.as_bytes().as_ptr_range();
        assert!(source_range.contains(&password.as_ptr()));
        assert_eq!(format!("{input:?}"), "PasswordLoginRequest { .. }");
        let omitted: PasswordLoginRequest<'_> = serde_json::from_str("{}").unwrap();
        assert!(omitted.password.is_none());
        for invalid in [r#"{"password":1}"#, r#"{"deviceIdentifier":false}"#] {
            assert!(serde_json::from_str::<PasswordLoginRequest<'_>>(invalid).is_err());
        }
    }

    #[test]
    fn password_login_all_private_types_redact_without_owner_debug_bound() {
        let account = PasswordLoginAccount {
            owner: Owner(OWNER),
            enabled: false,
        };
        assert_eq!(format!("{account:?}"), "PasswordLoginAccount { .. }");
        let input = request();
        let mut mock = Mock::new();
        let grant = VaultService::new(&mut mock)
            .authenticate_password(&input)
            .unwrap();
        assert_eq!(
            format!("{:?}", grant.device()),
            "PasswordLoginDevice { .. }"
        );
        assert_eq!(format!("{grant:?}"), "AuthorizedPasswordGrant { .. }");
        assert_eq!(format!("{input:?}"), "PasswordLoginRequest { .. }");
    }
}
