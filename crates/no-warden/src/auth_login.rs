//! Provider-driven login with an approved authentication request and its access code.
//!
//! The adapter decodes form fields, supplies the peer address/time, verifies any additional
//! account policy and issues tokens. This module never verifies a master password, performs
//! cryptography, reads a clock, registers a device or signs a token.

use crate::{
    ApiError, VaultService, auth_requests::AuthRequestStorage, identity::Secret,
    wire::AuthRequestLoginRequest,
};

/// Five minutes, measured from request creation rather than approval.
pub const AUTH_REQUEST_LOGIN_LIFETIME_NANOS: i128 = 300_000_000_000;

/// Trusted adapter metadata. The IP is compared exactly, without normalization.
#[derive(Clone, Copy)]
pub struct AuthRequestLoginContext<'a> {
    pub request_ip: &'a str,
    pub now_unix_nanos: i128,
}
impl core::fmt::Debug for AuthRequestLoginContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestLoginContext")
            .finish_non_exhaustive()
    }
}

/// Private provider state returned only after constant-time access-code verification.
/// Owner/IP and timestamps are not wire responses; Debug redacts all fields.
#[derive(Clone, Copy)]
pub struct AuthRequestLoginRecord<'a> {
    pub id: &'a str,
    pub owner_id: &'a str,
    pub request_ip: &'a str,
    pub approved: Option<bool>,
    pub used: bool,
    pub created_at_unix_nanos: i128,
    pub account_enabled: bool,
}
impl core::fmt::Debug for AuthRequestLoginRecord<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestLoginRecord")
            .finish_non_exhaustive()
    }
}

/// New login-device metadata. It need not match the device that created the request.
/// Raw identifiers, names and type strings remain opaque, including blank values.
#[derive(Clone, Copy)]
pub struct AuthRequestLoginDevice<'a> {
    pub identifier: &'a str,
    pub name: &'a str,
    pub device_type: &'a str,
}
impl core::fmt::Debug for AuthRequestLoginDevice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestLoginDevice")
            .finish_non_exhaustive()
    }
}

/// Authority produced only after a verified, enabled request is consumed successfully.
///
/// The owned account handle releases all provider borrows before host device registration
/// and issuance. It requires no core allocation and does not expose the access code. Issue
/// password-method authority with refresh capability; this grant is not a vault unlock key.
/// It deliberately has no public constructor, Serialize, Clone or Copy implementation.
pub struct AuthorizedAuthRequestGrant<'a, O: AsRef<str>> {
    owner: O,
    client_id: &'a str,
    device: AuthRequestLoginDevice<'a>,
}
impl<O: AsRef<str>> core::fmt::Debug for AuthorizedAuthRequestGrant<'_, O> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizedAuthRequestGrant")
            .finish_non_exhaustive()
    }
}
impl<'a, O: AsRef<str>> AuthorizedAuthRequestGrant<'a, O> {
    pub fn user_id(&self) -> &str {
        self.owner.as_ref()
    }
    pub const fn client_id(&self) -> &'a str {
        self.client_id
    }
    pub const fn device(&self) -> AuthRequestLoginDevice<'a> {
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

/// Opt-in login, sharing AuthRequestStorage's provider-owned email account handle.
///
/// Hold the application's operation lock across lookup, verification and consumption.
/// auth_request_login must verify the supplied opaque code with a constant-time verifier,
/// return None for missing/foreign requests or wrong codes, and leave all state unchanged.
/// Return the owner's authoritative enabled status and full-width creation timestamp.
/// Do not log, normalize or serialize the code. Email lookup receives username.trim(); the
/// inherited provider applies Unicode lowercase, without further trimming/normalization.
///
/// consume_auth_request_login atomically compares exact owner/ID, approved=Some(true) and
/// unused state, then sets only the authentication timestamp to now_unix_nanos. Return false
/// if another consumer won or the row no longer qualifies. A failure must roll back its
/// mutation. Preserve request key/hash/approval/response fields, account revision, devices,
/// credentials, vaults and foreign state. The operation lock must keep validated fields
/// stable between the two provider calls; the compare-and-set prevents double consumption.
///
/// Hosts must complete any required 2FA/mail/SSO/administrative policy BEFORE this service
/// consumes a request. Supporting this trait alone does not implement those policies, rate
/// limits, notifications, expiry cleanup or token issuance. A host may wrap consumption,
/// device registration and token/session issuance in one rollback transaction; that is a
/// stronger failure boundary than the pinned upstream's later issuance steps.
pub trait AuthRequestLoginStorage: AuthRequestStorage {
    fn auth_request_login(
        &mut self,
        owner: &str,
        id: &str,
        code: &Secret<'_>,
    ) -> Result<Option<AuthRequestLoginRecord<'_>>, Self::Error>;

    fn consume_auth_request_login(
        &mut self,
        owner: &str,
        id: &str,
        now_unix_nanos: i128,
    ) -> Result<bool, Self::Error>;
}
impl<T: AuthRequestLoginStorage + ?Sized> AuthRequestLoginStorage for &mut T {
    fn auth_request_login(
        &mut self,
        owner: &str,
        id: &str,
        code: &Secret<'_>,
    ) -> Result<Option<AuthRequestLoginRecord<'_>>, Self::Error> {
        (**self).auth_request_login(owner, id, code)
    }
    fn consume_auth_request_login(
        &mut self,
        owner: &str,
        id: &str,
        now_unix_nanos: i128,
    ) -> Result<bool, Self::Error> {
        (**self).consume_auth_request_login(owner, id, now_unix_nanos)
    }
}

fn unavailable() -> ApiError {
    ApiError::invalid(
        "authRequest",
        "Username or access code is incorrect. Try again",
    )
}

impl<S: AuthRequestLoginStorage> VaultService<S> {
    pub fn authenticate_auth_request<'a>(
        &mut self,
        request: &AuthRequestLoginRequest<'a>,
        context: &AuthRequestLoginContext<'_>,
    ) -> Result<AuthorizedAuthRequestGrant<'a, S::OwnerId>, ApiError> {
        let required = |field| ApiError::invalid(field, "A required grant field is missing.");
        if request.grant_type != Some("password") {
            return Err(ApiError::invalid("grant_type", "Unsupported grant type."));
        }
        let code = request
            .password
            .as_ref()
            .ok_or_else(|| required("password"))?;
        let id = request
            .auth_request
            .ok_or_else(|| required("authRequest"))?;
        let client_id = request.client_id.ok_or_else(|| required("client_id"))?;
        if request.scope != Some("api offline_access") {
            return Err(ApiError::invalid("scope", "Unsupported password scope."));
        }
        let username = request.username.ok_or_else(|| required("username"))?;
        let device = AuthRequestLoginDevice {
            identifier: request
                .device_identifier
                .ok_or_else(|| required("deviceIdentifier"))?,
            name: request.device_name.ok_or_else(|| required("deviceName"))?,
            device_type: request.device_type.ok_or_else(|| required("deviceType"))?,
        };
        let owner = self
            .storage_mut()
            .auth_request_owner(username.trim())
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        let record = self
            .storage_mut()
            .auth_request_login(owner.as_ref(), id, code)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        let unexpired = record
            .created_at_unix_nanos
            .checked_add(AUTH_REQUEST_LOGIN_LIFETIME_NANOS)
            .is_some_and(|deadline| context.now_unix_nanos < deadline);
        if record.owner_id != owner.as_ref()
            || record.id != id
            || record.approved != Some(true)
            || record.used
            || !unexpired
            || record.request_ip != context.request_ip
            || !record.account_enabled
        {
            return Err(unavailable());
        }
        if !self
            .storage_mut()
            .consume_auth_request_login(owner.as_ref(), id, context.now_unix_nanos)
            .map_err(S::map_error)?
        {
            return Err(unavailable());
        }
        Ok(AuthorizedAuthRequestGrant {
            owner,
            client_id,
            device,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind, Storage,
        auth_requests::{AuthRequestContext, AuthRequestRecord},
        devices::{DeviceRecord, DeviceRegistration, DeviceStorage},
        service::ItemMetadata,
        wire::{AuthRequestCreateRequest, CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{string::String, vec, vec::Vec};

    const OWNER: &str = "private-owner";
    const ID: &str = "opaque-request-id";
    const CODE: &str = "private-code\0雪";
    const IP: &str = "127.0.0.1";

    // Owned, stack-sized provider handle deliberately has no Debug/Clone/Copy bound.
    struct Owner(&'static str);
    impl AsRef<str> for Owner {
        fn as_ref(&self) -> &str {
            self.0
        }
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fail {
        Owner,
        Read,
        Consume,
    }
    struct Mock {
        email: &'static str,
        code: &'static str,
        record: AuthRequestLoginRecord<'static>,
        calls: Vec<&'static str>,
        last_email: String,
        consumed_at: Option<i128>,
        missing_record: bool,
        misdirect: bool,
        lost_race: bool,
        fail: Option<Fail>,
        error: ErrorKind,
        unrelated: (usize, &'static str),
    }
    impl Mock {
        fn new() -> Self {
            Self {
                email: "alice@example.test",
                code: CODE,
                record: AuthRequestLoginRecord {
                    id: ID,
                    owner_id: OWNER,
                    request_ip: IP,
                    approved: Some(true),
                    used: false,
                    created_at_unix_nanos: 0,
                    account_enabled: true,
                },
                calls: vec![],
                last_email: String::new(),
                consumed_at: None,
                missing_record: false,
                misdirect: false,
                lost_race: false,
                fail: None,
                error: ErrorKind::Storage,
                unrelated: (7, "vault/account/devices/credentials/other-requests"),
            }
        }
        fn call(&mut self, label: &'static str, fail: Fail) -> Result<(), ErrorKind> {
            self.calls.push(label);
            if self.fail == Some(fail) {
                Err(self.error)
            } else {
                Ok(())
            }
        }
        fn assert_unchanged(&self) {
            assert!(!self.record.used);
            assert_eq!(self.consumed_at, None);
            assert_eq!(
                self.unrelated,
                (7, "vault/account/devices/credentials/other-requests")
            );
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
    impl DeviceStorage for Mock {
        type Devices<'a> = &'a [DeviceRecord<'a>];
        fn known_device(&mut self, _: &str, _: &str) -> Result<bool, Self::Error> {
            unreachable!()
        }
        fn devices(&mut self, _: &str) -> Result<Self::Devices<'_>, Self::Error> {
            unreachable!()
        }
        fn device(&mut self, _: &str, _: &str) -> Result<Option<DeviceRecord<'_>>, Self::Error> {
            unreachable!()
        }
        fn register_device(
            &mut self,
            _: &str,
            _: &DeviceRegistration<'_>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }
    }
    impl AuthRequestStorage for Mock {
        type OwnerId = Owner;
        type Requests<'a> = &'a [AuthRequestRecord<'a>];
        fn auth_request_owner(
            &mut self,
            email: &str,
        ) -> Result<Option<Self::OwnerId>, Self::Error> {
            self.call("owner", Fail::Owner)?;
            self.last_email = email.into();
            Ok((email.to_lowercase() == self.email).then_some(Owner(OWNER)))
        }
        fn create_auth_request(
            &mut self,
            _: &str,
            _: &AuthRequestCreateRequest<'_>,
            _: &AuthRequestContext<'_>,
        ) -> Result<AuthRequestRecord<'_>, Self::Error> {
            unreachable!()
        }
        fn auth_request(
            &mut self,
            _: &str,
            _: &str,
        ) -> Result<Option<AuthRequestRecord<'_>>, Self::Error> {
            unreachable!()
        }
        fn auth_requests(&mut self, _: &str) -> Result<Self::Requests<'_>, Self::Error> {
            unreachable!()
        }
    }
    impl AuthRequestLoginStorage for Mock {
        fn auth_request_login(
            &mut self,
            owner: &str,
            id: &str,
            code: &Secret<'_>,
        ) -> Result<Option<AuthRequestLoginRecord<'_>>, Self::Error> {
            self.call("read", Fail::Read)?;
            // Test double only. Production providers must use constant-time verification.
            Ok((!self.missing_record
                && code.expose_secret() == self.code
                && (self.misdirect || (owner == self.record.owner_id && id == self.record.id)))
                .then_some(self.record))
        }
        fn consume_auth_request_login(
            &mut self,
            owner: &str,
            id: &str,
            now_unix_nanos: i128,
        ) -> Result<bool, Self::Error> {
            self.calls.push("consume");
            if self.lost_race
                || owner != self.record.owner_id
                || id != self.record.id
                || self.record.approved != Some(true)
                || self.record.used
            {
                return Ok(false);
            }
            let before = (self.record.used, self.consumed_at);
            self.record.used = true;
            self.consumed_at = Some(now_unix_nanos);
            if self.fail == Some(Fail::Consume) {
                (self.record.used, self.consumed_at) = before;
                return Err(self.error);
            }
            Ok(true)
        }
    }
    fn request() -> AuthRequestLoginRequest<'static> {
        AuthRequestLoginRequest {
            grant_type: Some("password"),
            password: Some(Secret::new(CODE)),
            auth_request: Some(ID),
            client_id: Some("cli"),
            scope: Some("api offline_access"),
            username: Some(" \tALICE@EXAMPLE.TEST\u{2003}"),
            device_identifier: Some("new-login-device\0雪"),
            device_name: Some("  new device\r\n"),
            device_type: Some("not a number"),
        }
    }
    fn context() -> AuthRequestLoginContext<'static> {
        AuthRequestLoginContext {
            request_ip: IP,
            now_unix_nanos: 1,
        }
    }
    fn rejected(
        mock: &mut Mock,
        request: &AuthRequestLoginRequest<'_>,
        ctx: &AuthRequestLoginContext<'_>,
    ) {
        let error = VaultService::new(&mut *mock)
            .authenticate_auth_request(request, ctx)
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert!(!std::format!("{error:?}").contains(CODE));
        assert!(!mock.calls.contains(&"consume"));
    }

    #[test]
    fn missing_or_unsupported_grant_fields_never_call_a_provider() {
        for field in 0..9 {
            let mut input = request();
            match field {
                0 => input.grant_type = None,
                1 => input.password = None,
                2 => input.auth_request = None,
                3 => input.client_id = None,
                4 => input.scope = None,
                5 => input.username = None,
                6 => input.device_identifier = None,
                7 => input.device_name = None,
                _ => input.device_type = None,
            }
            let mut mock = Mock::new();
            rejected(&mut mock, &input, &context());
            assert!(mock.calls.is_empty());
            mock.assert_unchanged();
        }
        for value in [
            "",
            "Password",
            " password",
            "client_credentials",
            "refresh_token",
        ] {
            let mut input = request();
            input.grant_type = Some(value);
            let mut mock = Mock::new();
            rejected(&mut mock, &input, &context());
            assert!(mock.calls.is_empty());
        }
        for value in [
            "",
            "api",
            "offline_access api",
            "api offline_access ",
            "api  offline_access",
        ] {
            let mut input = request();
            input.scope = Some(value);
            let mut mock = Mock::new();
            rejected(&mut mock, &input, &context());
            assert!(mock.calls.is_empty());
        }
    }

    #[test]
    fn successful_login_owns_password_authority_and_only_consumes_once() {
        let mut mock = Mock::new();
        let input = request();
        let grant = VaultService::new(&mut mock)
            .authenticate_auth_request(&input, &context())
            .unwrap();
        assert_eq!(mock.calls, ["owner", "read", "consume"]);
        assert_eq!(mock.last_email, "ALICE@EXAMPLE.TEST");
        assert_eq!(mock.consumed_at, Some(1));
        assert!(mock.record.used);
        // The grant releases the provider borrow and remains usable after the provider drops.
        drop(mock);
        assert_eq!(grant.user_id(), OWNER);
        assert_eq!(grant.client_id(), "cli");
        assert_eq!(grant.scope(), "api offline_access");
        assert_eq!(grant.expires_in(), 7200);
        assert!(grant.allows_refresh());
        assert_eq!(grant.device().identifier, input.device_identifier.unwrap());
        assert_eq!(grant.device().name, input.device_name.unwrap());
        assert_eq!(grant.device().device_type, "not a number");

        let mut mock = Mock::new();
        let mut service = VaultService::new(&mut mock);
        let _first = service
            .authenticate_auth_request(&input, &context())
            .unwrap();
        assert!(
            service
                .authenticate_auth_request(&input, &context())
                .is_err()
        );
        assert_eq!(
            mock.calls
                .iter()
                .filter(|label| **label == "consume")
                .count(),
            1
        );
    }

    #[test]
    fn expiry_is_creation_based_strict_at_nanosecond_boundary_and_checked_for_overflow() {
        for (created, now, valid) in [
            (0, AUTH_REQUEST_LOGIN_LIFETIME_NANOS - 1, true),
            (0, AUTH_REQUEST_LOGIN_LIFETIME_NANOS, false),
            (0, AUTH_REQUEST_LOGIN_LIFETIME_NANOS + 1, false),
            (1_000, -1, true), // Pinned upstream does not reject future creation timestamps.
            (
                i128::MIN,
                i128::MIN + AUTH_REQUEST_LOGIN_LIFETIME_NANOS - 1,
                true,
            ),
            (
                i128::MAX - AUTH_REQUEST_LOGIN_LIFETIME_NANOS,
                i128::MAX - 1,
                true,
            ),
            (i128::MAX - AUTH_REQUEST_LOGIN_LIFETIME_NANOS + 1, 0, false),
            (i128::MAX, 0, false),
        ] {
            let mut mock = Mock::new();
            mock.record.created_at_unix_nanos = created;
            let ctx = AuthRequestLoginContext {
                now_unix_nanos: now,
                ..context()
            };
            let result = VaultService::new(&mut mock).authenticate_auth_request(&request(), &ctx);
            assert_eq!(result.is_ok(), valid, "created={created} now={now}");
            assert_eq!(mock.record.used, valid);
            assert_eq!(mock.consumed_at, valid.then_some(now));
            if !valid {
                assert!(!mock.calls.contains(&"consume"));
            }
        }
    }

    #[test]
    fn pending_rejected_used_disabled_or_misdirected_records_never_consume() {
        for case in 0..7 {
            let mut mock = Mock::new();
            match case {
                0 => mock.record.approved = None,
                1 => mock.record.approved = Some(false),
                2 => mock.record.used = true,
                3 => mock.record.account_enabled = false,
                4 => mock.missing_record = true,
                5 => {
                    mock.record.owner_id = "foreign-owner";
                    mock.misdirect = true;
                }
                _ => {
                    mock.record.id = "other-request";
                    mock.misdirect = true;
                }
            }
            let used_before = mock.record.used;
            rejected(&mut mock, &request(), &context());
            assert_eq!(mock.record.used, used_before);
            assert_eq!(mock.consumed_at, None);
        }
    }

    #[test]
    fn wrong_owners_codes_and_exact_ip_mismatches_never_consume() {
        for case in 0..6 {
            let mut mock = Mock::new();
            let mut input = request();
            let mut ctx = context();
            match case {
                0 => input.username = Some("bob@example.test"),
                1 => input.password = Some(Secret::new("wrong-code")),
                2 => input.password = Some(Secret::new("private-code\0雪 ")),
                3 => input.auth_request = Some("OPAQUE-REQUEST-ID"),
                4 => ctx.request_ip = "::ffff:127.0.0.1",
                _ => ctx.request_ip = "127.0.0.1 ",
            }
            rejected(&mut mock, &input, &ctx);
            mock.assert_unchanged();
        }
    }

    #[test]
    fn present_empty_and_opaque_fields_keep_new_login_device_metadata() {
        let mut mock = Mock::new();
        mock.email = "";
        mock.code = "";
        mock.record.id = "";
        let input = AuthRequestLoginRequest {
            grant_type: Some("password"),
            password: Some(Secret::new("")),
            auth_request: Some(""),
            client_id: Some(""),
            scope: Some("api offline_access"),
            username: Some(" \t\u{2003}"),
            device_identifier: Some(""),
            device_name: Some(""),
            device_type: Some(""),
        };
        let grant = VaultService::new(&mut mock)
            .authenticate_auth_request(&input, &context())
            .unwrap();
        assert_eq!(grant.client_id(), "");
        assert_eq!(grant.device().identifier, "");
        assert_eq!(grant.device().name, "");
        assert_eq!(grant.device().device_type, "");
        assert!(mock.last_email.is_empty());
        assert!(mock.record.used);
        // Nonempty opaque values are returned verbatim rather than checked against the requester.
        let mut mock = Mock::new();
        let mut input = request();
        input.client_id = Some(" future/client\0雪 ");
        input.device_type = Some("-2147483649");
        let grant = VaultService::new(&mut mock)
            .authenticate_auth_request(&input, &context())
            .unwrap();
        assert_eq!(grant.client_id(), " future/client\0雪 ");
        assert_eq!(grant.device().device_type, "-2147483649");
    }

    #[test]
    fn a_lost_consume_race_returns_no_authority_without_a_second_mutation() {
        let mut mock = Mock::new();
        mock.lost_race = true;
        let error = VaultService::new(&mut mock)
            .authenticate_auth_request(&request(), &context())
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(mock.calls, ["owner", "read", "consume"]);
        mock.assert_unchanged();
    }

    #[test]
    fn provider_errors_preserve_consumption_and_shared_typed_error_mapping() {
        for fail in [Fail::Owner, Fail::Read, Fail::Consume] {
            for kind in [ErrorKind::Conflict, ErrorKind::Storage] {
                let mut mock = Mock::new();
                mock.fail = Some(fail);
                mock.error = kind;
                let error = VaultService::new(&mut mock)
                    .authenticate_auth_request(&request(), &context())
                    .unwrap_err();
                assert_eq!(error.kind, kind);
                assert_eq!(error.message, "Static provider failure");
                mock.assert_unchanged();
            }
        }
    }

    #[test]
    fn debug_redacts_context_record_device_and_owned_authority_without_owner_debug_bounds() {
        let mut mock = Mock::new();
        let input = request();
        let ctx = context();
        let record_debug = std::format!("{:?}", mock.record);
        let grant = VaultService::new(&mut mock)
            .authenticate_auth_request(&input, &ctx)
            .unwrap();
        let output = std::format!(
            "{ctx:?}{input:?}{record_debug}{:?}{grant:?}",
            grant.device()
        );
        for private in [
            OWNER,
            ID,
            CODE,
            IP,
            "cli",
            "alice",
            "new-login-device",
            "not a number",
        ] {
            assert!(!output.contains(private));
        }
        assert!(output.contains("AuthorizedAuthRequestGrant"));
    }
}
