//! Reusable password-method refresh authorization over a current device authority.
//!
//! Providers verify opaque proofs, validity times and device/account bindings. This
//! module has no clock, cryptography, token encoding, persistent token state or allocator.
//! Refresh is not one-time consumption: a still-valid proof can authorize repeated grants.

use crate::{ApiError, Storage, VaultService, identity::Secret, wire::RefreshTokenRequest};

/// Trusted method recorded by the proof issuer, never selected by a request field.
/// This service currently supports only Password; the others are explicit rejection states.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshMethod {
    Password,
    Sso,
    UserApiKey,
    OrgApiKey,
}

/// Identity resolved from a verified proof's current device authority and its account.
/// Owner and device handles are owned values with no allocation, Debug or Clone bound.
/// A device identifier can be empty; the provider must still resolve its exact binding.
/// This internal state has redacted Debug and no Serialize implementation.
pub struct RefreshIdentity<O: AsRef<str>, D: AsRef<str>> {
    pub owner: O,
    pub device_identifier: D,
    pub method: RefreshMethod,
}
impl<O: AsRef<str>, D: AsRef<str>> core::fmt::Debug for RefreshIdentity<O, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RefreshIdentity").finish_non_exhaustive()
    }
}

/// Provider verification result: absent identity means the proof cannot authorize refresh.
pub type RefreshVerification<I, E> = Result<Option<I>, E>;

/// Sealed authority to issue password-method access and refresh tokens.
///
/// No proof is retained or exposed. Owned account/device handles release provider borrows
/// before issuance. This type has no public constructor, Serialize, Clone or Copy. Its
/// client ID comes solely from the current request, independent of prior token client IDs.
pub struct AuthorizedRefreshGrant<'a, O: AsRef<str>, D: AsRef<str>> {
    owner: O,
    device_identifier: D,
    client_id: &'a str,
}
impl<O: AsRef<str>, D: AsRef<str>> core::fmt::Debug for AuthorizedRefreshGrant<'_, O, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthorizedRefreshGrant")
            .finish_non_exhaustive()
    }
}
impl<'a, O: AsRef<str>, D: AsRef<str>> AuthorizedRefreshGrant<'a, O, D> {
    pub fn user_id(&self) -> &str {
        self.owner.as_ref()
    }
    pub fn device_identifier(&self) -> &str {
        self.device_identifier.as_ref()
    }
    pub const fn client_id(&self) -> &'a str {
        self.client_id
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

/// Opt-in password-method refresh without imposing new hooks on existing Storage adapters.
///
/// Hold the application's operation lock/transaction across verification, preparation and
/// issuance, keeping account/device authority stable. verify_refresh_token must verify
/// authenticity and validity time, resolve the CURRENT persistent device authority and its
/// existing account, and return None for invalid, expired, revoked or unbound proofs. A
/// proof's method and owner come from trusted issuance/storage, never caller owner/device
/// fields. Pass the exact opaque Secret to the provider without core trimming or decoding.
/// JWT providers own signature/issuer/nbf/exp policy, including upstream whitespace removal
/// and 30-second leeway if targeting that contract; an adapter may use opaque stored handles.
///
/// Verification must not consume or rotate a valid proof. Repeated use stays valid while
/// its original validity time and current device authority permit it. Issuing a new proof
/// must not extend the original proof's deadline or invalidate still-valid earlier proofs.
/// Source refresh JWTs can even have identical bytes when reissued within one second.
/// Revocation/reset must invalidate old persistent device authority and all proofs tied to
/// it; recreating the same device identifier must not revive an old proof. Existing access
/// tokens retain their original deadlines, subject to separate source revocation rules.
///
/// prepare_password_refresh completes current password-method policy and device activity
/// before issuance. Do not add an account-enabled or old security-stamp comparison: the
/// pinned password refresh path does neither. Account keys, credentials, client KDF,
/// revision, vault contents and unrelated devices must stay unchanged. Policy/clock/crypto,
/// token response projection and durable issuance are adapter responsibilities. Earlier
/// successful activity writes may survive a later failure upstream; whole-operation rollback
/// is not promised here. A host may provide a stronger atomic issuance boundary. Unsupported
/// SSO/API methods are rejected before preparation; their source activity-before-failure
/// behavior and SSO policy/exchange semantics remain outside this password-only service.
pub trait RefreshStorage: Storage {
    type OwnerId: AsRef<str>;
    type DeviceId: AsRef<str>;

    fn verify_refresh_token(
        &mut self,
        refresh_token: &Secret<'_>,
    ) -> RefreshVerification<RefreshIdentity<Self::OwnerId, Self::DeviceId>, Self::Error>;

    fn prepare_password_refresh(
        &mut self,
        owner: &str,
        device_identifier: &str,
    ) -> Result<(), Self::Error>;
}
impl<T: RefreshStorage + ?Sized> RefreshStorage for &mut T {
    type OwnerId = T::OwnerId;
    type DeviceId = T::DeviceId;

    fn verify_refresh_token(
        &mut self,
        refresh_token: &Secret<'_>,
    ) -> Result<Option<RefreshIdentity<Self::OwnerId, Self::DeviceId>>, Self::Error> {
        (**self).verify_refresh_token(refresh_token)
    }
    fn prepare_password_refresh(
        &mut self,
        owner: &str,
        device_identifier: &str,
    ) -> Result<(), Self::Error> {
        (**self).prepare_password_refresh(owner, device_identifier)
    }
}

fn unavailable() -> ApiError {
    ApiError::invalid("refresh_token", "Invalid refresh token")
}

impl<S: RefreshStorage> VaultService<S> {
    /// Authorize a password-method refresh without consuming its proof. The transport
    /// maps invalid-proof errors to the refresh-specific invalid_grant response envelope.
    pub fn authenticate_refresh<'a>(
        &mut self,
        request: &RefreshTokenRequest<'a>,
    ) -> Result<AuthorizedRefreshGrant<'a, S::OwnerId, S::DeviceId>, ApiError> {
        if request.grant_type != Some("refresh_token") {
            return Err(ApiError::invalid("grant_type", "Unsupported grant type."));
        }
        let proof = request
            .refresh_token
            .as_ref()
            .ok_or_else(|| ApiError::invalid("refresh_token", "refresh_token cannot be blank"))?;
        let identity = self
            .storage_mut()
            .verify_refresh_token(proof)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        if identity.owner.as_ref().is_empty() || identity.method != RefreshMethod::Password {
            return Err(unavailable());
        }
        self.storage_mut()
            .prepare_password_refresh(identity.owner.as_ref(), identity.device_identifier.as_ref())
            .map_err(S::map_error)?;
        Ok(AuthorizedRefreshGrant {
            owner: identity.owner,
            device_identifier: identity.device_identifier,
            client_id: request.client_id.unwrap_or("undefined"),
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
    const DEVICE: &str = "private-device\0雪";
    const PROOF: &str = " private-refresh-proof\0雪\n ";
    // Owned bounded handles deliberately have no Debug, Clone or Copy implementations.
    struct Handle(&'static str);
    impl AsRef<str> for Handle {
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
        proof: &'static str,
        owner: &'static str,
        device: &'static str,
        method: RefreshMethod,
        account_present: bool,
        device_present: bool,
        proof_authority: u32,
        current_authority: u32,
        now: i64,
        expires_at: i64,
        enabled: bool,
        stamp_matches: bool,
        calls: Vec<&'static str>,
        received_proof: String,
        prepared: Option<(String, String)>,
        touches: usize,
        fail: Option<Fail>,
        failure: ErrorKind,
        unrelated: [u8; 8],
    }
    impl Mock {
        fn new() -> Self {
            Self {
                proof: PROOF,
                owner: OWNER,
                device: DEVICE,
                method: RefreshMethod::Password,
                account_present: true,
                device_present: true,
                proof_authority: 4,
                current_authority: 4,
                now: 1,
                expires_at: 100,
                enabled: true,
                stamp_matches: true,
                calls: vec![],
                received_proof: String::new(),
                prepared: None,
                touches: 0,
                fail: None,
                failure: ErrorKind::Storage,
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
    impl RefreshStorage for Mock {
        type OwnerId = Handle;
        type DeviceId = Handle;
        fn verify_refresh_token(
            &mut self,
            refresh_token: &Secret<'_>,
        ) -> Result<Option<RefreshIdentity<Handle, Handle>>, Self::Error> {
            self.calls.push("verify");
            self.received_proof = refresh_token.expose_secret().into();
            if self.fail == Some(Fail::Verify) {
                return Err(self.failure);
            }
            // Explicit test double only. Real providers own cryptographic/clock policy.
            let valid = refresh_token.expose_secret() == self.proof
                && self.account_present
                && self.device_present
                && self.proof_authority == self.current_authority
                && self.now < self.expires_at;
            Ok(valid.then_some(RefreshIdentity {
                owner: Handle(self.owner),
                device_identifier: Handle(self.device),
                method: self.method,
            }))
        }
        fn prepare_password_refresh(
            &mut self,
            owner: &str,
            device_identifier: &str,
        ) -> Result<(), Self::Error> {
            self.calls.push("prepare");
            assert_eq!(owner, self.owner);
            assert_eq!(device_identifier, self.device);
            self.prepared = Some((owner.into(), device_identifier.into()));
            self.touches += 1;
            if self.fail == Some(Fail::Prepare) {
                return Err(self.failure);
            }
            Ok(())
        }
    }
    fn request() -> RefreshTokenRequest<'static> {
        RefreshTokenRequest {
            grant_type: Some("refresh_token"),
            refresh_token: Some(Secret::new(PROOF)),
            client_id: Some("private-client\0雪"),
        }
    }
    fn error(mock: &mut Mock, request: &RefreshTokenRequest<'_>) -> ApiError {
        VaultService::new(mock)
            .authenticate_refresh(request)
            .unwrap_err()
    }

    #[test]
    fn refresh_grant_and_proof_presence_fail_before_provider() {
        for grant_type in [None, Some(""), Some("Refresh_token"), Some("password")] {
            let mut mock = Mock::new();
            let mut input = request();
            input.grant_type = grant_type;
            input.refresh_token = None;
            assert_eq!(error(&mut mock, &input).field, Some("grant_type"));
            assert!(mock.calls.is_empty());
        }
        let mut mock = Mock::new();
        let mut input = request();
        input.refresh_token = None;
        let failure = error(&mut mock, &input);
        assert_eq!(failure.message, "refresh_token cannot be blank");
        assert_eq!(failure.status_code(), 400);
        assert!(mock.calls.is_empty());
    }

    #[test]
    fn refresh_passes_raw_proof_and_prepares_trusted_identity_before_grant() {
        let mut mock = Mock::new();
        let input = request();
        let grant = VaultService::new(&mut mock)
            .authenticate_refresh(&input)
            .unwrap();
        assert_eq!(grant.user_id(), OWNER);
        assert_eq!(grant.device_identifier(), DEVICE);
        assert_eq!(grant.client_id(), input.client_id.unwrap());
        assert_eq!(grant.scope(), "api offline_access");
        assert_eq!(grant.expires_in(), 7200);
        assert!(grant.allows_refresh());
        assert_eq!(mock.received_proof, PROOF);
        assert_eq!(mock.calls, ["verify", "prepare"]);
        assert_eq!(mock.touches, 1);
        assert_eq!(mock.unrelated, [7; 8]);
        // Neither owner nor device borrows the provider after authorization.
        mock.owner = "changed-provider-cache";
        mock.device = "changed-device-cache";
        assert_eq!(grant.user_id(), OWNER);
        assert_eq!(grant.device_identifier(), DEVICE);
    }

    #[test]
    fn refresh_same_proof_replays_until_its_original_provider_deadline() {
        let mut mock = Mock::new();
        for now in [1, 2, 99] {
            mock.now = now;
            let grant = VaultService::new(&mut mock)
                .authenticate_refresh(&request())
                .unwrap();
            assert_eq!(grant.user_id(), OWNER);
            assert_eq!(mock.expires_at, 100);
            assert_eq!(mock.current_authority, 4);
        }
        assert_eq!(mock.touches, 3);
        mock.now = 100;
        assert_eq!(error(&mut mock, &request()), unavailable());
        assert_eq!(mock.touches, 3);
        assert_eq!(mock.unrelated, [7; 8]);
    }

    #[test]
    fn refresh_missing_client_defaults_and_present_empty_client_device_are_preserved() {
        let mut mock = Mock::new();
        mock.device = "";
        for client_id in [None, Some(""), Some("replacement-client\0雪")] {
            let mut input = request();
            input.client_id = client_id;
            let grant = VaultService::new(&mut mock)
                .authenticate_refresh(&input)
                .unwrap();
            assert_eq!(grant.client_id(), client_id.unwrap_or("undefined"));
            assert_eq!(grant.device_identifier(), "");
        }
        assert_eq!(mock.touches, 3);
    }

    #[test]
    fn refresh_present_empty_proof_is_verified_without_blank_rejection() {
        let mut mock = Mock::new();
        mock.proof = "";
        let mut input = request();
        input.refresh_token = Some(Secret::new(""));
        assert!(
            VaultService::new(&mut mock)
                .authenticate_refresh(&input)
                .is_ok()
        );
        assert_eq!(mock.calls, ["verify", "prepare"]);
        assert_eq!(mock.received_proof, "");
        // Acceptance is the test provider's decision, not a claim that an empty JWT is valid.
    }

    #[test]
    fn refresh_invalid_expired_revoked_and_unbound_proofs_fail_without_preparation() {
        for invalid in 0..5 {
            let mut mock = Mock::new();
            let mut input = request();
            match invalid {
                0 => input.refresh_token = Some(Secret::new(PROOF.trim())),
                1 => mock.now = 101,
                2 => mock.current_authority += 1,
                3 => mock.device_present = false,
                _ => mock.account_present = false,
            }
            assert_eq!(error(&mut mock, &input), unavailable());
            assert_eq!(mock.calls, ["verify"]);
            assert_eq!(mock.touches, 0);
            assert_eq!(mock.unrelated, [7; 8]);
        }
    }

    #[test]
    fn refresh_unsupported_methods_and_empty_owner_fail_before_preparation() {
        for method in [
            RefreshMethod::Sso,
            RefreshMethod::UserApiKey,
            RefreshMethod::OrgApiKey,
        ] {
            let mut mock = Mock::new();
            mock.method = method;
            assert_eq!(error(&mut mock, &request()), unavailable());
            assert_eq!(mock.calls, ["verify"]);
            assert_eq!(mock.touches, 0);
        }
        let mut mock = Mock::new();
        mock.owner = "";
        assert_eq!(error(&mut mock, &request()), unavailable());
        assert_eq!(mock.calls, ["verify"]);
    }

    #[test]
    fn refresh_does_not_add_enabled_or_old_security_stamp_checks() {
        let mut mock = Mock::new();
        mock.enabled = false;
        mock.stamp_matches = false;
        let grant = VaultService::new(&mut mock)
            .authenticate_refresh(&request())
            .unwrap();
        assert_eq!(grant.user_id(), OWNER);
        assert!(!mock.enabled && !mock.stamp_matches);
        assert_eq!(mock.calls, ["verify", "prepare"]);
        assert_eq!(mock.unrelated, [7; 8]);
    }

    #[test]
    fn refresh_provider_failures_keep_typed_errors_without_false_rollback_promises() {
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
                assert_eq!(mock.touches, usize::from(fail == Fail::Prepare));
                assert_eq!(mock.unrelated, [7; 8]);
            }
        }
    }

    #[test]
    fn refresh_borrowed_adapter_forwards_verification_and_preparation() {
        let mut mock = Mock::new();
        let mut borrowed = &mut mock;
        let grant = VaultService::new(&mut borrowed)
            .authenticate_refresh(&request())
            .unwrap();
        assert_eq!(grant.user_id(), OWNER);
        assert_eq!(mock.calls, ["verify", "prepare"]);
    }

    #[test]
    fn refresh_wire_borrows_proof_and_ignores_unrelated_form_view_fields() {
        let json = r#"{"grant_type":"refresh_token","refreshtoken":"private-proof","clientid":"","scope":"ignored","deviceIdentifier":"ignored","owner":"forged"}"#;
        let input: RefreshTokenRequest<'_> = serde_json::from_str(json).unwrap();
        assert_eq!(input.client_id, Some(""));
        let proof = input.refresh_token.as_ref().unwrap().expose_secret();
        assert_eq!(proof, "private-proof");
        assert!(json.as_bytes().as_ptr_range().contains(&proof.as_ptr()));
        assert_eq!(format!("{input:?}"), "RefreshTokenRequest { .. }");
        let missing: RefreshTokenRequest<'_> = serde_json::from_str("{}").unwrap();
        assert!(missing.refresh_token.is_none() && missing.client_id.is_none());
        for invalid in [r#"{"refresh_token":1}"#, r#"{"client_id":false}"#] {
            assert!(serde_json::from_str::<RefreshTokenRequest<'_>>(invalid).is_err());
        }
    }

    #[test]
    fn refresh_private_identity_request_and_grant_debug_redact_without_handle_bounds() {
        let identity = RefreshIdentity {
            owner: Handle(OWNER),
            device_identifier: Handle(DEVICE),
            method: RefreshMethod::Password,
        };
        assert_eq!(format!("{identity:?}"), "RefreshIdentity { .. }");
        let input = request();
        let mut mock = Mock::new();
        let grant = VaultService::new(&mut mock)
            .authenticate_refresh(&input)
            .unwrap();
        assert_eq!(format!("{grant:?}"), "AuthorizedRefreshGrant { .. }");
        assert_eq!(format!("{input:?}"), "RefreshTokenRequest { .. }");
    }
}
