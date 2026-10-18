//! Provider-driven personal API-key management and client-credentials authorization.
//!
//! Credential verification, randomness, confidential persistence, time, transport policy,
//! rate limiting, device registration, and token signing belong to the host. These services
//! never decrypt a vault or handle the user's plaintext master password.

use core::fmt;
use serde::Deserialize;

use crate::{
    ApiError, Storage, VaultService,
    service::require_owner,
    wire::{ApiKeyResponse, ClientCredentialsRequest, PasswordOrOtpRequest},
};

/// Borrowed sensitive input with redacted formatting and explicit exposure.
///
/// The embedding application owns and clears its input buffers. This borrowed wrapper
/// cannot erase them. It deliberately has no Display, Clone, Copy, equality, or Serialize
/// implementation; providers must perform credential verification themselves.
///
/// ```compile_fail
/// fn serializable<T: serde::Serialize>(_: &T) {}
/// let secret = no_warden::identity::Secret::new("test-only-secret");
/// serializable(&secret);
/// ```
#[derive(Deserialize)]
#[serde(transparent)]
pub struct Secret<'a>(#[serde(borrow)] &'a str);

impl<'a> Secret<'a> {
    pub const fn new(value: &'a str) -> Self {
        Self(value)
    }

    pub const fn expose_secret(&self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for Secret<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

#[derive(Debug)]
pub enum ReauthenticationProof<'a> {
    MasterPasswordHash(Secret<'a>),
    ProtectedActionOtp(Secret<'a>),
}

impl<'a> PasswordOrOtpRequest<'a> {
    pub fn proof(&self) -> Result<ReauthenticationProof<'a>, ApiError> {
        match (&self.master_password_hash, &self.otp) {
            (Some(password), None) => Ok(ReauthenticationProof::MasterPasswordHash(Secret::new(
                password.expose_secret(),
            ))),
            (None, Some(otp)) => Ok(ReauthenticationProof::ProtectedActionOtp(Secret::new(
                otp.expose_secret(),
            ))),
            _ => Err(ApiError::invalid(
                "reauthentication",
                "Exactly one reauthentication proof is required.",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyDevice<'a> {
    pub identifier: &'a str,
    pub name: &'a str,
    pub device_type: &'a str,
}

/// Verified user API-key authority, distinct from password/refresh authority.
///
/// Only this module constructs a grant after provider verification. The external issuer
/// must preserve its API-only scope and access-only lifetime, without issuing refresh
/// authority or treating this credential as a plaintext-vault unlock key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedApiKeyGrant<'a> {
    user_id: &'a str,
    client_id: &'a str,
    device: ApiKeyDevice<'a>,
}

impl<'a> AuthorizedApiKeyGrant<'a> {
    pub const fn user_id(&self) -> &'a str {
        self.user_id
    }
    pub const fn client_id(&self) -> &'a str {
        self.client_id
    }
    pub const fn device(&self) -> ApiKeyDevice<'a> {
        self.device
    }
    pub const fn scope(&self) -> &'static str {
        "api"
    }
    pub const fn expires_in(&self) -> u32 {
        7200
    }
    pub const fn allows_refresh(&self) -> bool {
        false
    }
}

/// Opt-in identity operations sharing the application's existing storage error mapping.
///
/// Keep reauthentication and key access within the authenticated operation's lock/context.
/// Verify password hashes with the password provider. Protected-action OTP verification
/// must check its account, purpose, expiry, and consumption policy; it is not TOTP. Hosts
/// without that provider must reject the proof. No credential may appear in diagnostics.
///
/// Get-or-create must return the original key without a revision change when one exists.
/// Otherwise it securely generates and confidentially stores a recoverable key, atomically
/// with the account revision. Rotation securely replaces the key and advances the revision;
/// a failure must preserve the previous key/revision. Neither operation revokes existing
/// bearer/refresh sessions or changes the security stamp. Future old-key logins fail.
/// Upstream keys contain 30 securely random ASCII alphanumeric characters; key inputs are
/// opaque credentials, not encrypted-string envelopes. Do not store keys in profile/sync
/// documents or other public account data.
///
/// API-key verification must require an enabled account and use an appropriate constant-time
/// credential verifier. It must not generate missing keys or accept password credentials.
/// Host rate limiting, device policy/registration, and issuance happen outside this crate;
/// supporting this interface alone does not implement those controls. Persist issued
/// API-key authority separately from password refresh authority, with no refresh token.
pub trait IdentityStorage: Storage {
    fn verify_reauthentication(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error>;

    fn get_or_create_api_key(&mut self, owner: &str) -> Result<ApiKeyResponse<'_>, Self::Error>;

    fn rotate_api_key(&mut self, owner: &str) -> Result<ApiKeyResponse<'_>, Self::Error>;

    fn verify_api_key(
        &mut self,
        user_id: &str,
        secret: &Secret<'_>,
        device: ApiKeyDevice<'_>,
    ) -> Result<bool, Self::Error>;
}

impl<T: IdentityStorage + ?Sized> IdentityStorage for &mut T {
    fn verify_reauthentication(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).verify_reauthentication(owner, proof)
    }
    fn get_or_create_api_key(&mut self, owner: &str) -> Result<ApiKeyResponse<'_>, Self::Error> {
        (**self).get_or_create_api_key(owner)
    }
    fn rotate_api_key(&mut self, owner: &str) -> Result<ApiKeyResponse<'_>, Self::Error> {
        (**self).rotate_api_key(owner)
    }
    fn verify_api_key(
        &mut self,
        user_id: &str,
        secret: &Secret<'_>,
        device: ApiKeyDevice<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).verify_api_key(user_id, secret, device)
    }
}

fn reauthenticate<S: IdentityStorage>(
    storage: &mut S,
    owner: &str,
    request: &PasswordOrOtpRequest<'_>,
) -> Result<(), ApiError> {
    require_owner(owner)?;
    if !storage
        .verify_reauthentication(owner, request.proof()?)
        .map_err(S::map_error)?
    {
        return Err(ApiError::invalid(
            "reauthentication",
            "Reauthentication failed.",
        ));
    }
    Ok(())
}

impl<S: IdentityStorage> VaultService<S> {
    pub fn get_api_key(
        &mut self,
        owner: &str,
        request: &PasswordOrOtpRequest<'_>,
    ) -> Result<ApiKeyResponse<'_>, ApiError> {
        reauthenticate(self.storage_mut(), owner, request)?;
        self.storage_mut()
            .get_or_create_api_key(owner)
            .map_err(S::map_error)
    }

    pub fn rotate_api_key(
        &mut self,
        owner: &str,
        request: &PasswordOrOtpRequest<'_>,
    ) -> Result<ApiKeyResponse<'_>, ApiError> {
        reauthenticate(self.storage_mut(), owner, request)?;
        self.storage_mut()
            .rotate_api_key(owner)
            .map_err(S::map_error)
    }

    pub fn authenticate_api_key<'a>(
        &mut self,
        request: &ClientCredentialsRequest<'a>,
    ) -> Result<AuthorizedApiKeyGrant<'a>, ApiError> {
        let required = |field| ApiError::invalid(field, "A required grant field is missing.");
        if request.grant_type != Some("client_credentials") {
            return Err(ApiError::invalid("grant_type", "Unsupported grant type."));
        }
        let client_id = request.client_id.ok_or_else(|| required("client_id"))?;
        let secret = request
            .client_secret
            .as_ref()
            .ok_or_else(|| required("client_secret"))?;
        if request.scope != Some("api") {
            return Err(ApiError::invalid("scope", "Unsupported API-key scope."));
        }
        let device = ApiKeyDevice {
            identifier: request
                .device_identifier
                .ok_or_else(|| required("deviceIdentifier"))?,
            name: request.device_name.ok_or_else(|| required("deviceName"))?,
            device_type: request.device_type.ok_or_else(|| required("deviceType"))?,
        };
        let user_id = client_id.strip_prefix("user.").ok_or(ApiError::invalid(
            "client_id",
            "A user API-key client identifier is required.",
        ))?;
        if !self
            .storage_mut()
            .verify_api_key(user_id, secret, device)
            .map_err(S::map_error)?
        {
            return Err(ApiError::invalid(
                "client_credentials",
                "Invalid client credentials.",
            ));
        }
        Ok(AuthorizedApiKeyGrant {
            user_id,
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
    use std::{
        string::{String, ToString},
        vec::Vec,
    };

    const ACCOUNT: &str = "opaque:User/Case";
    const CLIENT: &str = "user.opaque:User/Case";
    const FIRST_KEY: &str = "012345678901234567890123456789";
    const SECOND_KEY: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcd";

    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Backend,
        Conflict,
    }

    struct Memory {
        key: Option<&'static str>,
        revision: usize,
        revision_date: String,
        enabled: bool,
        otp_available: bool,
        sessions: (bool, bool),
        calls: Vec<&'static str>,
        fail_at: Option<&'static str>,
        failure: Failure,
        received_user: Option<String>,
        received_device: Option<(String, String, String)>,
    }

    impl fmt::Debug for Memory {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("Memory")
                .field("calls", &self.calls)
                .finish_non_exhaustive()
        }
    }

    impl Memory {
        fn new() -> Self {
            Self {
                key: None,
                revision: 0,
                revision_date: "revision-0".into(),
                enabled: true,
                otp_available: true,
                sessions: (true, true),
                calls: Vec::new(),
                fail_at: None,
                failure: Failure::Backend,
                received_user: None,
                received_device: None,
            }
        }
        fn called(&mut self, name: &'static str) -> Result<(), Failure> {
            self.calls.push(name);
            if self.fail_at == Some(name) {
                Err(self.failure)
            } else {
                Ok(())
            }
        }
        fn update(&mut self, key: &'static str) {
            self.key = Some(key);
            self.revision += 1;
            self.revision_date = std::format!("revision-{}", self.revision);
        }
        fn response(&self) -> ApiKeyResponse<'_> {
            ApiKeyResponse {
                api_key: Secret::new(self.key.unwrap()),
                revision_date: &self.revision_date,
            }
        }
    }

    impl Storage for Memory {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::Backend => ApiError::new(ErrorKind::Storage, "Identity provider failed."),
                Failure::Conflict => {
                    ApiError::new(ErrorKind::Conflict, "Retry the identity operation.")
                }
            }
        }
        fn account_exists(&mut self, _: &str) -> Result<bool, Failure> {
            unreachable!()
        }
        fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), Failure> {
            unreachable!()
        }
        fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            unreachable!()
        }
        fn save_folder(&mut self, _: &str, _: &str, _: &FolderRequest<'_>) -> Result<(), Failure> {
            unreachable!()
        }
        fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), Failure> {
            unreachable!()
        }
        fn cipher_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            unreachable!()
        }
        fn save_cipher(&mut self, _: &str, _: &str, _: &CipherRequest<'_>) -> Result<(), Failure> {
            unreachable!()
        }
        fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), Failure> {
            unreachable!()
        }
        fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), Failure> {
            unreachable!()
        }
    }

    impl IdentityStorage for Memory {
        fn verify_reauthentication(
            &mut self,
            owner: &str,
            proof: ReauthenticationProof<'_>,
        ) -> Result<bool, Failure> {
            self.called("verify_reauthentication")?;
            if owner != ACCOUNT {
                return Ok(false);
            }
            // Deterministic fixtures only. Real providers must use their credential verifier.
            Ok(match proof {
                ReauthenticationProof::MasterPasswordHash(password) => {
                    password.expose_secret() == "authorization-hash"
                }
                ReauthenticationProof::ProtectedActionOtp(otp) => {
                    let valid =
                        self.otp_available && otp.expose_secret() == "protected-action-proof";
                    if valid {
                        self.otp_available = false;
                    }
                    valid
                }
            })
        }
        fn get_or_create_api_key(&mut self, _: &str) -> Result<ApiKeyResponse<'_>, Failure> {
            self.called("get_or_create_api_key")?;
            if self.key.is_none() {
                self.update(FIRST_KEY);
            }
            Ok(self.response())
        }
        fn rotate_api_key(&mut self, _: &str) -> Result<ApiKeyResponse<'_>, Failure> {
            self.called("rotate_api_key")?;
            self.update(SECOND_KEY);
            Ok(self.response())
        }
        fn verify_api_key(
            &mut self,
            user_id: &str,
            secret: &Secret<'_>,
            device: ApiKeyDevice<'_>,
        ) -> Result<bool, Failure> {
            self.called("verify_api_key")?;
            self.received_user = Some(user_id.to_string());
            self.received_device = Some((
                device.identifier.to_string(),
                device.name.to_string(),
                device.device_type.to_string(),
            ));
            Ok(self.enabled && user_id == ACCOUNT && self.key == Some(secret.expose_secret()))
        }
    }

    fn password_proof() -> PasswordOrOtpRequest<'static> {
        PasswordOrOtpRequest {
            master_password_hash: Some(Secret::new("authorization-hash")),
            otp: None,
        }
    }
    fn credentials() -> ClientCredentialsRequest<'static> {
        ClientCredentialsRequest {
            grant_type: Some("client_credentials"),
            client_id: Some(CLIENT),
            client_secret: Some(Secret::new(FIRST_KEY)),
            scope: Some("api"),
            device_identifier: Some(""),
            device_name: Some(""),
            device_type: Some("iOS"),
        }
    }

    #[test]
    fn exactly_one_proof_is_checked_before_any_provider_call() {
        let mut storage = Memory::new();
        for request in [
            PasswordOrOtpRequest {
                master_password_hash: None,
                otp: None,
            },
            PasswordOrOtpRequest {
                master_password_hash: Some(Secret::new("authorization-hash")),
                otp: Some(Secret::new("protected-action-proof")),
            },
        ] {
            for rotate in [false, true] {
                let mut service = VaultService::new(&mut storage);
                let error = if rotate {
                    service.rotate_api_key(ACCOUNT, &request)
                } else {
                    service.get_api_key(ACCOUNT, &request)
                }
                .unwrap_err();
                assert_eq!(error.status_code(), 400);
            }
        }
        assert_eq!(
            VaultService::new(&mut storage)
                .get_api_key("", &password_proof())
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert!(storage.calls.is_empty());
        assert!(storage.key.is_none());
    }

    #[test]
    fn failed_password_and_consumed_protected_action_proofs_cannot_reveal_a_key() {
        let mut storage = Memory::new();
        let wrong = PasswordOrOtpRequest {
            master_password_hash: Some(Secret::new("wrong authorization hash")),
            otp: None,
        };
        assert_eq!(
            VaultService::new(&mut storage)
                .get_api_key(ACCOUNT, &wrong)
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(storage.calls, ["verify_reauthentication"]);
        assert!(storage.key.is_none());
        let otp = PasswordOrOtpRequest {
            master_password_hash: None,
            otp: Some(Secret::new("protected-action-proof")),
        };
        {
            let mut service = VaultService::new(&mut storage);
            assert_eq!(
                service
                    .get_api_key(ACCOUNT, &otp)
                    .unwrap()
                    .api_key
                    .expose_secret(),
                FIRST_KEY
            );
        }
        let previous_revision = storage.revision;
        assert!(
            VaultService::new(&mut storage)
                .rotate_api_key(ACCOUNT, &otp)
                .is_err()
        );
        assert_eq!(storage.key, Some(FIRST_KEY));
        assert_eq!(storage.revision, previous_revision);
    }

    #[test]
    fn repeated_get_preserves_key_and_revision_and_rotation_preserves_existing_sessions() {
        let mut storage = Memory::new();
        let proof = password_proof();
        for _ in 0..2 {
            let mut service = VaultService::new(&mut storage);
            let response = service.get_api_key(ACCOUNT, &proof).unwrap();
            assert_eq!(response.api_key.expose_secret(), FIRST_KEY);
            assert_eq!(response.revision_date, "revision-1");
        }
        assert!(
            VaultService::new(&mut storage)
                .authenticate_api_key(&credentials())
                .is_ok()
        );
        {
            let mut service = VaultService::new(&mut storage);
            let response = service.rotate_api_key(ACCOUNT, &proof).unwrap();
            assert_eq!(response.api_key.expose_secret(), SECOND_KEY);
            assert_eq!(response.revision_date, "revision-2");
        }
        assert_eq!(storage.sessions, (true, true));
        assert!(
            VaultService::new(&mut storage)
                .authenticate_api_key(&credentials())
                .is_err()
        );
        let mut rotated = credentials();
        rotated.client_secret = Some(Secret::new(SECOND_KEY));
        assert!(
            VaultService::new(&mut storage)
                .authenticate_api_key(&rotated)
                .is_ok()
        );
    }

    #[test]
    fn invalid_request_fields_never_reach_the_credential_provider() {
        type Mutator = fn(&mut ClientCredentialsRequest<'static>);
        let cases: &[(&str, Mutator)] = &[
            ("grant_type", |request| request.grant_type = None),
            ("grant_type", |request| {
                request.grant_type = Some("password")
            }),
            ("client_id", |request| request.client_id = None),
            ("client_secret", |request| request.client_secret = None),
            ("scope", |request| request.scope = None),
            ("scope", |request| {
                request.scope = Some("api offline_access")
            }),
            ("scope", |request| request.scope = Some("api.organization")),
            ("scope", |request| request.scope = Some(" api")),
            ("deviceIdentifier", |request| {
                request.device_identifier = None
            }),
            ("deviceName", |request| request.device_name = None),
            ("deviceType", |request| request.device_type = None),
            ("client_id", |request| {
                request.client_id = Some("USER.opaque:User/Case")
            }),
            ("client_id", |request| {
                request.client_id = Some("organization.opaque:User/Case")
            }),
        ];
        for (field, mutate) in cases {
            let mut request = credentials();
            mutate(&mut request);
            let mut storage = Memory::new();
            assert_eq!(
                VaultService::new(&mut storage)
                    .authenticate_api_key(&request)
                    .unwrap_err()
                    .field,
                Some(*field)
            );
            assert!(storage.calls.is_empty());
        }
        let mut request = credentials();
        request.grant_type = Some("password");
        request.client_secret = None;
        let mut storage = Memory::new();
        assert_eq!(
            VaultService::new(&mut storage)
                .authenticate_api_key(&request)
                .unwrap_err()
                .field,
            Some("grant_type")
        );
        assert!(storage.calls.is_empty());
    }

    #[test]
    fn verified_grants_preserve_raw_identity_and_device_fields_and_cannot_refresh() {
        let mut storage = Memory::new();
        storage.key = Some(FIRST_KEY);
        let request = credentials();
        let grant = VaultService::new(&mut storage)
            .authenticate_api_key(&request)
            .unwrap();
        assert_eq!(grant.user_id(), ACCOUNT);
        assert_eq!(grant.client_id(), CLIENT);
        assert_eq!(grant.scope(), "api");
        assert_eq!(grant.expires_in(), 7200);
        assert!(!grant.allows_refresh());
        assert_eq!(
            grant.device(),
            ApiKeyDevice {
                identifier: "",
                name: "",
                device_type: "iOS"
            }
        );
        assert_eq!(storage.received_user.as_deref(), Some(ACCOUNT));
        assert_eq!(
            storage.received_device,
            Some(("".into(), "".into(), "iOS".into()))
        );
        assert_eq!(storage.calls, ["verify_api_key"]);
        assert!(!std::format!("{grant:?}").contains(FIRST_KEY));
    }

    #[test]
    fn invalid_missing_and_disabled_credentials_share_one_safe_error_without_creating_keys() {
        let mut errors = Vec::new();
        for case in 0..4 {
            let mut request = credentials();
            let mut storage = Memory::new();
            storage.key = Some(FIRST_KEY);
            match case {
                0 => request.client_secret = Some(Secret::new("wrong secret")),
                1 => request.client_id = Some("user.opaque:user/case"),
                2 => storage.enabled = false,
                _ => storage.key = None,
            }
            let before = storage.key;
            let error = VaultService::new(&mut storage)
                .authenticate_api_key(&request)
                .unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert!(!std::format!("{error:?}").contains("wrong secret"));
            assert_eq!(storage.calls, ["verify_api_key"]);
            assert_eq!(storage.key, before);
            assert_eq!(storage.revision, 0);
            errors.push(error);
        }
        assert!(errors.windows(2).all(|pair| pair[0] == pair[1]));
    }

    #[test]
    fn provider_errors_preserve_key_authority_and_use_the_existing_error_mapper() {
        for call in [
            "verify_reauthentication",
            "get_or_create_api_key",
            "rotate_api_key",
            "verify_api_key",
        ] {
            for failure in [Failure::Backend, Failure::Conflict] {
                let mut storage = Memory::new();
                storage.update(FIRST_KEY);
                storage.fail_at = Some(call);
                storage.failure = failure;
                let expected = match failure {
                    Failure::Backend => ErrorKind::Storage,
                    Failure::Conflict => ErrorKind::Conflict,
                };
                let mut service = VaultService::new(&mut storage);
                let error = match call {
                    "rotate_api_key" => service
                        .rotate_api_key(ACCOUNT, &password_proof())
                        .unwrap_err(),
                    "verify_api_key" => service.authenticate_api_key(&credentials()).unwrap_err(),
                    _ => service.get_api_key(ACCOUNT, &password_proof()).unwrap_err(),
                };
                assert_eq!(error.kind, expected);
                assert_eq!(storage.key, Some(FIRST_KEY));
                assert_eq!(storage.revision, 1);
                assert_eq!(storage.sessions, (true, true));
                assert!(!storage.calls.contains(&"rotate_api_key") || call == "rotate_api_key");
            }
        }
    }
}
