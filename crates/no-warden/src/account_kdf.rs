//! Client KDF changes with opaque credential replacement through opt-in providers.
//!
//! Only the signed KDF value is shared with registration. This endpoint has a distinct,
//! nested-only wire schema and verifies the old password before inspecting the new values.
//! Password hashing, Unicode salt policy, stamp randomness, clocks and storage stay outside
//! the allocation-free core.

use crate::{
    ApiError, Storage, VaultService,
    identity::Secret,
    service::require_owner,
    wire::{AccountKdfRequest, RegistrationKdf},
};

/// Validated credential transition. Only this module can construct a plan after checking
/// the old proof, both complete KDF values, both salts and the signed KDF policy.
/// No hash/key is logged, normalized, interpreted as plaintext or implicitly serialized.
pub struct ValidatedAccountKdf<'a> {
    old_password_hash: Secret<'a>,
    new_password_hash: Secret<'a>,
    key: Secret<'a>,
    kdf: RegistrationKdf,
}
impl core::fmt::Debug for ValidatedAccountKdf<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatedAccountKdf")
            .finish_non_exhaustive()
    }
}
impl ValidatedAccountKdf<'_> {
    pub const fn old_password_hash(&self) -> &Secret<'_> {
        &self.old_password_hash
    }
    pub const fn new_password_hash(&self) -> &Secret<'_> {
        &self.new_password_hash
    }
    pub const fn key(&self) -> &Secret<'_> {
        &self.key
    }
    pub const fn kdf(&self) -> RegistrationKdf {
        self.kdf
    }
}

/// Opt-in KDF changes, preserving existing Storage and identity implementations.
/// Hold the authenticated operation's lock across each service call, or recheck the old
/// proof under the mutation transaction so a concurrent credential change cannot be lost.
///
/// verify_account_kdf_password verifies the exact old client server-authorization hash
/// using the provider's password verifier. Return None for missing accounts or invalid
/// proofs. Return an owned handle to the authoritative account salt on success; a String
/// or caller-bounded buffer can implement AsRef<str> without requiring an allocator here.
/// The salt must not come from untrusted document extensions. Its versioned normalization
/// is provider policy: the pinned upstream trims/Unicode-lowercases its stored email,
/// whereas release 1.37.4 compares the stored email exactly. The core compares the returned
/// salt exactly and never normalizes a request. Protected-action OTP is not accepted here.
///
/// change_account_kdf securely hashes the new opaque proof, replaces only the wrapped user
/// key and normalized client KDF fields, generates a fresh private stamp and advances account
/// revision. Invalidate ordinary prior bearer/refresh/remember authority, including the
/// acting device's authority, while preserving device registrations and their push state.
/// Preserve an existing password-change previous-stamp exception and its original deadline;
/// it can still authorize only its configured routes after normal device/JWT guards.
/// Preserve asymmetric keys, user-key IDs, API credentials, hints, all auth requests,
/// vault data and foreign accounts. Recheck the old proof when the operation is not protected
/// by a shared lock. The core never issues new session authority as part of this operation.
///
/// The provider defines its persistence boundary. An atomic credential/KDF/key/stamp/
/// revision/session transaction with rollback on error is stronger than upstream's sequential
/// refresh rotation and user save; merely returning an error does not promise rollback.
/// Notifications excluding the acting device, external delivery and time belong to adapters.
/// No plaintext-password, cipher re-encryption or envelope/base64 validation is performed.
pub trait AccountKdfStorage: Storage {
    type Salt: AsRef<str>;

    fn verify_account_kdf_password(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
    ) -> Result<Option<Self::Salt>, Self::Error>;
    fn change_account_kdf(
        &mut self,
        owner: &str,
        plan: &ValidatedAccountKdf<'_>,
    ) -> Result<(), Self::Error>;
}
impl<T: AccountKdfStorage + ?Sized> AccountKdfStorage for &mut T {
    type Salt = T::Salt;

    fn verify_account_kdf_password(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
    ) -> Result<Option<Self::Salt>, Self::Error> {
        (**self).verify_account_kdf_password(owner, password)
    }
    fn change_account_kdf(
        &mut self,
        owner: &str,
        plan: &ValidatedAccountKdf<'_>,
    ) -> Result<(), Self::Error> {
        (**self).change_account_kdf(owner, plan)
    }
}

fn validated_kdf(mut kdf: RegistrationKdf) -> Result<RegistrationKdf, ApiError> {
    if kdf.kdf == 0 && kdf.kdf_iterations < 100_000 {
        return Err(ApiError::invalid(
            "kdfIterations",
            "PBKDF2 KDF iterations must be at least 100000.",
        ));
    }
    if kdf.kdf == 1 {
        if kdf.kdf_iterations < 1 {
            return Err(ApiError::invalid(
                "kdfIterations",
                "Argon2 KDF iterations must be at least 1.",
            ));
        }
        match kdf.kdf_memory {
            Some(15..=1024) => {}
            Some(_) => {
                return Err(ApiError::invalid(
                    "kdfMemory",
                    "Argon2 memory must be between 15 MB and 1024 MB.",
                ));
            }
            None => {
                return Err(ApiError::invalid(
                    "kdfMemory",
                    "Argon2 memory parameter is required.",
                ));
            }
        }
        match kdf.kdf_parallelism {
            Some(1..=16) => {}
            Some(_) => {
                return Err(ApiError::invalid(
                    "kdfParallelism",
                    "Argon2 parallelism must be between 1 and 16.",
                ));
            }
            None => {
                return Err(ApiError::invalid(
                    "kdfParallelism",
                    "Argon2 parallelism parameter is required.",
                ));
            }
        }
    } else {
        kdf.kdf_memory = None;
        kdf.kdf_parallelism = None;
    }
    Ok(kdf)
}

impl<S: AccountKdfStorage> VaultService<S> {
    pub fn change_kdf(
        &mut self,
        owner: &str,
        request: &AccountKdfRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let salt = self
            .storage_mut()
            .verify_account_kdf_password(owner, &request.master_password_hash)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("masterPasswordHash", "Invalid password"))?;
        let authentication = &request.authentication_data;
        let unlock = &request.unlock_data;
        if authentication.kdf != unlock.kdf {
            return Err(ApiError::invalid(
                "authenticationData",
                "KDF settings must be equal for authentication and unlock",
            ));
        }
        if salt.as_ref() != authentication.salt || salt.as_ref() != unlock.salt {
            return Err(ApiError::invalid("salt", "Invalid master password salt"));
        }
        let kdf = validated_kdf(unlock.kdf)?;
        let plan = ValidatedAccountKdf {
            old_password_hash: Secret::new(request.master_password_hash.expose_secret()),
            new_password_hash: Secret::new(
                authentication
                    .master_password_authentication_hash
                    .expose_secret(),
            ),
            key: Secret::new(unlock.master_key_wrapped_user_key.expose_secret()),
            kdf,
        };
        self.storage_mut()
            .change_account_kdf(owner, &plan)
            .map_err(S::map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind,
        service::ItemMetadata,
        wire::{
            AccountKdfAuthentication, AccountKdfUnlock, CipherRequest, FolderRequest,
            RegisterRequest,
        },
    };
    use std::{string::String, vec, vec::Vec};

    const OWNER: &str = "authenticated-owner";
    const OLD: &str = "private-old-proof\0雪";
    const SALT: &str = "owner@example.test";

    #[derive(Clone, Eq, PartialEq)]
    struct State {
        password: String,
        key: String,
        kdf: RegistrationKdf,
        stamp: u32,
        revision: u32,
        sessions: usize,
        devices: usize,
        retained: (&'static str, &'static str, &'static str, usize),
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fail {
        Verify,
        Commit,
    }
    struct Mock {
        calls: Vec<&'static str>,
        state: State,
        salt: &'static str,
        fail: Option<Fail>,
        commit_then_fail: bool,
        concurrent_change: bool,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                calls: vec![],
                state: State {
                    password: String::from(OLD),
                    key: String::from("prior-wrapped-key"),
                    kdf: pbkdf(),
                    stamp: 1,
                    revision: 10,
                    sessions: 4,
                    devices: 3,
                    retained: ("asymmetric/API/ID/hint", "vault", "foreign-owner", 6),
                },
                salt: SALT,
                fail: None,
                commit_then_fail: false,
                concurrent_change: false,
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
    impl AccountKdfStorage for Mock {
        type Salt = &'static str;
        fn verify_account_kdf_password(
            &mut self,
            owner: &str,
            password: &Secret<'_>,
        ) -> Result<Option<Self::Salt>, Self::Error> {
            self.calls.push("verify");
            if self.fail == Some(Fail::Verify) {
                return Err(ErrorKind::Storage);
            }
            // Equality is confined to this test double; real providers own verification.
            Ok(
                (owner == OWNER && password.expose_secret() == self.state.password)
                    .then_some(self.salt),
            )
        }
        fn change_account_kdf(
            &mut self,
            owner: &str,
            plan: &ValidatedAccountKdf<'_>,
        ) -> Result<(), Self::Error> {
            self.calls.push("commit");
            assert!(owner == OWNER);
            if self.concurrent_change {
                return Err(ErrorKind::Conflict);
            }
            assert!(plan.old_password_hash().expose_secret() == self.state.password);
            assert!(!std::format!("{plan:?}").contains("private"));
            if self.fail == Some(Fail::Commit) && !self.commit_then_fail {
                return Err(ErrorKind::Storage);
            }
            self.state.password = String::from(plan.new_password_hash().expose_secret());
            self.state.key = String::from(plan.key().expose_secret());
            self.state.kdf = plan.kdf();
            self.state.stamp += 1;
            self.state.revision += 1;
            self.state.sessions = 0;
            if self.fail == Some(Fail::Commit) {
                Err(ErrorKind::Storage)
            } else {
                Ok(())
            }
        }
    }
    fn pbkdf() -> RegistrationKdf {
        RegistrationKdf {
            kdf: 0,
            kdf_iterations: 100_000,
            kdf_memory: None,
            kdf_parallelism: None,
        }
    }
    fn argon() -> RegistrationKdf {
        RegistrationKdf {
            kdf: 1,
            kdf_iterations: 1,
            kdf_memory: Some(15),
            kdf_parallelism: Some(1),
        }
    }
    fn request(kdf: RegistrationKdf) -> AccountKdfRequest<'static> {
        AccountKdfRequest {
            authentication_data: AccountKdfAuthentication {
                salt: SALT,
                kdf,
                master_password_authentication_hash: Secret::new("private-new-proof\0雪"),
            },
            unlock_data: AccountKdfUnlock {
                salt: SALT,
                kdf,
                master_key_wrapped_user_key: Secret::new("private-future-key\0雪"),
            },
            master_password_hash: Secret::new(OLD),
        }
    }

    #[test]
    fn kdf_change_authenticates_before_examining_new_credentials() {
        let mut mock = Mock::new();
        let before = mock.state.clone();
        let mut request = request(argon());
        request.unlock_data.kdf.kdf_iterations = 0;
        request.unlock_data.salt = "wrong-salt";
        assert_eq!(
            VaultService::new(&mut mock)
                .change_kdf("", &request)
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(mock.calls.is_empty());
        for owner in [OWNER, "foreign-owner"] {
            request.master_password_hash = Secret::new("wrong-proof");
            let error = VaultService::new(&mut mock)
                .change_kdf(owner, &request)
                .unwrap_err();
            assert_eq!(error.message, "Invalid password");
            assert!(mock.state == before);
        }
        assert_eq!(mock.calls, ["verify", "verify"]);
    }

    #[test]
    fn kdf_change_compares_complete_kdf_then_exact_salts_before_policy() {
        let mut mock = Mock::new();
        let before = mock.state.clone();
        let mut request = request(pbkdf());
        // Even fields that will later be cleared must match before normalization.
        request.authentication_data.kdf.kdf_memory = Some(30);
        request.unlock_data.salt = "wrong";
        let error = VaultService::new(&mut mock)
            .change_kdf(OWNER, &request)
            .unwrap_err();
        assert!(error.message.starts_with("KDF settings must be equal"));
        request.authentication_data.kdf = request.unlock_data.kdf;
        request.authentication_data.kdf.kdf_iterations = 1;
        request.unlock_data.kdf.kdf_iterations = 1;
        let error = VaultService::new(&mut mock)
            .change_kdf(OWNER, &request)
            .unwrap_err();
        assert_eq!(error.message, "Invalid master password salt");
        request.unlock_data.salt = SALT;
        let error = VaultService::new(&mut mock)
            .change_kdf(OWNER, &request)
            .unwrap_err();
        assert_eq!(error.field, Some("kdfIterations"));
        assert!(mock.state == before);
        assert_eq!(mock.calls, ["verify", "verify", "verify"]);
    }

    #[test]
    fn kdf_change_enforces_signed_thresholds_without_an_upper_or_unknown_type_cap() {
        for (kdf, field) in [
            (
                RegistrationKdf {
                    kdf_iterations: 99_999,
                    ..pbkdf()
                },
                "kdfIterations",
            ),
            (
                RegistrationKdf {
                    kdf_iterations: i32::MIN,
                    ..pbkdf()
                },
                "kdfIterations",
            ),
            (
                RegistrationKdf {
                    kdf_iterations: 0,
                    ..argon()
                },
                "kdfIterations",
            ),
            (
                RegistrationKdf {
                    kdf_memory: None,
                    ..argon()
                },
                "kdfMemory",
            ),
            (
                RegistrationKdf {
                    kdf_memory: Some(14),
                    ..argon()
                },
                "kdfMemory",
            ),
            (
                RegistrationKdf {
                    kdf_memory: Some(1025),
                    ..argon()
                },
                "kdfMemory",
            ),
            (
                RegistrationKdf {
                    kdf_parallelism: None,
                    ..argon()
                },
                "kdfParallelism",
            ),
            (
                RegistrationKdf {
                    kdf_parallelism: Some(0),
                    ..argon()
                },
                "kdfParallelism",
            ),
            (
                RegistrationKdf {
                    kdf_parallelism: Some(17),
                    ..argon()
                },
                "kdfParallelism",
            ),
        ] {
            let mut mock = Mock::new();
            let before = mock.state.clone();
            let error = VaultService::new(&mut mock)
                .change_kdf(OWNER, &request(kdf))
                .unwrap_err();
            assert_eq!(error.field, Some(field));
            assert!(mock.state == before && mock.calls == ["verify"]);
        }
        for kdf in [
            pbkdf(),
            RegistrationKdf {
                kdf_iterations: i32::MAX,
                ..pbkdf()
            },
            argon(),
            RegistrationKdf {
                kdf_iterations: i32::MAX,
                kdf_memory: Some(1024),
                kdf_parallelism: Some(16),
                ..argon()
            },
            RegistrationKdf {
                kdf: i32::MIN,
                kdf_iterations: i32::MIN,
                kdf_memory: Some(-1),
                kdf_parallelism: Some(i32::MAX),
            },
            RegistrationKdf {
                kdf: i32::MAX,
                kdf_iterations: -1,
                kdf_memory: Some(0),
                kdf_parallelism: Some(0),
            },
        ] {
            let mut mock = Mock::new();
            VaultService::new(&mut mock)
                .change_kdf(OWNER, &request(kdf))
                .unwrap();
            let expected = if kdf.kdf == 1 {
                kdf
            } else {
                RegistrationKdf {
                    kdf_memory: None,
                    kdf_parallelism: None,
                    ..kdf
                }
            };
            assert_eq!(mock.state.kdf, expected);
            assert_eq!(mock.calls, ["verify", "commit"]);
        }
    }

    #[test]
    fn kdf_change_preserves_opaque_empty_credentials_and_unrelated_state() {
        for (hash, key) in [("", ""), ("future-proof\0雪", "future-key\0雪")] {
            let mut mock = Mock::new();
            let before = mock.state.clone();
            let mut request = request(argon());
            request
                .authentication_data
                .master_password_authentication_hash = Secret::new(hash);
            request.unlock_data.master_key_wrapped_user_key = Secret::new(key);
            VaultService::new(&mut mock)
                .change_kdf(OWNER, &request)
                .unwrap();
            assert!(mock.state.password == hash && mock.state.key == key);
            assert_eq!(mock.state.stamp, before.stamp + 1);
            assert_eq!(mock.state.revision, before.revision + 1);
            assert_eq!(mock.state.sessions, 0);
            assert!(mock.state.devices == before.devices && mock.state.retained == before.retained);
            let error = VaultService::new(&mut mock)
                .change_kdf(OWNER, &request)
                .unwrap_err();
            assert_eq!(error.message, "Invalid password");
        }
    }

    #[test]
    fn kdf_change_uses_provider_salt_policy_without_normalizing_request_strings() {
        let mut mock = Mock::new();
        mock.salt = " Opaque-雪@EXAMPLE.test ";
        let mut request = request(pbkdf());
        let error = VaultService::new(&mut mock)
            .change_kdf(OWNER, &request)
            .unwrap_err();
        assert_eq!(error.message, "Invalid master password salt");
        request.authentication_data.salt = mock.salt;
        request.unlock_data.salt = mock.salt;
        VaultService::new(&mut mock)
            .change_kdf(OWNER, &request)
            .unwrap();
        assert_eq!(mock.calls, ["verify", "verify", "commit"]);
    }

    #[test]
    fn kdf_change_preserves_provider_errors_and_explicit_commit_boundaries() {
        for fail in [Fail::Verify, Fail::Commit] {
            let mut mock = Mock::new();
            let before = mock.state.clone();
            mock.fail = Some(fail);
            let error = VaultService::new(&mut mock)
                .change_kdf(OWNER, &request(pbkdf()))
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Storage);
            assert!(mock.state == before);
        }
        let mut mock = Mock::new();
        mock.concurrent_change = true;
        let before = mock.state.clone();
        let error = VaultService::new(&mut mock)
            .change_kdf(OWNER, &request(argon()))
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert!(mock.state == before);
        mock.concurrent_change = false;
        mock.fail = Some(Fail::Commit);
        mock.commit_then_fail = true;
        let error = VaultService::new(&mut mock)
            .change_kdf(OWNER, &request(argon()))
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Storage);
        assert!(mock.state != before && mock.state.sessions == 0);
        // An error alone never proves that a non-transactional provider rolled back.
        assert!(mock.state.devices == before.devices && mock.state.retained == before.retained);
    }
}
