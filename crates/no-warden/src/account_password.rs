//! Password changes and the pinned previous-stamp follow-up policy.
//!
//! Password verification, authoritative email lookup, clocks, stamp comparisons, credential
//! hashing, persistence and notifications belong to adapters. Current client KDF metadata is
//! preserved: this endpoint compares nested request KDF values but does not validate or save
//! them. Event logging before validation and external delivery are not core capabilities.

use crate::{
    ApiError, Storage, VaultService, identity::Secret, service::require_owner,
    wire::AccountPasswordRequest,
};

/// Provider-owned state after successful old-password verification. No allocator or Debug
/// bound is imposed on the authoritative, exact stored-email salt handle.
pub struct AccountPasswordState<Salt: AsRef<str>> {
    pub salt: Salt,
    pub password_hints_allowed: bool,
}
impl<Salt: AsRef<str>> core::fmt::Debug for AccountPasswordState<Salt> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AccountPasswordState")
            .finish_non_exhaustive()
    }
}

/// Decision for an already authenticated JWT whose stamp differs from the current stamp.
/// Expired asks the adapter to clear the persisted exception and attempt an account save,
/// even when the requested route or stamp would also be rejected. No clock/storage runs here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreviousStampAuthorization {
    Allowed,
    Expired,
    RouteDenied,
    StampDenied,
}

/// Exact policy installed by the pinned password-change handler. The four values are logical
/// upstream handler names, not arbitrary HTTP path aliases. `get_api_webauthn` is the
/// authenticated `/api/webauthn` metadata handler; it does not authorize the differently
/// named two-factor `get_webauthn` handler.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PasswordChangeStampPolicy;
impl PasswordChangeStampPolicy {
    pub const fn routes(self) -> &'static [&'static str; 4] {
        &[
            "post_rotatekey",
            "get_contacts",
            "get_public_keys",
            "get_api_webauthn",
        ]
    }
    pub const fn lifetime_seconds(self) -> i64 {
        120
    }
    /// Supply integer Unix seconds, matching the upstream timestamp precision. Overflow
    /// cannot create an unbounded grant: None means the provider must fail closed.
    pub const fn expires_at(self, issued_at: i64) -> Option<i64> {
        issued_at.checked_add(self.lifetime_seconds())
    }
    pub fn allows_route(self, logical_route: &str) -> bool {
        self.routes().contains(&logical_route)
    }
    /// Call only after JWT signature/expiry, owner and current owned-device checks, and
    /// only when the token stamp differs from the current stamp. The provider supplies an
    /// account-bound exception and a securely verified comparison with its previous stamp.
    /// At exactly expires_at the exception is still valid; checks are expiry, route, stamp.
    /// This is repeatable, not one-shot, and can admit either password or API-key bearers.
    pub fn authorize_previous_stamp(
        self,
        now: i64,
        expires_at: i64,
        logical_route: &str,
        verified_stamp_matches: bool,
    ) -> PreviousStampAuthorization {
        if now > expires_at {
            PreviousStampAuthorization::Expired
        } else if !self.allows_route(logical_route) {
            PreviousStampAuthorization::RouteDenied
        } else if !verified_stamp_matches {
            PreviousStampAuthorization::StampDenied
        } else {
            PreviousStampAuthorization::Allowed
        }
    }
}

/// Private validated credential replacement. Only this module selects the accepted request
/// branch and cleans the hint. No client KDF value is exposed for mutation by this plan.
pub struct ValidatedAccountPassword<'a> {
    old_password_hash: Secret<'a>,
    new_password_hash: Secret<'a>,
    key: Secret<'a>,
    master_password_hint: Option<&'a str>,
}
impl core::fmt::Debug for ValidatedAccountPassword<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatedAccountPassword")
            .finish_non_exhaustive()
    }
}
impl ValidatedAccountPassword<'_> {
    pub const fn old_password_hash(&self) -> &Secret<'_> {
        &self.old_password_hash
    }
    pub const fn new_password_hash(&self) -> &Secret<'_> {
        &self.new_password_hash
    }
    pub const fn key(&self) -> &Secret<'_> {
        &self.key
    }
    pub const fn master_password_hint(&self) -> Option<&str> {
        self.master_password_hint
    }
    pub const fn stamp_exception_policy(&self) -> PasswordChangeStampPolicy {
        PasswordChangeStampPolicy
    }
}

/// Opt-in password changes. Hold an operation lock or recheck the old proof within the
/// commit transaction so concurrent changes cannot overwrite an already changed password.
/// Verify the exact old client server-authorization hash with the provider verifier, returning
/// None for an invalid proof or missing owner. Never accept a protected-action OTP here.
/// Return the authoritative stored email exactly, with no trim/lowercase normalization, plus
/// the current password-hint policy; never use client JSON extensions as trusted state.
///
/// The commit securely hashes the new proof, replaces the wrapped key and cleaned/cleared
/// hint, saves the current PRE-reset stamp and four-route/120-second exception policy, then
/// generates a fresh private stamp and account revision. Invalidate old refresh/remember
/// authority and ordinary bearer access, including the acting device. Preserve all matching
/// previous-stamp JWTs' limited follow-up authority, including API-key sessions, within their
/// own token expiry and the exception window. The policy requires a currently existing owned
/// device; never grant a new token/refresh or bypass JWT/owner/device checks from this plan.
///
/// Preserve client KDF fields, asymmetric keys, user-key IDs, API credentials, devices/push,
/// auth requests, vaults and foreign owners. Every password change replaces any older exception
/// with its then-current stamp. KDF changes, direct stamp reset, refresh and login do not clear
/// that exception upstream; deleting/recreating the same owned device can affect admission.
/// Current-stamp requests must not inspect/clear an expired exception. On a mismatched stamp,
/// Expired requires clearing it and a best-effort account save before denial, even on another
/// route. The provider owns confidential comparison, timestamps and persistence of this state.
///
/// Atomic rollback of the credential/key/hint/stamp/exception/revision/session changes is a
/// provider guarantee stronger than upstream's sequential refresh rotations and save. A
/// provider error alone does not prove rollback. Notifications excluding the acting device,
/// pre-validation event logging and supported external side effects remain adapter work.
pub trait AccountPasswordStorage: Storage {
    type Salt: AsRef<str>;

    fn verify_account_password(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
    ) -> Result<Option<AccountPasswordState<Self::Salt>>, Self::Error>;
    fn change_account_password(
        &mut self,
        owner: &str,
        plan: &ValidatedAccountPassword<'_>,
    ) -> Result<(), Self::Error>;
}
impl<T: AccountPasswordStorage + ?Sized> AccountPasswordStorage for &mut T {
    type Salt = T::Salt;

    fn verify_account_password(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
    ) -> Result<Option<AccountPasswordState<Self::Salt>>, Self::Error> {
        (**self).verify_account_password(owner, password)
    }
    fn change_account_password(
        &mut self,
        owner: &str,
        plan: &ValidatedAccountPassword<'_>,
    ) -> Result<(), Self::Error> {
        (**self).change_account_password(owner, plan)
    }
}

impl<S: AccountPasswordStorage> VaultService<S> {
    pub fn change_password(
        &mut self,
        owner: &str,
        request: &AccountPasswordRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let state = self
            .storage_mut()
            .verify_account_password(owner, &request.master_password_hash)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("masterPasswordHash", "Invalid password"))?;
        let (new_hash, key) = if let (Some(authentication), Some(unlock)) =
            (&request.authentication_data, &request.unlock_data)
        {
            if authentication.kdf != unlock.kdf {
                return Err(ApiError::invalid(
                    "authenticationData",
                    "KDF settings must be equal for authentication and unlock",
                ));
            }
            if state.salt.as_ref() != authentication.salt || state.salt.as_ref() != unlock.salt {
                return Err(ApiError::invalid("salt", "Invalid master password salt"));
            }
            (
                &authentication.master_password_authentication_hash,
                &unlock.master_key_wrapped_user_key,
            )
        } else if let (Some(hash), Some(key)) = (&request.new_master_password_hash, &request.key) {
            (hash, key)
        } else {
            return Err(ApiError::invalid("password", "Invalid request!"));
        };
        let hint = request
            .master_password_hint
            .map(str::trim)
            .filter(|hint| !hint.is_empty());
        if hint.is_some() && !state.password_hints_allowed {
            return Err(ApiError::invalid(
                "masterPasswordHint",
                "Password hints have been disabled by the administrator. Remove the hint and try again.",
            ));
        }
        let plan = ValidatedAccountPassword {
            old_password_hash: Secret::new(request.master_password_hash.expose_secret()),
            new_password_hash: Secret::new(new_hash.expose_secret()),
            key: Secret::new(key.expose_secret()),
            master_password_hint: hint,
        };
        self.storage_mut()
            .change_account_password(owner, &plan)
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
            RegisterRequest, RegistrationKdf,
        },
    };
    use std::{string::String, vec, vec::Vec};

    const OWNER: &str = "authenticated-owner";
    const SALT: &str = "Exact-雪@EXAMPLE.test";
    const OLD: &str = "private-old-proof\0雪";

    #[derive(Clone, Eq, PartialEq)]
    struct State {
        password: String,
        key: String,
        hint: Option<String>,
        stamp: u32,
        revision: u32,
        sessions: usize,
        followup: (u32, i64),
        retained: (RegistrationKdf, usize, &'static str, &'static str),
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fail {
        Verify,
        Commit,
    }
    struct Mock {
        calls: Vec<&'static str>,
        state: State,
        hints_allowed: bool,
        fail: Option<Fail>,
        commit_then_fail: bool,
        recheck_rejects: bool,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                calls: vec![],
                state: State {
                    password: String::from(OLD),
                    key: String::from("prior-key"),
                    hint: Some(String::from("prior-hint")),
                    stamp: 10,
                    revision: 20,
                    sessions: 4,
                    followup: (9, 30),
                    retained: (kdf(), 3, "API/asymmetric/ID/vault", "foreign/authrequests"),
                },
                hints_allowed: true,
                fail: None,
                commit_then_fail: false,
                recheck_rejects: false,
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
    impl AccountPasswordStorage for Mock {
        type Salt = &'static str;
        fn verify_account_password(
            &mut self,
            owner: &str,
            password: &Secret<'_>,
        ) -> Result<Option<AccountPasswordState<Self::Salt>>, Self::Error> {
            self.calls.push("verify");
            if self.fail == Some(Fail::Verify) {
                return Err(ErrorKind::Storage);
            }
            // Test-only comparison; real providers own constant-time credential verification.
            Ok(
                (owner == OWNER && password.expose_secret() == self.state.password).then_some(
                    AccountPasswordState {
                        salt: SALT,
                        password_hints_allowed: self.hints_allowed,
                    },
                ),
            )
        }
        fn change_account_password(
            &mut self,
            owner: &str,
            plan: &ValidatedAccountPassword<'_>,
        ) -> Result<(), Self::Error> {
            self.calls.push("commit");
            assert!(owner == OWNER);
            if self.recheck_rejects {
                return Err(ErrorKind::Conflict);
            }
            assert!(plan.old_password_hash().expose_secret() == self.state.password);
            assert!(!std::format!("{plan:?}").contains("private"));
            if self.fail == Some(Fail::Commit) && !self.commit_then_fail {
                return Err(ErrorKind::Storage);
            }
            let policy = plan.stamp_exception_policy();
            self.state.followup = (self.state.stamp, policy.expires_at(1000).unwrap());
            self.state.password = String::from(plan.new_password_hash().expose_secret());
            self.state.key = String::from(plan.key().expose_secret());
            self.state.hint = plan.master_password_hint().map(String::from);
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
    fn kdf() -> RegistrationKdf {
        RegistrationKdf {
            kdf: 0,
            kdf_iterations: 600_000,
            kdf_memory: None,
            kdf_parallelism: None,
        }
    }
    fn legacy() -> AccountPasswordRequest<'static> {
        AccountPasswordRequest {
            master_password_hash: Secret::new(OLD),
            master_password_hint: None,
            authentication_data: None,
            unlock_data: None,
            new_master_password_hash: Some(Secret::new("private-legacy-proof")),
            key: Some(Secret::new("private-legacy-key")),
        }
    }
    fn nested() -> AccountPasswordRequest<'static> {
        let mut request = legacy();
        request.authentication_data = Some(AccountKdfAuthentication {
            salt: SALT,
            kdf: kdf(),
            master_password_authentication_hash: Secret::new("private-nested-proof"),
        });
        request.unlock_data = Some(AccountKdfUnlock {
            salt: SALT,
            kdf: kdf(),
            master_key_wrapped_user_key: Secret::new("private-nested-key"),
        });
        request
    }

    #[test]
    fn password_change_verifies_owner_and_old_proof_before_branch_or_hint_policy() {
        let mut mock = Mock::new();
        let before = mock.state.clone();
        let mut request = nested();
        request.unlock_data.as_mut().unwrap().salt = "wrong-salt";
        request.master_password_hint = Some("disallowed");
        mock.hints_allowed = false;
        assert_eq!(
            VaultService::new(&mut mock)
                .change_password("", &request)
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(mock.calls.is_empty());
        for owner in [OWNER, "foreign"] {
            request.master_password_hash = Secret::new("wrong-proof");
            let error = VaultService::new(&mut mock)
                .change_password(owner, &request)
                .unwrap_err();
            assert_eq!(error.message, "Invalid password");
        }
        assert!(mock.state == before && mock.calls == ["verify", "verify"]);
    }

    #[test]
    fn password_change_prefers_complete_nested_and_falls_back_only_for_partial_nested() {
        let mut mock = Mock::new();
        VaultService::new(&mut mock)
            .change_password(OWNER, &nested())
            .unwrap();
        assert!(
            mock.state.password == "private-nested-proof" && mock.state.key == "private-nested-key"
        );
        for missing_authentication in [false, true] {
            let mut mock = Mock::new();
            let mut request = nested();
            if missing_authentication {
                request.authentication_data = None;
            } else {
                request.unlock_data = None;
            }
            VaultService::new(&mut mock)
                .change_password(OWNER, &request)
                .unwrap();
            assert!(
                mock.state.password == "private-legacy-proof"
                    && mock.state.key == "private-legacy-key"
            );
            let mut mock = Mock::new();
            request.key = None;
            let error = VaultService::new(&mut mock)
                .change_password(OWNER, &request)
                .unwrap_err();
            assert_eq!(error.message, "Invalid request!");
            assert_eq!(mock.calls, ["verify"]);
        }
        let mut mock = Mock::new();
        let mut request = nested();
        request.unlock_data.as_mut().unwrap().kdf.kdf_memory = Some(99);
        let error = VaultService::new(&mut mock)
            .change_password(OWNER, &request)
            .unwrap_err();
        assert!(error.message.starts_with("KDF settings must be equal"));
        assert_eq!(mock.calls, ["verify"]); // Complete legacy credentials cannot bypass an invalid nested pair.
    }

    #[test]
    fn password_change_compares_full_request_kdf_and_exact_email_without_kdf_policy_or_mutation() {
        let mut mock = Mock::new();
        let before = mock.state.clone();
        let mut request = nested();
        let arbitrary = RegistrationKdf {
            kdf: 1,
            kdf_iterations: -9,
            kdf_memory: Some(-8),
            kdf_parallelism: None,
        };
        request.authentication_data.as_mut().unwrap().kdf = arbitrary;
        request.unlock_data.as_mut().unwrap().kdf = arbitrary;
        request.authentication_data.as_mut().unwrap().salt = "exact-雪@example.test";
        let error = VaultService::new(&mut mock)
            .change_password(OWNER, &request)
            .unwrap_err();
        assert_eq!(error.message, "Invalid master password salt");
        assert!(mock.state == before);
        request.authentication_data.as_mut().unwrap().salt = SALT;
        VaultService::new(&mut mock)
            .change_password(OWNER, &request)
            .unwrap();
        assert!(mock.state.retained == before.retained); // Stored KDF, devices, API/key/vault/foreign state stay unchanged.
        assert_eq!(mock.state.followup, (before.stamp, 1120));
        assert_eq!(mock.state.stamp, before.stamp + 1);
        assert_eq!(mock.state.revision, before.revision + 1);
        assert_eq!(mock.state.sessions, 0);
    }

    #[test]
    fn password_change_cleans_or_clears_hints_after_credential_selection() {
        for (input, expected) in [
            (None, None),
            (Some("\u{2003}\n\t"), None),
            (Some("\u{2003} hint\0雪 \n"), Some("hint\0雪")),
        ] {
            let mut mock = Mock::new();
            let mut request = legacy();
            request.master_password_hint = input;
            VaultService::new(&mut mock)
                .change_password(OWNER, &request)
                .unwrap();
            assert!(mock.state.hint.as_deref() == expected);
        }
        for hint in [None, Some(" \n\t")] {
            let mut mock = Mock::new();
            mock.hints_allowed = false;
            let mut request = legacy();
            request.master_password_hint = hint;
            VaultService::new(&mut mock)
                .change_password(OWNER, &request)
                .unwrap();
            assert!(mock.state.hint.is_none());
        }
        let mut mock = Mock::new();
        mock.hints_allowed = false;
        let before = mock.state.clone();
        let mut request = nested();
        request.master_password_hint = Some(" nonblank ");
        request.unlock_data.as_mut().unwrap().salt = "wrong";
        assert_eq!(
            VaultService::new(&mut mock)
                .change_password(OWNER, &request)
                .unwrap_err()
                .field,
            Some("salt")
        );
        request.unlock_data.as_mut().unwrap().salt = SALT;
        assert_eq!(
            VaultService::new(&mut mock)
                .change_password(OWNER, &request)
                .unwrap_err()
                .field,
            Some("masterPasswordHint")
        );
        assert!(mock.state == before && mock.calls == ["verify", "verify"]);
    }

    #[test]
    fn password_change_preserves_empty_and_future_credentials_and_replaces_old_exception() {
        for (proof, key) in [("", ""), ("future-proof\0雪", "future-key\0雪")] {
            let mut mock = Mock::new();
            let before = mock.state.clone();
            let mut request = legacy();
            request.new_master_password_hash = Some(Secret::new(proof));
            request.key = Some(Secret::new(key));
            VaultService::new(&mut mock)
                .change_password(OWNER, &request)
                .unwrap();
            assert!(mock.state.password == proof && mock.state.key == key);
            assert!(mock.state.retained == before.retained);
            request.master_password_hash = Secret::new(proof);
            VaultService::new(&mut mock)
                .change_password(OWNER, &request)
                .unwrap();
            assert_eq!(mock.state.followup, (before.stamp + 1, 1120));
            assert_eq!(mock.state.stamp, before.stamp + 2);
        }
    }

    #[test]
    fn password_change_preserves_typed_provider_errors_without_assuming_rollback() {
        for fail in [Fail::Verify, Fail::Commit] {
            let mut mock = Mock::new();
            let before = mock.state.clone();
            mock.fail = Some(fail);
            let error = VaultService::new(&mut mock)
                .change_password(OWNER, &legacy())
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Storage);
            assert!(mock.state == before);
        }
        let mut mock = Mock::new();
        let before = mock.state.clone();
        mock.recheck_rejects = true;
        assert_eq!(
            VaultService::new(&mut mock)
                .change_password(OWNER, &legacy())
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
        assert!(mock.state == before);
        mock.recheck_rejects = false;
        mock.fail = Some(Fail::Commit);
        mock.commit_then_fail = true;
        assert_eq!(
            VaultService::new(&mut mock)
                .change_password(OWNER, &legacy())
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        assert!(mock.state != before && mock.state.retained == before.retained);
    }

    #[test]
    fn previous_stamp_policy_keeps_exact_routes_inclusive_expiry_and_repeated_access() {
        let policy = PasswordChangeStampPolicy;
        assert_eq!(policy.lifetime_seconds(), 120);
        assert_eq!(policy.expires_at(1000), Some(1120));
        assert_eq!(policy.expires_at(i64::MAX), None);
        assert_eq!(policy.expires_at(i64::MIN), Some(i64::MIN + 120));
        assert_eq!(
            policy.routes(),
            &[
                "post_rotatekey",
                "get_contacts",
                "get_public_keys",
                "get_api_webauthn"
            ]
        );
        for route in policy.routes() {
            for now in [999, 1119, 1120, 1120] {
                assert_eq!(
                    policy.authorize_previous_stamp(now, 1120, route, true),
                    PreviousStampAuthorization::Allowed
                );
            }
        }
        for route in [
            "",
            "get_public_key",
            "get_public_keys_admin",
            "get_webauthn",
            "post_password",
            "POST_ROTATEKEY",
            "/api/users/id/public-key",
        ] {
            assert!(!policy.allows_route(route));
            assert_eq!(
                policy.authorize_previous_stamp(1120, 1120, route, true),
                PreviousStampAuthorization::RouteDenied
            );
        }
    }

    #[test]
    fn previous_stamp_policy_checks_expiry_before_route_before_verified_stamp() {
        let policy = PasswordChangeStampPolicy;
        assert_eq!(
            policy.authorize_previous_stamp(1121, 1120, "unrelated", false),
            PreviousStampAuthorization::Expired
        );
        assert_eq!(
            policy.authorize_previous_stamp(1120, 1120, "unrelated", false),
            PreviousStampAuthorization::RouteDenied
        );
        assert_eq!(
            policy.authorize_previous_stamp(1120, 1120, "get_public_keys", false),
            PreviousStampAuthorization::StampDenied
        );
        // Signature, token expiry, current-stamp fast path and owned-device existence are
        // provider prerequisites, never facts inferred from this pure previous-stamp check.
        assert_eq!(
            policy.authorize_previous_stamp(1120, 1120, "get_public_keys", true),
            PreviousStampAuthorization::Allowed
        );
    }
}
