//! Password verification and security-stamp reset through opt-in account providers.
//!
//! Password hashing, internal verifier cost, stamp randomness, time, persistence,
//! credential/session revocation, device cleanup and notifications belong to adapters.
//! Security-stamp values never pass through these request or response models.

use crate::{
    ApiError, Storage, VaultService,
    identity::{ReauthenticationProof, Secret},
    service::require_owner,
    wire::{
        MasterPasswordPolicy, MasterPasswordPolicyResponse, PasswordOrOtpRequest,
        SecretVerificationRequest,
    },
};

/// Opt-in security operations preserving existing Storage/IdentityStorage implementations.
/// Hold the authenticated operation's lock/context across each complete service call.
///
/// Verify exact opaque client server-authorization hashes with the password provider.
/// ProtectedActionOtp is a purpose/account-bound protected-action proof, not an account
/// TOTP. Successful verification must enforce expiry and consume it (delete_if_valid=true).
/// Providers without this capability must reject that proof. Password checks do not consume
/// a credential. Never log, normalize or serialize either proof.
///
/// upgrade_account_password_verifier runs only after successful password verification.
/// It concerns the SERVER's stored verifier cost, never the client's KDF metadata. Current
/// or stronger verifiers are unchanged; a stale verifier may be rebuilt using the same proof
/// and saved with an account revision. Preserve keys, stamp, sessions, devices, API credentials,
/// client KDF and vaults. The provider owns the pinned failure distinction: password-rebuild
/// failures propagate, while a subsequent best-effort user-save failure can be ignored.
/// Policy lookup follows the upgrade, so a later lookup error does not imply rollback of an
/// already-persisted upgrade. Return only accepted/confirmed applicable organization policy
/// aggregation, or None for the personal Object-only response; arbitrary SSO policies remain
/// outside this typed representation.
///
/// reset_account_security_stamp generates and persists fresh private stamp state, advances
/// account revision and invalidates every owner device's bearer/refresh/remember authority,
/// including the current caller, then removes owner devices. Preserve the account password,
/// keys, client KDF, API secret, vaults, foreign accounts and all authentication-request rows.
/// Preserve any existing password-change previous-stamp exception and its original deadline.
/// Deleted devices prevent its use, but recreating the same owned device identifier can
/// make a still-valid old JWT eligible for the exception again, following upstream guards.
/// Providers define/document their persistence boundary: an atomic stamp/revision/session/
/// device transaction is stronger than upstream's sequential mutations. A failure does not
/// universally imply rollback; an earlier protected-action OTP may already be consumed.
/// Hosts can wrap the entire service operation if they supply that stronger guarantee.
/// Notifications, external push cleanup and actual transport delivery remain adapter duties;
/// implementing this trait does not establish those capabilities.
pub trait AccountSecurityStorage: Storage {
    fn verify_account_security_proof(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error>;
    fn upgrade_account_password_verifier(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
    ) -> Result<(), Self::Error>;
    fn account_master_password_policy(
        &mut self,
        owner: &str,
    ) -> Result<Option<MasterPasswordPolicy>, Self::Error>;
    fn reset_account_security_stamp(&mut self, owner: &str) -> Result<(), Self::Error>;
}

impl<T: AccountSecurityStorage + ?Sized> AccountSecurityStorage for &mut T {
    fn verify_account_security_proof(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).verify_account_security_proof(owner, proof)
    }
    fn upgrade_account_password_verifier(
        &mut self,
        owner: &str,
        password: &Secret<'_>,
    ) -> Result<(), Self::Error> {
        (**self).upgrade_account_password_verifier(owner, password)
    }
    fn account_master_password_policy(
        &mut self,
        owner: &str,
    ) -> Result<Option<MasterPasswordPolicy>, Self::Error> {
        (**self).account_master_password_policy(owner)
    }
    fn reset_account_security_stamp(&mut self, owner: &str) -> Result<(), Self::Error> {
        (**self).reset_account_security_stamp(owner)
    }
}

impl<S: AccountSecurityStorage> VaultService<S> {
    pub fn verify_password(
        &mut self,
        owner: &str,
        request: &SecretVerificationRequest<'_>,
    ) -> Result<MasterPasswordPolicyResponse, ApiError> {
        require_owner(owner)?;
        if !self
            .storage_mut()
            .verify_account_security_proof(
                owner,
                ReauthenticationProof::MasterPasswordHash(Secret::new(
                    request.master_password_hash.expose_secret(),
                )),
            )
            .map_err(S::map_error)?
        {
            return Err(ApiError::invalid("masterPasswordHash", "Invalid password"));
        }
        self.storage_mut()
            .upgrade_account_password_verifier(owner, &request.master_password_hash)
            .map_err(S::map_error)?;
        let policy = self
            .storage_mut()
            .account_master_password_policy(owner)
            .map_err(S::map_error)?;
        Ok(MasterPasswordPolicyResponse { policy })
    }

    pub fn reset_security_stamp(
        &mut self,
        owner: &str,
        request: &PasswordOrOtpRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let proof = request.proof()?;
        if !self
            .storage_mut()
            .verify_account_security_proof(owner, proof)
            .map_err(S::map_error)?
        {
            return Err(ApiError::invalid(
                "reauthentication",
                "Reauthentication failed.",
            ));
        }
        self.storage_mut()
            .reset_account_security_stamp(owner)
            .map_err(S::map_error)
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
    use std::{vec, vec::Vec};

    const OWNER: &str = "verified-owner";
    const PASSWORD: &str = "private-client-hash\0雪";
    const OTP: &str = "purpose-bound-private-otp";
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fail {
        Verify,
        Upgrade,
        Policy,
        Reset,
    }
    struct Mock {
        calls: Vec<&'static str>,
        expected_password: &'static str,
        otp_available: bool,
        cost: u32,
        target: u32,
        revision: u32,
        stamp: u32,
        owner_authority: (usize, usize, usize),
        foreign_authority: (usize, usize, usize),
        auth_requests: (usize, usize, usize),
        client_kdf: (i32, i32),
        private_account: (&'static str, &'static str, &'static str),
        policy: Option<MasterPasswordPolicy>,
        fail: Option<Fail>,
        error: ErrorKind,
        reset_commits_before_error: bool,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                calls: vec![],
                expected_password: PASSWORD,
                otp_available: true,
                cost: 5,
                target: 5,
                revision: 10,
                stamp: 1,
                owner_authority: (3, 2, 3),
                foreign_authority: (2, 1, 1),
                auth_requests: (4, 2, 1),
                client_kdf: (0, 600_000),
                private_account: ("unchanged-password", "opaque-key", "recoverable-api-key"),
                policy: None,
                fail: None,
                error: ErrorKind::Storage,
                reset_commits_before_error: false,
            }
        }
        fn call(&mut self, name: &'static str, fail: Fail) -> Result<(), ErrorKind> {
            self.calls.push(name);
            if self.fail == Some(fail) {
                Err(self.error)
            } else {
                Ok(())
            }
        }
        fn preserved_account_and_foreign_state(&self) {
            assert_eq!(self.foreign_authority, (2, 1, 1));
            assert_eq!(self.auth_requests, (4, 2, 1));
            assert_eq!(self.client_kdf, (0, 600_000));
            assert!(
                self.private_account == ("unchanged-password", "opaque-key", "recoverable-api-key")
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
    impl AccountSecurityStorage for Mock {
        fn verify_account_security_proof(
            &mut self,
            owner: &str,
            proof: ReauthenticationProof<'_>,
        ) -> Result<bool, Self::Error> {
            self.call("verify", Fail::Verify)?;
            if owner != OWNER {
                return Ok(false);
            }
            // Test double only. Real providers verify password hashes and protected-action
            // purpose/account/expiry/consumption using their own crypto and storage.
            match proof {
                ReauthenticationProof::MasterPasswordHash(hash) => {
                    Ok(hash.expose_secret() == self.expected_password)
                }
                ReauthenticationProof::ProtectedActionOtp(otp) => {
                    if !self.otp_available || otp.expose_secret() != OTP {
                        return Ok(false);
                    }
                    self.otp_available = false;
                    Ok(true)
                }
            }
        }
        fn upgrade_account_password_verifier(
            &mut self,
            owner: &str,
            password: &Secret<'_>,
        ) -> Result<(), Self::Error> {
            self.call("upgrade", Fail::Upgrade)?;
            assert!(owner == OWNER && password.expose_secret() == self.expected_password);
            if self.cost < self.target {
                self.cost = self.target;
                self.revision += 1;
            }
            Ok(())
        }
        fn account_master_password_policy(
            &mut self,
            owner: &str,
        ) -> Result<Option<MasterPasswordPolicy>, Self::Error> {
            self.call("policy", Fail::Policy)?;
            assert!(owner == OWNER);
            Ok(self.policy)
        }
        fn reset_account_security_stamp(&mut self, owner: &str) -> Result<(), Self::Error> {
            self.calls.push("reset");
            assert!(owner == OWNER);
            if self.fail == Some(Fail::Reset) && !self.reset_commits_before_error {
                return Err(self.error);
            }
            self.stamp += 1;
            self.revision += 1;
            self.owner_authority = (0, 0, 0);
            if self.fail == Some(Fail::Reset) {
                Err(self.error)
            } else {
                Ok(())
            }
        }
    }
    fn password() -> SecretVerificationRequest<'static> {
        SecretVerificationRequest {
            master_password_hash: Secret::new(PASSWORD),
        }
    }
    fn reset_password() -> PasswordOrOtpRequest<'static> {
        PasswordOrOtpRequest {
            master_password_hash: Some(Secret::new(PASSWORD)),
            otp: None,
        }
    }
    fn reset_otp() -> PasswordOrOtpRequest<'static> {
        PasswordOrOtpRequest {
            master_password_hash: None,
            otp: Some(Secret::new(OTP)),
        }
    }

    #[test]
    fn unauthenticated_security_operations_never_call_the_provider() {
        let mut mock = Mock::new();
        let mut service = VaultService::new(&mut mock);
        assert_eq!(
            service
                .verify_password("", &password())
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            service
                .reset_security_stamp("", &reset_password())
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(mock.calls.is_empty());
        assert_eq!(mock.owner_authority, (3, 2, 3));
        mock.preserved_account_and_foreign_state();
    }

    #[test]
    fn password_verification_orders_internal_upgrade_then_policy_and_preserves_client_authority() {
        let mut mock = Mock::new();
        let response = VaultService::new(&mut mock)
            .verify_password(OWNER, &password())
            .unwrap();
        assert_eq!(mock.calls, ["verify", "upgrade", "policy"]);
        assert_eq!(response.policy, None);
        assert_eq!((mock.cost, mock.revision, mock.stamp), (5, 10, 1));
        assert_eq!(mock.owner_authority, (3, 2, 3));
        mock.cost = 2;
        mock.policy = Some(MasterPasswordPolicy {
            min_complexity: Some(3),
            min_length: Some(16),
            require_upper: true,
            enforce_on_login: true,
            ..MasterPasswordPolicy::default()
        });
        mock.calls.clear();
        let response = VaultService::new(&mut mock)
            .verify_password(OWNER, &password())
            .unwrap();
        assert_eq!(response.policy, mock.policy);
        assert_eq!(mock.calls, ["verify", "upgrade", "policy"]);
        assert_eq!((mock.cost, mock.revision, mock.stamp), (5, 11, 1));
        VaultService::new(&mut mock)
            .verify_password(OWNER, &password())
            .unwrap();
        assert_eq!(mock.revision, 11); // Current verifier remains a no-op.
        assert_eq!(mock.owner_authority, (3, 2, 3));
        mock.preserved_account_and_foreign_state();
    }

    #[test]
    fn invalid_passwords_or_wrong_owners_cannot_upgrade_read_policy_or_reset_state() {
        for (owner, supplied) in [(OWNER, "wrong"), (OWNER, ""), ("other-owner", PASSWORD)] {
            let mut mock = Mock::new();
            let request = SecretVerificationRequest {
                master_password_hash: Secret::new(supplied),
            };
            let error = VaultService::new(&mut mock)
                .verify_password(owner, &request)
                .unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert_eq!(mock.calls, ["verify"]);
            assert_eq!((mock.revision, mock.stamp), (10, 1));
            assert_eq!(mock.owner_authority, (3, 2, 3));
            mock.preserved_account_and_foreign_state();
        }
        let mut mock = Mock::new();
        mock.expected_password = "";
        VaultService::new(&mut mock)
            .verify_password(
                OWNER,
                &SecretVerificationRequest {
                    master_password_hash: Secret::new(""),
                },
            )
            .unwrap();
        assert_eq!(mock.calls, ["verify", "upgrade", "policy"]); // Opaque blank proofs are provider decisions.
        let mut mock = Mock::new();
        assert_eq!(
            VaultService::new(&mut mock)
                .reset_security_stamp("other-owner", &reset_password())
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(mock.calls, ["verify"]);
        assert_eq!(mock.owner_authority, (3, 2, 3));
    }

    #[test]
    fn stamp_reset_requires_exactly_one_valid_proof_before_any_reset() {
        for request in [
            PasswordOrOtpRequest {
                master_password_hash: None,
                otp: None,
            },
            PasswordOrOtpRequest {
                master_password_hash: Some(Secret::new(PASSWORD)),
                otp: Some(Secret::new(OTP)),
            },
        ] {
            let mut mock = Mock::new();
            assert_eq!(
                VaultService::new(&mut mock)
                    .reset_security_stamp(OWNER, &request)
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert!(mock.calls.is_empty());
            assert!(mock.otp_available);
        }
        for request in [
            PasswordOrOtpRequest {
                master_password_hash: Some(Secret::new("wrong")),
                otp: None,
            },
            PasswordOrOtpRequest {
                master_password_hash: None,
                otp: Some(Secret::new("wrong")),
            },
        ] {
            let mut mock = Mock::new();
            assert_eq!(
                VaultService::new(&mut mock)
                    .reset_security_stamp(OWNER, &request)
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(mock.calls, ["verify"]);
            assert!(mock.otp_available);
            assert_eq!(mock.owner_authority, (3, 2, 3));
        }
    }

    #[test]
    fn stamp_reset_removes_all_owner_authority_without_upgrading_or_destroying_requests() {
        for use_otp in [false, true] {
            let mut mock = Mock::new();
            mock.cost = 2;
            let request = if use_otp {
                reset_otp()
            } else {
                reset_password()
            };
            VaultService::new(&mut mock)
                .reset_security_stamp(OWNER, &request)
                .unwrap();
            assert_eq!(mock.calls, ["verify", "reset"]);
            assert_eq!(mock.owner_authority, (0, 0, 0));
            assert_eq!((mock.stamp, mock.revision, mock.cost), (2, 11, 2));
            assert_eq!(mock.otp_available, !use_otp);
            mock.preserved_account_and_foreign_state();
        }
    }

    #[test]
    fn provider_errors_preserve_mapping_and_do_not_imply_rollback_of_prior_upgrade() {
        for kind in [ErrorKind::Storage, ErrorKind::Conflict] {
            for fail in [Fail::Verify, Fail::Upgrade, Fail::Policy] {
                let mut mock = Mock::new();
                mock.fail = Some(fail);
                mock.error = kind;
                mock.cost = 2;
                let error = VaultService::new(&mut mock)
                    .verify_password(OWNER, &password())
                    .unwrap_err();
                assert_eq!(error.kind, kind);
                assert_eq!(error.message, "Static provider failure");
                assert_eq!(mock.revision, if fail == Fail::Policy { 11 } else { 10 });
                assert_eq!(mock.stamp, 1);
                assert_eq!(mock.owner_authority, (3, 2, 3));
                mock.preserved_account_and_foreign_state();
            }
        }
    }

    #[test]
    fn protected_action_consumption_and_reset_errors_follow_the_provider_commit_boundary() {
        for committed in [false, true] {
            let mut mock = Mock::new();
            mock.fail = Some(Fail::Reset);
            mock.reset_commits_before_error = committed;
            let error = VaultService::new(&mut mock)
                .reset_security_stamp(OWNER, &reset_otp())
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Storage);
            assert!(!mock.otp_available); // Proof consumption preceded the reset provider failure.
            assert_eq!(mock.calls, ["verify", "reset"]);
            assert_eq!(
                mock.owner_authority,
                if committed { (0, 0, 0) } else { (3, 2, 3) }
            );
            assert_eq!(mock.stamp, if committed { 2 } else { 1 });
            mock.fail = None;
            mock.calls.clear();
            assert_eq!(
                VaultService::new(&mut mock)
                    .reset_security_stamp(OWNER, &reset_otp())
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(mock.calls, ["verify"]);
            mock.preserved_account_and_foreign_state();
        }
    }
}
