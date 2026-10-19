//! Reauthenticated account deletion through opt-in allocation-free providers.
//!
//! HTTP guards, password verification, protected-action OTPs, organization policy,
//! transactions and storage cleanup remain the embedding application's duties.

use crate::{
    ApiError, Storage, VaultService, identity::ReauthenticationProof, service::require_owner,
    wire::PasswordOrOtpRequest,
};

/// Account deletion without requiring identity/API-key or account-security providers.
/// Keep the authenticated operation's lock/context across the entire service call.
///
/// Verify the opaque client server-authorization hash against the authenticated account.
/// Protected-action OTPs must check account, purpose and expiry, and successful verification
/// consumes the proof (`delete_if_valid=true`). They are not TOTP. Reject unsupported proof
/// types. Do not normalize, log or serialize either credential. A consumed OTP can remain
/// consumed if a subsequent policy check or deletion fails; the core does not roll it back.
///
/// After verification, enforce applicable trusted deletion policy before changing state.
/// An organization-aware provider must reject deletion of a last confirmed organization
/// owner, following the pinned upstream policy. Other policy and storage failures use the
/// existing `Storage::map_error`; this interface does not implement organization membership
/// or authorize removal of an organization vault.
///
/// Delete the account and all its dependent personal vault data, attachment bytes and
/// download capabilities, private credentials/keys/API secrets, sessions, devices,
/// authentication requests, settings and private account metadata. Preserve unrelated
/// accounts, organization vaults and shared service configuration/signing state. No account
/// revision is left to update after successful deletion. The deletion and its dependent
/// cleanup must commit atomically: an error leaves this state unchanged. This is stronger
/// than upstream's sequential cleanup; it does not imply rollback of earlier proof
/// consumption or delivery of any external notifications. Embeddings must document their
/// supported cleanup families and upstream-version differences rather than assuming this
/// provider contract proves full account-lifecycle compatibility.
pub trait AccountDeletionStorage: Storage {
    fn verify_account_deletion_proof(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error>;

    fn delete_account(&mut self, owner: &str) -> Result<(), Self::Error>;
}

impl<T: AccountDeletionStorage + ?Sized> AccountDeletionStorage for &mut T {
    fn verify_account_deletion_proof(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).verify_account_deletion_proof(owner, proof)
    }

    fn delete_account(&mut self, owner: &str) -> Result<(), Self::Error> {
        (**self).delete_account(owner)
    }
}

impl<S: AccountDeletionStorage> VaultService<S> {
    /// Verify exactly one proof before asking the provider to check policy and delete
    /// the authenticated account. The request cannot choose another account identifier.
    pub fn delete_account(
        &mut self,
        owner: &str,
        request: &PasswordOrOtpRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let proof = request.proof()?;
        if !self
            .storage_mut()
            .verify_account_deletion_proof(owner, proof)
            .map_err(S::map_error)?
        {
            return Err(ApiError::invalid(
                "reauthentication",
                "Reauthentication failed.",
            ));
        }
        self.storage_mut()
            .delete_account(owner)
            .map_err(S::map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind,
        identity::Secret,
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };

    const OWNER: &str = "verified-owner";
    const FOREIGN: &str = "other-owner";
    const PASSWORD: &str = "private-delete-proof";
    const OTP: &str = "private-purpose-bound-delete-otp";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Verify,
        Delete,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Stage {
        Verify,
        Policy,
        Children,
        Account,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Failure {
        LastOwner,
        Policy,
        Storage,
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Account {
        id: &'static str,
        private: &'static str,
        vault: [bool; 3],
        attachment_bytes: [bool; 2],
        capabilities: [bool; 2],
        sessions: u8,
        devices: u8,
        auth_requests: [bool; 3],
        domains: bool,
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct State {
        accounts: [Option<Account>; 2],
        shared_signer: &'static str,
        organization_payload: &'static str,
    }
    impl core::fmt::Debug for State {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("State([REDACTED])")
        }
    }
    impl State {
        fn new() -> Self {
            let account = Account {
                id: OWNER,
                private: "keys-password-api-stamp",
                vault: [true; 3],
                attachment_bytes: [true; 2],
                capabilities: [true; 2],
                sessions: 3,
                devices: 2,
                auth_requests: [true; 3],
                domains: true,
            };
            Self {
                accounts: [
                    Some(account),
                    Some(Account {
                        id: FOREIGN,
                        ..account
                    }),
                ],
                shared_signer: "shared-signer",
                organization_payload: "foreign-org-data",
            }
        }
    }
    struct Bounded<'a> {
        state: State,
        password: &'a str,
        expected_pointer: Option<usize>,
        otp_available: bool,
        calls: [Option<Call>; 4],
        count: usize,
        fail: Option<Stage>,
        failure: Failure,
    }
    impl core::fmt::Debug for Bounded<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Bounded")
                .field("calls", &self.calls)
                .finish_non_exhaustive()
        }
    }
    impl Bounded<'_> {
        fn new() -> Self {
            Self {
                state: State::new(),
                password: PASSWORD,
                expected_pointer: None,
                otp_available: true,
                calls: [None; 4],
                count: 0,
                fail: None,
                failure: Failure::Storage,
            }
        }
        fn record(&mut self, call: Call) {
            self.calls[self.count] = Some(call);
            self.count += 1;
        }
        fn check(&self, stage: Stage) -> Result<(), Failure> {
            if self.fail == Some(stage) {
                Err(self.failure)
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Bounded<'_> {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::LastOwner => ApiError::invalid("account", "Can't delete last owner"),
                Failure::Policy => ApiError::new(
                    ErrorKind::Forbidden,
                    "Deletion policy rejected the account.",
                ),
                Failure::Storage => {
                    ApiError::new(ErrorKind::Storage, "Account deletion provider failed.")
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
    impl AccountDeletionStorage for Bounded<'_> {
        fn verify_account_deletion_proof(
            &mut self,
            owner: &str,
            proof: ReauthenticationProof<'_>,
        ) -> Result<bool, Failure> {
            self.record(Call::Verify);
            self.check(Stage::Verify)?;
            if owner != OWNER || self.state.accounts[0].is_none() {
                return Ok(false);
            }
            Ok(match proof {
                ReauthenticationProof::MasterPasswordHash(secret) => {
                    if let Some(pointer) = self.expected_pointer {
                        assert_eq!(secret.expose_secret().as_ptr() as usize, pointer);
                    }
                    secret.expose_secret() == self.password
                }
                ReauthenticationProof::ProtectedActionOtp(secret) => {
                    let valid = self.otp_available && secret.expose_secret() == OTP;
                    if valid {
                        self.otp_available = false;
                    }
                    valid
                }
            })
        }
        fn delete_account(&mut self, owner: &str) -> Result<(), Failure> {
            self.record(Call::Delete);
            self.check(Stage::Policy)?;
            let mut staged = self.state;
            let slot = staged
                .accounts
                .iter_mut()
                .find(|slot| slot.is_some_and(|account| account.id == owner))
                .ok_or(Failure::Storage)?;
            let account = slot.as_mut().ok_or(Failure::Storage)?;
            account.vault.fill(false);
            account.attachment_bytes.fill(false);
            account.capabilities.fill(false);
            account.sessions = 0;
            account.devices = 0;
            account.auth_requests.fill(false);
            account.domains = false;
            self.check(Stage::Children)?;
            *slot = None;
            self.check(Stage::Account)?;
            self.state = staged;
            Ok(())
        }
    }
    fn password(value: &str) -> PasswordOrOtpRequest<'_> {
        PasswordOrOtpRequest {
            master_password_hash: Some(Secret::new(value)),
            otp: None,
        }
    }
    fn otp() -> PasswordOrOtpRequest<'static> {
        PasswordOrOtpRequest {
            master_password_hash: None,
            otp: Some(Secret::new(OTP)),
        }
    }

    #[test]
    fn deletion_authentication_and_exactly_one_proof_precede_provider_access() {
        let mut service = VaultService::new(Bounded::new());
        assert_eq!(
            service
                .delete_account("", &password(PASSWORD))
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
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
            assert_eq!(
                service
                    .delete_account("", &request)
                    .unwrap_err()
                    .status_code(),
                401
            );
            assert_eq!(
                service
                    .delete_account(OWNER, &request)
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
        assert_eq!(service.storage().count, 0);
        assert_eq!(service.storage().state, State::new());
    }

    #[test]
    fn deletion_rejected_password_otp_or_owner_never_reaches_policy_or_cleanup() {
        for (owner, request) in [
            (OWNER, password("wrong-private-proof")),
            (FOREIGN, password(PASSWORD)),
            (
                OWNER,
                PasswordOrOtpRequest {
                    master_password_hash: None,
                    otp: Some(Secret::new("wrong-private-otp")),
                },
            ),
        ] {
            let mut service = VaultService::new(Bounded::new());
            assert_eq!(
                service
                    .delete_account(owner, &request)
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(
                service.storage().calls,
                [Some(Call::Verify), None, None, None]
            );
            assert_eq!(service.storage().state, State::new());
            assert!(service.storage().otp_available);
        }
    }

    #[test]
    fn deletion_both_proof_types_remove_only_the_verified_account_and_dependents() {
        for request in [password(PASSWORD), otp()] {
            let mut storage = Bounded::new();
            VaultService::new(&mut storage)
                .delete_account(OWNER, &request)
                .unwrap();
            let mut expected = State::new();
            expected.accounts[0] = None;
            assert_eq!(storage.state, expected);
            assert_eq!(
                storage.calls,
                [Some(Call::Verify), Some(Call::Delete), None, None]
            );
        }
    }

    #[test]
    fn deletion_last_owner_and_policy_failures_remain_typed_after_valid_proof() {
        for (failure, status) in [(Failure::LastOwner, 400), (Failure::Policy, 403)] {
            let mut storage = Bounded::new();
            storage.fail = Some(Stage::Policy);
            storage.failure = failure;
            let error = VaultService::new(&mut storage)
                .delete_account(OWNER, &password(PASSWORD))
                .unwrap_err();
            assert_eq!(error.status_code(), status);
            assert_eq!(
                storage.calls,
                [Some(Call::Verify), Some(Call::Delete), None, None]
            );
            assert_eq!(storage.state, State::new());
        }
    }

    #[test]
    fn deletion_provider_failures_preserve_atomic_state_and_error_mapping() {
        for stage in [Stage::Verify, Stage::Children, Stage::Account] {
            let mut storage = Bounded::new();
            storage.fail = Some(stage);
            let error = VaultService::new(&mut storage)
                .delete_account(OWNER, &password(PASSWORD))
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Storage);
            assert_eq!(storage.count, if stage == Stage::Verify { 1 } else { 2 });
            assert_eq!(storage.state, State::new());
        }
    }

    #[test]
    fn deletion_does_not_roll_back_a_previously_consumed_protected_action_proof() {
        for stage in [Stage::Policy, Stage::Children, Stage::Account] {
            let mut storage = Bounded::new();
            storage.fail = Some(stage);
            assert!(
                VaultService::new(&mut storage)
                    .delete_account(OWNER, &otp())
                    .is_err()
            );
            assert!(!storage.otp_available);
            assert_eq!(storage.state, State::new());
            storage.fail = None;
            assert_eq!(
                VaultService::new(&mut storage)
                    .delete_account(OWNER, &otp())
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(storage.state, State::new());
        }
    }

    #[test]
    fn deletion_borrows_opaque_proofs_and_keeps_requests_and_errors_redacted() {
        let input =
            br#"{"MasterPasswordHash":"private-caller-delete-proof","unknownOwner":"other-owner"}"#;
        let request: PasswordOrOtpRequest<'_> = serde_json::from_slice(input).unwrap();
        let proof = request
            .master_password_hash
            .as_ref()
            .unwrap()
            .expose_secret();
        assert!(
            (input.as_ptr() as usize..input.as_ptr() as usize + input.len())
                .contains(&(proof.as_ptr() as usize))
        );
        let mut storage = Bounded::new();
        storage.password = proof;
        storage.expected_pointer = Some(proof.as_ptr() as usize);
        VaultService::new(&mut storage)
            .delete_account(OWNER, &request)
            .unwrap();
        assert!(storage.state.accounts[0].is_none() && storage.state.accounts[1].is_some());
        for opaque in ["", "future\0proof 雪"] {
            let mut storage = Bounded::new();
            storage.password = opaque;
            storage.expected_pointer = Some(opaque.as_ptr() as usize);
            VaultService::new(&mut storage)
                .delete_account(OWNER, &password(opaque))
                .unwrap();
        }
        let mut service = VaultService::new(Bounded::new());
        let error = service.delete_account(OWNER, &request).unwrap_err();
        for rendered in [
            std::format!("{request:?}"),
            std::format!("{:?}", otp()),
            std::format!("{error:?} {error}"),
        ] {
            assert!(!rendered.contains(proof) && !rendered.contains(OTP));
        }
    }
}
