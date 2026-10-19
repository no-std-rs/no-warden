//! Reauthenticated personal-vault deletion through an opt-in persistence provider.
//!
//! The authenticated owner and personal scope must be resolved by the adapter.
//! Credential verification, protected-action OTPs, transactions, clocks, attachment
//! storage, notifications and organization authorization stay outside this crate.

use crate::{
    ApiError, Storage, VaultService, identity::ReauthenticationProof, service::require_owner,
    wire::PasswordOrOtpRequest,
};

/// Personal purge operations, independent of API-key or account-security providers.
/// Hold the authenticated operation's lock/context across the complete service call.
///
/// Verify the exact opaque client server-authorization hash with the password provider.
/// Protected-action OTPs must be bound to the account and purpose, unexpired, and
/// consumed on successful verification (`delete_if_valid=true`); they are not TOTP.
/// An adapter without protected-action OTP support must reject that proof. Never log,
/// normalize or serialize either credential. Verification may consume an OTP before a
/// later purge failure; the service does not promise rollback of that prior operation.
///
/// Purge every personal cipher owned by this account, including active, trashed and
/// archived items, all owned folders, and the removed ciphers' attachment bytes,
/// download capabilities and archive/folder annotations. Advance the owner's account
/// revision even when the personal vault is already empty. Preserve account credentials,
/// client KDF, keys, security stamp/exception, sessions, devices, authentication requests,
/// domain settings, organization data and every foreign owner's unrelated state.
///
/// This provider contract requires the purge mutation and revision to commit atomically:
/// a purge error leaves that vault state and revision unchanged. It is stronger than
/// upstream's sequential deletions, which can retain earlier mutations after an error.
/// A provider can wrap proof consumption as well if it offers that additional guarantee.
/// Notifications and external cleanup remain adapter responsibilities; implementing this
/// interface alone does not supply their delivery or organization-purge authorization.
pub trait VaultPurgeStorage: Storage {
    fn verify_vault_purge_proof(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error>;

    fn purge_personal_vault(&mut self, owner: &str) -> Result<(), Self::Error>;
}

impl<T: VaultPurgeStorage + ?Sized> VaultPurgeStorage for &mut T {
    fn verify_vault_purge_proof(
        &mut self,
        owner: &str,
        proof: ReauthenticationProof<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).verify_vault_purge_proof(owner, proof)
    }

    fn purge_personal_vault(&mut self, owner: &str) -> Result<(), Self::Error> {
        (**self).purge_personal_vault(owner)
    }
}

impl<S: VaultPurgeStorage> VaultService<S> {
    /// Delete only the authenticated owner's personal vault after exactly one proof.
    /// Organization/query selection belongs to the adapter and cannot change this scope.
    pub fn purge_personal_vault(
        &mut self,
        owner: &str,
        request: &PasswordOrOtpRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let proof = request.proof()?;
        if !self
            .storage_mut()
            .verify_vault_purge_proof(owner, proof)
            .map_err(S::map_error)?
        {
            return Err(ApiError::invalid(
                "reauthentication",
                "Reauthentication failed.",
            ));
        }
        self.storage_mut()
            .purge_personal_vault(owner)
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
    const FOREIGN: &str = "foreign-owner";
    const PASSWORD: &str = "private-client-hash";
    const OTP: &str = "private-purpose-bound-proof";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Verify,
        Purge,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fail {
        Verify,
        Ciphers,
        Folders,
        Revision,
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Cipher {
        owner: &'static str,
        deleted: bool,
        archived: bool,
        organization: bool,
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct State {
        ciphers: [Option<Cipher>; 4],
        folders: [Option<&'static str>; 3],
        attachments: [Option<usize>; 4],
        grants: [Option<usize>; 4],
        annotations: [Option<usize>; 4],
        revision: u64,
        foreign_revision: u64,
        preserved: [&'static str; 8],
    }
    impl core::fmt::Debug for State {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("State([REDACTED])")
        }
    }
    impl State {
        fn new() -> Self {
            Self {
                ciphers: [
                    Some(Cipher {
                        owner: OWNER,
                        deleted: false,
                        archived: false,
                        organization: false,
                    }),
                    Some(Cipher {
                        owner: OWNER,
                        deleted: true,
                        archived: true,
                        organization: false,
                    }),
                    Some(Cipher {
                        owner: FOREIGN,
                        deleted: false,
                        archived: true,
                        organization: false,
                    }),
                    Some(Cipher {
                        owner: OWNER,
                        deleted: false,
                        archived: false,
                        organization: true,
                    }),
                ],
                folders: [Some(OWNER), Some(FOREIGN), Some(OWNER)],
                attachments: [Some(0), Some(1), Some(2), Some(3)],
                grants: [Some(0), Some(1), Some(2), Some(3)],
                annotations: [Some(0), Some(1), Some(2), Some(3)],
                revision: 10,
                foreign_revision: 20,
                preserved: [
                    "password",
                    "keys/client-kdf",
                    "stamp/exception",
                    "sessions",
                    "devices",
                    "authentication-requests",
                    "domain-settings",
                    "api-key",
                ],
            }
        }
        fn purged(mut self) -> Self {
            self.ciphers[0] = None;
            self.ciphers[1] = None;
            self.folders[0] = None;
            self.folders[2] = None;
            for entries in [
                &mut self.attachments,
                &mut self.grants,
                &mut self.annotations,
            ] {
                entries[0] = None;
                entries[1] = None;
            }
            self.revision += 1;
            self
        }
    }
    struct Bounded<'a> {
        state: State,
        calls: [Option<Call>; 4],
        call_count: usize,
        password: &'a str,
        expected_password_pointer: Option<usize>,
        otp_available: bool,
        fail: Option<Fail>,
        error: ErrorKind,
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
                calls: [None; 4],
                call_count: 0,
                password: PASSWORD,
                expected_password_pointer: None,
                otp_available: true,
                fail: None,
                error: ErrorKind::Storage,
            }
        }
        fn call(&mut self, call: Call) {
            self.calls[self.call_count] = Some(call);
            self.call_count += 1;
        }
        fn fail_at(&self, point: Fail) -> Result<(), ErrorKind> {
            if self.fail == Some(point) {
                Err(self.error)
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Bounded<'_> {
        type Error = ErrorKind;
        fn map_error(error: Self::Error) -> ApiError {
            ApiError::new(error, "Personal purge provider failed.")
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
    impl VaultPurgeStorage for Bounded<'_> {
        fn verify_vault_purge_proof(
            &mut self,
            owner: &str,
            proof: ReauthenticationProof<'_>,
        ) -> Result<bool, Self::Error> {
            self.call(Call::Verify);
            self.fail_at(Fail::Verify)?;
            if owner != OWNER {
                return Ok(false);
            }
            Ok(match proof {
                ReauthenticationProof::MasterPasswordHash(secret) => {
                    if let Some(pointer) = self.expected_password_pointer {
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
        fn purge_personal_vault(&mut self, owner: &str) -> Result<(), Self::Error> {
            self.call(Call::Purge);
            let mut staged = self.state;
            let mut removed = [false; 4];
            for (index, cipher) in staged.ciphers.iter_mut().enumerate() {
                if cipher.is_some_and(|cipher| cipher.owner == owner && !cipher.organization) {
                    *cipher = None;
                    removed[index] = true;
                }
            }
            for entries in [
                &mut staged.attachments,
                &mut staged.grants,
                &mut staged.annotations,
            ] {
                for entry in entries {
                    if entry.is_some_and(|index| removed[index]) {
                        *entry = None;
                    }
                }
            }
            self.fail_at(Fail::Ciphers)?;
            for folder in &mut staged.folders {
                if *folder == Some(owner) {
                    *folder = None;
                }
            }
            self.fail_at(Fail::Folders)?;
            staged.revision += 1;
            self.fail_at(Fail::Revision)?;
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
    fn purge_authentication_and_exactly_one_proof_precede_every_provider_call() {
        let mut service = VaultService::new(Bounded::new());
        for request in [
            password(PASSWORD),
            PasswordOrOtpRequest {
                master_password_hash: None,
                otp: None,
            },
        ] {
            assert_eq!(
                service.purge_personal_vault("", &request).unwrap_err().kind,
                ErrorKind::Unauthorized
            );
        }
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
                    .purge_personal_vault(OWNER, &request)
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
        assert_eq!(service.storage().call_count, 0);
        assert_eq!(service.storage().state, State::new());
    }

    #[test]
    fn purge_wrong_password_otp_or_owner_never_reaches_mutation() {
        for (owner, request) in [
            (OWNER, password("wrong-private-proof")),
            (
                OWNER,
                PasswordOrOtpRequest {
                    master_password_hash: None,
                    otp: Some(Secret::new("wrong-private-otp")),
                },
            ),
            (FOREIGN, password(PASSWORD)),
        ] {
            let mut service = VaultService::new(Bounded::new());
            let error = service.purge_personal_vault(owner, &request).unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert_eq!(
                service.storage().calls,
                [Some(Call::Verify), None, None, None]
            );
            assert_eq!(service.storage().state, State::new());
            assert!(service.storage().otp_available);
        }
    }

    #[test]
    fn purge_both_proof_types_remove_all_personal_states_and_preserve_other_authority() {
        for request in [password(PASSWORD), otp()] {
            let mut storage = Bounded::new();
            VaultService::new(&mut storage)
                .purge_personal_vault(OWNER, &request)
                .unwrap();
            assert_eq!(
                storage.calls,
                [Some(Call::Verify), Some(Call::Purge), None, None]
            );
            assert_eq!(storage.state, State::new().purged());
        }
    }

    #[test]
    fn purge_empty_vault_still_advances_revision_on_each_verified_operation() {
        let mut storage = Bounded::new();
        storage.state = State::new().purged();
        let mut expected = storage.state;
        for _ in 0..2 {
            VaultService::new(&mut storage)
                .purge_personal_vault(OWNER, &password(PASSWORD))
                .unwrap();
            expected.revision += 1;
            assert_eq!(storage.state, expected);
        }
    }

    #[test]
    fn purge_provider_failures_keep_atomic_vault_state_and_typed_error_mapping() {
        for point in [Fail::Verify, Fail::Ciphers, Fail::Folders, Fail::Revision] {
            for kind in [ErrorKind::Storage, ErrorKind::Conflict] {
                let mut storage = Bounded::new();
                storage.fail = Some(point);
                storage.error = kind;
                let error = VaultService::new(&mut storage)
                    .purge_personal_vault(OWNER, &password(PASSWORD))
                    .unwrap_err();
                assert_eq!(error.kind, kind);
                assert_eq!(storage.state, State::new());
                assert_eq!(
                    storage.call_count,
                    if point == Fail::Verify { 1 } else { 2 }
                );
            }
        }
    }

    #[test]
    fn purge_consumed_protected_action_proof_does_not_imply_rollback_on_later_failure() {
        let mut storage = Bounded::new();
        storage.fail = Some(Fail::Revision);
        let error = VaultService::new(&mut storage)
            .purge_personal_vault(OWNER, &otp())
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Storage);
        assert!(!storage.otp_available);
        assert_eq!(storage.state, State::new());
        storage.fail = None;
        assert_eq!(
            VaultService::new(&mut storage)
                .purge_personal_vault(OWNER, &otp())
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(storage.state, State::new());
    }

    #[test]
    fn purge_borrows_opaque_caller_buffers_and_never_formats_credentials() {
        let input = br#"{"MasterPasswordHash":"private-caller-proof","ignored":true}"#;
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
        storage.expected_password_pointer = Some(proof.as_ptr() as usize);
        VaultService::new(&mut storage)
            .purge_personal_vault(OWNER, &request)
            .unwrap();
        assert_eq!(storage.state, State::new().purged());
        for opaque in ["", "future\0opaque 雪"] {
            let mut storage = Bounded::new();
            storage.password = opaque;
            storage.expected_password_pointer = Some(opaque.as_ptr() as usize);
            VaultService::new(&mut storage)
                .purge_personal_vault(OWNER, &password(opaque))
                .unwrap();
        }
        for rendered in [
            std::format!("{request:?}"),
            std::format!("{:?}", otp()),
            std::format!("{:?}", password("private-caller-proof").proof().unwrap()),
        ] {
            assert!(!rendered.contains("private-caller-proof") && !rendered.contains(OTP));
        }
        let mut service = VaultService::new(Bounded::new());
        let error = service
            .purge_personal_vault(OWNER, &password("private-caller-proof"))
            .unwrap_err();
        assert!(!std::format!("{error:?} {error}").contains("private-caller-proof"));
    }
}
