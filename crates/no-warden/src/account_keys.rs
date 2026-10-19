//! Owner-only key-pair initialization/read and authenticated public-key discovery.
//!
//! Key strings are opaque, including empty strings. These operations neither decrypt
//! nor validate cryptographic envelopes. HTTP parsing, authenticated identity, clocks,
//! persistence, and transactions belong to the embedding application.

use crate::{
    ApiError, ErrorKind, Storage, VaultService,
    identity::Secret,
    service::require_owner,
    wire::{
        AccountKeys, AccountKeysResponse, InitializedAccountKeysResponse, UserPublicKeyResponse,
        WebAuthnCredentialsResponse,
    },
};

/// Borrowed persisted state. `Some("")` is an existing key, distinct from absence.
pub struct AccountKeyState<'a> {
    pub key: &'a str,
    pub public_key: Option<&'a str>,
    pub encrypted_private_key: Option<&'a str>,
}

impl core::fmt::Debug for AccountKeyState<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AccountKeyState([REDACTED])")
    }
}

/// Opt-in account key operations sharing the existing provider error mapper.
///
/// Hold the embedding application's lock/transaction across an entire service call.
/// Private state is read only for the verified owner argument. The public-key lookup
/// deliberately allows any authenticated account to read another account's public key;
/// it must not return private account state or require a shared organization.
/// Resolve identifiers without normalizing spelling/case. A missing user/public key is
/// `None`; an existing empty public key is `Some("")`.
///
/// Initialization must insert both opaque fields only when both are absent, atomically
/// with the account revision. Never overwrite even one existing field, including an empty
/// one. Provider errors leave both keys, account revision, and unrelated data unchanged.
/// No cipher data, security stamp, user-key ID, or existing session authority changes.
pub trait AccountKeyStorage: Storage {
    fn account_key_state(
        &mut self,
        owner: &str,
    ) -> Result<Option<AccountKeyState<'_>>, Self::Error>;
    fn initialize_account_keys(
        &mut self,
        owner: &str,
        request: &AccountKeys<'_>,
    ) -> Result<(), Self::Error>;
    fn user_public_key(&mut self, user_id: &str) -> Result<Option<&str>, Self::Error>;
}

impl<T: AccountKeyStorage + ?Sized> AccountKeyStorage for &mut T {
    fn account_key_state(
        &mut self,
        owner: &str,
    ) -> Result<Option<AccountKeyState<'_>>, Self::Error> {
        (**self).account_key_state(owner)
    }
    fn initialize_account_keys(
        &mut self,
        owner: &str,
        request: &AccountKeys<'_>,
    ) -> Result<(), Self::Error> {
        (**self).initialize_account_keys(owner, request)
    }
    fn user_public_key(&mut self, user_id: &str) -> Result<Option<&str>, Self::Error> {
        (**self).user_public_key(user_id)
    }
}

fn unavailable() -> ApiError {
    ApiError::new(
        ErrorKind::NotFound,
        "The requested account keys are unavailable.",
    )
}

impl<S: Storage> VaultService<S> {
    /// Returns the pinned empty credential metadata after the adapter authenticates
    /// the owner. This operation reads no provider state and changes no account data.
    /// It does not enumerate registered two-factor keys or enable passkey login.
    pub fn get_webauthn_credentials(
        &self,
        owner: &str,
    ) -> Result<WebAuthnCredentialsResponse, ApiError> {
        require_owner(owner)?;
        Ok(WebAuthnCredentialsResponse)
    }
}

impl<S: AccountKeyStorage> VaultService<S> {
    pub fn get_account_keys(&mut self, owner: &str) -> Result<AccountKeysResponse<'_>, ApiError> {
        require_owner(owner)?;
        let state = self
            .storage_mut()
            .account_key_state(owner)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        let public_key = state.public_key.ok_or_else(unavailable)?;
        let private_key = state.encrypted_private_key.ok_or_else(unavailable)?;
        Ok(AccountKeysResponse {
            key: (!state.key.is_empty()).then_some(Secret::new(state.key)),
            public_key,
            private_key: Secret::new(private_key),
        })
    }

    pub fn initialize_account_keys<'a>(
        &mut self,
        owner: &str,
        request: &AccountKeys<'a>,
    ) -> Result<InitializedAccountKeysResponse<'a>, ApiError> {
        require_owner(owner)?;
        let state = self
            .storage_mut()
            .account_key_state(owner)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        if state.public_key.is_some() || state.encrypted_private_key.is_some() {
            return Err(ApiError::invalid(
                "keys",
                "The account already has a key pair.",
            ));
        }
        self.storage_mut()
            .initialize_account_keys(owner, request)
            .map_err(S::map_error)?;
        Ok(InitializedAccountKeysResponse {
            public_key: request.public_key,
            private_key: Secret::new(request.encrypted_private_key),
        })
    }

    pub fn get_user_public_key<'a>(
        &'a mut self,
        owner: &str,
        user_id: &'a str,
    ) -> Result<UserPublicKeyResponse<'a>, ApiError> {
        require_owner(owner)?;
        let public_key = self
            .storage_mut()
            .user_public_key(user_id)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        Ok(UserPublicKeyResponse {
            user_id,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };

    #[derive(Clone, Eq, PartialEq)]
    struct Record {
        key: String,
        public_key: Option<String>,
        private_key: Option<String>,
        revision: usize,
        unrelated: String,
    }
    impl core::fmt::Debug for Record {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("Record")
                .field("revision", &self.revision)
                .finish_non_exhaustive()
        }
    }
    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Backend,
        AlreadyInitialized,
    }
    struct Memory {
        records: BTreeMap<String, Record>,
        calls: Vec<&'static str>,
        fail_at: Option<&'static str>,
        failure: Failure,
    }
    impl core::fmt::Debug for Memory {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("Memory")
                .field("calls", &self.calls)
                .finish_non_exhaustive()
        }
    }
    impl Memory {
        fn new() -> Self {
            Self {
                records: BTreeMap::from([
                    (
                        "alice".into(),
                        Record {
                            key: "wrapped-user-key".into(),
                            public_key: None,
                            private_key: None,
                            revision: 3,
                            unrelated: "preserved".into(),
                        },
                    ),
                    (
                        "bob".into(),
                        Record {
                            key: "foreign-user-key".into(),
                            public_key: Some("foreign-public-key".into()),
                            private_key: Some("foreign-private-key".into()),
                            revision: 7,
                            unrelated: "preserved".into(),
                        },
                    ),
                ]),
                calls: Vec::new(),
                fail_at: None,
                failure: Failure::Backend,
            }
        }
        fn fail(&self, operation: &str) -> Result<(), Failure> {
            if self.fail_at == Some(operation) {
                Err(self.failure)
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Memory {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::Backend => {
                    ApiError::new(ErrorKind::Storage, "Account key provider failed.")
                }
                Failure::AlreadyInitialized => {
                    ApiError::invalid("keys", "The account already has a key pair.")
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
    impl AccountKeyStorage for Memory {
        fn account_key_state(
            &mut self,
            owner: &str,
        ) -> Result<Option<AccountKeyState<'_>>, Failure> {
            self.calls.push("state");
            self.fail("state")?;
            Ok(self.records.get(owner).map(|record| AccountKeyState {
                key: &record.key,
                public_key: record.public_key.as_deref(),
                encrypted_private_key: record.private_key.as_deref(),
            }))
        }
        fn initialize_account_keys(
            &mut self,
            owner: &str,
            request: &AccountKeys<'_>,
        ) -> Result<(), Failure> {
            self.calls.push("initialize");
            let mut staged = self.records.clone();
            let record = staged.get_mut(owner).ok_or(Failure::Backend)?;
            if record.public_key.is_some() || record.private_key.is_some() {
                return Err(Failure::AlreadyInitialized);
            }
            record.public_key = Some(request.public_key.to_string());
            record.private_key = Some(request.encrypted_private_key.to_string());
            record.revision += 1;
            // A late error after changing both fields/revision must leave persisted state intact.
            self.fail("initialize")?;
            self.records = staged;
            Ok(())
        }
        fn user_public_key(&mut self, user_id: &str) -> Result<Option<&str>, Failure> {
            self.calls.push("public");
            self.fail("public")?;
            Ok(self
                .records
                .get(user_id)
                .and_then(|record| record.public_key.as_deref()))
        }
    }
    fn request() -> AccountKeys<'static> {
        AccountKeys {
            encrypted_private_key: "future-private:opaque",
            public_key: "future-public:opaque",
        }
    }

    #[test]
    fn webauthn_credentials_require_authentication_without_reading_storage() {
        let service = VaultService::new(Memory::new());
        assert_eq!(
            service.get_webauthn_credentials("").unwrap_err().kind,
            ErrorKind::Unauthorized
        );
        assert!(service.storage().calls.is_empty());
    }

    #[test]
    fn webauthn_credentials_do_not_require_stored_keys_or_an_opt_in_key_provider() {
        fn get<S: Storage>(
            service: &VaultService<S>,
            owner: &str,
        ) -> Result<WebAuthnCredentialsResponse, ApiError> {
            service.get_webauthn_credentials(owner)
        }

        let mut storage = Memory::new();
        storage.fail_at = Some("state");
        let before = storage.records.clone();
        let service = VaultService::new(&mut storage);
        for owner in ["alice", "bob", "adapter-verified-owner"] {
            let response = get(&service, owner).unwrap();
            assert_eq!(
                serde_json::to_value(response).unwrap(),
                serde_json::json!({"object":"list","data":[],"continuationToken":null})
            );
        }
        assert!(service.storage().calls.is_empty());
        assert_eq!(service.storage().records, before);
    }

    #[test]
    fn unauthenticated_key_operations_do_not_reach_any_provider() {
        let mut service = VaultService::new(Memory::new());
        assert_eq!(
            service.get_account_keys("").unwrap_err().kind,
            ErrorKind::Unauthorized
        );
        assert_eq!(
            service
                .initialize_account_keys("", &request())
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert_eq!(
            service.get_user_public_key("", "bob").unwrap_err().kind,
            ErrorKind::Unauthorized
        );
        assert!(service.storage().calls.is_empty());
    }

    #[test]
    fn initialization_rejects_either_existing_field_including_empty_partial_pairs() {
        for public in [None, Some(""), Some("existing-public")] {
            for private in [None, Some(""), Some("existing-private")] {
                if public.is_none() && private.is_none() {
                    continue;
                }
                let mut storage = Memory::new();
                let record = storage.records.get_mut("alice").unwrap();
                record.public_key = public.map(ToString::to_string);
                record.private_key = private.map(ToString::to_string);
                let before = storage.records.clone();
                let mut service = VaultService::new(&mut storage);
                let error = service
                    .initialize_account_keys("alice", &request())
                    .unwrap_err();
                assert_eq!(error.status_code(), 400);
                assert_eq!(service.storage().calls, ["state"]);
                assert_eq!(service.storage().records, before);
            }
        }
    }

    #[test]
    fn initialization_preserves_opaque_empty_future_and_escaped_strings_without_touching_other_state()
     {
        for (private, public) in [
            ("", ""),
            ("future.v42:no-envelope", "not-base64"),
            ("quoted\"\n雪 🔐", "public\\escaped\t🦀"),
        ] {
            let mut storage = Memory::new();
            let foreign = storage.records["bob"].clone();
            let mut service = VaultService::new(&mut storage);
            let request = AccountKeys {
                encrypted_private_key: private,
                public_key: public,
            };
            let response = service.initialize_account_keys("alice", &request).unwrap();
            assert_eq!(response.private_key.expose_secret(), private);
            assert_eq!(response.public_key, public);
            // The response borrows its request, leaving provider access available.
            let saved = &service.storage().records["alice"];
            assert_eq!(saved.private_key.as_deref(), Some(private));
            assert_eq!(saved.public_key.as_deref(), Some(public));
            assert_eq!(saved.revision, 4);
            assert_eq!(saved.key, "wrapped-user-key");
            assert_eq!(saved.unrelated, "preserved");
            assert_eq!(service.storage().records["bob"], foreign);
            assert_eq!(service.storage().calls, ["state", "initialize"]);
            assert_eq!(
                serde_json::to_value(&response).unwrap(),
                serde_json::json!({"privateKey":private,"publicKey":public,"object":"keys"})
            );
        }
    }

    #[test]
    fn own_reads_require_both_fields_but_keep_empty_pairs_and_empty_user_key_null() {
        for (public, private) in [
            (None, None),
            (Some("public"), None),
            (None, Some("private")),
        ] {
            let mut storage = Memory::new();
            let record = storage.records.get_mut("alice").unwrap();
            record.public_key = public.map(ToString::to_string);
            record.private_key = private.map(ToString::to_string);
            let before = storage.records.clone();
            let mut service = VaultService::new(&mut storage);
            assert_eq!(
                service.get_account_keys("alice").unwrap_err().status_code(),
                404
            );
            assert_eq!(service.storage().records, before);
        }
        let mut storage = Memory::new();
        let record = storage.records.get_mut("alice").unwrap();
        record.key.clear();
        record.public_key = Some(String::new());
        record.private_key = Some(String::new());
        let mut service = VaultService::new(&mut storage);
        let response = serde_json::to_value(service.get_account_keys("alice").unwrap()).unwrap();
        assert!(response["key"].is_null());
        assert_eq!(response["publicKey"], "");
        assert_eq!(response["privateKey"], "");
        assert_eq!(
            response["accountKeys"]["publicKeyEncryptionKeyPair"]["wrappedPrivateKey"],
            ""
        );
        assert_eq!(
            service
                .get_account_keys("missing")
                .unwrap_err()
                .status_code(),
            404
        );
        assert_eq!(
            service
                .initialize_account_keys("missing", &request())
                .unwrap_err()
                .status_code(),
            404
        );
    }

    #[test]
    fn public_lookup_allows_other_users_and_never_returns_private_or_user_keys() {
        let mut storage = Memory::new();
        let mut service = VaultService::new(&mut storage);
        let public =
            serde_json::to_value(service.get_user_public_key("alice", "bob").unwrap()).unwrap();
        assert_eq!(
            public,
            serde_json::json!({"userId":"bob","publicKey":"foreign-public-key","object":"userKey"})
        );
        assert_eq!(service.storage().calls, ["public"]);
        for id in ["alice", "missing", "BOB"] {
            assert_eq!(
                service
                    .get_user_public_key("alice", id)
                    .unwrap_err()
                    .status_code(),
                404
            );
        }
        service
            .storage_mut()
            .records
            .get_mut("alice")
            .unwrap()
            .public_key = Some(String::new());
        let public = service.get_user_public_key("bob", "alice").unwrap();
        assert_eq!(public.public_key, "");
    }

    #[test]
    fn provider_failures_preserve_keys_revisions_and_existing_error_mapping() {
        for operation in ["state", "public"] {
            let mut storage = Memory::new();
            storage.fail_at = Some(operation);
            let before = storage.records.clone();
            let mut service = VaultService::new(&mut storage);
            if operation == "state" {
                assert_eq!(
                    service.get_account_keys("bob").unwrap_err().kind,
                    ErrorKind::Storage
                );
                assert_eq!(
                    service
                        .initialize_account_keys("alice", &request())
                        .unwrap_err()
                        .kind,
                    ErrorKind::Storage
                );
            } else {
                assert_eq!(
                    service
                        .get_user_public_key("alice", "bob")
                        .unwrap_err()
                        .kind,
                    ErrorKind::Storage
                );
            }
            assert_eq!(service.storage().records, before);
        }
        for (failure, expected) in [
            (Failure::Backend, ErrorKind::Storage),
            (Failure::AlreadyInitialized, ErrorKind::InvalidRequest),
        ] {
            let mut storage = Memory::new();
            storage.fail_at = Some("initialize");
            storage.failure = failure;
            let before = storage.records.clone();
            let mut service = VaultService::new(&mut storage);
            assert_eq!(
                service
                    .initialize_account_keys("alice", &request())
                    .unwrap_err()
                    .kind,
                expected
            );
            assert_eq!(service.storage().records, before);
            service.storage_mut().fail_at = None;
            service
                .initialize_account_keys("alice", &request())
                .unwrap();
            let response =
                serde_json::to_value(service.get_account_keys("alice").unwrap()).unwrap();
            assert_eq!(response["key"], "wrapped-user-key");
            assert_eq!(service.storage().records["alice"].revision, 4);
        }
    }
}
