//! Authenticated profile metadata mutations without allocation or normalization.
//!
//! The adapter supplies verified identity and builds the complete HTTP profile response.
//! These services mutate only the requested field; they are not full account lifecycle APIs.

use crate::{
    ApiError, Storage, VaultService,
    service::require_owner,
    wire::{AvatarUpdateRequest, ProfileUpdateRequest},
};

/// Opt-in persistence for account metadata using the shared storage error mapper.
///
/// Owner IDs must come from verified authentication, never request metadata. Hold the
/// application's lock/transaction for the entire service operation. Each successful call
/// stores the exact field value and advances the owner's account revision atomically,
/// including repeated writes of the current value. `None` clears the avatar field.
///
/// Provider failures preserve both metadata and revisions. Changes must preserve all other
/// fields, including account keys, password verifiers, API credentials, security stamps,
/// user-key IDs, sessions, vault payloads, and foreign accounts. Clocks, persistence and
/// complete profile serialization belong to the adapter, outside this allocation-free core.
pub trait AccountProfileStorage: Storage {
    fn update_profile_name(
        &mut self,
        owner: &str,
        request: &ProfileUpdateRequest<'_>,
    ) -> Result<(), Self::Error>;

    fn update_avatar_color(
        &mut self,
        owner: &str,
        request: &AvatarUpdateRequest<'_>,
    ) -> Result<(), Self::Error>;
}

impl<T: AccountProfileStorage + ?Sized> AccountProfileStorage for &mut T {
    fn update_profile_name(
        &mut self,
        owner: &str,
        request: &ProfileUpdateRequest<'_>,
    ) -> Result<(), Self::Error> {
        (**self).update_profile_name(owner, request)
    }

    fn update_avatar_color(
        &mut self,
        owner: &str,
        request: &AvatarUpdateRequest<'_>,
    ) -> Result<(), Self::Error> {
        (**self).update_avatar_color(owner, request)
    }
}

impl<S: AccountProfileStorage> VaultService<S> {
    pub fn update_profile(
        &mut self,
        owner: &str,
        request: &ProfileUpdateRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        if request.name.len() > 50 {
            return Err(ApiError::invalid(
                "name",
                "The profile name must be at most 50 UTF-8 bytes.",
            ));
        }
        self.storage_mut()
            .update_profile_name(owner, request)
            .map_err(S::map_error)
    }

    pub fn update_avatar(
        &mut self,
        owner: &str,
        request: &AvatarUpdateRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        if request.avatar_color.is_some_and(|color| color.len() != 7) {
            return Err(ApiError::invalid(
                "avatarColor",
                "The avatar color must contain exactly seven UTF-8 bytes.",
            ));
        }
        self.storage_mut()
            .update_avatar_color(owner, request)
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
    use std::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };

    #[derive(Clone, Eq, PartialEq)]
    struct Account {
        name: String,
        avatar: Option<String>,
        revision: usize,
        credentials: (&'static str, &'static str, &'static str),
        sessions: [bool; 2],
        vault: (&'static str, &'static str),
    }
    impl core::fmt::Debug for Account {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter
                .debug_struct("Account")
                .field("revision", &self.revision)
                .finish_non_exhaustive()
        }
    }
    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Backend,
        Conflict,
        Missing,
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Operation {
        Name,
        Avatar,
    }
    struct Memory {
        accounts: BTreeMap<String, Account>,
        calls: Vec<Operation>,
        fail: Option<Failure>,
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
            let account = Account {
                name: "original".into(),
                avatar: Some("abcdefg".into()),
                revision: 7,
                credentials: (
                    "test-password-verifier",
                    "test-api-key",
                    "test-wrapped-keys",
                ),
                sessions: [true, true],
                vault: ("opaque-folder", "opaque-cipher"),
            };
            Self {
                accounts: BTreeMap::from([
                    ("alice".into(), account.clone()),
                    ("bob".into(), account),
                ]),
                calls: Vec::new(),
                fail: None,
            }
        }
        fn commit(
            &mut self,
            owner: &str,
            operation: Operation,
            value: Option<&str>,
        ) -> Result<(), Failure> {
            self.calls.push(operation);
            let mut staged = self.accounts.clone();
            let account = staged.get_mut(owner).ok_or(Failure::Missing)?;
            match operation {
                Operation::Name => account.name = value.unwrap().to_string(),
                Operation::Avatar => account.avatar = value.map(ToString::to_string),
            }
            account.revision += 1;
            if let Some(error) = self.fail {
                return Err(error);
            }
            self.accounts = staged;
            Ok(())
        }
    }
    impl Storage for Memory {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::Backend => ApiError::new(ErrorKind::Storage, "Profile provider failed."),
                Failure::Conflict => {
                    ApiError::new(ErrorKind::Conflict, "Retry the profile operation.")
                }
                Failure::Missing => ApiError::new(ErrorKind::NotFound, "Account unavailable."),
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
    impl AccountProfileStorage for Memory {
        fn update_profile_name(
            &mut self,
            owner: &str,
            request: &ProfileUpdateRequest<'_>,
        ) -> Result<(), Failure> {
            self.commit(owner, Operation::Name, Some(request.name))
        }
        fn update_avatar_color(
            &mut self,
            owner: &str,
            request: &AvatarUpdateRequest<'_>,
        ) -> Result<(), Failure> {
            self.commit(owner, Operation::Avatar, request.avatar_color)
        }
    }

    #[test]
    fn raw_profile_names_preserve_empty_whitespace_controls_and_fifty_utf8_bytes() {
        let ascii = "x".repeat(50);
        let accented = "é".repeat(25);
        let emoji = std::format!("{}ab", "🔐".repeat(12));
        for name in [
            "",
            " \t\n\0 ",
            "é",
            "e\u{301}",
            "quoted\"雪",
            &ascii,
            &accented,
            &emoji,
        ] {
            let mut storage = Memory::new();
            let mut expected = storage.accounts.clone();
            expected.get_mut("alice").unwrap().name = name.to_string();
            expected.get_mut("alice").unwrap().revision = 8;
            let mut service = VaultService::new(&mut storage);
            service
                .update_profile("alice", &ProfileUpdateRequest { name })
                .unwrap();
            assert_eq!(service.storage().accounts, expected);
            assert_eq!(service.storage().calls, [Operation::Name]);
        }
    }

    #[test]
    fn excessive_profile_byte_lengths_fail_before_any_provider_call() {
        let ascii = "x".repeat(51);
        let accented = std::format!("{}a", "é".repeat(25));
        let emoji = std::format!("{}abc", "🔐".repeat(12));
        let mut service = VaultService::new(Memory::new());
        let before = service.storage().accounts.clone();
        for name in [&ascii, &accented, &emoji] {
            assert_eq!(name.len(), 51);
            let error = service
                .update_profile("alice", &ProfileUpdateRequest { name })
                .unwrap_err();
            assert_eq!(error.field, Some("name"));
            assert_eq!(error.status_code(), 400);
        }
        assert!(service.storage().calls.is_empty());
        assert_eq!(service.storage().accounts, before);
    }

    #[test]
    fn avatar_values_are_exactly_seven_bytes_without_format_checks_and_none_clears() {
        for color in [
            Some("abcdefg"),
            Some("!!!!!!!"),
            Some("aé🔐"),
            Some("éééa"),
            None,
        ] {
            let mut storage = Memory::new();
            let mut expected = storage.accounts.clone();
            let account = expected.get_mut("alice").unwrap();
            account.avatar = color.map(ToString::to_string);
            account.revision = 8;
            let mut service = VaultService::new(&mut storage);
            service
                .update_avatar(
                    "alice",
                    &AvatarUpdateRequest {
                        avatar_color: color,
                    },
                )
                .unwrap();
            assert_eq!(service.storage().accounts, expected);
            assert_eq!(service.storage().calls, [Operation::Avatar]);
        }
        let mut service = VaultService::new(Memory::new());
        let before = service.storage().accounts.clone();
        for color in ["", "#12345", "#1234567", "ééé", "🔐🔐", "#12345é"] {
            let error = service
                .update_avatar(
                    "alice",
                    &AvatarUpdateRequest {
                        avatar_color: Some(color),
                    },
                )
                .unwrap_err();
            assert_eq!(error.field, Some("avatarColor"));
            assert_eq!(error.status_code(), 400);
        }
        assert!(service.storage().calls.is_empty());
        assert_eq!(service.storage().accounts, before);
    }

    #[test]
    fn authenticated_updates_always_commit_even_repeated_values_or_clears() {
        let mut service = VaultService::new(Memory::new());
        for _ in 0..2 {
            service
                .update_profile("alice", &ProfileUpdateRequest { name: "original" })
                .unwrap();
        }
        for _ in 0..2 {
            service
                .update_avatar("alice", &AvatarUpdateRequest { avatar_color: None })
                .unwrap();
        }
        assert_eq!(service.storage().accounts["alice"].revision, 11);
        assert_eq!(service.storage().accounts["bob"].revision, 7);
        assert_eq!(
            service.storage().calls,
            [
                Operation::Name,
                Operation::Name,
                Operation::Avatar,
                Operation::Avatar
            ]
        );
    }

    #[test]
    fn unauthenticated_updates_never_reach_the_provider_even_for_invalid_values() {
        let mut service = VaultService::new(Memory::new());
        for name in ["valid", &"x".repeat(51)] {
            assert_eq!(
                service
                    .update_profile("", &ProfileUpdateRequest { name })
                    .unwrap_err()
                    .kind,
                ErrorKind::Unauthorized
            );
        }
        for avatar_color in [None, Some("too short")] {
            assert_eq!(
                service
                    .update_avatar("", &AvatarUpdateRequest { avatar_color })
                    .unwrap_err()
                    .kind,
                ErrorKind::Unauthorized
            );
        }
        assert!(service.storage().calls.is_empty());
    }

    #[test]
    fn provider_failures_preserve_metadata_revisions_and_unrelated_account_authority() {
        for (failure, kind) in [
            (Failure::Backend, ErrorKind::Storage),
            (Failure::Conflict, ErrorKind::Conflict),
        ] {
            for operation in [Operation::Name, Operation::Avatar] {
                let mut storage = Memory::new();
                storage.fail = Some(failure);
                let before = storage.accounts.clone();
                let mut service = VaultService::new(&mut storage);
                let error = match operation {
                    Operation::Name => service.update_profile(
                        "alice",
                        &ProfileUpdateRequest {
                            name: "replacement",
                        },
                    ),
                    Operation::Avatar => {
                        service.update_avatar("alice", &AvatarUpdateRequest { avatar_color: None })
                    }
                }
                .unwrap_err();
                assert_eq!(error.kind, kind);
                assert_eq!(service.storage().accounts, before);
                assert_eq!(service.storage().calls, [operation]);
            }
        }
        let mut service = VaultService::new(Memory::new());
        assert_eq!(
            service
                .update_profile("missing", &ProfileUpdateRequest { name: "valid" })
                .unwrap_err()
                .kind,
            ErrorKind::NotFound
        );
    }
}
