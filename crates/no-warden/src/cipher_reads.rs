//! Allocation-free read authorization for the ordinary, details and admin cipher aliases.
//!
//! The pinned handlers share the same access check. An admin-named path grants no extra
//! authority. HTTP authentication, UUID decoding/guards and opaque response projection
//! belong to adapters; this module neither decrypts nor models a cipher JSON response.

use crate::{ApiError, Storage, VaultService, service::require_owner};

/// Opt-in cipher reads, independent of bulk write or identity providers.
///
/// `None` means the requested cipher does not exist; `Some(false)` means it exists but
/// is inaccessible to this authenticated account; `Some(true)` permits a read. The default
/// personal-vault implementation compares the metadata owner without filtering deleted or
/// archived state. Shared-vault embeddings can override this hook with trusted readable
/// access independently of write access. An admin-named route must not bypass this check.
///
/// Resolve identifiers exactly without case normalization. Read authorization must not
/// mutate cipher/account revisions, ciphertext, archive/trash state, credentials or other
/// owners' data. Provider caches may be updated. Hold the embedding application's lock or
/// consistent snapshot across authorization and response projection; the returned grant is
/// an operation-local result, not a durable capability or permission to mutate the cipher.
pub trait CipherReadStorage: Storage {
    fn cipher_read_access(&mut self, owner: &str, id: &str) -> Result<Option<bool>, Self::Error> {
        self.cipher_metadata(id)
            .map(|metadata| metadata.map(|metadata| metadata.owner_id == owner))
    }
}

impl<T: CipherReadStorage + ?Sized> CipherReadStorage for &mut T {
    fn cipher_read_access(&mut self, owner: &str, id: &str) -> Result<Option<bool>, Self::Error> {
        (**self).cipher_read_access(owner, id)
    }
}

/// Sealed borrowed scope for a successful cipher read. Only the service constructs it.
/// No provider-owned ciphertext or writable authority is carried by this result.
pub struct AuthorizedCipherRead<'a> {
    owner: &'a str,
    id: &'a str,
}

impl core::fmt::Debug for AuthorizedCipherRead<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthorizedCipherRead([REDACTED])")
    }
}

impl<'a> AuthorizedCipherRead<'a> {
    pub const fn owner(&self) -> &'a str {
        self.owner
    }
    pub const fn id(&self) -> &'a str {
        self.id
    }
}

impl<S: CipherReadStorage> VaultService<S> {
    /// Authorize a read for a verified owner without changing the cipher's lifecycle.
    /// Adapters authenticate and guard/decode the raw path before calling this service.
    pub fn authorize_cipher_read<'a>(
        &mut self,
        owner: &'a str,
        id: &'a str,
    ) -> Result<AuthorizedCipherRead<'a>, ApiError> {
        require_owner(owner)?;
        match self
            .storage_mut()
            .cipher_read_access(owner, id)
            .map_err(S::map_error)?
        {
            None => Err(ApiError::invalid("cipher", "Cipher doesn't exist")),
            Some(false) => Err(ApiError::invalid("cipher", "Cipher is not owned by user")),
            Some(true) => Ok(AuthorizedCipherRead { owner, id }),
        }
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

    const OWNER: &str = "verified-owner";
    const FOREIGN: &str = "foreign-owner";
    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Record {
        id: &'static str,
        owner: &'static str,
        deleted: bool,
        archived: bool,
        readable: bool,
        writable: bool,
        revision: u64,
        ciphertext: &'static str,
    }
    impl core::fmt::Debug for Record {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("Record([REDACTED])")
        }
    }
    struct Bounded<const SHARED: bool> {
        records: [Record; 4],
        reads: usize,
        access_calls: usize,
        error: Option<ErrorKind>,
    }
    impl<const SHARED: bool> Bounded<SHARED> {
        fn new() -> Self {
            let active = Record {
                id: "Active-Id",
                owner: OWNER,
                deleted: false,
                archived: false,
                readable: true,
                writable: true,
                revision: 7,
                ciphertext: "opaque-ciphertext\0雪",
            };
            Self {
                records: [
                    active,
                    Record {
                        id: "Trashed-Id",
                        deleted: true,
                        ..active
                    },
                    Record {
                        id: "Archived-Id",
                        archived: true,
                        ..active
                    },
                    Record {
                        id: "Shared-Id",
                        owner: FOREIGN,
                        writable: false,
                        ..active
                    },
                ],
                reads: 0,
                access_calls: 0,
                error: None,
            }
        }
    }
    impl<const SHARED: bool> Storage for Bounded<SHARED> {
        type Error = ErrorKind;
        fn map_error(kind: ErrorKind) -> ApiError {
            ApiError::new(kind, "Cipher read provider failed.")
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
        fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
            self.reads += 1;
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(self
                .records
                .iter()
                .find(|record| record.id == id)
                .map(|record| ItemMetadata {
                    owner_id: record.owner,
                    deleted: record.deleted,
                }))
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
    impl CipherReadStorage for Bounded<false> {}
    impl CipherReadStorage for Bounded<true> {
        fn cipher_read_access(
            &mut self,
            owner: &str,
            id: &str,
        ) -> Result<Option<bool>, Self::Error> {
            self.access_calls += 1;
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(self
                .records
                .iter()
                .find(|record| record.id == id)
                .map(|record| owner == OWNER && record.readable))
        }
    }

    #[test]
    fn cipher_read_authentication_precedes_every_personal_or_shared_provider_call() {
        let mut personal = VaultService::new(Bounded::<false>::new());
        assert_eq!(
            personal
                .authorize_cipher_read("", "Active-Id")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(personal.storage().reads, 0);
        let mut shared = VaultService::new(Bounded::<true>::new());
        assert_eq!(
            shared
                .authorize_cipher_read("", "Shared-Id")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(shared.storage().access_calls, 0);
    }

    #[test]
    fn cipher_reads_keep_active_trash_archive_and_ciphertext_unchanged() {
        let mut storage = Bounded::<false>::new();
        let before = storage.records;
        let mut service = VaultService::new(&mut storage);
        for id in ["Active-Id", "Trashed-Id", "Archived-Id"] {
            let grant = service.authorize_cipher_read(OWNER, id).unwrap();
            assert_eq!(grant.owner(), OWNER);
            assert_eq!(grant.id(), id);
        }
        assert_eq!(storage.reads, 3);
        assert_eq!(storage.records, before);
    }

    #[test]
    fn cipher_reads_distinguish_missing_and_inaccessible_without_authority() {
        let mut service = VaultService::new(Bounded::<false>::new());
        for (id, message) in [
            ("Missing-Id", "Cipher doesn't exist"),
            ("Shared-Id", "Cipher is not owned by user"),
        ] {
            let error = service.authorize_cipher_read(OWNER, id).unwrap_err();
            assert_eq!(error.status_code(), 400);
            assert_eq!(error.message, message);
        }
        assert_eq!(service.storage().reads, 2);
    }

    #[test]
    fn shared_read_override_survives_borrowing_and_does_not_require_write_access() {
        let mut storage = Bounded::<true>::new();
        let before = storage.records;
        assert!(!storage.records[3].writable);
        let grant = VaultService::new(&mut storage)
            .authorize_cipher_read(OWNER, "Shared-Id")
            .unwrap();
        assert_eq!(grant.owner(), OWNER);
        assert_eq!(grant.id(), "Shared-Id");
        assert_eq!(storage.access_calls, 1);
        assert_eq!(storage.reads, 0);
        assert_eq!(storage.records, before);
        storage.records[3].readable = false;
        assert_eq!(
            VaultService::new(&mut storage)
                .authorize_cipher_read(OWNER, "Shared-Id")
                .unwrap_err()
                .message,
            "Cipher is not owned by user"
        );
    }

    #[test]
    fn cipher_read_provider_errors_preserve_mapping_and_persisted_state() {
        for kind in [
            ErrorKind::Storage,
            ErrorKind::Conflict,
            ErrorKind::Forbidden,
        ] {
            let mut storage = Bounded::<false>::new();
            let before = storage.records;
            storage.error = Some(kind);
            let error = VaultService::new(&mut storage)
                .authorize_cipher_read(OWNER, "Active-Id")
                .unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(storage.records, before);
        }
    }

    #[test]
    fn cipher_read_grants_borrow_exact_identifiers_and_redact_private_scope() {
        let owner_buffer = *b"verified-owner";
        let id_buffer = *b"Active-Id";
        let owner = core::str::from_utf8(&owner_buffer).unwrap();
        let id = core::str::from_utf8(&id_buffer).unwrap();
        let mut service = VaultService::new(Bounded::<false>::new());
        let grant = service.authorize_cipher_read(owner, id).unwrap();
        assert_eq!(grant.owner().as_ptr(), owner.as_ptr());
        assert_eq!(grant.id().as_ptr(), id.as_ptr());
        let debug = std::format!("{grant:?}");
        assert!(!debug.contains(owner) && !debug.contains(id));
        assert_eq!(
            service
                .authorize_cipher_read(owner, "active-id")
                .unwrap_err()
                .message,
            "Cipher doesn't exist"
        );
        assert_eq!(
            service
                .authorize_cipher_read(owner, "")
                .unwrap_err()
                .message,
            "Cipher doesn't exist"
        );
    }
}
