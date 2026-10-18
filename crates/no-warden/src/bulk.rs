//! Allocation-free selected-cipher validation and an opt-in atomic provider contract.
//!
//! The authenticated caller must hold the storage lock or transaction across access
//! preflight and commit. Atomic rollback is stronger than the reference server's sequential
//! bulk writes. Archive access is intentionally separate from write access for providers
//! that later support shared vaults; an admin-named HTTP alias never bypasses these checks.

use crate::{ApiError, Storage, VaultService, service::require_owner};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherBulkOperation {
    Trash,
    Restore,
    Delete,
    Archive,
    Unarchive,
}

impl CipherBulkOperation {
    pub const fn requires_write(self) -> bool {
        matches!(self, Self::Trash | Self::Restore | Self::Delete)
    }
}

/// The authenticated account's access to one cipher, independent of its lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CipherAccess {
    pub readable: bool,
    pub writable: bool,
}

/// Unique, exact-string IDs with every target authorized before entering the provider.
///
/// IDs are sorted; their order is not an upstream response-order guarantee. Providers must
/// keep the preflight access decision valid under the operation's lock or transaction.
#[derive(Clone, Copy, Debug)]
pub struct ValidatedCipherBulk<'plan, 'ids> {
    operation: CipherBulkOperation,
    ids: &'plan [&'ids str],
}

impl<'ids> ValidatedCipherBulk<'_, 'ids> {
    pub const fn operation(&self) -> CipherBulkOperation {
        self.operation
    }

    pub const fn ids(&self) -> &[&'ids str] {
        self.ids
    }
}

/// An explicit opt-in provider for selected-cipher operations.
///
/// Commit all selected items, per-user archive entries, and account revisions together.
/// Any error must leave all of them unchanged, including failures after earlier writes.
/// Notifications belong after a successful commit. The service never commits an empty set.
///
/// Trash sets a fresh deletion timestamp even for a previously trashed cipher; Restore
/// clears that timestamp even for an active cipher. Both refresh cipher and account
/// revisions and preserve the account's archive state. Delete permanently removes active
/// or trashed ciphers. Archive sets a fresh per-user archive timestamp, and Unarchive clears
/// it, preserving deletion state and the cipher's revision/updated timestamp. Both archive
/// operations refresh the acting account's revision even when repeating the same state.
/// Preserve all remaining encrypted fields and metadata of surviving ciphers.
pub trait CipherBulkStorage: Storage {
    /// Personal-vault default. Shared-vault providers can override this to distinguish
    /// read access from write access without weakening authorization on other operations.
    fn cipher_access(
        &mut self,
        owner: &str,
        id: &str,
    ) -> Result<Option<CipherAccess>, Self::Error> {
        Ok(self.cipher_metadata(id)?.map(|metadata| {
            let owned = metadata.owner_id == owner;
            CipherAccess {
                readable: owned,
                writable: owned,
            }
        }))
    }

    fn commit_cipher_bulk(
        &mut self,
        owner: &str,
        plan: &ValidatedCipherBulk<'_, '_>,
    ) -> Result<(), Self::Error>;
}

impl<T: CipherBulkStorage + ?Sized> CipherBulkStorage for &mut T {
    fn cipher_access(
        &mut self,
        owner: &str,
        id: &str,
    ) -> Result<Option<CipherAccess>, Self::Error> {
        (**self).cipher_access(owner, id)
    }

    fn commit_cipher_bulk(
        &mut self,
        owner: &str,
        plan: &ValidatedCipherBulk<'_, '_>,
    ) -> Result<(), Self::Error> {
        (**self).commit_cipher_bulk(owner, plan)
    }
}

impl<S: CipherBulkStorage> VaultService<S> {
    /// Validate a complete selection, then delegate one atomic provider operation.
    ///
    /// Supply scratch capacity for the raw input count, including duplicates. Strings
    /// borrow the caller's input and are never normalized. The first returned-count scratch
    /// entries contain sorted unique IDs for a restore/archive response lookup. Scratch
    /// contents are unspecified on error; persistent state remains unchanged. Sorting and
    /// deduplication use O(N log N) time without allocation. A borrowed host slice and
    /// `CipherIdsRequest::ids.iter().copied()` can both supply this iterator.
    pub fn bulk_ciphers<'ids>(
        &mut self,
        owner: &str,
        operation: CipherBulkOperation,
        ids: impl IntoIterator<Item = &'ids str>,
        scratch: &mut [&'ids str],
    ) -> Result<usize, ApiError> {
        require_owner(owner)?;
        let mut count = 0;
        for id in ids {
            let slot = scratch.get_mut(count).ok_or(ApiError::invalid(
                "ids",
                "The selected-ID buffer is too small.",
            ))?;
            *slot = id;
            count += 1;
        }
        if count == 0 {
            return Ok(0);
        }
        let selected = &mut scratch[..count];
        selected.sort_unstable();
        let mut unique = 0;
        for index in 0..selected.len() {
            if unique == 0 || selected[index] != selected[unique - 1] {
                selected[unique] = selected[index];
                unique += 1;
            }
        }
        let selected = &selected[..unique];
        for id in selected {
            let access = self
                .storage_mut()
                .cipher_access(owner, id)
                .map_err(S::map_error)?;
            if !access.is_some_and(|access| {
                if operation.requires_write() {
                    access.writable
                } else {
                    access.readable
                }
            }) {
                return Err(ApiError::invalid(
                    "ids",
                    "A selected cipher is unavailable for this operation.",
                ));
            }
        }
        self.storage_mut()
            .commit_cipher_bulk(
                owner,
                &ValidatedCipherBulk {
                    operation,
                    ids: selected,
                },
            )
            .map_err(S::map_error)?;
        Ok(unique)
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

    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Backend,
        Conflict,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Cipher {
        owner: &'static str,
        deleted: Option<usize>,
        revision: usize,
        ciphertext: &'static str,
    }

    #[derive(Clone, Debug, Default)]
    struct Memory {
        ciphers: BTreeMap<String, Cipher>,
        archives: BTreeMap<(String, String), usize>,
        revisions: BTreeMap<String, usize>,
        clock: usize,
        reads: usize,
        commits: usize,
        fail_after: Option<usize>,
        failure: Option<Failure>,
    }

    // Only metadata reads and the opt-in bulk provider are used by this service.
    macro_rules! unused_storage_methods {
        () => {
            fn account_exists(&mut self, _: &str) -> Result<bool, Failure> {
                unreachable!()
            }
            fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), Failure> {
                unreachable!()
            }
            fn folder_metadata(&mut self, _: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
                unreachable!()
            }
            fn save_folder(
                &mut self,
                _: &str,
                _: &str,
                _: &FolderRequest<'_>,
            ) -> Result<(), Failure> {
                unreachable!()
            }
            fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), Failure> {
                unreachable!()
            }
            fn save_cipher(
                &mut self,
                _: &str,
                _: &str,
                _: &CipherRequest<'_>,
            ) -> Result<(), Failure> {
                unreachable!()
            }
            fn set_cipher_deleted(&mut self, _: &str, _: &str, _: bool) -> Result<(), Failure> {
                unreachable!()
            }
            fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), Failure> {
                unreachable!()
            }
        };
    }

    impl Storage for Memory {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::Backend => ApiError::new(ErrorKind::Storage, "Provider failed."),
                Failure::Conflict => ApiError::new(ErrorKind::Conflict, "Retry the transaction."),
            }
        }
        fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            self.reads += 1;
            Ok(self.ciphers.get(id).map(|cipher| ItemMetadata {
                owner_id: cipher.owner,
                deleted: cipher.deleted.is_some(),
            }))
        }
        unused_storage_methods!();
    }

    impl CipherBulkStorage for Memory {
        fn commit_cipher_bulk(
            &mut self,
            owner: &str,
            plan: &ValidatedCipherBulk<'_, '_>,
        ) -> Result<(), Failure> {
            self.commits += 1;
            let mut staged = self.clone();
            for (index, id) in plan.ids().iter().enumerate() {
                staged.clock += 1;
                match plan.operation() {
                    CipherBulkOperation::Trash | CipherBulkOperation::Restore => {
                        let cipher = staged.ciphers.get_mut(*id).unwrap();
                        cipher.deleted = (plan.operation() == CipherBulkOperation::Trash)
                            .then_some(staged.clock);
                        cipher.revision = staged.clock;
                    }
                    CipherBulkOperation::Delete => {
                        staged.ciphers.remove(*id).unwrap();
                        staged.archives.retain(|(_, cipher), _| cipher != id);
                    }
                    CipherBulkOperation::Archive => {
                        staged
                            .archives
                            .insert((owner.to_string(), id.to_string()), staged.clock);
                    }
                    CipherBulkOperation::Unarchive => {
                        staged.archives.remove(&(owner.to_string(), id.to_string()));
                    }
                }
                staged.revisions.insert(owner.to_string(), staged.clock);
                if self.fail_after == Some(index + 1) {
                    return Err(self.failure.unwrap_or(Failure::Backend));
                }
            }
            *self = staged;
            Ok(())
        }
    }

    #[derive(Debug)]
    struct ReadOnly(Memory);

    impl Storage for ReadOnly {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            Memory::map_error(error)
        }
        fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            self.0.cipher_metadata(id)
        }
        unused_storage_methods!();
    }

    impl CipherBulkStorage for ReadOnly {
        fn cipher_access(&mut self, _: &str, id: &str) -> Result<Option<CipherAccess>, Failure> {
            Ok(self.0.ciphers.contains_key(id).then_some(CipherAccess {
                readable: true,
                writable: false,
            }))
        }
        fn commit_cipher_bulk(
            &mut self,
            owner: &str,
            plan: &ValidatedCipherBulk<'_, '_>,
        ) -> Result<(), Failure> {
            self.0.commit_cipher_bulk(owner, plan)
        }
    }

    fn memory(ids: &[&str]) -> Memory {
        Memory {
            ciphers: ids
                .iter()
                .map(|id| {
                    (
                        id.to_string(),
                        Cipher {
                            owner: "alice",
                            deleted: None,
                            revision: 7,
                            ciphertext: "opaque encrypted payload",
                        },
                    )
                })
                .collect(),
            clock: 10,
            ..Memory::default()
        }
    }

    #[test]
    fn selection_uses_exact_string_deduplication_before_one_provider_commit() {
        let mut storage = memory(&["opaque:One/id", "opaque:one/id"]);
        let ids = ["opaque:one/id", "opaque:One/id", "opaque:one/id"];
        let mut scratch = [""; 4];
        let count = VaultService::new(&mut storage)
            .bulk_ciphers("alice", CipherBulkOperation::Trash, ids, &mut scratch)
            .unwrap();
        assert_eq!(count, 2);
        assert_eq!(&scratch[..count], ["opaque:One/id", "opaque:one/id"]);
        assert_eq!(storage.reads, 2);
        assert_eq!(storage.commits, 1);
        assert!(
            storage
                .ciphers
                .values()
                .all(|cipher| cipher.deleted.is_some()
                    && cipher.ciphertext == "opaque encrypted payload")
        );
    }

    #[test]
    fn empty_selections_and_short_scratch_do_not_read_or_mutate_storage() {
        let mut storage = memory(&["one"]);
        let before = storage.ciphers.clone();
        let mut service = VaultService::new(&mut storage);
        assert_eq!(
            service
                .bulk_ciphers("", CipherBulkOperation::Trash, [], &mut [])
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        assert_eq!(
            service
                .bulk_ciphers("alice", CipherBulkOperation::Delete, [], &mut [])
                .unwrap(),
            0
        );
        assert_eq!(
            service
                .bulk_ciphers(
                    "alice",
                    CipherBulkOperation::Restore,
                    ["one", "one"],
                    &mut [""]
                )
                .unwrap_err()
                .field,
            Some("ids")
        );
        assert_eq!(storage.reads, 0);
        assert_eq!(storage.commits, 0);
        assert_eq!(storage.ciphers, before);
        assert_eq!(storage.clock, 10);
        assert!(storage.revisions.is_empty());
    }

    #[test]
    fn missing_and_foreign_targets_reject_the_whole_selection_with_the_same_error() {
        let mut storage = memory(&["a-owned", "z-foreign"]);
        storage.ciphers.get_mut("z-foreign").unwrap().owner = "bob";
        let before = storage.ciphers.clone();
        let mut errors = Vec::new();
        for denied in ["z-foreign", "z-missing"] {
            for operation in [
                CipherBulkOperation::Trash,
                CipherBulkOperation::Restore,
                CipherBulkOperation::Delete,
                CipherBulkOperation::Archive,
                CipherBulkOperation::Unarchive,
            ] {
                let error = VaultService::new(&mut storage)
                    .bulk_ciphers("alice", operation, ["a-owned", denied], &mut [""; 2])
                    .unwrap_err();
                assert_eq!(error.status_code(), 400);
                assert_eq!(error.field, Some("ids"));
                errors.push(error);
            }
        }
        assert!(errors.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(storage.commits, 0);
        assert_eq!(storage.ciphers, before);
    }

    #[test]
    fn trash_and_restore_refresh_revisions_and_preserve_archive_state() {
        let mut storage = memory(&["one"]);
        let archive_key = ("alice".into(), "one".into());
        storage.archives.insert(archive_key.clone(), 3);
        for (operation, expected_deleted, expected_revision) in [
            (CipherBulkOperation::Trash, Some(11), 11),
            (CipherBulkOperation::Trash, Some(12), 12),
            (CipherBulkOperation::Restore, None, 13),
            (CipherBulkOperation::Restore, None, 14),
        ] {
            VaultService::new(&mut storage)
                .bulk_ciphers("alice", operation, ["one"], &mut [""])
                .unwrap();
            assert_eq!(storage.ciphers["one"].deleted, expected_deleted);
            assert_eq!(storage.ciphers["one"].revision, expected_revision);
            assert_eq!(storage.revisions["alice"], expected_revision);
            assert_eq!(storage.archives[&archive_key], 3);
        }
        VaultService::new(&mut storage)
            .bulk_ciphers(
                "alice",
                CipherBulkOperation::Delete,
                ["one", "one"],
                &mut [""; 2],
            )
            .unwrap();
        assert!(storage.ciphers.is_empty());
        assert!(storage.archives.is_empty());
    }

    #[test]
    fn archive_is_per_user_and_preserves_cipher_revision_and_trash_state() {
        let mut storage = memory(&["one"]);
        storage.ciphers.get_mut("one").unwrap().deleted = Some(5);
        let cipher = storage.ciphers["one"].clone();
        let alice_key = ("alice".into(), "one".into());
        let bob_key = ("bob".into(), "one".into());
        storage.archives.insert(bob_key.clone(), 8);
        for (operation, archive, revision) in [
            (CipherBulkOperation::Archive, Some(11), 11),
            (CipherBulkOperation::Archive, Some(12), 12),
            (CipherBulkOperation::Unarchive, None, 13),
            (CipherBulkOperation::Unarchive, None, 14),
        ] {
            VaultService::new(&mut storage)
                .bulk_ciphers("alice", operation, ["one"], &mut [""])
                .unwrap();
            assert_eq!(storage.archives.get(&alice_key).copied(), archive);
            assert_eq!(storage.archives[&bob_key], 8);
            assert_eq!(storage.revisions["alice"], revision);
            assert_eq!(storage.ciphers["one"], cipher);
        }
    }

    #[test]
    fn read_only_access_allows_archiving_but_rejects_write_operations() {
        let mut storage = ReadOnly(memory(&["one"]));
        for operation in [CipherBulkOperation::Archive, CipherBulkOperation::Unarchive] {
            VaultService::new(&mut storage)
                .bulk_ciphers("reader", operation, ["one"], &mut [""])
                .unwrap();
        }
        for operation in [
            CipherBulkOperation::Trash,
            CipherBulkOperation::Restore,
            CipherBulkOperation::Delete,
        ] {
            assert_eq!(
                VaultService::new(&mut storage)
                    .bulk_ciphers("reader", operation, ["one"], &mut [""])
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
        assert_eq!(storage.0.commits, 2);
        assert_eq!(storage.0.ciphers["one"].revision, 7);
        assert_eq!(storage.0.ciphers["one"].deleted, None);
        assert!(storage.0.revisions.contains_key("reader"));
        assert!(!storage.0.revisions.contains_key("alice"));
    }

    #[test]
    fn provider_errors_rollback_all_selected_items_archive_entries_and_revisions() {
        for operation in [
            CipherBulkOperation::Trash,
            CipherBulkOperation::Restore,
            CipherBulkOperation::Delete,
            CipherBulkOperation::Archive,
            CipherBulkOperation::Unarchive,
        ] {
            for failure in [Failure::Backend, Failure::Conflict] {
                let mut storage = memory(&["one", "two"]);
                storage.archives.insert(("alice".into(), "one".into()), 3);
                storage.revisions.insert("alice".into(), 9);
                storage.fail_after = Some(2);
                storage.failure = Some(failure);
                let before = (
                    storage.ciphers.clone(),
                    storage.archives.clone(),
                    storage.revisions.clone(),
                );
                let error = VaultService::new(&mut storage)
                    .bulk_ciphers("alice", operation, ["one", "two"], &mut [""; 2])
                    .unwrap_err();
                assert_eq!(
                    error.kind,
                    match failure {
                        Failure::Backend => ErrorKind::Storage,
                        Failure::Conflict => ErrorKind::Conflict,
                    }
                );
                assert_eq!(
                    (storage.ciphers, storage.archives, storage.revisions),
                    before
                );
                assert_eq!(storage.clock, 10);
                assert_eq!(storage.commits, 1);
            }
        }
    }
}
