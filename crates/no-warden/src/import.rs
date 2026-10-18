//! Personal import validation and the atomic persistence boundary.
//!
//! The provider commits the complete batch or rolls it back on failure. This is a stronger
//! persistence contract than Vaultwarden's sequential import writes. Account/key checks
//! retain this crate's personal-vault creation policy; they are not an assertion that every
//! upstream import path performs the same checks.

use core::marker::PhantomData;

use crate::{
    ApiError, Storage, VaultService,
    service::{require_owner, validate_encrypted_for},
    validation,
    wire::{CipherRequest, FolderRelationship, FolderRequest, ImportFolderRequest, ImportRequest},
};

/// Indexed borrowed data shared by configurable decoders and host-owned slices.
///
/// Each index below the corresponding count must return an entry, and the entries and
/// counts must remain unchanged for the service call and provider transaction.
pub trait ImportData<'a> {
    fn folder_count(&self) -> usize;
    fn folder(&self, index: usize) -> Option<&ImportFolderRequest<'a>>;
    fn cipher_count(&self) -> usize;
    fn cipher(&self, index: usize) -> Option<&CipherRequest<'a>>;
    fn relationship_count(&self) -> usize;
    fn relationship(&self, index: usize) -> Option<&FolderRelationship>;
}

/// A host may decode any batch size into its own memory and lend it to the core.
#[derive(Clone, Copy, Debug)]
pub struct ImportView<'batch, 'a> {
    pub folders: &'batch [ImportFolderRequest<'a>],
    pub ciphers: &'batch [CipherRequest<'a>],
    pub folder_relationships: &'batch [FolderRelationship],
}

impl<'a> ImportData<'a> for ImportView<'_, 'a> {
    fn folder_count(&self) -> usize {
        self.folders.len()
    }
    fn folder(&self, index: usize) -> Option<&ImportFolderRequest<'a>> {
        self.folders.get(index)
    }
    fn cipher_count(&self) -> usize {
        self.ciphers.len()
    }
    fn cipher(&self, index: usize) -> Option<&CipherRequest<'a>> {
        self.ciphers.get(index)
    }
    fn relationship_count(&self) -> usize {
        self.folder_relationships.len()
    }
    fn relationship(&self, index: usize) -> Option<&FolderRelationship> {
        self.folder_relationships.get(index)
    }
}

impl<'a, const F: usize, const C: usize, const R: usize> ImportData<'a>
    for ImportRequest<'a, F, C, R>
{
    fn folder_count(&self) -> usize {
        self.folders.len()
    }
    fn folder(&self, index: usize) -> Option<&ImportFolderRequest<'a>> {
        self.folders.get(index)
    }
    fn cipher_count(&self) -> usize {
        self.ciphers.len()
    }
    fn cipher(&self, index: usize) -> Option<&CipherRequest<'a>> {
        self.ciphers.get(index)
    }
    fn relationship_count(&self) -> usize {
        self.folder_relationships.len()
    }
    fn relationship(&self, index: usize) -> Option<&FolderRelationship> {
        self.folder_relationships.get(index)
    }
}

/// Configurable import-specific validation, independent of decoder capacities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportPolicy {
    /// Vaultwarden's default encrypted-note limit is 10,000 bytes; its increased-note
    /// configuration permits 100,000. The embedding application chooses its policy.
    pub maximum_encrypted_notes_bytes: usize,
}

impl Default for ImportPolicy {
    fn default() -> Self {
        Self {
            maximum_encrypted_notes_bytes: 10_000,
        }
    }
}

/// A batch whose personal-vault fields were checked before entering the provider.
///
/// Only `VaultService` can create this value. Providers must still enforce their capacity,
/// ID uniqueness, account existence, and transactional persistence constraints.
#[derive(Debug)]
pub struct ValidatedImport<'batch, 'a, I: ImportData<'a> + ?Sized> {
    data: &'batch I,
    payload: PhantomData<&'a ()>,
}

impl<'a, I: ImportData<'a> + ?Sized> ValidatedImport<'_, 'a, I> {
    pub const fn data(&self) -> &I {
        self.data
    }

    /// Resolve the final relationship for a cipher. Duplicate keys use the last entry;
    /// an absent relationship or an out-of-range folder means no folder. Relationships
    /// for nonexistent ciphers are ignored, matching the upstream import route.
    /// This scans the relationships once per call; use `fill_folder_mapping` to resolve
    /// an entire batch in linear time.
    pub fn folder_index_for_cipher(&self, cipher_index: usize) -> Option<usize> {
        if cipher_index >= self.data.cipher_count() {
            return None;
        }
        let mut folder = None;
        for index in 0..self.data.relationship_count() {
            if let Some(relationship) = self.data.relationship(index) {
                if relationship.key == cipher_index {
                    folder = (relationship.value < self.data.folder_count())
                        .then_some(relationship.value);
                }
            }
        }
        folder
    }

    /// Resolve every cipher's folder index into caller-owned storage in O(C + R) time,
    /// where C is the cipher count and R is the relationship count. No allocation occurs.
    ///
    /// The output must have at least C entries. A shorter buffer returns an error without
    /// changing it. On success the first C entries are replaced, and any trailing entries
    /// remain unchanged. Missing relationships and out-of-range folder indices produce
    /// `None`; duplicate cipher indices use the last entry, including one that clears a
    /// previously valid mapping. Relationships for nonexistent ciphers are ignored.
    pub fn fill_folder_mapping(&self, output: &mut [Option<usize>]) -> Result<(), ApiError> {
        let cipher_count = self.data.cipher_count();
        if output.len() < cipher_count {
            return Err(ApiError::invalid(
                "folderRelationships",
                "The folder mapping buffer is too small.",
            ));
        }
        let output = &mut output[..cipher_count];
        output.fill(None);
        let folder_count = self.data.folder_count();
        for index in 0..self.data.relationship_count() {
            if let Some(relationship) = self.data.relationship(index) {
                if let Some(slot) = output.get_mut(relationship.key) {
                    *slot = (relationship.value < folder_count).then_some(relationship.value);
                }
            }
        }
        Ok(())
    }

    /// Prepare a fresh cipher using the provider's resolved folder ID. Incoming `folderId`
    /// and `lastKnownRevisionDate` must not control creation; all ciphertext and key metadata
    /// are retained. Pass `None` when `folder_index_for_cipher` returns `None`.
    pub fn cipher_for_create<'request>(
        &'request self,
        index: usize,
        folder_id: Option<&'request str>,
    ) -> Option<CipherRequest<'request>>
    where
        'a: 'request,
    {
        let mut request = self.data.cipher(index)?.clone();
        request.folder_id = folder_id;
        request.last_known_revision_date = None;
        Some(request)
    }
}

/// An explicit opt-in provider for atomic personal-vault imports.
///
/// Under the operation's exclusive lock/transaction, snapshot the owner's existing folders.
/// Reuse a supplied folder ID only when it belongs to that snapshot, without renaming it.
/// For missing, unknown, or foreign IDs, allocate a fresh globally unique ID and save the
/// imported encrypted name. Keep a folder-index-to-ID mapping and use the plan's final
/// relationship for every cipher, replacing its incoming `folderId` even when unmapped.
/// Every cipher gets a fresh ID and no source revision; preserve its encrypted fields and
/// opaque client key IDs. Commit the batch and owner revision together. An error must leave
/// all folders, ciphers, and the owner revision unchanged, including errors after earlier
/// writes. Publish change notifications only after a successful commit.
pub trait ImportStorage: Storage {
    fn commit_personal_import<'a, I: ImportData<'a> + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedImport<'_, 'a, I>,
    ) -> Result<(), Self::Error>;
}

impl<T: ImportStorage + ?Sized> ImportStorage for &mut T {
    fn commit_personal_import<'a, I: ImportData<'a> + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedImport<'_, 'a, I>,
    ) -> Result<(), Self::Error> {
        (**self).commit_personal_import(owner, plan)
    }
}

impl<S: ImportStorage> VaultService<S> {
    pub fn import_personal<'a, I: ImportData<'a> + ?Sized>(
        &mut self,
        owner: &str,
        data: &I,
    ) -> Result<(), ApiError> {
        self.import_personal_with_policy(owner, data, ImportPolicy::default())
    }

    pub fn import_personal_with_policy<'a, I: ImportData<'a> + ?Sized>(
        &mut self,
        owner: &str,
        data: &I,
        policy: ImportPolicy,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let missing = || ApiError::invalid("import", "The import batch is incomplete.");
        for index in 0..data.folder_count() {
            let folder = data.folder(index).ok_or_else(missing)?;
            validation::validate_folder(&FolderRequest { name: folder.name })?;
        }
        for index in 0..data.cipher_count() {
            let cipher = data.cipher(index).ok_or_else(missing)?;
            validation::validate_cipher(cipher)?;
            validate_encrypted_for(owner, cipher)?;
            if cipher
                .notes
                .is_some_and(|notes| notes.len() > policy.maximum_encrypted_notes_bytes)
            {
                return Err(ApiError::invalid(
                    "notes",
                    "Encrypted notes exceed the import limit.",
                ));
            }
        }
        for index in 0..data.relationship_count() {
            data.relationship(index).ok_or_else(missing)?;
        }
        if let Some(current) = self
            .storage_mut()
            .user_key_id(owner)
            .map_err(S::map_error)?
        {
            for index in 0..data.cipher_count() {
                if data
                    .cipher(index)
                    .ok_or_else(missing)?
                    .encrypted_by_key_id
                    .is_some_and(|candidate| candidate != current)
                {
                    return Err(ApiError::invalid(
                        "encryptedByKeyId",
                        "The cipher was encrypted with another user key.",
                    ));
                }
            }
        }
        self.storage_mut()
            .commit_personal_import(
                owner,
                &ValidatedImport {
                    data,
                    payload: PhantomData,
                },
            )
            .map_err(S::map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorKind, service::ItemMetadata, wire::RegisterRequest};
    use serde_json::Value;
    use std::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };

    const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[derive(Clone, Copy, Debug)]
    struct Failure;

    #[derive(Clone, Debug, Default)]
    struct Memory {
        folders: BTreeMap<String, (String, String)>,
        ciphers: BTreeMap<String, (String, Value)>,
        revision: usize,
        next_id: usize,
        current_key: Option<&'static str>,
        fail_after: Option<usize>,
        attempts: usize,
    }

    impl Storage for Memory {
        type Error = Failure;
        fn user_key_id(&mut self, _: &str) -> Result<Option<&str>, Failure> {
            Ok(self.current_key)
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

    impl Memory {
        fn fresh_id(&mut self) -> String {
            loop {
                self.next_id += 1;
                let id = std::format!("fresh-{}", self.next_id);
                if !self.folders.contains_key(&id) && !self.ciphers.contains_key(&id) {
                    return id;
                }
            }
        }
    }

    impl ImportStorage for Memory {
        fn commit_personal_import<'a, I: ImportData<'a> + ?Sized>(
            &mut self,
            owner: &str,
            plan: &ValidatedImport<'_, 'a, I>,
        ) -> Result<(), Failure> {
            self.attempts += 1;
            // Stage a complete candidate. None of these writes become visible on error.
            let mut staged = self.clone();
            let snapshot = self.folders.clone();
            let mut folder_ids = Vec::new();
            let mut folder_mapping = std::vec![None; plan.data().cipher_count()];
            plan.fill_folder_mapping(&mut folder_mapping).unwrap();
            let mut writes = 0;
            for index in 0..plan.data().folder_count() {
                let folder = plan.data().folder(index).unwrap();
                let id = match folder
                    .id
                    .filter(|id| snapshot.get(*id).is_some_and(|(user, _)| user == owner))
                {
                    Some(id) => id.to_string(),
                    None => {
                        let id = staged.fresh_id();
                        staged
                            .folders
                            .insert(id.clone(), (owner.to_string(), folder.name.to_string()));
                        writes += 1;
                        if self.fail_after == Some(writes) {
                            return Err(Failure);
                        }
                        id
                    }
                };
                folder_ids.push(id);
            }
            for (index, folder_index) in folder_mapping.iter().enumerate() {
                let folder = folder_index.map(|index| folder_ids[index].as_str());
                let cipher = plan.cipher_for_create(index, folder).unwrap();
                let id = staged.fresh_id();
                staged.ciphers.insert(
                    id,
                    (owner.to_string(), serde_json::to_value(cipher).unwrap()),
                );
                writes += 1;
                if self.fail_after == Some(writes) {
                    return Err(Failure);
                }
            }
            staged.revision += 1;
            *self = staged;
            Ok(())
        }
    }

    fn cipher() -> CipherRequest<'static> {
        serde_json::from_str(r#"{"type":1,"data":"opaque sealed JSON","encryptedFor":"alice","encryptedByKeyId":"opaque:key/id","key":"7.AAECAw==","folderId":"ignored-client-folder","lastKnownRevisionDate":"source-revision"}"#).unwrap()
    }

    #[test]
    fn bulk_folder_mapping_matches_last_wins_rules_and_preserves_unused_capacity() {
        let folders = [ImportFolderRequest {
            id: None,
            name: ENCRYPTED,
        }; 2];
        let ciphers = [cipher(), cipher(), cipher()];
        let relationships = [
            FolderRelationship { key: 0, value: 0 },
            FolderRelationship { key: 0, value: 1 },
            FolderRelationship { key: 1, value: 0 },
            FolderRelationship {
                key: 1,
                value: usize::MAX,
            },
            FolderRelationship {
                key: usize::MAX,
                value: 0,
            },
        ];
        let batch = ImportView {
            folders: &folders,
            ciphers: &ciphers,
            folder_relationships: &relationships,
        };
        let plan = ValidatedImport {
            data: &batch,
            payload: PhantomData,
        };
        let mut output = [Some(77); 4];
        plan.fill_folder_mapping(&mut output).unwrap();
        assert_eq!(output, [Some(1), None, None, Some(77)]);
        for (index, entry) in output[..ciphers.len()].iter().enumerate() {
            assert_eq!(*entry, plan.folder_index_for_cipher(index));
        }
    }

    #[test]
    fn bulk_folder_mapping_rejects_short_output_before_changing_it() {
        let ciphers = [cipher(), cipher()];
        let batch = ImportView {
            folders: &[],
            ciphers: &ciphers,
            folder_relationships: &[],
        };
        let plan = ValidatedImport {
            data: &batch,
            payload: PhantomData,
        };
        let mut output = [Some(123)];
        assert_eq!(
            plan.fill_folder_mapping(&mut output).unwrap_err().field,
            Some("folderRelationships")
        );
        assert_eq!(output, [Some(123)]);
        let empty = ImportView {
            folders: &[],
            ciphers: &[],
            folder_relationships: &[],
        };
        let plan = ValidatedImport {
            data: &empty,
            payload: PhantomData,
        };
        plan.fill_folder_mapping(&mut output).unwrap();
        assert_eq!(output, [Some(123)]);
        plan.fill_folder_mapping(&mut []).unwrap();
    }

    #[test]
    fn import_relationships_override_source_folders_with_last_entry_winning() {
        let folders = [ImportFolderRequest {
            id: None,
            name: ENCRYPTED,
        }; 2];
        let ciphers = [cipher(), cipher(), cipher()];
        let relationships = [
            FolderRelationship { key: 0, value: 0 },
            FolderRelationship { key: 0, value: 1 },
            FolderRelationship { key: 1, value: 0 },
            FolderRelationship { key: 1, value: 99 },
            FolderRelationship { key: 99, value: 0 },
        ];
        let batch = ImportView {
            folders: &folders,
            ciphers: &ciphers,
            folder_relationships: &relationships,
        };
        let mut storage = Memory {
            current_key: Some("opaque:key/id"),
            ..Memory::default()
        };
        VaultService::new(&mut storage)
            .import_personal("alice", &batch)
            .unwrap();
        let imported: Vec<_> = storage.ciphers.values().map(|(_, value)| value).collect();
        assert_eq!(imported[0]["folderId"], "fresh-2");
        assert!(imported[1]["folderId"].is_null());
        assert!(imported[2]["folderId"].is_null());
        for document in imported {
            assert!(document["lastKnownRevisionDate"].is_null());
            assert_eq!(document["data"], "opaque sealed JSON");
            assert_eq!(document["encryptedFor"], "alice");
            assert_eq!(document["encryptedByKeyId"], "opaque:key/id");
            assert_eq!(document["key"], "7.AAECAw==");
        }
        assert_eq!(storage.revision, 1);
        assert_eq!(storage.attempts, 1);
    }

    #[test]
    fn owned_folder_reuse_preserves_name_and_foreign_ids_create_distinct_folders() {
        let folders = [
            ImportFolderRequest {
                id: Some("owned"),
                name: ENCRYPTED,
            },
            ImportFolderRequest {
                id: Some("foreign"),
                name: ENCRYPTED,
            },
            ImportFolderRequest {
                id: Some("foreign"),
                name: ENCRYPTED,
            },
            ImportFolderRequest {
                id: Some("unknown"),
                name: ENCRYPTED,
            },
        ];
        let batch = ImportView {
            folders: &folders,
            ciphers: &[],
            folder_relationships: &[],
        };
        let mut storage = Memory::default();
        storage.folders.insert(
            "owned".into(),
            ("alice".into(), "unchanged ciphertext".into()),
        );
        storage.folders.insert(
            "foreign".into(),
            ("bob".into(), "foreign ciphertext".into()),
        );
        VaultService::new(&mut storage)
            .import_personal("alice", &batch)
            .unwrap();
        assert_eq!(storage.folders["owned"].1, "unchanged ciphertext");
        assert_eq!(storage.folders["foreign"].0, "bob");
        assert_eq!(storage.folders["foreign"].1, "foreign ciphertext");
        assert_eq!(storage.folders.len(), 5);
        assert!(!storage.folders.contains_key("unknown"));
    }

    #[test]
    fn a_late_invalid_cipher_folder_or_key_prevents_the_provider_call() {
        let folders = [ImportFolderRequest {
            id: None,
            name: ENCRYPTED,
        }];
        let mut invalid = cipher();
        invalid.key = Some("plaintext key");
        let mut ciphers = [cipher(), invalid];
        let mut storage = Memory::default();
        let batch = ImportView {
            folders: &folders,
            ciphers: &ciphers,
            folder_relationships: &[],
        };
        assert_eq!(
            VaultService::new(&mut storage)
                .import_personal("alice", &batch)
                .unwrap_err()
                .field,
            Some("key")
        );
        ciphers[1] = cipher();
        ciphers[1].encrypted_for = Some("bob");
        let batch = ImportView {
            folders: &folders,
            ciphers: &ciphers,
            folder_relationships: &[],
        };
        assert_eq!(
            VaultService::new(&mut storage)
                .import_personal("alice", &batch)
                .unwrap_err()
                .field,
            Some("encryptedFor")
        );
        ciphers[1] = cipher();
        storage.current_key = Some("rotated-key");
        let batch = ImportView {
            folders: &folders,
            ciphers: &ciphers,
            folder_relationships: &[],
        };
        assert_eq!(
            VaultService::new(&mut storage)
                .import_personal("alice", &batch)
                .unwrap_err()
                .field,
            Some("encryptedByKeyId")
        );
        let invalid_folders = [
            folders[0],
            ImportFolderRequest {
                id: None,
                name: "plaintext",
            },
        ];
        let batch = ImportView {
            folders: &invalid_folders,
            ciphers: &[],
            folder_relationships: &[],
        };
        assert!(
            VaultService::new(&mut storage)
                .import_personal("alice", &batch)
                .is_err()
        );
        assert_eq!(storage.attempts, 0);
        assert!(storage.folders.is_empty());
        assert!(storage.ciphers.is_empty());
        assert_eq!(storage.revision, 0);
    }

    #[test]
    fn provider_failures_rollback_partial_folders_ciphers_and_revision() {
        let folders = [ImportFolderRequest {
            id: None,
            name: ENCRYPTED,
        }];
        let ciphers = [cipher(), cipher()];
        let relationships = [FolderRelationship { key: 0, value: 0 }];
        let batch = ImportView {
            folders: &folders,
            ciphers: &ciphers,
            folder_relationships: &relationships,
        };
        for fail_after in 1..=3 {
            let mut storage = Memory {
                fail_after: Some(fail_after),
                revision: 7,
                ..Memory::default()
            };
            storage
                .folders
                .insert("before".into(), ("alice".into(), ENCRYPTED.into()));
            let before = storage.folders.clone();
            let error = VaultService::new(&mut storage)
                .import_personal("alice", &batch)
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::Storage);
            assert_eq!(storage.folders, before);
            assert!(storage.ciphers.is_empty());
            assert_eq!(storage.revision, 7);
            assert_eq!(storage.next_id, 0);
        }
    }

    #[test]
    fn empty_import_and_optional_legacy_key_ids_are_accepted() {
        let mut storage = Memory::default();
        let empty = ImportView {
            folders: &[],
            ciphers: &[],
            folder_relationships: &[],
        };
        assert_eq!(
            VaultService::new(&mut storage)
                .import_personal("", &empty)
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
        VaultService::new(&mut storage)
            .import_personal("alice", &empty)
            .unwrap();
        let mut request = cipher();
        request.encrypted_by_key_id = None;
        storage.current_key = Some("migrated-key");
        let ciphers = [request];
        let batch = ImportView {
            folders: &[],
            ciphers: &ciphers,
            folder_relationships: &[],
        };
        VaultService::new(&mut storage)
            .import_personal("alice", &batch)
            .unwrap();
        assert_eq!(storage.attempts, 2);
        assert_eq!(storage.ciphers.len(), 1);
    }

    #[test]
    fn import_notes_policy_is_configurable_without_changing_batch_capacity() {
        let mut request = cipher();
        request.notes = Some(ENCRYPTED);
        let ciphers = [request];
        let batch = ImportView {
            folders: &[],
            ciphers: &ciphers,
            folder_relationships: &[],
        };
        let mut storage = Memory::default();
        let mut service = VaultService::new(&mut storage);
        let policy = ImportPolicy {
            maximum_encrypted_notes_bytes: ENCRYPTED.len() - 1,
        };
        assert_eq!(
            service
                .import_personal_with_policy("alice", &batch, policy)
                .unwrap_err()
                .field,
            Some("notes")
        );
        assert_eq!(service.storage().attempts, 0);
        service.import_personal("alice", &batch).unwrap();
    }
}
