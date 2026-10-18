//! Personal-vault business rules over an application-provided persistence adapter.
//!
//! Every owner argument must come from a verified authentication context. Never take it
//! directly from an untrusted request. Hold the application's storage lock or transaction
//! for an entire service operation so ownership checks and mutations remain atomic.
use crate::{
    ApiError, ErrorKind,
    validation::{self, KdfPolicy},
    wire::{CipherCreateRequest, CipherRequest, FolderRequest, RegisterRequest},
};

pub use crate::attachment::{
    AttachmentAction, AttachmentMetadata, AttachmentStorage, AttachmentWrite,
    AuthorizedAttachmentDownload, ValidatedAttachment,
};
pub use crate::bulk::{CipherAccess, CipherBulkOperation, CipherBulkStorage, ValidatedCipherBulk};
pub use crate::identity::{
    ApiKeyDevice, AuthorizedApiKeyGrant, IdentityStorage, ReauthenticationProof, Secret,
};
pub use crate::import::{ImportData, ImportPolicy, ImportStorage, ImportView, ValidatedImport};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ItemMetadata<'a> {
    pub owner_id: &'a str,
    pub deleted: bool,
}

/// Persistence boundary. Ciphertext must be preserved verbatim.
///
/// Account email lookup must use ASCII case-insensitive comparison. Deleting a folder must
/// clear that folder reference on its owner's ciphers. The application supplies globally
/// unique identifiers, revision timestamps, durability, and transactions. Adapters supporting
/// conditional updates must check `last_known_revision_date` before replacing a cipher.
pub trait Storage {
    type Error;

    /// Preserve typed provider conflicts without exposing backend diagnostics.
    /// Conditional writes must compare revisions under the operation's lock/transaction.
    fn map_error(error: Self::Error) -> ApiError {
        storage_error(error)
    }

    /// Return the authenticated account's current key ID when available.
    /// Override this when accounts support the user-key-ID migration API.
    fn user_key_id(&mut self, _owner: &str) -> Result<Option<&str>, Self::Error> {
        Ok(None)
    }

    fn account_exists(&mut self, email: &str) -> Result<bool, Self::Error>;
    fn insert_account(
        &mut self,
        id: &str,
        request: &RegisterRequest<'_>,
    ) -> Result<(), Self::Error>;
    fn folder_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error>;
    fn save_folder(
        &mut self,
        owner: &str,
        id: &str,
        request: &FolderRequest<'_>,
    ) -> Result<(), Self::Error>;
    fn delete_folder(&mut self, owner: &str, id: &str) -> Result<(), Self::Error>;
    fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error>;
    fn save_cipher(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherRequest<'_>,
    ) -> Result<(), Self::Error>;
    fn set_cipher_deleted(
        &mut self,
        owner: &str,
        id: &str,
        deleted: bool,
    ) -> Result<(), Self::Error>;
    fn delete_cipher(&mut self, owner: &str, id: &str) -> Result<(), Self::Error>;
}

impl<T: Storage + ?Sized> Storage for &mut T {
    type Error = T::Error;
    fn map_error(error: Self::Error) -> ApiError {
        T::map_error(error)
    }
    fn user_key_id(&mut self, owner: &str) -> Result<Option<&str>, Self::Error> {
        (**self).user_key_id(owner)
    }

    fn account_exists(&mut self, email: &str) -> Result<bool, Self::Error> {
        (**self).account_exists(email)
    }

    fn insert_account(
        &mut self,
        id: &str,
        request: &RegisterRequest<'_>,
    ) -> Result<(), Self::Error> {
        (**self).insert_account(id, request)
    }

    fn folder_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
        (**self).folder_metadata(id)
    }

    fn save_folder(
        &mut self,
        owner: &str,
        id: &str,
        request: &FolderRequest<'_>,
    ) -> Result<(), Self::Error> {
        (**self).save_folder(owner, id, request)
    }

    fn delete_folder(&mut self, owner: &str, id: &str) -> Result<(), Self::Error> {
        (**self).delete_folder(owner, id)
    }

    fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Self::Error> {
        (**self).cipher_metadata(id)
    }

    fn save_cipher(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherRequest<'_>,
    ) -> Result<(), Self::Error> {
        (**self).save_cipher(owner, id, request)
    }

    fn set_cipher_deleted(
        &mut self,
        owner: &str,
        id: &str,
        deleted: bool,
    ) -> Result<(), Self::Error> {
        (**self).set_cipher_deleted(owner, id, deleted)
    }

    fn delete_cipher(&mut self, owner: &str, id: &str) -> Result<(), Self::Error> {
        (**self).delete_cipher(owner, id)
    }
}

#[derive(Debug)]
pub struct VaultService<S> {
    storage: S,
    kdf_policy: KdfPolicy,
}

impl<S: Storage> VaultService<S> {
    pub fn new(storage: S) -> Self {
        Self {
            storage,
            kdf_policy: KdfPolicy::default(),
        }
    }
    pub const fn with_kdf_policy(storage: S, kdf_policy: KdfPolicy) -> Self {
        Self {
            storage,
            kdf_policy,
        }
    }
    pub const fn storage(&self) -> &S {
        &self.storage
    }
    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }
    pub fn into_storage(self) -> S {
        self.storage
    }

    pub fn register(&mut self, id: &str, request: &RegisterRequest<'_>) -> Result<(), ApiError> {
        validate_id(id)?;
        validation::validate_registration(request, self.kdf_policy)?;
        if self
            .storage
            .account_exists(request.email)
            .map_err(S::map_error)?
        {
            return Err(ApiError::new(
                ErrorKind::Conflict,
                "An account with this email already exists.",
            ));
        }
        self.storage
            .insert_account(id, request)
            .map_err(S::map_error)
    }

    pub fn create_folder(
        &mut self,
        owner: &str,
        id: &str,
        request: &FolderRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        validate_id(id)?;
        validation::validate_folder(request)?;
        if self
            .storage
            .folder_metadata(id)
            .map_err(S::map_error)?
            .is_some()
        {
            return Err(conflict());
        }
        self.storage
            .save_folder(owner, id, request)
            .map_err(S::map_error)
    }

    pub fn update_folder(
        &mut self,
        owner: &str,
        id: &str,
        request: &FolderRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        validation::validate_folder(request)?;
        self.check_folder(owner, id)?;
        self.storage
            .save_folder(owner, id, request)
            .map_err(S::map_error)
    }

    pub fn delete_folder(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        self.check_folder(owner, id)?;
        self.storage.delete_folder(owner, id).map_err(S::map_error)
    }

    pub fn create_cipher(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        validate_id(id)?;
        validation::validate_cipher(request)?;
        validate_encrypted_for(owner, request)?;
        if let Some(candidate) = request.encrypted_by_key_id {
            if self
                .storage
                .user_key_id(owner)
                .map_err(S::map_error)?
                .is_some_and(|current| current != candidate)
            {
                return Err(ApiError::invalid(
                    "encryptedByKeyId",
                    "The cipher was encrypted with another user key.",
                ));
            }
        }
        self.check_cipher_folder(owner, request.folder_id)?;
        if self
            .storage
            .cipher_metadata(id)
            .map_err(S::map_error)?
            .is_some()
        {
            return Err(conflict());
        }
        let mut creating = request.clone();
        creating.last_known_revision_date = None;
        self.storage
            .save_cipher(owner, id, &creating)
            .map_err(S::map_error)
    }

    pub fn create_cipher_wrapped(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherCreateRequest<'_>,
    ) -> Result<(), ApiError> {
        if request
            .collection_ids
            .as_ref()
            .is_some_and(|ids| !ids.is_empty())
        {
            return Err(ApiError::invalid(
                "collectionIds",
                "Collections are not supported by the personal-vault service.",
            ));
        }
        // `create_cipher` discards a source item's revision on every fresh insert.
        self.create_cipher(owner, id, &request.cipher)
    }

    pub fn update_cipher(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        validation::validate_cipher(request)?;
        validate_encrypted_for(owner, request)?;
        if self.check_cipher(owner, id)? {
            return Err(ApiError::new(
                ErrorKind::Conflict,
                "Restore a deleted cipher before updating it.",
            ));
        }
        self.check_cipher_folder(owner, request.folder_id)?;
        self.storage
            .save_cipher(owner, id, request)
            .map_err(S::map_error)
    }

    pub fn soft_delete_cipher(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        if self.check_cipher(owner, id)? {
            return Ok(());
        }
        self.storage
            .set_cipher_deleted(owner, id, true)
            .map_err(S::map_error)
    }

    pub fn restore_cipher(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        if !self.check_cipher(owner, id)? {
            return Ok(());
        }
        self.storage
            .set_cipher_deleted(owner, id, false)
            .map_err(S::map_error)
    }

    pub fn delete_cipher(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        self.check_cipher(owner, id)?;
        self.storage.delete_cipher(owner, id).map_err(S::map_error)
    }

    fn check_folder(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        match self.storage.folder_metadata(id).map_err(S::map_error)? {
            Some(metadata) if metadata.owner_id == owner => Ok(()),
            _ => Err(not_found()),
        }
    }

    fn check_cipher_folder(
        &mut self,
        owner: &str,
        folder_id: Option<&str>,
    ) -> Result<(), ApiError> {
        if let Some(id) = folder_id {
            match self.check_folder(owner, id) {
                Ok(()) => (),
                Err(error) if error.kind == ErrorKind::NotFound => {
                    return Err(ApiError::invalid(
                        "folderId",
                        "Folder does not exist in this vault.",
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn check_cipher(&mut self, owner: &str, id: &str) -> Result<bool, ApiError> {
        match self.storage.cipher_metadata(id).map_err(S::map_error)? {
            Some(metadata) if metadata.owner_id == owner => Ok(metadata.deleted),
            _ => Err(not_found()),
        }
    }
}

pub(crate) fn require_owner(owner: &str) -> Result<(), ApiError> {
    if owner.is_empty() {
        Err(ApiError::new(
            ErrorKind::Unauthorized,
            "Authentication is required.",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_encrypted_for(
    owner: &str,
    request: &CipherRequest<'_>,
) -> Result<(), ApiError> {
    if request
        .encrypted_for
        .is_some_and(|account| account != owner)
    {
        Err(ApiError::invalid(
            "encryptedFor",
            "The cipher was encrypted for another account.",
        ))
    } else {
        Ok(())
    }
}

fn validate_id(id: &str) -> Result<(), ApiError> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        Err(ApiError::invalid("id", "A valid identifier is required."))
    } else {
        Ok(())
    }
}

fn storage_error<E>(_: E) -> ApiError {
    ApiError::new(ErrorKind::Storage, "Storage operation failed.")
}
fn conflict() -> ApiError {
    ApiError::new(
        ErrorKind::Conflict,
        "An item with this identifier already exists.",
    )
}
fn not_found() -> ApiError {
    ApiError::new(ErrorKind::NotFound, "The requested item was not found.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::{String, ToString};
    const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[derive(Clone, Copy, Debug)]
    enum Failure {
        Backend,
        Stale,
    }

    #[derive(Debug, Default)]
    struct Memory {
        fail_save: Option<Failure>,
        current_key: Option<&'static str>,
        received_revision: Option<String>,
        folder: Option<(String, String)>,
        cipher: Option<(String, String, bool)>,
        writes: usize,
        reads: usize,
    }

    impl Storage for Memory {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::Stale => ApiError::new(ErrorKind::Conflict, "Sync and retry."),
                Failure::Backend => storage_error(error),
            }
        }
        fn user_key_id(&mut self, _: &str) -> Result<Option<&str>, Failure> {
            self.reads += 1;
            Ok(self.current_key)
        }
        fn account_exists(&mut self, _: &str) -> Result<bool, Failure> {
            Ok(false)
        }
        fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), Failure> {
            self.writes += 1;
            Ok(())
        }
        fn folder_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            self.reads += 1;
            Ok(self
                .folder
                .as_ref()
                .filter(|(key, _)| key == id)
                .map(|(_, owner)| ItemMetadata {
                    owner_id: owner,
                    deleted: false,
                }))
        }
        fn save_folder(
            &mut self,
            owner: &str,
            id: &str,
            _: &FolderRequest<'_>,
        ) -> Result<(), Failure> {
            self.folder = Some((id.to_string(), owner.to_string()));
            self.writes += 1;
            Ok(())
        }
        fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), Failure> {
            self.folder = None;
            self.writes += 1;
            Ok(())
        }
        fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Failure> {
            self.reads += 1;
            Ok(self
                .cipher
                .as_ref()
                .filter(|(key, _, _)| key == id)
                .map(|(_, owner, deleted)| ItemMetadata {
                    owner_id: owner,
                    deleted: *deleted,
                }))
        }
        fn save_cipher(
            &mut self,
            owner: &str,
            id: &str,
            request: &CipherRequest<'_>,
        ) -> Result<(), Failure> {
            if let Some(error) = self.fail_save {
                return Err(error);
            }
            self.received_revision = request.last_known_revision_date.map(ToString::to_string);
            self.cipher = Some((id.to_string(), owner.to_string(), false));
            self.writes += 1;
            Ok(())
        }
        fn set_cipher_deleted(&mut self, _: &str, _: &str, deleted: bool) -> Result<(), Failure> {
            self.cipher.as_mut().unwrap().2 = deleted;
            self.writes += 1;
            Ok(())
        }
        fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), Failure> {
            self.cipher = None;
            self.writes += 1;
            Ok(())
        }
    }

    fn cipher() -> CipherRequest<'static> {
        CipherRequest {
            kind: 2,
            name: Some(ENCRYPTED),
            data: None,
            notes: None,
            folder_id: None,
            organization_id: None,
            encrypted_for: None,
            encrypted_by_key_id: None,
            key: None,
            favorite: false,
            reprompt: 0,
            login: None,
            secure_note: Some(crate::wire::SecureNote { kind: 0 }),
            card: None,
            identity: None,
            ssh_key: None,
            fields: None,
            password_history: None,
            last_known_revision_date: None,
            archived_date: None,
        }
    }

    #[test]
    fn ownership_and_trash_lifecycle_prevent_unwanted_writes() {
        let mut service = VaultService::new(Memory::default());
        let request = cipher();
        service.create_cipher("alice", "cipher", &request).unwrap();
        assert_eq!(
            service
                .update_cipher("bob", "cipher", &request)
                .unwrap_err()
                .kind,
            ErrorKind::NotFound
        );
        assert_eq!(
            service.delete_cipher("bob", "cipher").unwrap_err().kind,
            ErrorKind::NotFound
        );
        assert_eq!(service.storage().writes, 1);
        service.soft_delete_cipher("alice", "cipher").unwrap();
        service.soft_delete_cipher("alice", "cipher").unwrap();
        assert_eq!(service.storage().writes, 2);
        assert_eq!(
            service
                .update_cipher("alice", "cipher", &request)
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
        service.restore_cipher("alice", "cipher").unwrap();
        service.update_cipher("alice", "cipher", &request).unwrap();
        service.delete_cipher("alice", "cipher").unwrap();
        assert!(service.storage().cipher.is_none());
    }

    #[test]
    fn foreign_folder_and_invalid_payload_do_not_mutate_storage() {
        let mut service = VaultService::new(Memory::default());
        service
            .create_folder("alice", "folder", &FolderRequest { name: ENCRYPTED })
            .unwrap();
        let mut request = cipher();
        request.folder_id = Some("folder");
        assert_eq!(
            service
                .create_cipher("bob", "cipher", &request)
                .unwrap_err()
                .field,
            Some("folderId")
        );
        request.name = Some("plaintext");
        assert_eq!(
            service
                .create_cipher("alice", "cipher", &request)
                .unwrap_err()
                .kind,
            ErrorKind::InvalidRequest
        );
        assert_eq!(service.storage().writes, 1);
        assert_eq!(
            service
                .create_folder("", "other", &FolderRequest { name: ENCRYPTED })
                .unwrap_err()
                .kind,
            ErrorKind::Unauthorized
        );
    }

    #[test]
    fn cipher_encryption_owner_is_checked_before_storage_access() {
        let mut service = VaultService::new(Memory::default());
        let mut request = cipher();
        request.encrypted_for = Some("alice");
        request.encrypted_by_key_id = Some("opaque:key/id");
        request.key = Some(ENCRYPTED);
        service.create_cipher("alice", "cipher", &request).unwrap();
        let reads = service.storage().reads;
        let writes = service.storage().writes;
        request.encrypted_for = Some("bob");
        request.folder_id = Some("unknown-folder");
        assert_eq!(
            service
                .create_cipher("alice", "second", &request)
                .unwrap_err()
                .field,
            Some("encryptedFor")
        );
        assert_eq!(
            service
                .update_cipher("alice", "cipher", &request)
                .unwrap_err()
                .field,
            Some("encryptedFor")
        );
        assert_eq!(service.storage().reads, reads);
        assert_eq!(service.storage().writes, writes);
    }

    #[test]
    fn malformed_cipher_keys_are_rejected_before_storage_access() {
        let mut service = VaultService::new(Memory::default());
        let mut request = cipher();
        request.key = Some("unwrapped plaintext key");
        assert_eq!(
            service
                .create_cipher("alice", "cipher", &request)
                .unwrap_err()
                .field,
            Some("key")
        );
        assert_eq!(
            service
                .update_cipher("alice", "cipher", &request)
                .unwrap_err()
                .field,
            Some("key")
        );
        assert_eq!(service.storage().reads, 0);
        assert_eq!(service.storage().writes, 0);
    }

    #[test]
    fn current_key_ids_guard_creates_and_legacy_ids_remain_optional() {
        let mut request = cipher();
        request.encrypted_by_key_id = Some("stale-key");
        let mut storage = Memory {
            current_key: Some("current-key"),
            ..Memory::default()
        };
        let mut service = VaultService::new(&mut storage);
        assert_eq!(
            service
                .create_cipher("alice", "cipher", &request)
                .unwrap_err()
                .field,
            Some("encryptedByKeyId")
        );
        assert_eq!(service.storage().writes, 0);
        request.encrypted_by_key_id = Some("current-key");
        service.create_cipher("alice", "cipher", &request).unwrap();
        request.encrypted_by_key_id = None;
        service.create_cipher("alice", "legacy", &request).unwrap();
        let mut legacy = VaultService::new(Memory::default());
        request.encrypted_by_key_id = Some("opaque-unmigrated-id");
        legacy.create_cipher("alice", "cipher", &request).unwrap();
    }

    #[test]
    fn provider_conflicts_survive_borrowed_storage_without_mutation() {
        for (failure, kind, status) in [
            (Failure::Stale, ErrorKind::Conflict, 409),
            (Failure::Backend, ErrorKind::Storage, 500),
        ] {
            let mut storage = Memory {
                cipher: Some(("cipher".into(), "alice".into(), false)),
                fail_save: Some(failure),
                ..Memory::default()
            };
            let mut service = VaultService::new(&mut storage);
            let mut request = cipher();
            request.last_known_revision_date = Some("stale-revision");
            let error = service
                .update_cipher("alice", "cipher", &request)
                .unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(error.status_code(), status);
            assert_eq!(service.storage().writes, 0);
            assert_eq!(service.storage().cipher.as_ref().unwrap().0, "cipher");
        }
    }

    #[test]
    fn personal_clone_discards_source_revision_and_rejects_collections() {
        let mut request = CipherCreateRequest {
            cipher: cipher(),
            collection_ids: None,
        };
        request.cipher.last_known_revision_date = Some("source-revision");
        let mut service = VaultService::new(Memory::default());
        service
            .create_cipher_wrapped("alice", "clone", &request)
            .unwrap();
        assert!(service.storage().received_revision.is_none());
        let mut ids = crate::bounded::BoundedList::new();
        ids.push("unsupported-collection").unwrap();
        request.collection_ids = Some(ids);
        assert_eq!(
            service
                .create_cipher_wrapped("alice", "other", &request)
                .unwrap_err()
                .field,
            Some("collectionIds")
        );
        assert_eq!(service.storage().writes, 1);
    }
}
