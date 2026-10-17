//! Personal-vault business rules over an application-provided persistence adapter.
//!
//! Every owner argument must come from a verified authentication context. Never take it
//! directly from an untrusted request. Hold the application's storage lock or transaction
//! for an entire service operation so ownership checks and mutations remain atomic.
use crate::{
    ApiError, ErrorKind,
    validation::{self, KdfPolicy},
    wire::{CipherRequest, FolderRequest, RegisterRequest},
};

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
            .map_err(storage_error)?
        {
            return Err(ApiError::new(
                ErrorKind::Conflict,
                "An account with this email already exists.",
            ));
        }
        self.storage
            .insert_account(id, request)
            .map_err(storage_error)
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
            .map_err(storage_error)?
            .is_some()
        {
            return Err(conflict());
        }
        self.storage
            .save_folder(owner, id, request)
            .map_err(storage_error)
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
            .map_err(storage_error)
    }

    pub fn delete_folder(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        self.check_folder(owner, id)?;
        self.storage.delete_folder(owner, id).map_err(storage_error)
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
        self.check_cipher_folder(owner, request.folder_id)?;
        if self
            .storage
            .cipher_metadata(id)
            .map_err(storage_error)?
            .is_some()
        {
            return Err(conflict());
        }
        self.storage
            .save_cipher(owner, id, request)
            .map_err(storage_error)
    }

    pub fn update_cipher(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        validation::validate_cipher(request)?;
        if self.check_cipher(owner, id)? {
            return Err(ApiError::new(
                ErrorKind::Conflict,
                "Restore a deleted cipher before updating it.",
            ));
        }
        self.check_cipher_folder(owner, request.folder_id)?;
        self.storage
            .save_cipher(owner, id, request)
            .map_err(storage_error)
    }

    pub fn soft_delete_cipher(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        if self.check_cipher(owner, id)? {
            return Ok(());
        }
        self.storage
            .set_cipher_deleted(owner, id, true)
            .map_err(storage_error)
    }

    pub fn restore_cipher(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        if !self.check_cipher(owner, id)? {
            return Ok(());
        }
        self.storage
            .set_cipher_deleted(owner, id, false)
            .map_err(storage_error)
    }

    pub fn delete_cipher(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        require_owner(owner)?;
        self.check_cipher(owner, id)?;
        self.storage.delete_cipher(owner, id).map_err(storage_error)
    }

    fn check_folder(&mut self, owner: &str, id: &str) -> Result<(), ApiError> {
        match self.storage.folder_metadata(id).map_err(storage_error)? {
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
        match self.storage.cipher_metadata(id).map_err(storage_error)? {
            Some(metadata) if metadata.owner_id == owner => Ok(metadata.deleted),
            _ => Err(not_found()),
        }
    }
}

fn require_owner(owner: &str) -> Result<(), ApiError> {
    if owner.is_empty() {
        Err(ApiError::new(
            ErrorKind::Unauthorized,
            "Authentication is required.",
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

    #[derive(Debug, Default)]
    struct Memory {
        folder: Option<(String, String)>,
        cipher: Option<(String, String, bool)>,
        writes: usize,
    }

    impl Storage for Memory {
        type Error = ();
        fn account_exists(&mut self, _: &str) -> Result<bool, ()> {
            Ok(false)
        }
        fn insert_account(&mut self, _: &str, _: &RegisterRequest<'_>) -> Result<(), ()> {
            self.writes += 1;
            Ok(())
        }
        fn folder_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
            Ok(self
                .folder
                .as_ref()
                .filter(|(key, _)| key == id)
                .map(|(_, owner)| ItemMetadata {
                    owner_id: owner,
                    deleted: false,
                }))
        }
        fn save_folder(&mut self, owner: &str, id: &str, _: &FolderRequest<'_>) -> Result<(), ()> {
            self.folder = Some((id.to_string(), owner.to_string()));
            self.writes += 1;
            Ok(())
        }
        fn delete_folder(&mut self, _: &str, _: &str) -> Result<(), ()> {
            self.folder = None;
            self.writes += 1;
            Ok(())
        }
        fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, ()> {
            Ok(self
                .cipher
                .as_ref()
                .filter(|(key, _, _)| key == id)
                .map(|(_, owner, deleted)| ItemMetadata {
                    owner_id: owner,
                    deleted: *deleted,
                }))
        }
        fn save_cipher(&mut self, owner: &str, id: &str, _: &CipherRequest<'_>) -> Result<(), ()> {
            self.cipher = Some((id.to_string(), owner.to_string(), false));
            self.writes += 1;
            Ok(())
        }
        fn set_cipher_deleted(&mut self, _: &str, _: &str, deleted: bool) -> Result<(), ()> {
            self.cipher.as_mut().unwrap().2 = deleted;
            self.writes += 1;
            Ok(())
        }
        fn delete_cipher(&mut self, _: &str, _: &str) -> Result<(), ()> {
            self.cipher = None;
            self.writes += 1;
            Ok(())
        }
    }

    fn cipher() -> CipherRequest<'static> {
        CipherRequest {
            kind: 2,
            name: ENCRYPTED,
            notes: None,
            folder_id: None,
            organization_id: None,
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
        request.name = "plaintext";
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
}
