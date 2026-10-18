//! An owned, allocation-free storage consumer for generic secure notes.
//! Authentication, encryption, revision clocks, transport, and durable storage
//! belong to the embedding application. Capacities are intentional hard limits.
#![no_std]
#![forbid(unsafe_code)]

use no_warden::{
    ErrorKind, Storage, VaultService,
    service::ItemMetadata,
    wire::{CipherRequest, FolderRequest, PreloginResponse, RegisterRequest, SecureNote},
};

pub const ACCOUNTS: usize = 2;
pub const FOLDERS: usize = 2;
pub const CIPHERS: usize = 2;
pub const ID_BYTES: usize = 64;
pub const TEXT_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Capacity,
    TextTooLong,
    Missing,
    WrongOwner,
    Unsupported,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Text<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Text<N> {
    fn copy(value: &str) -> Result<Self, Error> {
        if value.len() > N {
            return Err(Error::TextTooLong);
        }
        let mut text = Self {
            bytes: [0; N],
            len: value.len(),
        };
        text.bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(text)
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).expect("copied UTF-8")
    }
}
impl<const N: usize> core::fmt::Debug for Text<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Text")
            .field("bytes", &self.len)
            .finish_non_exhaustive()
    }
}
fn optional<const N: usize>(value: Option<&str>) -> Result<Option<Text<N>>, Error> {
    value.map(Text::copy).transpose()
}
fn slot<T>(entries: &[Option<T>], matches: impl Fn(&T) -> bool) -> Result<usize, Error> {
    entries
        .iter()
        .position(|entry| entry.as_ref().is_some_and(&matches))
        .or_else(|| entries.iter().position(Option::is_none))
        .ok_or(Error::Capacity)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Account {
    pub id: Text<ID_BYTES>,
    pub email: Text<TEXT_BYTES>,
    pub kdf: PreloginResponse,
    pub wrapped_user_key: Text<TEXT_BYTES>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Folder {
    pub id: Text<ID_BYTES>,
    pub owner: Text<ID_BYTES>,
    pub name: Text<TEXT_BYTES>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cipher {
    pub id: Text<ID_BYTES>,
    pub owner: Text<ID_BYTES>,
    pub name: Text<TEXT_BYTES>,
    pub notes: Option<Text<TEXT_BYTES>>,
    pub folder_id: Option<Text<ID_BYTES>>,
    pub encrypted_for: Option<Text<ID_BYTES>>,
    pub encrypted_by_key_id: Option<Text<ID_BYTES>>,
    pub key: Option<Text<TEXT_BYTES>>,
    pub favorite: bool,
    pub reprompt: u8,
    pub deleted: bool,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FixedVault {
    accounts: [Option<Account>; ACCOUNTS],
    folders: [Option<Folder>; FOLDERS],
    ciphers: [Option<Cipher>; CIPHERS],
}
impl FixedVault {
    pub fn account(&self, id: &str) -> Option<&Account> {
        self.accounts
            .iter()
            .flatten()
            .find(|value| value.id.as_str() == id)
    }
    pub fn cipher(&self, id: &str) -> Option<&Cipher> {
        self.ciphers
            .iter()
            .flatten()
            .find(|value| value.id.as_str() == id)
    }
    fn require_account(&self, owner: &str) -> Result<(), Error> {
        self.account(owner).map(|_| ()).ok_or(Error::Missing)
    }
}
impl Storage for FixedVault {
    type Error = Error;
    fn account_exists(&mut self, email: &str) -> Result<bool, Error> {
        Ok(self
            .accounts
            .iter()
            .flatten()
            .any(|value| value.email.as_str().eq_ignore_ascii_case(email)))
    }
    fn insert_account(&mut self, id: &str, request: &RegisterRequest<'_>) -> Result<(), Error> {
        if request.keys.is_some() {
            return Err(Error::Unsupported);
        }
        if self.account(id).is_some() {
            return Err(Error::Capacity);
        }
        let index = slot(&self.accounts, |_| false)?;
        let value = Account {
            id: Text::copy(id)?,
            email: Text::copy(request.email)?,
            kdf: request.prelogin(),
            wrapped_user_key: Text::copy(request.key)?,
        };
        self.accounts[index] = Some(value);
        Ok(())
    }
    fn folder_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Error> {
        Ok(self
            .folders
            .iter()
            .flatten()
            .find(|v| v.id.as_str() == id)
            .map(|v| ItemMetadata {
                owner_id: v.owner.as_str(),
                deleted: false,
            }))
    }
    fn cipher_metadata(&mut self, id: &str) -> Result<Option<ItemMetadata<'_>>, Error> {
        Ok(self.cipher(id).map(|v| ItemMetadata {
            owner_id: v.owner.as_str(),
            deleted: v.deleted,
        }))
    }
    fn save_folder(
        &mut self,
        owner: &str,
        id: &str,
        request: &FolderRequest<'_>,
    ) -> Result<(), Error> {
        self.require_account(owner)?;
        let index = slot(&self.folders, |v| v.id.as_str() == id)?;
        if self.folders[index]
            .as_ref()
            .is_some_and(|v| v.owner.as_str() != owner)
        {
            return Err(Error::WrongOwner);
        }
        let value = Folder {
            id: Text::copy(id)?,
            owner: Text::copy(owner)?,
            name: Text::copy(request.name)?,
        };
        self.folders[index] = Some(value);
        Ok(())
    }
    fn save_cipher(
        &mut self,
        owner: &str,
        id: &str,
        request: &CipherRequest<'_>,
    ) -> Result<(), Error> {
        self.require_account(owner)?;
        // Reject data this deliberately small adapter cannot preserve.
        if request.kind != 2
            || request.data.is_some()
            || request.fields.is_some()
            || request.password_history.is_some()
            || request.last_known_revision_date.is_some()
            || request.login.is_some()
            || request.card.is_some()
            || request.identity.is_some()
            || request.ssh_key.is_some()
        {
            return Err(Error::Unsupported);
        }
        let name = request.name.ok_or(Error::Unsupported)?;
        let index = slot(&self.ciphers, |v| v.id.as_str() == id)?;
        if self.ciphers[index]
            .as_ref()
            .is_some_and(|v| v.owner.as_str() != owner)
        {
            return Err(Error::WrongOwner);
        }
        let value = Cipher {
            id: Text::copy(id)?,
            owner: Text::copy(owner)?,
            name: Text::copy(name)?,
            notes: optional(request.notes)?,
            folder_id: optional(request.folder_id)?,
            encrypted_for: optional(request.encrypted_for)?,
            encrypted_by_key_id: optional(request.encrypted_by_key_id)?,
            key: optional(request.key)?,
            favorite: request.favorite,
            reprompt: request.reprompt,
            deleted: false,
        };
        self.ciphers[index] = Some(value);
        Ok(())
    }
    fn delete_folder(&mut self, owner: &str, id: &str) -> Result<(), Error> {
        let index = self
            .folders
            .iter()
            .position(|v| {
                v.as_ref()
                    .is_some_and(|v| v.id.as_str() == id && v.owner.as_str() == owner)
            })
            .ok_or(Error::Missing)?;
        for cipher in self.ciphers.iter_mut().flatten() {
            if cipher.owner.as_str() == owner
                && cipher.folder_id.as_ref().is_some_and(|v| v.as_str() == id)
            {
                cipher.folder_id = None;
            }
        }
        self.folders[index] = None;
        Ok(())
    }
    fn set_cipher_deleted(&mut self, owner: &str, id: &str, deleted: bool) -> Result<(), Error> {
        let value = self
            .ciphers
            .iter_mut()
            .flatten()
            .find(|v| v.id.as_str() == id && v.owner.as_str() == owner)
            .ok_or(Error::Missing)?;
        value.deleted = deleted;
        Ok(())
    }
    fn delete_cipher(&mut self, owner: &str, id: &str) -> Result<(), Error> {
        let index = self
            .ciphers
            .iter()
            .position(|v| {
                v.as_ref()
                    .is_some_and(|v| v.id.as_str() == id && v.owner.as_str() == owner)
            })
            .ok_or(Error::Missing)?;
        self.ciphers[index] = None;
        Ok(())
    }
}

// Public envelope fixtures only; no real credentials or authenticated ciphertext.
const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
fn registration(email: &str) -> RegisterRequest<'_> {
    RegisterRequest {
        email,
        name: None,
        master_password_hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        master_password_hint: None,
        key: ENCRYPTED,
        kdf: 0,
        kdf_iterations: 600_000,
        kdf_memory: None,
        kdf_parallelism: None,
        keys: None,
    }
}
fn note() -> CipherRequest<'static> {
    CipherRequest {
        kind: 2,
        name: Some(ENCRYPTED),
        data: None,
        notes: Some(ENCRYPTED),
        folder_id: Some("folder"),
        organization_id: None,
        encrypted_for: Some("alice"),
        encrypted_by_key_id: Some("opaque:key/id"),
        key: Some(ENCRYPTED),
        favorite: false,
        reprompt: 0,
        login: None,
        secure_note: Some(SecureNote { kind: 0 }),
        card: None,
        identity: None,
        ssh_key: None,
        fields: None,
        password_history: None,
        last_known_revision_date: None,
    }
}

/// Runs on the host in tests and in the allocator-free RISC-V entry point.
pub fn exercise(vault: &mut FixedVault) {
    let mut service = VaultService::new(vault);
    service
        .register("alice", &registration("alice@example.test"))
        .unwrap();
    assert_eq!(
        service
            .storage()
            .account("alice")
            .unwrap()
            .wrapped_user_key
            .as_str(),
        ENCRYPTED
    );
    service
        .create_folder("alice", "folder", &FolderRequest { name: ENCRYPTED })
        .unwrap();
    let mut request = note();
    service.create_cipher("alice", "cipher", &request).unwrap();
    request.favorite = true;
    service.update_cipher("alice", "cipher", &request).unwrap();
    assert!(service.storage().cipher("cipher").unwrap().favorite);
    service.soft_delete_cipher("alice", "cipher").unwrap();
    assert!(service.storage().cipher("cipher").unwrap().deleted);
    service.restore_cipher("alice", "cipher").unwrap();
    assert!(!service.storage().cipher("cipher").unwrap().deleted);
    assert_eq!(
        service
            .update_cipher("bob", "cipher", &request)
            .unwrap_err()
            .field,
        Some("encryptedFor")
    );
    assert_eq!(
        service.delete_cipher("bob", "cipher").unwrap_err().kind,
        ErrorKind::NotFound
    );
    let stored = service.storage().cipher("cipher").unwrap();
    assert_eq!(stored.key.as_ref().unwrap().as_str(), ENCRYPTED);
    assert_eq!(
        stored.encrypted_by_key_id.as_ref().unwrap().as_str(),
        "opaque:key/id"
    );
    service.delete_folder("alice", "folder").unwrap();
    assert!(
        service
            .storage()
            .cipher("cipher")
            .unwrap()
            .folder_id
            .is_none()
    );
    request.folder_id = None;
    service.create_cipher("alice", "second", &request).unwrap();
    let before = (*service.storage()).clone();
    assert_eq!(
        service
            .create_cipher("alice", "overflow", &request)
            .unwrap_err()
            .kind,
        ErrorKind::Storage
    );
    assert_eq!(**service.storage(), before);
    service.delete_cipher("alice", "second").unwrap();
    service.create_cipher("alice", "reused", &request).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_service_lifecycle_ownership_and_capacity() {
        exercise(&mut FixedVault::default());
    }

    #[test]
    fn text_overflow_and_unsupported_payloads_never_partially_replace_items() {
        let mut vault = FixedVault::default();
        exercise(&mut vault);
        let before = vault.clone();
        let oversized = [b'x'; TEXT_BYTES + 1];
        let mut request = note();
        request.folder_id = None;
        request.notes = Some(core::str::from_utf8(&oversized).unwrap());
        assert_eq!(
            vault.save_cipher("alice", "cipher", &request),
            Err(Error::TextTooLong)
        );
        assert_eq!(vault, before);
        request.notes = None;
        request.last_known_revision_date = Some("unsupported-clock");
        assert_eq!(
            vault.save_cipher("alice", "cipher", &request),
            Err(Error::Unsupported)
        );
        assert_eq!(vault, before);
    }

    #[test]
    fn blobs_and_missing_names_are_rejected_without_dropping_stored_ciphertext() {
        let mut vault = FixedVault::default();
        exercise(&mut vault);
        let before = vault.clone();
        let mut request = note();
        request.folder_id = None;
        request.name = None;
        assert_eq!(
            vault.save_cipher("alice", "cipher", &request),
            Err(Error::Unsupported)
        );
        assert_eq!(vault, before);
        request.data = Some(r#"{"format_version":1,"wrapped_cek":"opaque","envelope":"opaque"}"#);
        let mut service = VaultService::new(&mut vault);
        assert_eq!(
            service
                .update_cipher("alice", "cipher", &request)
                .unwrap_err()
                .kind,
            ErrorKind::Storage
        );
        assert_eq!(vault, before);
    }
}
