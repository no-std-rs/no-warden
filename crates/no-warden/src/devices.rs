//! Device discovery and verified-login registration over adapter-owned storage.
//!
//! Device identifiers and names are opaque. Header decoding, path guards, clocks,
//! credential verification, pending-authentication workflows and push delivery stay outside
//! this module. Owner arguments must come from a verified authentication context.

use crate::{
    ApiError, Storage, VaultService,
    service::require_owner,
    wire::{DeviceListResponse, DeviceResponse, KnownDeviceRequest, KnownDeviceResponse},
};

/// Input supplied only after a successful password or personal API-key login.
/// The adapter parses the source device type into i32 (falling back to 14 when invalid).
#[derive(Clone, Copy)]
pub struct DeviceRegistration<'a> {
    pub identifier: &'a str,
    pub name: &'a str,
    pub device_type: i32,
}
impl core::fmt::Debug for DeviceRegistration<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceRegistration").finish_non_exhaustive()
    }
}

/// Optional read metadata. This does not implement an authentication-request lifecycle.
#[derive(Clone, Copy)]
pub struct PendingDeviceAuthRequest<'a> {
    pub id: &'a str,
    pub creation_date: &'a str,
}
impl core::fmt::Debug for PendingDeviceAuthRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingDeviceAuthRequest")
            .finish_non_exhaustive()
    }
}

/// Borrowed provider record. Internal ownership is checked by services and never serialized.
/// This record deliberately has no Serialize implementation; use the explicit wire projection.
#[derive(Clone, Copy)]
pub struct DeviceRecord<'a> {
    pub owner_id: &'a str,
    pub identifier: &'a str,
    pub name: &'a str,
    pub device_type: i32,
    pub creation_date: &'a str,
    pub pending_auth_request: Option<PendingDeviceAuthRequest<'a>>,
}
impl core::fmt::Debug for DeviceRecord<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceRecord").finish_non_exhaustive()
    }
}

/// Complete, stable indexed read view without a fixed list-size limit. Every index less
/// than len must exist, and the records must stay unchanged until serialization completes.
pub trait DeviceListData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<DeviceRecord<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: DeviceListData + ?Sized> DeviceListData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<DeviceRecord<'_>> {
        (**self).get(index)
    }
}
impl DeviceListData for [DeviceRecord<'_>] {
    fn len(&self) -> usize {
        <[DeviceRecord<'_>]>::len(self)
    }
    fn get(&self, index: usize) -> Option<DeviceRecord<'_>> {
        <[DeviceRecord<'_>]>::get(self, index).copied()
    }
}

/// Opt-in device registry. Hold the authenticated operation's storage lock/transaction.
///
/// known_device receives decoded UTF-8 email and the exact header identifier. The provider
/// must lowercase the email using Unicode lowercase WITHOUT trimming and resolve the exact
/// (owner, identifier) pair. Unknown users/devices return false. No bearer is required.
///
/// Authenticated reads must return only the requested owner's records. Registration is
/// called only after credential verification, uses a composite (owner, identifier) key,
/// and preserves initial name, type and creation timestamp on repeat logins. New rows use
/// an adapter clock. Registration may update device activity but must not change account
/// revision, credentials, sessions, vault records, pending-auth metadata or foreign state.
/// A provider error must preserve all prior registry and unrelated state atomically.
/// Device/session binding, login transaction boundaries and push policy belong to adapters.
pub trait DeviceStorage: Storage {
    type Devices<'a>: DeviceListData
    where
        Self: 'a;

    fn known_device(&mut self, decoded_email: &str, identifier: &str) -> Result<bool, Self::Error>;
    fn devices(&mut self, owner: &str) -> Result<Self::Devices<'_>, Self::Error>;
    fn device(
        &mut self,
        owner: &str,
        identifier: &str,
    ) -> Result<Option<DeviceRecord<'_>>, Self::Error>;
    fn register_device(
        &mut self,
        owner: &str,
        registration: &DeviceRegistration<'_>,
    ) -> Result<(), Self::Error>;
}
impl<T: DeviceStorage + ?Sized> DeviceStorage for &mut T {
    type Devices<'a>
        = T::Devices<'a>
    where
        Self: 'a;
    fn known_device(&mut self, decoded_email: &str, identifier: &str) -> Result<bool, Self::Error> {
        (**self).known_device(decoded_email, identifier)
    }
    fn devices(&mut self, owner: &str) -> Result<Self::Devices<'_>, Self::Error> {
        (**self).devices(owner)
    }
    fn device(
        &mut self,
        owner: &str,
        identifier: &str,
    ) -> Result<Option<DeviceRecord<'_>>, Self::Error> {
        (**self).device(owner, identifier)
    }
    fn register_device(
        &mut self,
        owner: &str,
        registration: &DeviceRegistration<'_>,
    ) -> Result<(), Self::Error> {
        (**self).register_device(owner, registration)
    }
}

fn unavailable() -> ApiError {
    ApiError::invalid("device", "No device found")
}
impl<S: DeviceStorage> VaultService<S> {
    /// Public discovery over already-decoded request headers; no normalization in the core.
    pub fn known_device(
        &mut self,
        request: &KnownDeviceRequest<'_>,
    ) -> Result<KnownDeviceResponse, ApiError> {
        self.storage_mut()
            .known_device(request.email, request.identifier)
            .map(KnownDeviceResponse)
            .map_err(S::map_error)
    }

    pub fn list_devices(
        &mut self,
        owner: &str,
    ) -> Result<DeviceListResponse<S::Devices<'_>>, ApiError> {
        require_owner(owner)?;
        let devices = self.storage_mut().devices(owner).map_err(S::map_error)?;
        for index in 0..devices.len() {
            let record = devices.get(index).ok_or_else(|| {
                ApiError::invalid("devices", "The device list view is incomplete.")
            })?;
            if record.owner_id != owner {
                return Err(unavailable());
            }
        }
        Ok(DeviceListResponse::new(devices))
    }

    pub fn get_device(
        &mut self,
        owner: &str,
        identifier: &str,
    ) -> Result<DeviceResponse<'_>, ApiError> {
        require_owner(owner)?;
        let device = self
            .storage_mut()
            .device(owner, identifier)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        if device.owner_id != owner || device.identifier != identifier {
            return Err(unavailable());
        }
        Ok(DeviceResponse::new(device))
    }

    /// The caller must supply a verified login owner, never a request's claimed owner.
    pub fn register_device(
        &mut self,
        owner: &str,
        registration: &DeviceRegistration<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        self.storage_mut()
            .register_device(owner, registration)
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
    struct Stored {
        owner: String,
        identifier: String,
        name: String,
        kind: i32,
        created: String,
        pending: Option<(String, String)>,
    }
    impl Stored {
        fn record(&self) -> DeviceRecord<'_> {
            DeviceRecord {
                owner_id: &self.owner,
                identifier: &self.identifier,
                name: &self.name,
                device_type: self.kind,
                creation_date: &self.created,
                pending_auth_request: self.pending.as_ref().map(|(id, created)| {
                    PendingDeviceAuthRequest {
                        id,
                        creation_date: created,
                    }
                }),
            }
        }
    }
    struct View<'a> {
        records: &'a BTreeMap<(String, String), Stored>,
        owner: String,
        leak: bool,
        incomplete: bool,
    }
    impl DeviceListData for View<'_> {
        fn len(&self) -> usize {
            self.records
                .values()
                .filter(|record| self.leak || record.owner == self.owner)
                .count()
        }
        fn get(&self, index: usize) -> Option<DeviceRecord<'_>> {
            if self.incomplete {
                return None;
            }
            self.records
                .values()
                .filter(|record| self.leak || record.owner == self.owner)
                .nth(index)
                .map(Stored::record)
        }
    }
    struct Mock {
        records: BTreeMap<(String, String), Stored>,
        emails: BTreeMap<String, String>,
        calls: usize,
        fail: Option<ErrorKind>,
        leak: bool,
        incomplete: bool,
        revision: u64,
        account_authority: &'static str,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                records: BTreeMap::new(),
                emails: BTreeMap::from([
                    ("owner@example.test".to_string(), "owner".to_string()),
                    ("foreign@example.test".to_string(), "foreign".to_string()),
                    ("i\u{307}d@example.test".to_string(), "owner".to_string()),
                ]),
                calls: 0,
                fail: None,
                leak: false,
                incomplete: false,
                revision: 71,
                account_authority: "unchanged-key-credentials-session-and-vault",
            }
        }
        fn call(&mut self) -> Result<(), ErrorKind> {
            self.calls += 1;
            self.fail.map_or(Ok(()), Err)
        }
    }
    impl Storage for Mock {
        type Error = ErrorKind;
        fn map_error(error: Self::Error) -> ApiError {
            ApiError::new(error, "Device provider failed.")
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
    impl DeviceStorage for Mock {
        type Devices<'a> = View<'a>;
        fn known_device(&mut self, email: &str, identifier: &str) -> Result<bool, Self::Error> {
            self.call()?;
            Ok(self.emails.get(&email.to_lowercase()).is_some_and(|owner| {
                self.records
                    .contains_key(&(owner.clone(), identifier.to_string()))
            }))
        }
        fn devices(&mut self, owner: &str) -> Result<Self::Devices<'_>, Self::Error> {
            self.call()?;
            Ok(View {
                records: &self.records,
                owner: owner.to_string(),
                leak: self.leak,
                incomplete: self.incomplete,
            })
        }
        fn device(
            &mut self,
            owner: &str,
            identifier: &str,
        ) -> Result<Option<DeviceRecord<'_>>, Self::Error> {
            self.call()?;
            if self.leak {
                return Ok(self.records.values().next().map(Stored::record));
            }
            Ok(self
                .records
                .get(&(owner.to_string(), identifier.to_string()))
                .map(Stored::record))
        }
        fn register_device(
            &mut self,
            owner: &str,
            registration: &DeviceRegistration<'_>,
        ) -> Result<(), Self::Error> {
            self.calls += 1;
            let before = self.records.clone();
            self.records
                .entry((owner.to_string(), registration.identifier.to_string()))
                .or_insert_with(|| Stored {
                    owner: owner.to_string(),
                    identifier: registration.identifier.to_string(),
                    name: registration.name.to_string(),
                    kind: registration.device_type,
                    created: "2026-10-18T00:00:00.000000Z".to_string(),
                    pending: None,
                });
            if let Some(error) = self.fail {
                self.records = before;
                return Err(error);
            }
            Ok(())
        }
    }
    fn registration(identifier: &str) -> DeviceRegistration<'_> {
        DeviceRegistration {
            identifier,
            name: "initial \"device\" 雪\0",
            device_type: -7,
        }
    }

    #[test]
    fn known_device_matches_lowercased_email_without_trimming_or_identifier_normalization() {
        let mut service = VaultService::new(Mock::new());
        service
            .register_device("owner", &registration("Opaque_+/雪"))
            .unwrap();
        for email in [
            "owner@example.test",
            "OWNER@EXAMPLE.TEST",
            "İD@example.test",
        ] {
            assert!(
                service
                    .known_device(&KnownDeviceRequest {
                        email,
                        identifier: "Opaque_+/雪",
                    })
                    .unwrap()
                    .0
            );
        }
        for (email, identifier) in [
            (" owner@example.test", "Opaque_+/雪"),
            ("owner@example.test ", "Opaque_+/雪"),
            ("foreign@example.test", "Opaque_+/雪"),
            ("unknown@example.test", "Opaque_+/雪"),
            ("owner@example.test", "opaque_+/雪"),
            ("owner@example.test", ""),
            ("", "Opaque_+/雪"),
        ] {
            assert!(
                !service
                    .known_device(&KnownDeviceRequest { email, identifier })
                    .unwrap()
                    .0
            );
        }
        assert_eq!(service.storage().revision, 71);
    }

    #[test]
    fn registration_retains_initial_metadata_and_composite_owner_identity_without_account_revision()
    {
        let mut store = Mock::new();
        let mut service = VaultService::new(&mut store);
        service
            .register_device("owner", &registration("shared"))
            .unwrap();
        service
            .register_device(
                "owner",
                &DeviceRegistration {
                    identifier: "shared",
                    name: "replacement",
                    device_type: i32::MAX,
                },
            )
            .unwrap();
        service
            .register_device("foreign", &registration("shared"))
            .unwrap();
        service.register_device("owner", &registration("")).unwrap();
        let saved = service
            .storage()
            .records
            .get(&("owner".into(), "shared".into()))
            .unwrap();
        assert_eq!(saved.name, registration("shared").name);
        assert_eq!(saved.kind, -7);
        assert_eq!(saved.created, "2026-10-18T00:00:00.000000Z");
        assert_eq!(service.storage().records.len(), 3);
        assert_eq!(service.storage().revision, 71);
        assert_eq!(
            service.storage().account_authority,
            "unchanged-key-credentials-session-and-vault"
        );
    }

    #[test]
    fn authenticated_reads_keep_empty_lists_and_missing_or_foreign_identifiers_private() {
        let mut service = VaultService::new(Mock::new());
        let empty = serde_json::to_value(service.list_devices("owner").unwrap()).unwrap();
        assert_eq!(
            empty,
            serde_json::json!({"data":[],"object":"list","continuationToken":null})
        );
        service
            .register_device("foreign", &registration("foreign-only"))
            .unwrap();
        for id in ["missing", "foreign-only"] {
            assert_eq!(
                service.get_device("owner", id).unwrap_err().status_code(),
                400
            );
        }
        service
            .register_device("owner", &registration("not-a-UUID"))
            .unwrap();
        let single =
            serde_json::to_value(service.get_device("owner", "not-a-UUID").unwrap()).unwrap();
        assert_eq!(single["identifier"], "not-a-UUID");
        assert_eq!(single["name"], registration("").name);
        assert_eq!(single["type"], -7);
        assert_eq!(single.as_object().unwrap().len(), 7);
        let list = serde_json::to_value(service.list_devices("owner").unwrap()).unwrap();
        assert_eq!(list["data"].as_array().unwrap().len(), 1);
        assert_eq!(list["data"][0]["identifier"], "not-a-UUID");
        assert_eq!(service.storage().revision, 71);
    }

    #[test]
    fn unauthenticated_device_operations_do_not_call_the_provider() {
        let mut service = VaultService::new(Mock::new());
        assert_eq!(
            service
                .register_device("", &registration(""))
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(service.list_devices("").unwrap_err().status_code(), 401);
        assert_eq!(service.get_device("", "").unwrap_err().status_code(), 401);
        assert_eq!(service.storage().calls, 0);
        assert!(service.storage().records.is_empty());
    }

    #[test]
    fn incomplete_or_misowned_provider_views_never_become_device_responses() {
        let mut service = VaultService::new(Mock::new());
        service
            .register_device("foreign", &registration("foreign"))
            .unwrap();
        service.storage_mut().leak = true;
        assert_eq!(
            service.list_devices("owner").unwrap_err().status_code(),
            400
        );
        assert_eq!(
            service
                .get_device("owner", "foreign")
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(
            service
                .get_device("foreign", "different-id")
                .unwrap_err()
                .status_code(),
            400
        );
        service.storage_mut().incomplete = true;
        assert_eq!(
            service.list_devices("foreign").unwrap_err().status_code(),
            400
        );
        assert_eq!(service.storage().records.len(), 1);
        assert_eq!(service.storage().revision, 71);
    }

    #[test]
    fn provider_errors_preserve_registry_and_unrelated_authority_with_typed_mapping() {
        let mut service = VaultService::new(Mock::new());
        service
            .register_device("owner", &registration("initial"))
            .unwrap();
        let before = service.storage().records.clone();
        for error in [ErrorKind::Conflict, ErrorKind::Storage] {
            service.storage_mut().fail = Some(error);
            assert_eq!(
                service
                    .register_device("owner", &registration("new"))
                    .unwrap_err()
                    .kind,
                error
            );
            assert_eq!(
                service.get_device("owner", "initial").unwrap_err().kind,
                error
            );
            assert_eq!(service.list_devices("owner").unwrap_err().kind, error);
            assert_eq!(
                service
                    .known_device(&KnownDeviceRequest {
                        email: "owner@example.test",
                        identifier: "initial"
                    })
                    .unwrap_err()
                    .kind,
                error
            );
            assert!(service.storage().records == before);
            assert_eq!(service.storage().revision, 71);
            assert_eq!(
                service.storage().account_authority,
                "unchanged-key-credentials-session-and-vault"
            );
        }
    }

    #[test]
    fn arbitrary_size_views_preserve_pending_metadata_and_all_devices() {
        let records: Vec<_> = (0..257)
            .map(|_| DeviceRecord {
                owner_id: "owner",
                identifier: "same-exact-id",
                name: "",
                device_type: i32::MIN,
                creation_date: "opaque provider timestamp",
                pending_auth_request: Some(PendingDeviceAuthRequest {
                    id: "pending",
                    creation_date: "pending-time",
                }),
            })
            .collect();
        assert_eq!(DeviceListData::len(records.as_slice()), 257);
        assert!(!DeviceListData::is_empty(records.as_slice()));
        let value = serde_json::to_value(DeviceListResponse::new(records.as_slice())).unwrap();
        let values = value["data"].as_array().unwrap();
        assert_eq!(values.len(), 257);
        assert!(
            values
                .iter()
                .all(|device| device.as_object().unwrap().len() == 10)
        );
        assert_eq!(
            values[256]["devicePendingAuthRequest"],
            serde_json::json!({"id":"pending","creationDate":"pending-time"})
        );
        assert_eq!(values[256]["type"], i32::MIN);
        assert!(values[256]["encryptedPublicKey"].is_null());
        assert!(values[256]["encryptedUserKey"].is_null());
        assert_eq!(values[256]["isTrusted"], false);
    }
}
