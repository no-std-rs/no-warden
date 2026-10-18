//! Authentication-request creation and discovery over adapter-owned state.
//!
//! Approval, access-code verification, login, notifications and expiry are separate APIs.
//! Clocks, UUID generation, email lowercase, IP/origin and HTTP guards belong to adapters.

use crate::{
    ApiError, VaultService,
    devices::DeviceStorage,
    service::require_owner,
    wire::{AuthRequestCreateRequest, AuthRequestListResponse, AuthRequestResponse},
};

/// Trusted metadata supplied by adapter request guards and configuration, not the JSON body.
#[derive(Clone, Copy)]
pub struct AuthRequestContext<'a> {
    pub device_type: i32,
    pub request_ip: &'a str,
    pub origin: &'a str,
}
impl core::fmt::Debug for AuthRequestContext<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestContext").finish_non_exhaustive()
    }
}

/// Private provider record. Explicit wire projections omit owner, device ID and access code.
/// No Serialize implementation is provided; Debug redacts all strings and key material.
#[derive(Clone, Copy)]
pub struct AuthRequestRecord<'a> {
    pub id: &'a str,
    pub owner_id: &'a str,
    pub request_device_identifier: &'a str,
    pub device_type: i32,
    pub request_ip: &'a str,
    pub access_code: &'a str,
    pub public_key: &'a str,
    pub key: Option<&'a str>,
    pub master_password_hash: Option<&'a str>,
    pub approved: Option<bool>,
    pub creation_date: &'a str,
    pub response_date: Option<&'a str>,
}
impl core::fmt::Debug for AuthRequestRecord<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuthRequestRecord").finish_non_exhaustive()
    }
}

/// Complete and stable indexed view, without a fixed request-count limit. Every index less
/// than len must exist. Fields/counts must stay unchanged until serialization completes.
pub trait AuthRequestListData {
    fn len(&self) -> usize;
    fn get(&self, index: usize) -> Option<AuthRequestRecord<'_>>;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
impl<T: AuthRequestListData + ?Sized> AuthRequestListData for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn get(&self, index: usize) -> Option<AuthRequestRecord<'_>> {
        (**self).get(index)
    }
}
impl AuthRequestListData for [AuthRequestRecord<'_>] {
    fn len(&self) -> usize {
        <[AuthRequestRecord<'_>]>::len(self)
    }
    fn get(&self, index: usize) -> Option<AuthRequestRecord<'_>> {
        <[AuthRequestRecord<'_>]>::get(self, index).copied()
    }
}

/// Opt-in authentication requests reusing the registered-device provider boundary.
/// Hold the application's operation lock for each service operation.
///
/// Email lookup performs Unicode lowercase WITHOUT trimming, returns an owned account ID,
/// and does not require authentication. The owned representation permits later device reads
/// and writes without allocating in the core or borrowing mutable provider state twice.
/// Creation occurs only after exact registered owner/device/type checks. Generate a fresh
/// UUID and creation timestamp, copy the opaque input strings and trusted type/IP, initialize
/// approved/key/master_password_hash/response_date to None, and commit atomically. Origin is
/// response configuration, not stored client input. Failure must preserve prior requests,
/// account revisions, device metadata/activity, credentials, sessions and vault state.
///
/// Reads return only the verified owner's records; lists may include approved/rejected rows
/// because the core projection filters strictly for approved=None. No age filtering belongs
/// to these methods: the pinned source purges expired requests separately. Notifications,
/// user events, public rate limits and authenticated session/path guards are adapter duties;
/// this boundary does not implement approval, response polling or authentication-request login.
pub trait AuthRequestStorage: DeviceStorage {
    type OwnerId: AsRef<str>;
    type Requests<'a>: AuthRequestListData
    where
        Self: 'a;

    fn auth_request_owner(&mut self, email: &str) -> Result<Option<Self::OwnerId>, Self::Error>;
    fn create_auth_request(
        &mut self,
        owner: &str,
        request: &AuthRequestCreateRequest<'_>,
        context: &AuthRequestContext<'_>,
    ) -> Result<AuthRequestRecord<'_>, Self::Error>;
    fn auth_request(
        &mut self,
        owner: &str,
        id: &str,
    ) -> Result<Option<AuthRequestRecord<'_>>, Self::Error>;
    fn auth_requests(&mut self, owner: &str) -> Result<Self::Requests<'_>, Self::Error>;
}
impl<T: AuthRequestStorage + ?Sized> AuthRequestStorage for &mut T {
    type OwnerId = T::OwnerId;
    type Requests<'a>
        = T::Requests<'a>
    where
        Self: 'a;
    fn auth_request_owner(&mut self, email: &str) -> Result<Option<Self::OwnerId>, Self::Error> {
        (**self).auth_request_owner(email)
    }
    fn create_auth_request(
        &mut self,
        owner: &str,
        request: &AuthRequestCreateRequest<'_>,
        context: &AuthRequestContext<'_>,
    ) -> Result<AuthRequestRecord<'_>, Self::Error> {
        (**self).create_auth_request(owner, request, context)
    }
    fn auth_request(
        &mut self,
        owner: &str,
        id: &str,
    ) -> Result<Option<AuthRequestRecord<'_>>, Self::Error> {
        (**self).auth_request(owner, id)
    }
    fn auth_requests(&mut self, owner: &str) -> Result<Self::Requests<'_>, Self::Error> {
        (**self).auth_requests(owner)
    }
}

/// Pinned Vaultwarden DeviceType display strings. Unknown raw integers retain their stored
/// value for device verification and only fall back to this display label in responses.
pub const fn device_type_name(value: i32) -> &'static str {
    match value {
        0 | 15 => "Android",
        1 => "iOS",
        2 => "Chrome Extension",
        3 => "Firefox Extension",
        4 => "Opera Extension",
        5 => "Edge Extension",
        6 => "Windows",
        7 => "macOS",
        8 => "Linux",
        9 => "Chrome",
        10 => "Firefox",
        11 => "Opera",
        12 => "Edge",
        13 => "Internet Explorer",
        16 => "UWP",
        17 => "Safari",
        18 => "Vivaldi",
        19 => "Vivaldi Extension",
        20 => "Safari Extension",
        21 => "SDK",
        22 => "Server",
        23 => "Windows CLI",
        24 => "macOS CLI",
        25 => "Linux CLI",
        26 => "DuckDuckGo",
        _ => "Unknown Browser",
    }
}

fn unavailable() -> ApiError {
    ApiError::invalid("authRequest", "AuthRequest doesn't exist")
}
impl<S: AuthRequestStorage> VaultService<S> {
    /// Public creation over validated adapter metadata, without trimming/normalizing strings.
    pub fn create_auth_request<'a>(
        &'a mut self,
        request: &AuthRequestCreateRequest<'_>,
        context: &AuthRequestContext<'a>,
    ) -> Result<AuthRequestResponse<'a>, ApiError> {
        let owner = self
            .storage_mut()
            .auth_request_owner(request.email)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        let device = self
            .storage_mut()
            .device(owner.as_ref(), request.device_identifier)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        if device.owner_id != owner.as_ref()
            || device.identifier != request.device_identifier
            || device.device_type != context.device_type
        {
            return Err(unavailable());
        }
        let record = self
            .storage_mut()
            .create_auth_request(owner.as_ref(), request, context)
            .map_err(S::map_error)?;
        if record.owner_id != owner.as_ref()
            || record.request_device_identifier != request.device_identifier
            || record.device_type != context.device_type
        {
            return Err(unavailable());
        }
        Ok(AuthRequestResponse::created(record, context.origin))
    }

    pub fn get_auth_request<'a>(
        &'a mut self,
        owner: &str,
        id: &str,
        origin: &'a str,
    ) -> Result<AuthRequestResponse<'a>, ApiError> {
        require_owner(owner)?;
        let record = self
            .storage_mut()
            .auth_request(owner, id)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        if record.owner_id != owner || record.id != id {
            return Err(unavailable());
        }
        Ok(AuthRequestResponse::stored(record, origin))
    }

    pub fn list_auth_requests<'a>(
        &'a mut self,
        owner: &str,
        origin: &'a str,
    ) -> Result<AuthRequestListResponse<'a, S::Requests<'a>>, ApiError> {
        require_owner(owner)?;
        let records = self
            .storage_mut()
            .auth_requests(owner)
            .map_err(S::map_error)?;
        for index in 0..records.len() {
            if records
                .get(index)
                .ok_or_else(|| {
                    ApiError::invalid("authRequests", "The auth request view is incomplete.")
                })?
                .owner_id
                != owner
            {
                return Err(unavailable());
            }
        }
        Ok(AuthRequestListResponse::new(records, origin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind, Storage,
        devices::DeviceRecord,
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{
        collections::BTreeMap,
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    #[derive(Clone, Eq, PartialEq)]
    struct Stored {
        id: String,
        owner: String,
        device: String,
        kind: i32,
        ip: String,
        code: String,
        public: String,
        key: Option<String>,
        hash: Option<String>,
        approved: Option<bool>,
        created: String,
        response: Option<String>,
    }
    impl Stored {
        fn view(&self) -> AuthRequestRecord<'_> {
            AuthRequestRecord {
                id: &self.id,
                owner_id: &self.owner,
                request_device_identifier: &self.device,
                device_type: self.kind,
                request_ip: &self.ip,
                access_code: &self.code,
                public_key: &self.public,
                key: self.key.as_deref(),
                master_password_hash: self.hash.as_deref(),
                approved: self.approved,
                creation_date: &self.created,
                response_date: self.response.as_deref(),
            }
        }
    }
    struct View<'a> {
        rows: &'a [Stored],
        owner: String,
        leak: bool,
        incomplete: bool,
    }
    impl AuthRequestListData for View<'_> {
        fn len(&self) -> usize {
            self.rows
                .iter()
                .filter(|r| self.leak || r.owner == self.owner)
                .count()
        }
        fn get(&self, index: usize) -> Option<AuthRequestRecord<'_>> {
            if self.incomplete {
                return None;
            }
            self.rows
                .iter()
                .filter(|r| self.leak || r.owner == self.owner)
                .nth(index)
                .map(Stored::view)
        }
    }
    #[derive(Clone, Copy, PartialEq)]
    enum Fail {
        Owner,
        Device,
        Create,
        Get,
        List,
    }
    struct Mock {
        emails: BTreeMap<String, String>,
        devices: Vec<DeviceRecord<'static>>,
        rows: Vec<Stored>,
        calls: Vec<&'static str>,
        fail: Option<Fail>,
        error: ErrorKind,
        misdirect_device: bool,
        misdirect_get: bool,
        leak: bool,
        incomplete: bool,
        revision: u64,
        authority: &'static str,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                emails: BTreeMap::from([
                    ("alice@example.test".into(), "alice".into()),
                    ("bob@example.test".into(), "bob".into()),
                    ("i\u{307}d@example.test".into(), "alice".into()),
                ]),
                devices: vec![
                    DeviceRecord {
                        owner_id: "alice",
                        identifier: "Device",
                        name: "initial",
                        device_type: 8,
                        creation_date: "device-date",
                        pending_auth_request: None,
                    },
                    DeviceRecord {
                        owner_id: "alice",
                        identifier: "",
                        name: "empty",
                        device_type: -1,
                        creation_date: "device-date",
                        pending_auth_request: None,
                    },
                    DeviceRecord {
                        owner_id: "alice",
                        identifier: "opaque_/+雪\0",
                        name: "opaque",
                        device_type: i32::MIN,
                        creation_date: "device-date",
                        pending_auth_request: None,
                    },
                    DeviceRecord {
                        owner_id: "bob",
                        identifier: "Bob-Device",
                        name: "bob",
                        device_type: 8,
                        creation_date: "device-date",
                        pending_auth_request: None,
                    },
                ],
                rows: Vec::new(),
                calls: Vec::new(),
                fail: None,
                error: ErrorKind::Storage,
                misdirect_device: false,
                misdirect_get: false,
                leak: false,
                incomplete: false,
                revision: 71,
                authority: "unchanged-keys-credentials-sessions-vault",
            }
        }
        fn call(&mut self, name: &'static str, stage: Fail) -> Result<(), ErrorKind> {
            self.calls.push(name);
            if self.fail == Some(stage) {
                Err(self.error)
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Mock {
        type Error = ErrorKind;
        fn map_error(error: Self::Error) -> ApiError {
            ApiError::new(error, "Auth request provider failed.")
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
        type Devices<'a> = &'a [DeviceRecord<'a>];
        fn known_device(&mut self, _: &str, _: &str) -> Result<bool, Self::Error> {
            unreachable!()
        }
        fn devices(&mut self, _: &str) -> Result<Self::Devices<'_>, Self::Error> {
            unreachable!()
        }
        fn device(
            &mut self,
            owner: &str,
            id: &str,
        ) -> Result<Option<DeviceRecord<'_>>, Self::Error> {
            self.call("device", Fail::Device)?;
            Ok(if self.misdirect_device {
                self.devices.first().copied()
            } else {
                self.devices
                    .iter()
                    .find(|d| d.owner_id == owner && d.identifier == id)
                    .copied()
            })
        }
        fn register_device(
            &mut self,
            _: &str,
            _: &crate::devices::DeviceRegistration<'_>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }
    }
    impl AuthRequestStorage for Mock {
        type OwnerId = String;
        type Requests<'a> = View<'a>;
        fn auth_request_owner(
            &mut self,
            email: &str,
        ) -> Result<Option<Self::OwnerId>, Self::Error> {
            self.call("owner", Fail::Owner)?;
            Ok(self.emails.get(&email.to_lowercase()).cloned())
        }
        fn create_auth_request(
            &mut self,
            owner: &str,
            request: &AuthRequestCreateRequest<'_>,
            context: &AuthRequestContext<'_>,
        ) -> Result<AuthRequestRecord<'_>, Self::Error> {
            self.calls.push("create");
            let before = self.rows.clone();
            self.rows.push(Stored {
                id: std::format!("00000000-0000-0000-0000-{:012}", self.rows.len() + 1),
                owner: owner.to_string(),
                device: request.device_identifier.to_string(),
                kind: context.device_type,
                ip: context.request_ip.to_string(),
                code: request.access_code.to_string(),
                public: request.public_key.to_string(),
                key: None,
                hash: None,
                approved: None,
                created: "2026-10-18T00:00:00.000000Z".into(),
                response: None,
            });
            if self.fail == Some(Fail::Create) {
                self.rows = before;
                return Err(self.error);
            }
            Ok(self.rows.last().unwrap().view())
        }
        fn auth_request(
            &mut self,
            owner: &str,
            id: &str,
        ) -> Result<Option<AuthRequestRecord<'_>>, Self::Error> {
            self.call("get", Fail::Get)?;
            Ok(if self.misdirect_get {
                self.rows.first().map(Stored::view)
            } else {
                self.rows
                    .iter()
                    .find(|r| r.owner == owner && r.id == id)
                    .map(Stored::view)
            })
        }
        fn auth_requests(&mut self, owner: &str) -> Result<Self::Requests<'_>, Self::Error> {
            self.call("list", Fail::List)?;
            Ok(View {
                rows: &self.rows,
                owner: owner.to_string(),
                leak: self.leak,
                incomplete: self.incomplete,
            })
        }
    }
    fn request() -> AuthRequestCreateRequest<'static> {
        AuthRequestCreateRequest {
            access_code: "opaque-code",
            device_identifier: "Device",
            email: "ALICE@EXAMPLE.TEST",
            public_key: "future-opaque-key",
        }
    }
    fn context() -> AuthRequestContext<'static> {
        AuthRequestContext {
            device_type: 8,
            request_ip: "2001:db8::1",
            origin: "https://configured-origin.test",
        }
    }
    fn create(service: &mut VaultService<Mock>) -> String {
        serde_json::to_value(service.create_auth_request(&request(), &context()).unwrap()).unwrap()
            ["id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn creation_requires_existing_account_exact_device_and_raw_matching_type_before_insert() {
        let mut service = VaultService::new(Mock::new());
        for bad in [
            AuthRequestCreateRequest {
                email: "unknown@example.test",
                ..request()
            },
            AuthRequestCreateRequest {
                email: " alice@example.test",
                ..request()
            },
            AuthRequestCreateRequest {
                email: "alice@example.test ",
                ..request()
            },
            AuthRequestCreateRequest {
                device_identifier: "device",
                ..request()
            },
            AuthRequestCreateRequest {
                device_identifier: "Bob-Device",
                ..request()
            },
        ] {
            service.storage_mut().calls.clear();
            assert_eq!(
                service
                    .create_auth_request(&bad, &context())
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert!(!service.storage().calls.contains(&"create"));
            assert!(service.storage().rows.is_empty());
        }
        assert_eq!(
            service
                .create_auth_request(
                    &request(),
                    &AuthRequestContext {
                        device_type: 14,
                        ..context()
                    }
                )
                .unwrap_err()
                .status_code(),
            400
        );
        // Distinct raw types must not compare equal through their fallback display label.
        assert_eq!(
            service
                .create_auth_request(
                    &AuthRequestCreateRequest {
                        device_identifier: "",
                        ..request()
                    },
                    &AuthRequestContext {
                        device_type: 27,
                        ..context()
                    },
                )
                .unwrap_err()
                .status_code(),
            400
        );
        service.storage_mut().misdirect_device = true;
        for bad in [
            AuthRequestCreateRequest {
                email: "bob@example.test",
                ..request()
            },
            AuthRequestCreateRequest {
                device_identifier: "different",
                ..request()
            },
        ] {
            assert_eq!(
                service
                    .create_auth_request(&bad, &context())
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
        assert!(service.storage().rows.is_empty());
    }

    #[test]
    fn public_creation_preserves_opaque_values_pending_none_and_unrelated_state() {
        let mut store = Mock::new();
        let mut service = VaultService::new(&mut store);
        for (identifier, kind, code, key, email) in [
            ("", -1, "", "", "ALICE@EXAMPLE.TEST"),
            (
                "opaque_/+雪\0",
                i32::MIN,
                "NUL\0雪",
                "future:\"opaque\n",
                "İD@example.test",
            ),
        ] {
            let request = AuthRequestCreateRequest {
                device_identifier: identifier,
                access_code: code,
                public_key: key,
                email,
            };
            let response = serde_json::to_value(
                service
                    .create_auth_request(
                        &request,
                        &AuthRequestContext {
                            device_type: kind,
                            ..context()
                        },
                    )
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(response.as_object().unwrap().len(), 11);
            assert_eq!(response["requestApproved"], false);
            assert_eq!(response["publicKey"], key);
            assert_eq!(response["requestDeviceType"], "Unknown Browser");
            assert_eq!(response["requestIpAddress"], context().request_ip);
            assert_eq!(response["origin"], context().origin);
            let stored = service.storage().rows.last().unwrap();
            assert_eq!(stored.device, identifier);
            assert_eq!(stored.code, code);
            assert_eq!(stored.public, key);
            assert_eq!(stored.kind, kind);
            assert!(
                stored.approved.is_none()
                    && stored.key.is_none()
                    && stored.hash.is_none()
                    && stored.response.is_none()
            );
        }
        assert_eq!(service.storage().revision, 71);
        assert_eq!(
            service.storage().authority,
            "unchanged-keys-credentials-sessions-vault"
        );
        assert_eq!(service.storage().devices[0].name, "initial");
    }

    #[test]
    fn authenticated_reads_require_owner_exact_id_and_preserve_stored_option_states() {
        let mut service = VaultService::new(Mock::new());
        let id = create(&mut service);
        let pending = serde_json::to_value(
            service
                .get_auth_request("alice", &id, "configured")
                .unwrap(),
        )
        .unwrap();
        assert!(pending["requestApproved"].is_null());
        assert!(pending["key"].is_null());
        assert!(pending["masterPasswordHash"].is_null());
        for owner in ["bob", "missing"] {
            assert_eq!(
                service
                    .get_auth_request(owner, &id, "configured")
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
        assert_eq!(
            service
                .get_auth_request("alice", "missing", "configured")
                .unwrap_err()
                .status_code(),
            400
        );
        for approved in [false, true] {
            let row = &mut service.storage_mut().rows[0];
            row.approved = Some(approved);
            row.key = Some("opaque-key\0".into());
            row.hash = Some("opaque-hash".into());
            row.response = Some("response-date".into());
            let response = serde_json::to_value(
                service
                    .get_auth_request("alice", &id, "new-configured-origin")
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(response["requestApproved"], approved);
            assert_eq!(response["key"], "opaque-key\0");
            assert_eq!(response["masterPasswordHash"], "opaque-hash");
            assert_eq!(response["responseDate"], "response-date");
            assert_eq!(response["origin"], "new-configured-origin");
        }
    }

    #[test]
    fn pending_lists_filter_only_none_keep_order_and_have_no_capacity_or_age_limit() {
        let mut service = VaultService::new(Mock::new());
        let empty =
            serde_json::to_value(service.list_auth_requests("alice", "origin").unwrap()).unwrap();
        assert_eq!(
            empty,
            serde_json::json!({"data":[],"object":"list","continuationToken":null})
        );
        create(&mut service);
        let template = service.storage().rows[0].clone();
        service.storage_mut().rows = (0..257)
            .map(|index| Stored {
                id: std::format!("request-{index}"),
                approved: match index % 3 {
                    0 => None,
                    1 => Some(false),
                    _ => Some(true),
                },
                created: "1900-01-01T00:00:00.000000Z".into(),
                ..template.clone()
            })
            .collect();
        let value =
            serde_json::to_value(service.list_auth_requests("alice", "origin").unwrap()).unwrap();
        let pending = value["data"].as_array().unwrap();
        assert_eq!(pending.len(), 86);
        for (index, record) in pending.iter().enumerate() {
            assert_eq!(record["id"], std::format!("request-{}", index * 3));
            assert!(record["requestApproved"].is_null());
            assert_eq!(record.as_object().unwrap().len(), 11);
        }
        assert_eq!(service.storage().rows.len(), 257);
        assert_eq!(service.storage().revision, 71);
    }

    #[test]
    fn unauthenticated_reads_and_misowned_or_incomplete_views_do_not_expose_records() {
        let mut service = VaultService::new(Mock::new());
        assert_eq!(
            service
                .get_auth_request("", "id", "origin")
                .unwrap_err()
                .status_code(),
            401
        );
        assert_eq!(
            service
                .list_auth_requests("", "origin")
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(service.storage().calls.is_empty());
        let id = create(&mut service);
        service.storage_mut().misdirect_get = true;
        for (owner, id) in [("bob", id.as_str()), ("alice", "different")] {
            assert_eq!(
                service
                    .get_auth_request(owner, id, "origin")
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
        service.storage_mut().leak = true;
        assert_eq!(
            service
                .list_auth_requests("bob", "origin")
                .unwrap_err()
                .status_code(),
            400
        );
        service.storage_mut().incomplete = true;
        assert_eq!(
            service
                .list_auth_requests("alice", "origin")
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(service.storage().rows.len(), 1);
    }

    #[test]
    fn provider_failures_preserve_state_and_shared_typed_error_mapping() {
        let mut service = VaultService::new(Mock::new());
        let id = create(&mut service);
        let before = service.storage().rows.clone();
        for error in [ErrorKind::Conflict, ErrorKind::Storage] {
            service.storage_mut().error = error;
            for stage in [Fail::Owner, Fail::Device, Fail::Create] {
                service.storage_mut().fail = Some(stage);
                assert_eq!(
                    service
                        .create_auth_request(&request(), &context())
                        .unwrap_err()
                        .kind,
                    error
                );
                assert!(service.storage().rows == before);
            }
            service.storage_mut().fail = Some(Fail::Get);
            assert_eq!(
                service
                    .get_auth_request("alice", &id, "origin")
                    .unwrap_err()
                    .kind,
                error
            );
            service.storage_mut().fail = Some(Fail::List);
            assert_eq!(
                service
                    .list_auth_requests("alice", "origin")
                    .unwrap_err()
                    .kind,
                error
            );
            assert!(service.storage().rows == before);
            assert_eq!(service.storage().revision, 71);
            assert_eq!(
                service.storage().authority,
                "unchanged-keys-credentials-sessions-vault"
            );
        }
    }

    #[test]
    fn device_type_display_names_cover_all_pinned_values_and_unknown_integers() {
        let expected = [
            "Android",
            "iOS",
            "Chrome Extension",
            "Firefox Extension",
            "Opera Extension",
            "Edge Extension",
            "Windows",
            "macOS",
            "Linux",
            "Chrome",
            "Firefox",
            "Opera",
            "Edge",
            "Internet Explorer",
            "Unknown Browser",
            "Android",
            "UWP",
            "Safari",
            "Vivaldi",
            "Vivaldi Extension",
            "Safari Extension",
            "SDK",
            "Server",
            "Windows CLI",
            "macOS CLI",
            "Linux CLI",
            "DuckDuckGo",
        ];
        for (value, name) in expected.iter().enumerate() {
            assert_eq!(device_type_name(value as i32), *name);
        }
        for value in [-1, i32::MIN, 27, i32::MAX] {
            assert_eq!(device_type_name(value), "Unknown Browser");
        }
    }
}
