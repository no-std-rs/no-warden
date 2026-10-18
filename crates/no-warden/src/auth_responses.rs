//! Authentication-request decisions and public code-protected response reads.
//!
//! Providers own constant-time code verification, clocks and atomic persistence. Verified
//! session identity, UUID/query guards, IP/proxy policy, notifications and expiry belong
//! to adapters. These operations neither grant a login nor consume a request for login.

use crate::{
    ApiError, VaultService,
    auth_requests::{AuthRequestContext, AuthRequestRecord, AuthRequestStorage},
    identity::Secret,
    service::require_owner,
    wire::{AuthRequestResponse, AuthRequestUpdateRequest},
};

/// Opt-in decisions and code-verified reads, reusing the request discovery boundary.
/// Hold the application's authenticated operation lock across each service call.
///
/// respond_auth_request atomically rechecks exact ownership and approved=None before any
/// mutation. Approval saves Some(true), Some(request.key), the exact optional hash, the
/// response device identifier and a fresh response timestamp. Rejection deletes the row
/// and returns an owned-cache snapshot preserving its prior approval/key/hash values, with
/// a fresh response_date even though no row remains. The snapshot must live in provider
/// storage; no post-commit database read is required. Errors roll back all decision/delete
/// effects. Preserve account revisions, device metadata/activity, credentials, sessions,
/// vaults, foreign requests and other fields. UUIDs and creation dates are unchanged.
///
/// auth_request_by_code must verify the exact opaque code with a constant-time provider.
/// Missing records and wrong codes both return None without exposing verification details.
/// Do not trim, normalize or serialize the supplied Secret. Return a stable borrowed record
/// only after code verification. Pending and approved records can be read repeatedly; no
/// approval prerequisite, login consumption, age filter or expiry mutation belongs here.
///
/// The adapter supplies verified owner/session device IDs, trusted client type/IP/origin,
/// guards path/query inputs and applies public rate policy. Approval notifications, user
/// events, response polling transport, expiry cleanup and authentication-request login are
/// separate capabilities; implementing this trait does not establish their compatibility.
pub trait AuthRequestResponseStorage: AuthRequestStorage {
    fn respond_auth_request(
        &mut self,
        owner: &str,
        id: &str,
        request: &AuthRequestUpdateRequest<'_>,
    ) -> Result<AuthRequestRecord<'_>, Self::Error>;

    fn auth_request_by_code(
        &mut self,
        id: &str,
        code: &Secret<'_>,
    ) -> Result<Option<AuthRequestRecord<'_>>, Self::Error>;
}

impl<T: AuthRequestResponseStorage + ?Sized> AuthRequestResponseStorage for &mut T {
    fn respond_auth_request(
        &mut self,
        owner: &str,
        id: &str,
        request: &AuthRequestUpdateRequest<'_>,
    ) -> Result<AuthRequestRecord<'_>, Self::Error> {
        (**self).respond_auth_request(owner, id, request)
    }
    fn auth_request_by_code(
        &mut self,
        id: &str,
        code: &Secret<'_>,
    ) -> Result<Option<AuthRequestRecord<'_>>, Self::Error> {
        (**self).auth_request_by_code(id, code)
    }
}

fn unavailable() -> ApiError {
    ApiError::invalid("authRequest", "AuthRequest doesn't exist")
}

impl<S: AuthRequestResponseStorage> VaultService<S> {
    /// Respond using the verified session device, which need not be the requesting device.
    /// Empty and other opaque session identifiers are valid when verified by the adapter.
    pub fn respond_auth_request<'a>(
        &'a mut self,
        owner: &str,
        id: &str,
        verified_response_device_identifier: &str,
        request: &AuthRequestUpdateRequest<'_>,
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
        if request.device_identifier != verified_response_device_identifier {
            return Err(unavailable());
        }
        if record.approved.is_some() {
            return Err(ApiError::invalid(
                "authRequest",
                "An authentication request with the same device already exists",
            ));
        }
        let response = self
            .storage_mut()
            .respond_auth_request(owner, id, request)
            .map_err(S::map_error)?;
        if response.owner_id != owner || response.id != id {
            return Err(unavailable());
        }
        Ok(AuthRequestResponse::stored(response, origin))
    }

    /// Public read after provider code verification. Type/IP compare exactly, without
    /// display-name mapping or address normalization. The request is not consumed.
    pub fn get_auth_request_response<'a>(
        &'a mut self,
        id: &str,
        code: &Secret<'_>,
        context: &AuthRequestContext<'a>,
    ) -> Result<AuthRequestResponse<'a>, ApiError> {
        let record = self
            .storage_mut()
            .auth_request_by_code(id, code)
            .map_err(S::map_error)?
            .ok_or_else(unavailable)?;
        if record.id != id
            || record.device_type != context.device_type
            || record.request_ip != context.request_ip
        {
            return Err(unavailable());
        }
        Ok(AuthRequestResponse::stored(record, context.origin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind, Storage,
        devices::{DeviceRecord, DeviceRegistration, DeviceStorage},
        service::ItemMetadata,
        wire::{AuthRequestCreateRequest, CipherRequest, FolderRequest, RegisterRequest},
    };
    use std::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    #[derive(Clone, Eq, PartialEq)]
    struct Row {
        id: &'static str,
        owner: &'static str,
        requesting_device: &'static str,
        kind: i32,
        ip: &'static str,
        code: &'static str,
        key: Option<String>,
        hash: Option<String>,
        approved: Option<bool>,
        response_date: Option<String>,
        response_device: Option<String>,
    }
    impl Row {
        fn view(&self) -> AuthRequestRecord<'_> {
            AuthRequestRecord {
                id: self.id,
                owner_id: self.owner,
                request_device_identifier: self.requesting_device,
                device_type: self.kind,
                request_ip: self.ip,
                access_code: self.code,
                public_key: "original-public-key",
                key: self.key.as_deref(),
                master_password_hash: self.hash.as_deref(),
                approved: self.approved,
                creation_date: "1900-01-01T00:00:00.000000Z",
                response_date: self.response_date.as_deref(),
            }
        }
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fail {
        Get,
        Respond,
        Code,
    }
    struct Mock {
        rows: Vec<Row>,
        snapshot: Option<Row>,
        calls: Vec<&'static str>,
        fail: Option<Fail>,
        error: ErrorKind,
        misdirect_read: bool,
        misdirect_code: bool,
        last_code: String,
        revision: u64,
        authority: &'static str,
    }
    impl Mock {
        fn new() -> Self {
            Self {
                rows: vec![Row {
                    id: "request",
                    owner: "alice",
                    requesting_device: "Requester",
                    kind: 25,
                    ip: "192.0.2.1",
                    code: "opaque+code \0雪",
                    key: None,
                    hash: None,
                    approved: None,
                    response_date: None,
                    response_device: None,
                }],
                snapshot: None,
                calls: Vec::new(),
                fail: None,
                error: ErrorKind::Storage,
                misdirect_read: false,
                misdirect_code: false,
                last_code: String::new(),
                revision: 71,
                authority: "unchanged-devices-credentials-sessions-vault",
            }
        }
        fn call(&mut self, name: &'static str, fail: Fail) -> Result<(), ErrorKind> {
            self.calls.push(name);
            if self.fail == Some(fail) {
                Err(self.error)
            } else {
                Ok(())
            }
        }
    }
    impl Storage for Mock {
        type Error = ErrorKind;
        fn map_error(error: Self::Error) -> ApiError {
            ApiError::new(error, "Auth response provider failed.")
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
        fn device(&mut self, _: &str, _: &str) -> Result<Option<DeviceRecord<'_>>, Self::Error> {
            unreachable!()
        }
        fn register_device(
            &mut self,
            _: &str,
            _: &DeviceRegistration<'_>,
        ) -> Result<(), Self::Error> {
            unreachable!()
        }
    }
    impl AuthRequestStorage for Mock {
        type OwnerId = &'static str;
        type Requests<'a> = &'a [AuthRequestRecord<'a>];
        fn auth_request_owner(&mut self, _: &str) -> Result<Option<Self::OwnerId>, Self::Error> {
            unreachable!()
        }
        fn create_auth_request(
            &mut self,
            _: &str,
            _: &AuthRequestCreateRequest<'_>,
            _: &AuthRequestContext<'_>,
        ) -> Result<AuthRequestRecord<'_>, Self::Error> {
            unreachable!()
        }
        fn auth_request(
            &mut self,
            owner: &str,
            id: &str,
        ) -> Result<Option<AuthRequestRecord<'_>>, Self::Error> {
            self.call("get", Fail::Get)?;
            Ok(if self.misdirect_read {
                self.rows.first().map(Row::view)
            } else {
                self.rows
                    .iter()
                    .find(|r| r.owner == owner && r.id == id)
                    .map(Row::view)
            })
        }
        fn auth_requests(&mut self, _: &str) -> Result<Self::Requests<'_>, Self::Error> {
            unreachable!()
        }
    }
    impl AuthRequestResponseStorage for Mock {
        fn respond_auth_request(
            &mut self,
            owner: &str,
            id: &str,
            request: &AuthRequestUpdateRequest<'_>,
        ) -> Result<AuthRequestRecord<'_>, Self::Error> {
            self.calls.push("respond");
            let before = self.rows.clone();
            let old_snapshot = self.snapshot.clone();
            let index = self
                .rows
                .iter()
                .position(|r| r.owner == owner && r.id == id)
                .ok_or(ErrorKind::InvalidRequest)?;
            if self.rows[index].approved.is_some() {
                return Err(ErrorKind::InvalidRequest);
            }
            let mut snapshot = self.rows[index].clone();
            snapshot.response_date = Some("2026-10-18T00:00:00.000000Z".into());
            if request.request_approved {
                snapshot.approved = Some(true);
                snapshot.key = Some(request.key.to_string());
                snapshot.hash = request.master_password_hash.map(ToString::to_string);
                snapshot.response_device = Some(request.device_identifier.to_string());
                self.rows[index] = snapshot.clone();
            } else {
                self.rows.remove(index);
            }
            if self.fail == Some(Fail::Respond) {
                self.rows = before;
                self.snapshot = old_snapshot;
                return Err(self.error);
            }
            self.snapshot = Some(snapshot);
            Ok(self.snapshot.as_ref().unwrap().view())
        }
        fn auth_request_by_code(
            &mut self,
            id: &str,
            code: &Secret<'_>,
        ) -> Result<Option<AuthRequestRecord<'_>>, Self::Error> {
            self.call("code", Fail::Code)?;
            self.last_code = code.expose_secret().to_string();
            // Test double only; real providers must use a constant-time verifier.
            let row = if self.misdirect_code {
                self.rows.first()
            } else {
                self.rows.iter().find(|r| r.id == id)
            };
            Ok(row
                .filter(|row| row.code == code.expose_secret())
                .map(Row::view))
        }
    }
    fn request(approved: bool) -> AuthRequestUpdateRequest<'static> {
        AuthRequestUpdateRequest {
            device_identifier: "Responder",
            key: "wrapped-new-key",
            master_password_hash: Some("wrapped-new-hash"),
            request_approved: approved,
        }
    }
    fn context() -> AuthRequestContext<'static> {
        AuthRequestContext {
            device_type: 25,
            request_ip: "192.0.2.1",
            origin: "https://configured.test",
        }
    }
    fn code() -> Secret<'static> {
        Secret::new("opaque+code \0雪")
    }

    #[test]
    fn unauthenticated_foreign_or_mismatched_session_decisions_never_mutate() {
        let mut service = VaultService::new(Mock::new());
        let before = service.storage().rows.clone();
        assert_eq!(
            service
                .respond_auth_request("", "request", "Responder", &request(true), "origin")
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(service.storage().calls.is_empty());
        for (owner, id, session) in [
            ("bob", "request", "Responder"),
            ("alice", "missing", "Responder"),
            ("alice", "request", "Requester"),
        ] {
            service.storage_mut().calls.clear();
            assert_eq!(
                service
                    .respond_auth_request(owner, id, session, &request(true), "origin")
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(service.storage().calls, ["get"]);
            assert!(service.storage().rows == before);
        }
    }

    #[test]
    fn already_decided_rows_are_rejected_before_the_provider_mutation() {
        let mut service = VaultService::new(Mock::new());
        for approved in [false, true] {
            service.storage_mut().rows[0].approved = Some(approved);
            service.storage_mut().calls.clear();
            assert_eq!(
                service
                    .respond_auth_request(
                        "alice",
                        "request",
                        "Responder",
                        &request(false),
                        "origin"
                    )
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(service.storage().calls, ["get"]);
            assert_eq!(service.storage().rows[0].approved, Some(approved));
        }
    }

    #[test]
    fn approval_saves_exact_opaque_key_and_hash_and_allows_distinct_or_empty_response_devices() {
        let mut store = Mock::new();
        let mut service = VaultService::new(&mut store);
        service.storage_mut().rows[0].hash = Some("prior-hash".into());
        let input = AuthRequestUpdateRequest {
            device_identifier: "",
            key: "",
            master_password_hash: None,
            request_approved: true,
        };
        let response = serde_json::to_value(
            service
                .respond_auth_request("alice", "request", "", &input, "configured-origin")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response.as_object().unwrap().len(), 11);
        assert_eq!(response["requestApproved"], true);
        assert_eq!(response["key"], "");
        assert!(response["masterPasswordHash"].is_null());
        assert_eq!(response["responseDate"], "2026-10-18T00:00:00.000000Z");
        assert_eq!(response["origin"], "configured-origin");
        let polled = serde_json::to_value(
            service
                .get_auth_request_response(
                    "request",
                    &code(),
                    &AuthRequestContext {
                        origin: "configured-origin",
                        ..context()
                    },
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(polled, response);
        assert_eq!(
            service.storage().rows[0].response_device.as_deref(),
            Some("")
        );
        assert_eq!(service.storage().rows[0].requesting_device, "Requester");
        assert_eq!(service.storage().revision, 71);
        assert_eq!(
            service.storage().authority,
            "unchanged-devices-credentials-sessions-vault"
        );
        let mut service = VaultService::new(Mock::new());
        let input = AuthRequestUpdateRequest {
            key: "future:\"opaque\0雪",
            master_password_hash: Some("\0wrapped-hash雪"),
            ..request(true)
        };
        let value = serde_json::to_value(
            service
                .respond_auth_request("alice", "request", "Responder", &input, "origin")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["key"], input.key);
        assert_eq!(
            value["masterPasswordHash"],
            input.master_password_hash.unwrap()
        );
        assert_eq!(value["publicKey"], "original-public-key");
        assert_eq!(
            service.storage().rows[0].response_device.as_deref(),
            Some("Responder")
        );
    }

    #[test]
    fn rejection_deletes_but_returns_prior_pending_fields_with_fresh_response_date() {
        let mut service = VaultService::new(Mock::new());
        service.storage_mut().rows[0].key = Some("prior-pending-key".into());
        service.storage_mut().rows[0].hash = Some("prior-pending-hash".into());
        let value = serde_json::to_value(
            service
                .respond_auth_request("alice", "request", "Responder", &request(false), "origin")
                .unwrap(),
        )
        .unwrap();
        assert!(service.storage().rows.is_empty());
        assert!(value["requestApproved"].is_null());
        assert_eq!(value["key"], "prior-pending-key");
        assert_eq!(value["masterPasswordHash"], "prior-pending-hash");
        assert_eq!(value["responseDate"], "2026-10-18T00:00:00.000000Z");
        assert_eq!(value["publicKey"], "original-public-key");
        assert_eq!(
            service
                .get_auth_request_response("request", &code(), &context())
                .unwrap_err()
                .status_code(),
            400
        );
        assert_eq!(service.storage().revision, 71);
    }

    #[test]
    fn public_polling_requires_exact_code_id_raw_type_and_ip_without_consuming_any_state() {
        let mut service = VaultService::new(Mock::new());
        let before = service.storage().rows.clone();
        let missing = service
            .get_auth_request_response("missing", &code(), &context())
            .unwrap_err();
        for wrong in [
            "",
            "opaque code \0雪",
            "opaque+code \0雪 ",
            "OPAQUE+code \0雪",
        ] {
            assert_eq!(
                service
                    .get_auth_request_response("request", &Secret::new(wrong), &context())
                    .unwrap_err(),
                missing
            );
        }
        for context in [
            AuthRequestContext {
                device_type: 24,
                ..context()
            },
            AuthRequestContext {
                request_ip: "192.0.2.2",
                ..context()
            },
        ] {
            assert_eq!(
                service
                    .get_auth_request_response("request", &code(), &context)
                    .unwrap_err(),
                missing
            );
        }
        for approved in [None, Some(false), Some(true)] {
            service.storage_mut().rows[0].approved = approved;
            for _ in 0..2 {
                let value = serde_json::to_value(
                    service
                        .get_auth_request_response("request", &code(), &context())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    value["requestApproved"],
                    serde_json::to_value(approved).unwrap()
                );
                assert_eq!(value["id"], "request");
                assert_eq!(service.storage().last_code, code().expose_secret());
            }
        }
        service.storage_mut().rows[0].approved = None;
        assert!(service.storage().rows == before);
        assert_eq!(service.storage().revision, 71);
        assert_eq!(
            service.storage().authority,
            "unchanged-devices-credentials-sessions-vault"
        );
        service.storage_mut().rows[0].kind = 0;
        assert_eq!(
            service
                .get_auth_request_response(
                    "request",
                    &code(),
                    &AuthRequestContext {
                        device_type: 15,
                        ..context()
                    }
                )
                .unwrap_err(),
            missing
        );
    }

    #[test]
    fn provider_failures_preserve_true_and_false_decisions_with_shared_error_mapping() {
        for approved in [false, true] {
            let mut service = VaultService::new(Mock::new());
            let before = service.storage().rows.clone();
            for error in [ErrorKind::Conflict, ErrorKind::Storage] {
                service.storage_mut().error = error;
                for stage in [Fail::Get, Fail::Respond] {
                    service.storage_mut().fail = Some(stage);
                    assert_eq!(
                        service
                            .respond_auth_request(
                                "alice",
                                "request",
                                "Responder",
                                &request(approved),
                                "origin"
                            )
                            .unwrap_err()
                            .kind,
                        error
                    );
                    assert!(service.storage().rows == before);
                }
                service.storage_mut().fail = Some(Fail::Code);
                assert_eq!(
                    service
                        .get_auth_request_response("request", &code(), &context())
                        .unwrap_err()
                        .kind,
                    error
                );
                assert!(service.storage().rows == before);
                assert_eq!(service.storage().revision, 71);
            }
        }
    }

    #[test]
    fn misdirected_provider_records_are_rejected_before_private_projections_or_writes() {
        let mut service = VaultService::new(Mock::new());
        service.storage_mut().misdirect_read = true;
        for (owner, id) in [("bob", "request"), ("alice", "different")] {
            assert_eq!(
                service
                    .respond_auth_request(owner, id, "Responder", &request(true), "origin")
                    .unwrap_err()
                    .status_code(),
                400
            );
        }
        assert!(!service.storage().calls.contains(&"respond"));
        assert!(service.storage().rows[0].approved.is_none());
        service.storage_mut().misdirect_code = true;
        assert_eq!(
            service
                .get_auth_request_response("different", &code(), &context())
                .unwrap_err()
                .status_code(),
            400
        );
    }
}
