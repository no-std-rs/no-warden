//! Device push-token ordering over opt-in persistence and relay providers.
//!
//! HTTP/path guards, public rate limits, relay configuration, clocks and network I/O belong
//! to adapters. Token updates target the verified session device, not the request path ID.

use crate::{
    ApiError, Storage, VaultService, service::require_owner, wire::DevicePushTokenRequest,
};

/// Internal lookup state; it deliberately does not implement Serialize or expose Debug data.
#[derive(Clone, Copy)]
pub struct DevicePushState<'a> {
    pub owner_id: &'a str,
    pub identifier: &'a str,
    pub push_token: Option<&'a str>,
}
impl core::fmt::Debug for DevicePushState<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DevicePushState").finish_non_exhaustive()
    }
}

/// Result of clearing all matching owner/device rows. The first provider-ordered push ID
/// is owned so a later mutable relay callback needs no allocation or borrowed-store alias.
/// Providers choose the handle representation, for example a bounded stack-owned string.
pub enum ClearedDevicePush<P> {
    Missing,
    Cleared { first_push_id: Option<P> },
}
impl<P> core::fmt::Debug for ClearedDevicePush<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Missing => f.write_str("ClearedDevicePush::Missing"),
            Self::Cleared { .. } => f
                .debug_struct("ClearedDevicePush::Cleared")
                .finish_non_exhaustive(),
        }
    }
}

/// Opt-in device persistence and push relay boundary, using Storage::map_error.
/// Hold the application's operation lock across each service call.
///
/// Lookup and token save use the verified (owner, session identifier), never a request path
/// identifier. Session identifiers can be empty or otherwise opaque. Saving atomically
/// persists the exact token and updates device activity, without changing account revision,
/// initial device metadata, sessions, vault records or foreign state. Save errors roll back.
/// The subsequent register callback owns push-enabled/device-type policy, UUID generation,
/// clocks and relay I/O. A registration error intentionally leaves the saved token/activity
/// in place; a repeated identical token skips both save and registration, including retries.
///
/// push_enabled is a pure configuration query without persistence/network access. Disabled
/// public clear calls must not read or mutate the registry or invoke relay callbacks. Enabled
/// clear_device_push_tokens selects the first existing device in provider order, clears tokens
/// for ALL owners with that exact identifier, and returns its owned optional push ID. Missing
/// rows return Missing. Clear errors preserve prior state; successful clears change no device
/// activity, account revisions, push IDs, credentials, sessions or vault state. Unregister is
/// called only for the first Some push ID, after clearing; its failure retains cleared tokens.
/// These ordered local/relay effects are deliberately not a whole-operation transaction.
///
/// The adapter must apply the unauthenticated clear endpoint's rate limit and path guard
/// before calling the core. A disabled reference adapter is not evidence of enabled relay
/// interoperability. Authentication requests, notifications and broader push policy remain
/// separate responsibilities.
pub trait DevicePushStorage: Storage {
    type PushId: AsRef<str>;

    fn push_enabled(&self) -> bool;
    fn device_push_state(
        &mut self,
        owner: &str,
        session_identifier: &str,
    ) -> Result<Option<DevicePushState<'_>>, Self::Error>;
    fn save_device_push_token(
        &mut self,
        owner: &str,
        session_identifier: &str,
        request: &DevicePushTokenRequest<'_>,
    ) -> Result<(), Self::Error>;
    fn register_device_push(
        &mut self,
        owner: &str,
        session_identifier: &str,
    ) -> Result<(), Self::Error>;
    fn clear_device_push_tokens(
        &mut self,
        identifier: &str,
    ) -> Result<ClearedDevicePush<Self::PushId>, Self::Error>;
    fn unregister_device_push(&mut self, push_id: &str) -> Result<(), Self::Error>;
}
impl<T: DevicePushStorage + ?Sized> DevicePushStorage for &mut T {
    type PushId = T::PushId;
    fn push_enabled(&self) -> bool {
        (**self).push_enabled()
    }
    fn device_push_state(
        &mut self,
        owner: &str,
        session_identifier: &str,
    ) -> Result<Option<DevicePushState<'_>>, Self::Error> {
        (**self).device_push_state(owner, session_identifier)
    }
    fn save_device_push_token(
        &mut self,
        owner: &str,
        session_identifier: &str,
        request: &DevicePushTokenRequest<'_>,
    ) -> Result<(), Self::Error> {
        (**self).save_device_push_token(owner, session_identifier, request)
    }
    fn register_device_push(
        &mut self,
        owner: &str,
        session_identifier: &str,
    ) -> Result<(), Self::Error> {
        (**self).register_device_push(owner, session_identifier)
    }
    fn clear_device_push_tokens(
        &mut self,
        identifier: &str,
    ) -> Result<ClearedDevicePush<Self::PushId>, Self::Error> {
        (**self).clear_device_push_tokens(identifier)
    }
    fn unregister_device_push(&mut self, push_id: &str) -> Result<(), Self::Error> {
        (**self).unregister_device_push(push_id)
    }
}

impl<S: DevicePushStorage> VaultService<S> {
    /// The caller supplies verified owner/session device IDs. The syntactically guarded
    /// request-path ID is intentionally absent from this API because it is not the target.
    pub fn set_device_push_token(
        &mut self,
        owner: &str,
        session_identifier: &str,
        request: &DevicePushTokenRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let state = self
            .storage_mut()
            .device_push_state(owner, session_identifier)
            .map_err(S::map_error)?
            .ok_or_else(|| ApiError::invalid("device", "No device found"))?;
        if state.owner_id != owner || state.identifier != session_identifier {
            return Err(ApiError::invalid("device", "No device found"));
        }
        if state.push_token == Some(request.push_token) {
            return Ok(());
        }
        self.storage_mut()
            .save_device_push_token(owner, session_identifier, request)
            .map_err(S::map_error)?;
        self.storage_mut()
            .register_device_push(owner, session_identifier)
            .map_err(S::map_error)
    }

    /// Public, with adapter-owned rate limiting and path validation. No owner is required.
    pub fn clear_device_push_token(&mut self, identifier: &str) -> Result<(), ApiError> {
        if !self.storage().push_enabled() {
            return Ok(());
        }
        if let ClearedDevicePush::Cleared {
            first_push_id: Some(push_id),
        } = self
            .storage_mut()
            .clear_device_push_tokens(identifier)
            .map_err(S::map_error)?
        {
            self.storage_mut()
                .unregister_device_push(push_id.as_ref())
                .map_err(S::map_error)?;
        }
        Ok(())
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
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    #[derive(Clone, Eq, PartialEq)]
    struct Row {
        owner: &'static str,
        id: &'static str,
        token: Option<String>,
        push_id: Option<&'static str>,
        activity: u64,
        name: &'static str,
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fail {
        Lookup,
        Save,
        Register,
        Clear,
        Unregister,
    }
    struct Mock {
        enabled: bool,
        rows: Vec<Row>,
        calls: Vec<&'static str>,
        fail: Option<Fail>,
        error: ErrorKind,
        misdirect: bool,
        unregistered: Vec<String>,
        revision: u64,
        authority: &'static str,
    }
    impl Mock {
        fn new(enabled: bool) -> Self {
            Self {
                enabled,
                rows: vec![
                    Row {
                        owner: "owner",
                        id: "session",
                        token: Some("old".into()),
                        push_id: Some("first-push"),
                        activity: 7,
                        name: "initial",
                    },
                    Row {
                        owner: "foreign",
                        id: "session",
                        token: Some("foreign".into()),
                        push_id: Some("second-push"),
                        activity: 8,
                        name: "foreign",
                    },
                    Row {
                        owner: "owner",
                        id: "unrelated",
                        token: Some("unrelated-token".into()),
                        push_id: Some("other-push"),
                        activity: 9,
                        name: "other",
                    },
                    Row {
                        owner: "owner",
                        id: "",
                        token: None,
                        push_id: None,
                        activity: 0,
                        name: "empty-id",
                    },
                ],
                calls: Vec::new(),
                fail: None,
                error: ErrorKind::Storage,
                misdirect: false,
                unregistered: Vec::new(),
                revision: 71,
                authority: "unchanged-keys-sessions-vault",
            }
        }
        fn failure(&self, stage: Fail) -> Result<(), ErrorKind> {
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
            ApiError::new(error, "Push provider failed.")
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
    impl DevicePushStorage for Mock {
        type PushId = String;
        fn push_enabled(&self) -> bool {
            self.enabled
        }
        fn device_push_state(
            &mut self,
            owner: &str,
            id: &str,
        ) -> Result<Option<DevicePushState<'_>>, Self::Error> {
            self.calls.push("lookup");
            self.failure(Fail::Lookup)?;
            let row = if self.misdirect {
                self.rows.first()
            } else {
                self.rows.iter().find(|r| r.owner == owner && r.id == id)
            };
            Ok(row.map(|row| DevicePushState {
                owner_id: row.owner,
                identifier: row.id,
                push_token: row.token.as_deref(),
            }))
        }
        fn save_device_push_token(
            &mut self,
            owner: &str,
            id: &str,
            request: &DevicePushTokenRequest<'_>,
        ) -> Result<(), Self::Error> {
            self.calls.push("save");
            let before = self.rows.clone();
            let row = self
                .rows
                .iter_mut()
                .find(|r| r.owner == owner && r.id == id)
                .ok_or(ErrorKind::Storage)?;
            row.token = Some(request.push_token.to_string());
            row.activity += 1;
            if let Err(error) = self.failure(Fail::Save) {
                self.rows = before;
                return Err(error);
            }
            Ok(())
        }
        fn register_device_push(&mut self, _: &str, _: &str) -> Result<(), Self::Error> {
            self.calls.push("register");
            self.failure(Fail::Register)
        }
        fn clear_device_push_tokens(
            &mut self,
            id: &str,
        ) -> Result<ClearedDevicePush<Self::PushId>, Self::Error> {
            self.calls.push("clear");
            let before = self.rows.clone();
            let Some(first) = self.rows.iter().find(|r| r.id == id) else {
                self.failure(Fail::Clear)?;
                return Ok(ClearedDevicePush::Missing);
            };
            let push_id = first.push_id.map(ToString::to_string);
            for row in self.rows.iter_mut().filter(|r| r.id == id) {
                row.token = None;
            }
            if let Err(error) = self.failure(Fail::Clear) {
                self.rows = before;
                return Err(error);
            }
            Ok(ClearedDevicePush::Cleared {
                first_push_id: push_id,
            })
        }
        fn unregister_device_push(&mut self, id: &str) -> Result<(), Self::Error> {
            self.calls.push("unregister");
            self.unregistered.push(id.to_string());
            self.failure(Fail::Unregister)
        }
    }
    fn request(token: &str) -> DevicePushTokenRequest<'_> {
        DevicePushTokenRequest { push_token: token }
    }

    #[test]
    fn authenticated_session_targets_allow_empty_identifiers_without_provider_access_for_missing_owner()
     {
        let mut store = Mock::new(false);
        let mut service = VaultService::new(&mut store);
        assert_eq!(
            service
                .set_device_push_token("", "session", &request("new"))
                .unwrap_err()
                .status_code(),
            401
        );
        assert!(service.storage().calls.is_empty());
        service
            .set_device_push_token("owner", "", &request("opaque:_/雪\0"))
            .unwrap();
        assert_eq!(
            service.storage().rows[3].token.as_deref(),
            Some("opaque:_/雪\0")
        );
        assert_eq!(service.storage().calls, ["lookup", "save", "register"]);
        assert_eq!(service.storage().revision, 71);
    }

    #[test]
    fn missing_foreign_or_misdirected_provider_records_never_reach_save_or_relay() {
        let mut service = VaultService::new(Mock::new(true));
        for (owner, id) in [("owner", "missing"), ("not-owner", "session")] {
            service.storage_mut().calls.clear();
            assert_eq!(
                service
                    .set_device_push_token(owner, id, &request("new"))
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(service.storage().calls, ["lookup"]);
        }
        service.storage_mut().misdirect = true;
        for (owner, id) in [("foreign", "session"), ("owner", "unrelated")] {
            service.storage_mut().calls.clear();
            assert_eq!(
                service
                    .set_device_push_token(owner, id, &request("new"))
                    .unwrap_err()
                    .status_code(),
                400
            );
            assert_eq!(service.storage().calls, ["lookup"]);
        }
        assert_eq!(service.storage().rows[0].token.as_deref(), Some("old"));
    }

    #[test]
    fn identical_tokens_skip_save_and_registration_while_none_and_empty_are_distinct() {
        let mut service = VaultService::new(Mock::new(false));
        service
            .set_device_push_token("owner", "session", &request("old"))
            .unwrap();
        assert_eq!(service.storage().calls, ["lookup"]);
        assert_eq!(service.storage().rows[0].activity, 7);
        service.storage_mut().calls.clear();
        service
            .set_device_push_token("owner", "", &request(""))
            .unwrap();
        assert_eq!(service.storage().calls, ["lookup", "save", "register"]);
        assert_eq!(service.storage().rows[3].token.as_deref(), Some(""));
        service.storage_mut().calls.clear();
        service
            .set_device_push_token("owner", "", &request(""))
            .unwrap();
        assert_eq!(service.storage().calls, ["lookup"]);
        assert_eq!(service.storage().rows[3].activity, 1);
    }

    #[test]
    fn registration_errors_retain_saved_tokens_and_identical_retry_does_not_register_again() {
        let mut service = VaultService::new(Mock::new(true));
        let before = service.storage().rows.clone();
        service.storage_mut().fail = Some(Fail::Register);
        service.storage_mut().error = ErrorKind::Conflict;
        assert_eq!(
            service
                .set_device_push_token("owner", "session", &request("changed"))
                .unwrap_err()
                .kind,
            ErrorKind::Conflict
        );
        assert_eq!(service.storage().calls, ["lookup", "save", "register"]);
        assert_eq!(service.storage().rows[0].token.as_deref(), Some("changed"));
        assert_eq!(service.storage().rows[0].activity, 8);
        assert!(service.storage().rows[1..] == before[1..]);
        assert_eq!(service.storage().rows[0].name, before[0].name);
        service.storage_mut().calls.clear();
        service
            .set_device_push_token("owner", "session", &request("changed"))
            .unwrap();
        assert_eq!(service.storage().calls, ["lookup"]);
        assert_eq!(service.storage().revision, 71);
        assert_eq!(service.storage().authority, "unchanged-keys-sessions-vault");
    }

    #[test]
    fn lookup_and_save_errors_stop_before_relay_and_preserve_existing_state() {
        let mut service = VaultService::new(Mock::new(true));
        let before = service.storage().rows.clone();
        for (fail, expected) in [
            (Fail::Lookup, &["lookup"][..]),
            (Fail::Save, &["lookup", "save"][..]),
        ] {
            service.storage_mut().fail = Some(fail);
            service.storage_mut().calls.clear();
            assert_eq!(
                service
                    .set_device_push_token("owner", "session", &request("changed"))
                    .unwrap_err()
                    .status_code(),
                500
            );
            assert_eq!(service.storage().calls, expected);
            assert!(service.storage().rows == before);
            assert_eq!(service.storage().revision, 71);
        }
    }

    #[test]
    fn public_disabled_clear_skips_storage_and_enabled_clear_targets_all_owners_then_first_push_id()
    {
        let mut service = VaultService::new(Mock::new(false));
        let before = service.storage().rows.clone();
        service.clear_device_push_token("session").unwrap();
        service.clear_device_push_token("missing").unwrap();
        assert!(service.storage().calls.is_empty());
        assert!(service.storage().rows == before);
        service.storage_mut().enabled = true;
        service.clear_device_push_token("session").unwrap();
        assert_eq!(service.storage().calls, ["clear", "unregister"]);
        assert_eq!(service.storage().unregistered, ["first-push"]);
        for row in &service.storage().rows[..2] {
            assert!(row.token.is_none());
        }
        assert!(service.storage().rows[2..] == before[2..]);
        for (row, old) in service.storage().rows.iter().zip(&before) {
            assert_eq!(row.activity, old.activity);
            assert_eq!(row.push_id, old.push_id);
        }
        service.storage_mut().calls.clear();
        service.clear_device_push_token("missing").unwrap();
        service.clear_device_push_token("").unwrap();
        assert_eq!(service.storage().calls, ["clear", "clear"]);
        assert_eq!(service.storage().unregistered.len(), 1);
        assert_eq!(service.storage().revision, 71);

        // The first matching device's absent push ID must not select another owner's ID.
        service.storage_mut().rows[0].push_id = None;
        service.storage_mut().rows[0].token = Some("first-reset".into());
        service.storage_mut().rows[1].token = Some("second-reset".into());
        service.storage_mut().calls.clear();
        service.clear_device_push_token("session").unwrap();
        assert_eq!(service.storage().calls, ["clear"]);
        assert_eq!(service.storage().unregistered.len(), 1);
        assert!(
            service.storage().rows[..2]
                .iter()
                .all(|row| row.token.is_none())
        );
    }

    #[test]
    fn clear_storage_errors_rollback_but_unregister_errors_leave_all_matching_tokens_cleared() {
        let mut service = VaultService::new(Mock::new(true));
        let before = service.storage().rows.clone();
        service.storage_mut().fail = Some(Fail::Clear);
        assert_eq!(
            service
                .clear_device_push_token("session")
                .unwrap_err()
                .status_code(),
            500
        );
        assert_eq!(service.storage().calls, ["clear"]);
        assert!(service.storage().rows == before);
        service.storage_mut().calls.clear();
        service.storage_mut().fail = Some(Fail::Unregister);
        assert_eq!(
            service
                .clear_device_push_token("session")
                .unwrap_err()
                .status_code(),
            500
        );
        assert_eq!(service.storage().calls, ["clear", "unregister"]);
        assert!(
            service.storage().rows[..2]
                .iter()
                .all(|r| r.token.is_none())
        );
        assert!(service.storage().rows[2..] == before[2..]);
        assert_eq!(service.storage().revision, 71);
        assert_eq!(service.storage().authority, "unchanged-keys-sessions-vault");
        let debug = std::format!(
            "{:?} {:?}",
            DevicePushState {
                owner_id: "hidden-owner",
                identifier: "hidden-id",
                push_token: Some("hidden-token")
            },
            ClearedDevicePush::Cleared {
                first_push_id: Some("hidden-push-id")
            }
        );
        assert!(!debug.contains("hidden"));
    }
}
