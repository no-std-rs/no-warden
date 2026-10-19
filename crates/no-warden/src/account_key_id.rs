//! A one-time user-key identifier migration over an atomic provider operation.
//!
//! Identifiers are opaque strings. This module imposes no content or length policy;
//! transports and caller-owned storage are responsible for their own resource limits.

use crate::{
    ApiError, ErrorKind, Storage, VaultService, service::require_owner, wire::UserKeyIdRequest,
};

/// An opaque identifier accepted for the authenticated account's one-time migration.
/// Only the service can construct this plan; it does not authorize a different account.
#[derive(Clone, Copy)]
pub struct ValidatedUserKeyId<'a> {
    user_key_id: &'a str,
}

impl<'a> ValidatedUserKeyId<'a> {
    pub const fn user_key_id(&self) -> &'a str {
        self.user_key_id
    }
}

impl core::fmt::Debug for ValidatedUserKeyId<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ValidatedUserKeyId([REDACTED])")
    }
}

/// Opt-in persistence for the user-key-ID migration without changing existing providers.
///
/// `owner` must identify the authenticated account. Atomically compare its current
/// identifier and set it only when absent. Any existing value, including `Some("")`,
/// returns `Ok(false)` without changing state. A successful write preserves the exact
/// string, advances only this account's revision, and returns `Ok(true)`.
///
/// Preserve all other account fields, credentials, keys, sessions, devices, settings,
/// vault payloads and unrelated accounts. Missing accounts and storage or policy failures
/// are provider errors mapped by `Storage::map_error`; they must leave state unchanged.
/// Make the comparison, write and revision update one transaction or equivalent atomic
/// operation. A separate `Storage::user_key_id` pre-read cannot replace this requirement.
/// This conditional atomic write is stronger than upstream's separate check and save.
/// Providers implementing that read hook must return the newly persisted identifier.
/// Keep the authenticated account context across the service call; the plan contains no
/// client-selected account identifier. Do not log either the plan or backend diagnostics.
pub trait AccountKeyIdStorage: Storage {
    fn set_user_key_id_if_absent(
        &mut self,
        owner: &str,
        update: &ValidatedUserKeyId<'_>,
    ) -> Result<bool, Self::Error>;
}

impl<T: AccountKeyIdStorage + ?Sized> AccountKeyIdStorage for &mut T {
    fn set_user_key_id_if_absent(
        &mut self,
        owner: &str,
        update: &ValidatedUserKeyId<'_>,
    ) -> Result<bool, Self::Error> {
        (**self).set_user_key_id_if_absent(owner, update)
    }
}

impl<S: AccountKeyIdStorage> VaultService<S> {
    /// Atomically backfill the authenticated account's missing opaque user-key identifier.
    pub fn set_user_key_id(
        &mut self,
        owner: &str,
        request: &UserKeyIdRequest<'_>,
    ) -> Result<(), ApiError> {
        require_owner(owner)?;
        let update = ValidatedUserKeyId {
            user_key_id: request.user_key_id,
        };
        if self
            .storage_mut()
            .set_user_key_id_if_absent(owner, &update)
            .map_err(S::map_error)?
        {
            Ok(())
        } else {
            Err(ApiError::new(
                ErrorKind::UnprocessableEntity,
                "Unexpected data",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, RegisterRequest},
    };
    use serde::Deserialize;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Failure {
        MissingOwner,
        Capacity,
        Backend,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct State<const N: usize> {
        bytes: [[u8; N]; 2],
        lengths: [Option<usize>; 2],
        revisions: [u64; 2],
        unrelated: [[u8; 8]; 2],
    }

    struct Bounded<const N: usize> {
        state: State<N>,
        calls: usize,
        fail: bool,
        request_pointer: Option<*const u8>,
    }

    impl<const N: usize> Bounded<N> {
        fn new() -> Self {
            Self {
                state: State {
                    bytes: [[0; N]; 2],
                    lengths: [None; 2],
                    revisions: [7, 19],
                    unrelated: [*b"ownerkey", *b"otherkey"],
                },
                calls: 0,
                fail: false,
                request_pointer: None,
            }
        }

        fn index(owner: &str) -> Result<usize, Failure> {
            match owner {
                "owner" => Ok(0),
                "foreign" => Ok(1),
                _ => Err(Failure::MissingOwner),
            }
        }

        fn value(&self, index: usize) -> Option<&str> {
            self.state.lengths[index]
                .map(|length| core::str::from_utf8(&self.state.bytes[index][..length]).unwrap())
        }
    }

    impl<const N: usize> Storage for Bounded<N> {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::MissingOwner => ApiError::new(ErrorKind::Unauthorized, "Unknown account"),
                Failure::Capacity => ApiError::new(ErrorKind::Storage, "Caller buffer is full"),
                Failure::Backend => {
                    ApiError::new(ErrorKind::Conflict, "Provider transaction failed")
                }
            }
        }
        fn user_key_id(&mut self, owner: &str) -> Result<Option<&str>, Failure> {
            Ok(self.value(Self::index(owner)?))
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

    impl<const N: usize> AccountKeyIdStorage for Bounded<N> {
        fn set_user_key_id_if_absent(
            &mut self,
            owner: &str,
            update: &ValidatedUserKeyId<'_>,
        ) -> Result<bool, Failure> {
            self.calls += 1;
            self.request_pointer = Some(update.user_key_id().as_ptr());
            let index = Self::index(owner)?;
            if self.state.lengths[index].is_some() {
                return Ok(false);
            }
            if self.fail {
                return Err(Failure::Backend);
            }
            let input = update.user_key_id().as_bytes();
            if input.len() > N {
                return Err(Failure::Capacity);
            }
            let mut next = self.state.clone();
            next.bytes[index][..input.len()].copy_from_slice(input);
            next.lengths[index] = Some(input.len());
            next.revisions[index] += 1;
            self.state = next;
            Ok(true)
        }
    }

    #[test]
    fn user_key_id_authentication_precedes_the_provider() {
        let mut provider = Bounded::<8>::new();
        let state = provider.state.clone();
        let error = VaultService::new(&mut provider)
            .set_user_key_id("", &UserKeyIdRequest { user_key_id: "id" })
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unauthorized);
        assert_eq!(provider.calls, 0);
        assert_eq!(provider.state, state);
    }

    #[test]
    fn user_key_id_empty_value_is_present_and_cannot_be_overwritten() {
        let mut provider = Bounded::<8>::new();
        VaultService::new(&mut provider)
            .set_user_key_id("owner", &UserKeyIdRequest { user_key_id: "" })
            .unwrap();
        assert_eq!(provider.user_key_id("owner").unwrap(), Some(""));
        let state = provider.state.clone();
        for next in ["", "new-id"] {
            let error = VaultService::new(&mut provider)
                .set_user_key_id("owner", &UserKeyIdRequest { user_key_id: next })
                .unwrap_err();
            assert_eq!(error.status_code(), 422);
            assert_eq!(error.message, "Unexpected data");
            assert_eq!(provider.state, state);
        }
    }

    #[test]
    fn user_key_id_long_unicode_and_control_data_stay_borrowed_and_exact() {
        let opaque = std::string::String::from("future:\0\n雪") + &"☃".repeat(4096);
        let mut provider = Bounded::<16384>::new();
        let request = UserKeyIdRequest {
            user_key_id: &opaque,
        };
        VaultService::new(&mut provider)
            .set_user_key_id("owner", &request)
            .unwrap();
        assert_eq!(provider.value(0), Some(opaque.as_str()));
        assert_eq!(provider.request_pointer, Some(opaque.as_ptr()));
        assert_eq!(provider.state.revisions, [8, 19]);
        assert_eq!(provider.state.unrelated, [*b"ownerkey", *b"otherkey"]);
        assert_eq!(provider.state.lengths[1], None);
    }

    #[test]
    fn user_key_id_existing_value_rejects_same_or_different_input_without_mutation() {
        let mut provider = Bounded::<32>::new();
        VaultService::new(&mut provider)
            .set_user_key_id(
                "owner",
                &UserKeyIdRequest {
                    user_key_id: "original",
                },
            )
            .unwrap();
        let state = provider.state.clone();
        for value in ["original", "replacement"] {
            let error = VaultService::new(&mut provider)
                .set_user_key_id("owner", &UserKeyIdRequest { user_key_id: value })
                .unwrap_err();
            assert_eq!(error.kind, ErrorKind::UnprocessableEntity);
            assert_eq!(provider.state, state);
        }
    }

    #[test]
    fn user_key_id_atomic_provider_errors_keep_typed_mapping_and_state() {
        let mut provider = Bounded::<8>::new();
        provider.fail = true;
        let state = provider.state.clone();
        let error = VaultService::new(&mut provider)
            .set_user_key_id("owner", &UserKeyIdRequest { user_key_id: "id" })
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Conflict);
        assert_eq!(error.message, "Provider transaction failed");
        assert_eq!(provider.state, state);
        provider.fail = false;
        VaultService::new(&mut provider)
            .set_user_key_id("owner", &UserKeyIdRequest { user_key_id: "id" })
            .unwrap();
    }

    #[test]
    fn user_key_id_provider_capacity_is_caller_policy_and_failure_is_atomic() {
        let mut provider = Bounded::<2>::new();
        let state = provider.state.clone();
        let error = VaultService::new(&mut provider)
            .set_user_key_id("owner", &UserKeyIdRequest { user_key_id: "雪" })
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Storage);
        assert_eq!(provider.state, state);
        let mut larger = Bounded::<3>::new();
        VaultService::new(&mut larger)
            .set_user_key_id("owner", &UserKeyIdRequest { user_key_id: "雪" })
            .unwrap();
        assert_eq!(larger.value(0), Some("雪"));
    }

    #[test]
    fn user_key_id_nested_borrowed_provider_forwarding_preserves_owner_isolation() {
        let mut provider = Bounded::<32>::new();
        let mut borrowed = &mut provider;
        VaultService::new(&mut borrowed)
            .set_user_key_id(
                "foreign",
                &UserKeyIdRequest {
                    user_key_id: "foreign-id",
                },
            )
            .unwrap();
        assert_eq!(provider.value(0), None);
        assert_eq!(provider.value(1), Some("foreign-id"));
        assert_eq!(provider.state.revisions, [7, 20]);
        let state = provider.state.clone();
        let error = VaultService::new(&mut provider)
            .set_user_key_id("missing", &UserKeyIdRequest { user_key_id: "id" })
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Unauthorized);
        assert_eq!(provider.state, state);
    }

    #[test]
    fn user_key_id_wire_schema_serialization_and_debug_keep_opaque_contract() {
        let input = br#"{"userKeyId":"opaque-id"}"#;
        let request = serde_json::from_slice::<UserKeyIdRequest<'_>>(input).unwrap();
        assert!(request.user_key_id.as_ptr() >= input.as_ptr());
        assert!(request.user_key_id.as_ptr() < input.as_ptr().wrapping_add(input.len()));
        assert_eq!(serde_json::to_vec(&request).unwrap(), input);
        for input in [br#"{"userKeyId":""}"#.as_slice(), br#"[""]"#] {
            assert_eq!(
                serde_json::from_slice::<UserKeyIdRequest<'_>>(input)
                    .unwrap()
                    .user_key_id,
                ""
            );
        }
        for input in [
            br#"{}"#.as_slice(),
            br#"[]"#,
            br#"{"userKeyId":null}"#,
            br#"{"userKeyId":7}"#,
        ] {
            assert!(serde_json::from_slice::<UserKeyIdRequest<'_>>(input).is_err());
        }
        let value = serde_json::json!({"userKeyId":"escaped\0雪\n"});
        let decoded = UserKeyIdRequest::deserialize(&value).unwrap();
        assert_eq!(decoded.user_key_id, "escaped\0雪\n");
        let plan = ValidatedUserKeyId {
            user_key_id: "private-test-value",
        };
        assert_eq!(std::format!("{plan:?}"), "ValidatedUserKeyId([REDACTED])");
        assert_eq!(std::format!("{decoded:?}"), "UserKeyIdRequest([REDACTED])");
    }
}
