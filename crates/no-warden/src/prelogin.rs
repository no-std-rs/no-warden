//! Public, allocation-free KDF discovery over a caller-provided lookup and selection policy.

use crate::{
    ApiError, Storage, VaultService,
    wire::{CompletePreloginResponse, PreloginKdfSettings, PreloginRequest},
};

/// Ordered unknown-account catalog. The two default entries deliberately retain their
/// distinct positions so provider-selected indices have the intended distribution.
pub const UNKNOWN_KDF_CATALOG: [PreloginKdfSettings; 6] = [
    PreloginKdfSettings {
        iterations: 600_000,
        kdf_type: 0,
        memory: None,
        parallelism: None,
    },
    PreloginKdfSettings {
        iterations: 600_000,
        kdf_type: 0,
        memory: None,
        parallelism: None,
    },
    PreloginKdfSettings {
        iterations: 100_000,
        kdf_type: 0,
        memory: None,
        parallelism: None,
    },
    PreloginKdfSettings {
        iterations: 5_000,
        kdf_type: 0,
        memory: None,
        parallelism: None,
    },
    PreloginKdfSettings {
        iterations: 3,
        kdf_type: 1,
        memory: Some(64),
        parallelism: Some(4),
    },
    PreloginKdfSettings {
        iterations: 6,
        kdf_type: 1,
        memory: Some(32),
        parallelism: Some(4),
    },
];

/// A checked provider-selected index, preventing an invalid catalog lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownKdfIndex(u8);

impl UnknownKdfIndex {
    pub const fn new(index: usize) -> Option<Self> {
        if index < UNKNOWN_KDF_CATALOG.len() {
            Some(Self(index as u8))
        } else {
            None
        }
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Trusted lookup result. Account existence is never included in the wire response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreloginLookup {
    Known(PreloginKdfSettings),
    Unknown(UnknownKdfIndex),
}

/// Opt-in prelogin lookup without HTTP, normalization, cryptography or a core clock.
///
/// Receive the exact decoded email, including empty strings and whitespace. Normalize it
/// once using Unicode trimming and lowercase, then use that same normalized value for
/// account lookup and, when absent, cryptographic catalog selection. Apply configured
/// request policy/rate limits before either lookup or unknown selection. The caller owns
/// those policies and the persisted secret/cryptographic selection implementation; no
/// request email should enter diagnostics. Preserve stored signed numeric settings as
/// given, including unknown KDF types and optional values, without registration validation.
///
/// Return an unknown index only when the account is absent; do not disguise backend errors
/// as an unknown account. Unknown selection must be stable for the same normalized email
/// and persistent secret across calls/restarts. Different secrets can select different
/// catalog entries. This operation must not mutate account/vault state, revisions,
/// credentials, sessions or devices. Secret initialization belongs outside this operation.
pub trait PreloginStorage: Storage {
    fn prelogin(&mut self, raw_email: &str) -> Result<PreloginLookup, Self::Error>;
}

impl<T: PreloginStorage + ?Sized> PreloginStorage for &mut T {
    fn prelogin(&mut self, raw_email: &str) -> Result<PreloginLookup, Self::Error> {
        (**self).prelogin(raw_email)
    }
}

impl<S: PreloginStorage> VaultService<S> {
    /// Discover KDF metadata without authentication or validation of opaque email content.
    pub fn prelogin(
        &mut self,
        request: &PreloginRequest<'_>,
    ) -> Result<CompletePreloginResponse, ApiError> {
        let settings = match self
            .storage_mut()
            .prelogin(request.email)
            .map_err(S::map_error)?
        {
            PreloginLookup::Known(settings) => settings,
            PreloginLookup::Unknown(index) => UNKNOWN_KDF_CATALOG[index.index()],
        };
        Ok(CompletePreloginResponse::from_settings(settings))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind,
        service::ItemMetadata,
        wire::{CipherRequest, FolderRequest, PreloginResponse, RegisterRequest},
    };
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Failure {
        Policy,
        Backend,
    }

    struct Provider {
        known: PreloginKdfSettings,
        index: UnknownKdfIndex,
        failure: Option<Failure>,
        calls: usize,
        selections: usize,
        last_raw: std::string::String,
        pointer: Option<*const u8>,
        unrelated: [u64; 4],
    }

    impl Provider {
        fn new(index: usize) -> Self {
            Self {
                known: PreloginKdfSettings {
                    iterations: i32::MIN,
                    kdf_type: -7,
                    memory: Some(-8),
                    parallelism: Some(i32::MAX),
                },
                index: UnknownKdfIndex::new(index).unwrap(),
                failure: None,
                calls: 0,
                selections: 0,
                last_raw: std::string::String::new(),
                pointer: None,
                unrelated: [3, 7, 11, 13],
            }
        }
    }

    impl Storage for Provider {
        type Error = Failure;
        fn map_error(error: Failure) -> ApiError {
            match error {
                Failure::Policy => ApiError::new(
                    ErrorKind::Forbidden,
                    "Discovery policy rejected the request",
                ),
                Failure::Backend => ApiError::new(ErrorKind::Storage, "Discovery backend failed"),
            }
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

    impl PreloginStorage for Provider {
        fn prelogin(&mut self, raw_email: &str) -> Result<PreloginLookup, Failure> {
            self.calls += 1;
            self.last_raw = raw_email.into();
            self.pointer = Some(raw_email.as_ptr());
            if let Some(error) = self.failure {
                return Err(error);
            }
            // A test provider supplies normalization; production selection needs its
            // own cryptographic implementation rather than this fixed test index.
            let normalized = raw_email.trim().to_lowercase();
            if normalized == "known@example.test" {
                Ok(PreloginLookup::Known(self.known))
            } else {
                self.selections += 1;
                Ok(PreloginLookup::Unknown(self.index))
            }
        }
    }

    #[test]
    fn prelogin_known_signed_settings_are_echoed_without_registration_validation() {
        let mut provider = Provider::new(0);
        let expected = provider.known;
        let state = provider.unrelated;
        let response = VaultService::new(&mut provider)
            .prelogin(&PreloginRequest {
                email: "known@example.test",
            })
            .unwrap();
        assert_eq!(response.settings(), expected);
        assert_eq!(provider.calls, 1);
        assert_eq!(provider.selections, 0);
        assert_eq!(provider.unrelated, state);
    }

    #[test]
    fn prelogin_raw_empty_unicode_and_control_email_reaches_the_provider_unchanged() {
        for email in ["", "\0雪\n", "\u{2002}KNOWN@EXAMPLE.TEST\u{a0}"] {
            let mut provider = Provider::new(4);
            let request = PreloginRequest { email };
            let response = VaultService::new(&mut provider).prelogin(&request).unwrap();
            assert_eq!(provider.last_raw, email);
            assert_eq!(provider.pointer, Some(email.as_ptr()));
            assert_eq!(provider.calls, 1);
            assert_eq!(
                response.settings(),
                if email.contains("KNOWN") {
                    provider.known
                } else {
                    UNKNOWN_KDF_CATALOG[4]
                }
            );
        }
    }

    #[test]
    fn prelogin_unknown_indices_are_bounded_and_keep_all_six_weighted_slots() {
        assert!(UnknownKdfIndex::new(6).is_none());
        assert!(UnknownKdfIndex::new(usize::MAX).is_none());
        let expected = [
            (0, 600_000, None, None),
            (0, 600_000, None, None),
            (0, 100_000, None, None),
            (0, 5_000, None, None),
            (1, 3, Some(64), Some(4)),
            (1, 6, Some(32), Some(4)),
        ];
        for (index, tuple) in expected.into_iter().enumerate() {
            assert_eq!(UnknownKdfIndex::new(index).unwrap().index(), index);
            let mut provider = Provider::new(index);
            let response = VaultService::new(&mut provider)
                .prelogin(&PreloginRequest { email: "unknown" })
                .unwrap();
            let settings = response.settings();
            assert_eq!(
                (
                    settings.kdf_type,
                    settings.iterations,
                    settings.memory,
                    settings.parallelism
                ),
                tuple
            );
            assert_eq!(provider.selections, 1);
            assert_eq!(provider.unrelated, [3, 7, 11, 13]);
        }
    }

    #[test]
    fn prelogin_complete_response_has_exact_legacy_nested_and_null_salt_fields() {
        for outcome in ["known@example.test", "unknown"] {
            let mut provider = Provider::new(5);
            let response = VaultService::new(&mut provider)
                .prelogin(&PreloginRequest { email: outcome })
                .unwrap();
            let settings = response.settings();
            let value = serde_json::to_value(response).unwrap();
            assert_eq!(
                value,
                json!({
                    "kdf":settings.kdf_type,"kdfIterations":settings.iterations,
                    "kdfMemory":settings.memory,"kdfParallelism":settings.parallelism,
                    "kdfSettings":{"iterations":settings.iterations,"kdfType":settings.kdf_type,"memory":settings.memory,"parallelism":settings.parallelism},
                    "salt":null
                })
            );
            assert_eq!(value.as_object().unwrap().len(), 6);
            assert_eq!(value["kdfSettings"].as_object().unwrap().len(), 4);
        }
    }

    #[test]
    fn prelogin_policy_and_backend_errors_are_not_disguised_as_unknown_accounts() {
        for (failure, kind) in [
            (Failure::Policy, ErrorKind::Forbidden),
            (Failure::Backend, ErrorKind::Storage),
        ] {
            let mut provider = Provider::new(4);
            provider.failure = Some(failure);
            let before = provider.unrelated;
            let error = VaultService::new(&mut provider)
                .prelogin(&PreloginRequest { email: "unknown" })
                .unwrap_err();
            assert_eq!(error.kind, kind);
            assert_eq!(provider.calls, 1);
            assert_eq!(provider.selections, 0);
            assert_eq!(provider.unrelated, before);
            assert!(!error.message.contains("unknown"));
        }
    }

    #[test]
    fn prelogin_nested_borrowed_provider_forwarding_keeps_selection_provider_owned() {
        let mut provider = Provider::new(3);
        let mut borrowed = &mut provider;
        let response = VaultService::new(&mut borrowed)
            .prelogin(&PreloginRequest { email: "unknown" })
            .unwrap();
        assert_eq!(response.settings(), UNKNOWN_KDF_CATALOG[3]);
        assert_eq!(provider.calls, 1);
        assert_eq!(provider.selections, 1);
    }

    #[test]
    fn prelogin_required_borrowed_email_keeps_canonical_schema_and_opaque_contents() {
        let input = br#"{"email":"opaque"}"#;
        let request: PreloginRequest<'_> = serde_json::from_slice(input).unwrap();
        assert_eq!(request.email, "opaque");
        assert!(request.email.as_ptr() >= input.as_ptr());
        assert!(request.email.as_ptr() < input.as_ptr().wrapping_add(input.len()));
        for input in [br#"{"email":""}"#.as_slice(), br#"[""]"#] {
            assert_eq!(
                serde_json::from_slice::<PreloginRequest<'_>>(input)
                    .unwrap()
                    .email,
                ""
            );
        }
        for input in [
            br#"{}"#.as_slice(),
            br#"[]"#,
            br#"{"Email":"wrong-case"}"#,
            br#"{"email":null}"#,
            br#"{"email":1}"#,
            br#"{"email":"a","email":"b"}"#,
        ] {
            assert!(serde_json::from_slice::<PreloginRequest<'_>>(input).is_err());
        }
        let value = json!({"email":"\0雪\n"});
        assert_eq!(
            PreloginRequest::deserialize(&value).unwrap().email,
            "\0雪\n"
        );
    }

    #[test]
    fn prelogin_legacy_unsigned_four_field_response_remains_available() {
        assert_eq!(
            serde_json::to_value(PreloginResponse::default()).unwrap(),
            json!({"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null})
        );
    }
}
