//! Ordinary email-token registration, with transport normalization and crypto in adapters.
//!
//! This opt-in API preserves opaque upstream key/hash strings and signed KDF fields. The
//! existing RegisterRequest, Storage::insert_account and strict embedding policy are unchanged.
//! Full flattened/untagged JSON parsing, SMTP/invite flows, JWTs, clocks and hashing remain
//! outside this allocation-free module.

use crate::{
    ApiError, Storage, VaultService,
    error::ErrorResponse,
    identity::Secret,
    wire::{
        AccountKeys, RegistrationCredentials, RegistrationFinishRequest,
        RegistrationFinishResponse, RegistrationKdf, RegistrationVerificationRequest,
        RegistrationVerificationToken,
    },
};

/// Nested-format mismatch is 422, distinct from ordinary request/provider API errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationError {
    InvalidFormat,
    Api(ApiError),
}
impl RegistrationError {
    pub const fn status_code(self) -> u16 {
        match self {
            Self::InvalidFormat => 422,
            Self::Api(error) => error.status_code(),
        }
    }
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidFormat => "Unexpected RegisterData format",
            Self::Api(error) => error.message,
        }
    }
    pub const fn response(self) -> ErrorResponse {
        ErrorResponse {
            object: "error",
            message: self.message(),
        }
    }
}
impl From<ApiError> for RegistrationError {
    fn from(error: ApiError) -> Self {
        Self::Api(error)
    }
}
impl core::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}
impl core::error::Error for RegistrationError {}

/// Trusted adapter-owned Unicode normalization, computed from the exact request email.
/// storage_email = raw_email.to_lowercase(); salt_email = raw_email.trim().to_lowercase().
/// No ASCII-only email validator or new email-size/format policy is applied by this API.
#[derive(Clone, Copy)]
pub struct RegistrationEmail<'a> {
    pub storage_email: &'a str,
    pub salt_email: &'a str,
}
impl core::fmt::Debug for RegistrationEmail<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistrationEmail").finish_non_exhaustive()
    }
}

/// Provider-owned, already signature/issuer/time-verified claims. The associated concrete
/// handle can own Strings or caller-bounded buffers; no allocator or Debug bound is imposed.
pub trait RegistrationClaims {
    fn subject(&self) -> &str;
    fn name(&self) -> Option<&str>;
    fn verified(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationState {
    pub registration_allowed: bool,
    pub has_password: bool,
    pub password_hints_allowed: bool,
    /// Adapter validation of storage_email using its upstream-compatible email/domain
    /// parser. Evaluated after proof/policy/KDF validation, immediately before commit.
    pub email_valid: bool,
}

/// Private validated commit plan. Name is only the verified claim's optional name; None
/// means a new account defaults to its storage email, or an eligible placeholder retains
/// its existing name. Keys=None similarly preserves any eligible placeholder key pair.
pub struct ValidatedRegistration<'a> {
    email: &'a str,
    name: Option<&'a str>,
    hash: &'a Secret<'a>,
    key: &'a Secret<'a>,
    keys: Option<&'a AccountKeys<'a>>,
    hint: Option<&'a str>,
    kdf: RegistrationKdf,
    email_verified: bool,
}
impl core::fmt::Debug for ValidatedRegistration<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValidatedRegistration")
            .finish_non_exhaustive()
    }
}
impl<'a> ValidatedRegistration<'a> {
    pub const fn email(&self) -> &'a str {
        self.email
    }
    pub const fn name(&self) -> Option<&'a str> {
        self.name
    }
    pub const fn master_password_hash(&self) -> &Secret<'_> {
        self.hash
    }
    pub const fn key(&self) -> &Secret<'_> {
        self.key
    }
    pub const fn keys(&self) -> Option<&AccountKeys<'_>> {
        self.keys
    }
    pub const fn master_password_hint(&self) -> Option<&'a str> {
        self.hint
    }
    pub const fn kdf(&self) -> RegistrationKdf {
        self.kdf
    }
    pub const fn email_verified(&self) -> bool {
        self.email_verified
    }
}

/// Opt-in ordinary, no-SMTP registration sharing the adapter's storage error mapper.
/// Hold the application's operation lock across each service call.
///
/// Verification policy implements signup restrictions plus the no-SMTP invitation exception
/// without consuming an invitation. Issuance returns an owned token handle; preserve the raw
/// request email/name in signed register-verification claims, verified=false in this flow,
/// with the provider's canonical origin|register_verify issuer and 30-minute lifetime.
/// Token clocks, signature/RNG, validation/leeway and persistence of signing material belong
/// to the provider. Existing accounts, malformed email strings and long names are not an
/// extra core verification-step rejection. SMTP delivery is a separate capability.
///
/// verify_registration_token verifies signature, issuer and time before returning owned
/// claims; invalid/missing proof returns None. No claims/token may enter diagnostics. State
/// combines the current normalized account's password-presence, signup/invitation allowance,
/// hint policy and upstream-compatible email validity without mutation. Email validation is
/// adapter-owned (including domain URL checks), not the existing strict ASCII embedding
/// validator. The opaque client hash is not a plaintext password.
///
/// finish_registration atomically rechecks signup eligibility and absence of an initialized
/// password, inserts/initializes the normalized account, securely hashes the client proof,
/// persists exact opaque key/keypair values and normalized KDF metadata, cleans its hint,
/// applies only the optional claim name and sets verified time only when requested. Own UUID,
/// clock, password-verifier preparation, initial account defaults and any supported invitation
/// effects in the provider. A failure must preserve all prior account/invitation state; this
/// stronger rollback guarantee does not claim the pinned upstream's earlier side effects.
/// Never overwrite an initialized account or persist unknown finish-document fields as
/// authoritative state. No existing strict Storage implementer has to implement this trait.
pub trait RegistrationStorage: Storage {
    type Token: AsRef<str>;
    type Claims: RegistrationClaims;

    fn registration_verification_allowed(&mut self, email: &str) -> Result<bool, Self::Error>;
    fn issue_registration_token(
        &mut self,
        request: &RegistrationVerificationRequest<'_>,
    ) -> Result<Self::Token, Self::Error>;
    fn verify_registration_token(
        &mut self,
        token: &Secret<'_>,
    ) -> Result<Option<Self::Claims>, Self::Error>;
    fn registration_state(&mut self, storage_email: &str)
    -> Result<RegistrationState, Self::Error>;
    fn finish_registration(&mut self, plan: &ValidatedRegistration<'_>) -> Result<(), Self::Error>;
}
impl<T: RegistrationStorage + ?Sized> RegistrationStorage for &mut T {
    type Token = T::Token;
    type Claims = T::Claims;
    fn registration_verification_allowed(&mut self, email: &str) -> Result<bool, Self::Error> {
        (**self).registration_verification_allowed(email)
    }
    fn issue_registration_token(
        &mut self,
        request: &RegistrationVerificationRequest<'_>,
    ) -> Result<Self::Token, Self::Error> {
        (**self).issue_registration_token(request)
    }
    fn verify_registration_token(
        &mut self,
        token: &Secret<'_>,
    ) -> Result<Option<Self::Claims>, Self::Error> {
        (**self).verify_registration_token(token)
    }
    fn registration_state(
        &mut self,
        storage_email: &str,
    ) -> Result<RegistrationState, Self::Error> {
        (**self).registration_state(storage_email)
    }
    fn finish_registration(&mut self, plan: &ValidatedRegistration<'_>) -> Result<(), Self::Error> {
        (**self).finish_registration(plan)
    }
}

fn denied() -> ApiError {
    ApiError::invalid(
        "registration",
        "Registration not allowed or user already exists",
    )
}

fn validated_kdf(mut kdf: RegistrationKdf) -> Result<RegistrationKdf, ApiError> {
    if kdf.kdf == 0 && kdf.kdf_iterations < 100_000 {
        return Err(ApiError::invalid(
            "kdfIterations",
            "PBKDF2 KDF iterations must be at least 100000.",
        ));
    }
    if kdf.kdf == 1 {
        if kdf.kdf_iterations < 1 {
            return Err(ApiError::invalid(
                "kdfIterations",
                "Argon2 KDF iterations must be at least 1.",
            ));
        }
        if !kdf
            .kdf_memory
            .is_some_and(|memory| (15..=1024).contains(&memory))
        {
            return Err(ApiError::invalid(
                "kdfMemory",
                "Argon2 memory must be between 15 MB and 1024 MB.",
            ));
        }
        if !kdf
            .kdf_parallelism
            .is_some_and(|parallelism| (1..=16).contains(&parallelism))
        {
            return Err(ApiError::invalid(
                "kdfParallelism",
                "Argon2 parallelism must be between 1 and 16.",
            ));
        }
    } else {
        kdf.kdf_memory = None;
        kdf.kdf_parallelism = None;
    }
    Ok(kdf)
}

impl<S: RegistrationStorage> VaultService<S> {
    pub fn request_registration_verification(
        &mut self,
        request: &RegistrationVerificationRequest<'_>,
    ) -> Result<RegistrationVerificationToken<S::Token>, ApiError> {
        if !self
            .storage_mut()
            .registration_verification_allowed(request.email)
            .map_err(S::map_error)?
        {
            return Err(denied());
        }
        self.storage_mut()
            .issue_registration_token(request)
            .map(RegistrationVerificationToken::new)
            .map_err(S::map_error)
    }

    pub fn finish_registration(
        &mut self,
        request: &RegistrationFinishRequest<'_>,
        email: &RegistrationEmail<'_>,
    ) -> Result<RegistrationFinishResponse, RegistrationError> {
        let (kdf, hash, key) = match &request.credentials {
            RegistrationCredentials::Legacy {
                kdf,
                master_password_hash,
                key,
            } => (*kdf, master_password_hash, key),
            RegistrationCredentials::Nested {
                authentication,
                unlock,
            } => {
                if authentication.kdf != unlock.kdf
                    || authentication.salt != email.salt_email
                    || unlock.salt != email.salt_email
                {
                    return Err(RegistrationError::InvalidFormat);
                }
                (authentication.kdf, &authentication.hash, &unlock.key)
            }
        };
        let token = request.email_verification_token.as_ref().ok_or_else(|| {
            ApiError::invalid(
                "emailVerificationToken",
                "Registration is missing required parameters",
            )
        })?;
        let claims = self
            .storage_mut()
            .verify_registration_token(token)
            .map_err(S::map_error)?
            .ok_or_else(|| {
                ApiError::invalid(
                    "emailVerificationToken",
                    "Invalid registration verification token",
                )
            })?;
        if claims.subject() != request.email {
            return Err(ApiError::invalid(
                "emailVerificationToken",
                "Email verification token does not match email",
            )
            .into());
        }
        if claims.name().is_some_and(|name| name.len() > 50) {
            return Err(ApiError::invalid(
                "name",
                "The field Name must be a string with a maximum length of 50.",
            )
            .into());
        }
        let hint = request
            .master_password_hint
            .map(str::trim)
            .filter(|hint| !hint.is_empty());
        let state = self
            .storage_mut()
            .registration_state(email.storage_email)
            .map_err(S::map_error)?;
        if hint.is_some() && !state.password_hints_allowed {
            return Err(ApiError::invalid(
                "masterPasswordHint",
                "Password hints have been disabled by the administrator.",
            )
            .into());
        }
        if state.has_password || !state.registration_allowed {
            return Err(denied().into());
        }
        let kdf = validated_kdf(kdf)?;
        if !state.email_valid {
            return Err(ApiError::invalid("email", "Email address is invalid.").into());
        }
        let plan = ValidatedRegistration {
            email: email.storage_email,
            name: claims.name(),
            hash,
            key,
            keys: request.keys.as_ref(),
            hint,
            kdf,
            email_verified: claims.verified(),
        };
        self.storage_mut()
            .finish_registration(&plan)
            .map_err(S::map_error)?;
        Ok(RegistrationFinishResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorKind,
        service::ItemMetadata,
        wire::{
            CipherRequest, FolderRequest, RegisterRequest, RegistrationAuthentication,
            RegistrationUnlock,
        },
    };
    use std::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    const EMAIL: &str = " ÜSER@EXAMPLE.TEST ";
    const STORED: &str = " üser@example.test ";
    const SALT: &str = "üser@example.test";
    const TOKEN: &str = "test-only-private-registration-token";

    // Neither provider-owned handle has a Debug bound or requires a core allocator.
    struct Token(&'static str);
    impl AsRef<str> for Token {
        fn as_ref(&self) -> &str {
            self.0
        }
    }
    #[derive(Clone)]
    struct Claims {
        subject: String,
        name: Option<String>,
        verified: bool,
    }
    impl RegistrationClaims for Claims {
        fn subject(&self) -> &str {
            &self.subject
        }
        fn name(&self) -> Option<&str> {
            self.name.as_deref()
        }
        fn verified(&self) -> bool {
            self.verified
        }
    }
    #[derive(Clone, Eq, PartialEq)]
    struct Saved {
        email: String,
        name: Option<String>,
        hash: String,
        key: String,
        keys: Option<(String, String)>,
        hint: Option<String>,
        kdf: RegistrationKdf,
        verified: bool,
    }
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Fail {
        Allowed,
        Issue,
        Verify,
        State,
        Commit,
    }
    struct Mock {
        allowed: bool,
        claims: Claims,
        state: RegistrationState,
        fail: Option<Fail>,
        error: ErrorKind,
        calls: Vec<&'static str>,
        issued: Option<(String, Option<String>)>,
        saved: Option<Saved>,
        last_policy_email: String,
        plan_debug: String,
        unrelated: (usize, bool),
    }
    impl Mock {
        fn new() -> Self {
            Self {
                allowed: true,
                claims: Claims {
                    subject: EMAIL.into(),
                    name: Some("claims-name".into()),
                    verified: false,
                },
                state: RegistrationState {
                    registration_allowed: true,
                    has_password: false,
                    password_hints_allowed: true,
                    email_valid: true,
                },
                fail: None,
                error: ErrorKind::Storage,
                calls: vec![],
                issued: None,
                saved: None,
                last_policy_email: String::new(),
                plan_debug: String::new(),
                unrelated: (7, true),
            }
        }
        fn call(&mut self, label: &'static str, fail: Fail) -> Result<(), ErrorKind> {
            self.calls.push(label);
            if self.fail == Some(fail) {
                Err(self.error)
            } else {
                Ok(())
            }
        }
        fn unchanged(&self) {
            assert!(self.saved.is_none());
            assert_eq!(self.unrelated, (7, true));
        }
    }
    impl Storage for Mock {
        type Error = ErrorKind;
        fn map_error(error: Self::Error) -> ApiError {
            ApiError::new(error, "Static provider failure")
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
    impl RegistrationStorage for Mock {
        type Token = Token;
        type Claims = Claims;
        fn registration_verification_allowed(&mut self, email: &str) -> Result<bool, Self::Error> {
            self.call("allowed", Fail::Allowed)?;
            self.last_policy_email = email.into();
            Ok(self.allowed)
        }
        fn issue_registration_token(
            &mut self,
            request: &RegistrationVerificationRequest<'_>,
        ) -> Result<Self::Token, Self::Error> {
            self.call("issue", Fail::Issue)?;
            self.issued = Some((request.email.into(), request.name.map(ToString::to_string)));
            Ok(Token(TOKEN))
        }
        fn verify_registration_token(
            &mut self,
            token: &Secret<'_>,
        ) -> Result<Option<Self::Claims>, Self::Error> {
            self.call("verify", Fail::Verify)?;
            // Mock only. Real providers verify JWT signature, issuer and time, not equality.
            Ok((token.expose_secret() == TOKEN).then(|| self.claims.clone()))
        }
        fn registration_state(
            &mut self,
            storage_email: &str,
        ) -> Result<RegistrationState, Self::Error> {
            self.call("state", Fail::State)?;
            self.last_policy_email = storage_email.into();
            Ok(self.state)
        }
        fn finish_registration(
            &mut self,
            plan: &ValidatedRegistration<'_>,
        ) -> Result<(), Self::Error> {
            self.calls.push("commit");
            self.plan_debug = std::format!("{plan:?}");
            let before = self.saved.clone();
            self.saved = Some(Saved {
                email: plan.email().into(),
                name: plan.name().map(ToString::to_string),
                hash: plan.master_password_hash().expose_secret().into(),
                key: plan.key().expose_secret().into(),
                keys: plan
                    .keys()
                    .map(|keys| (keys.encrypted_private_key.into(), keys.public_key.into())),
                hint: plan.master_password_hint().map(ToString::to_string),
                kdf: plan.kdf(),
                verified: plan.email_verified(),
            });
            if self.fail == Some(Fail::Commit) {
                self.saved = before;
                return Err(self.error);
            }
            Ok(())
        }
    }
    fn kdf() -> RegistrationKdf {
        RegistrationKdf {
            kdf: 0,
            kdf_iterations: 100_000,
            kdf_memory: Some(-1),
            kdf_parallelism: Some(-1),
        }
    }
    fn email() -> RegistrationEmail<'static> {
        RegistrationEmail {
            storage_email: STORED,
            salt_email: SALT,
        }
    }
    fn request(nested: bool) -> RegistrationFinishRequest<'static> {
        RegistrationFinishRequest {
            email: EMAIL,
            credentials: if nested {
                RegistrationCredentials::Nested {
                    authentication: RegistrationAuthentication {
                        kdf: kdf(),
                        salt: SALT,
                        hash: Secret::new("opaque-client-hash"),
                    },
                    unlock: RegistrationUnlock {
                        kdf: kdf(),
                        salt: SALT,
                        key: Secret::new("future-key\0雪"),
                    },
                }
            } else {
                RegistrationCredentials::Legacy {
                    kdf: kdf(),
                    master_password_hash: Secret::new("opaque-client-hash"),
                    key: Secret::new("future-key\0雪"),
                }
            },
            email_verification_token: Some(Secret::new(TOKEN)),
            keys: Some(AccountKeys {
                encrypted_private_key: "future-private\0雪",
                public_key: "future-public\0雪",
            }),
            master_password_hint: Some(" \t hint\0雪 \r\n"),
        }
    }
    fn rejected(mock: &mut Mock, input: &RegistrationFinishRequest<'_>, status: u16) {
        let error = VaultService::new(&mut *mock)
            .finish_registration(input, &email())
            .unwrap_err();
        assert_eq!(error.status_code(), status);
        assert!(!mock.calls.contains(&"commit"));
        mock.unchanged();
    }

    #[test]
    fn verification_policy_precedes_opaque_no_smtp_issuance_without_early_name_or_email_validation()
    {
        let long = "雪".repeat(30);
        for address in [EMAIL, "", "not an email\0雪"] {
            let mut mock = Mock::new();
            mock.state.has_password = true; // No-SMTP verification does not reject initialized users.
            mock.state.email_valid = false; // Email syntax is deferred until finish.
            let request = RegistrationVerificationRequest {
                email: address,
                name: Some(&long),
            };
            let token = VaultService::new(&mut mock)
                .request_registration_verification(&request)
                .unwrap();
            assert_eq!(mock.calls, ["allowed", "issue"]);
            assert_eq!(mock.last_policy_email, address);
            assert!(mock.issued.as_ref().is_some_and(
                |(email, name)| email == address && name.as_deref() == Some(long.as_str())
            ));
            drop(mock);
            assert!(token.expose_token() == TOKEN);
            assert!(!std::format!("{token:?}").contains(TOKEN));
        }
        let mut mock = Mock::new();
        mock.allowed = false;
        let error = VaultService::new(&mut mock)
            .request_registration_verification(&RegistrationVerificationRequest {
                email: EMAIL,
                name: None,
            })
            .unwrap_err();
        assert_eq!(error.status_code(), 400);
        assert_eq!(mock.calls, ["allowed"]);
        assert!(mock.issued.is_none());
        mock.unchanged();
    }

    #[test]
    fn nested_format_mismatch_precedes_missing_token_and_all_provider_calls() {
        for case in 0..4 {
            let mut mock = Mock::new();
            let mut input = request(true);
            input.email_verification_token = None;
            let RegistrationCredentials::Nested {
                authentication,
                unlock,
            } = &mut input.credentials
            else {
                unreachable!()
            };
            match case {
                0 => unlock.kdf.kdf_memory = None, // Compare raw KDF values before clearing non-Argon metadata.
                1 => authentication.salt = "ÜSER@EXAMPLE.TEST",
                2 => unlock.salt = STORED,
                _ => unlock.kdf.kdf_iterations += 1,
            }
            rejected(&mut mock, &input, 422);
            assert!(mock.calls.is_empty());
        }
        let mut mock = Mock::new();
        let mut input = request(true);
        input.email_verification_token = None;
        rejected(&mut mock, &input, 400);
        assert!(mock.calls.is_empty());
    }

    #[test]
    fn missing_invalid_and_raw_email_mismatched_proofs_never_read_state_or_insert() {
        for nested in [false, true] {
            let mut mock = Mock::new();
            let mut input = request(nested);
            input.email_verification_token = Some(Secret::new("wrong-token"));
            rejected(&mut mock, &input, 400);
            assert_eq!(mock.calls, ["verify"]);
            for subject in [STORED, SALT, "ÜSER@EXAMPLE.TEST", "another@example.test"] {
                let mut mock = Mock::new();
                mock.claims.subject = subject.into();
                rejected(&mut mock, &request(nested), 400);
                assert_eq!(mock.calls, ["verify"]);
            }
        }
    }

    #[test]
    fn claim_names_use_utf8_bytes_preserve_empty_and_never_take_finish_body_authority() {
        for name in [
            None,
            Some("".into()),
            Some("  \0雪  ".into()),
            Some("é".repeat(25)),
        ] {
            let mut mock = Mock::new();
            mock.claims.name = name.clone();
            VaultService::new(&mut mock)
                .finish_registration(&request(false), &email())
                .unwrap();
            let saved = mock.saved.as_ref().unwrap();
            assert!(saved.name == name);
            assert!(saved.email == STORED); // Unicode lowercase without trimming remains adapter-owned.
        }
        for name in ["a".repeat(51), "é".repeat(26)] {
            let mut mock = Mock::new();
            mock.claims.name = Some(name);
            rejected(&mut mock, &request(false), 400);
            assert_eq!(mock.calls, ["verify"]);
        }
    }

    #[test]
    fn password_hint_cleaning_preserves_unbounded_opaque_content_and_checks_cleaned_policy() {
        let long = "雪".repeat(300);
        let mut mock = Mock::new();
        let mut input = request(false);
        input.master_password_hint = Some(&long);
        VaultService::new(&mut mock)
            .finish_registration(&input, &email())
            .unwrap();
        assert!(mock.saved.unwrap().hint.as_deref() == Some(long.as_str()));
        for hint in [None, Some(" \t\r\n\u{2003}")] {
            let mut mock = Mock::new();
            mock.state.password_hints_allowed = false;
            let mut input = request(false);
            input.master_password_hint = hint;
            VaultService::new(&mut mock)
                .finish_registration(&input, &email())
                .unwrap();
            assert!(mock.saved.unwrap().hint.is_none());
        }
        let mut mock = Mock::new();
        VaultService::new(&mut mock)
            .finish_registration(&request(false), &email())
            .unwrap();
        assert!(mock.saved.unwrap().hint.as_deref() == Some("hint\0雪"));
    }

    #[test]
    fn signed_kdf_rules_match_pinned_thresholds_and_clear_every_non_argon_memory_field() {
        for (kind, iterations, memory, parallelism, valid) in [
            (0, 99_999, None, None, false),
            (0, 100_000, None, None, true),
            (0, i32::MAX, Some(-1), Some(i32::MIN), true),
            (1, 0, Some(15), Some(1), false),
            (1, 1, Some(15), Some(1), true),
            (1, i32::MAX, Some(1024), Some(16), true),
            (1, 1, None, Some(1), false),
            (1, 1, Some(14), Some(1), false),
            (1, 1, Some(1025), Some(1), false),
            (1, 1, Some(15), None, false),
            (1, 1, Some(15), Some(0), false),
            (1, 1, Some(15), Some(17), false),
            (-1, i32::MIN, Some(i32::MIN), Some(i32::MAX), true),
            (2, -7, Some(1), Some(100), true),
        ] {
            let data = RegistrationKdf {
                kdf: kind,
                kdf_iterations: iterations,
                kdf_memory: memory,
                kdf_parallelism: parallelism,
            };
            let mut input = request(false);
            let RegistrationCredentials::Legacy { kdf, .. } = &mut input.credentials else {
                unreachable!()
            };
            *kdf = data;
            let mut mock = Mock::new();
            let result = VaultService::new(&mut mock).finish_registration(&input, &email());
            assert_eq!(result.is_ok(), valid);
            if valid {
                let saved = mock.saved.unwrap();
                assert_eq!(saved.kdf.kdf, kind);
                assert_eq!(saved.kdf.kdf_iterations, iterations);
                assert_eq!(saved.kdf.kdf_memory, if kind == 1 { memory } else { None });
                assert_eq!(
                    saved.kdf.kdf_parallelism,
                    if kind == 1 { parallelism } else { None }
                );
            } else {
                mock.unchanged();
                assert!(!mock.calls.contains(&"commit"));
            }
        }
    }

    #[test]
    fn blocked_existing_password_and_disallowed_cleaned_hint_never_mutate() {
        for case in 0..3 {
            let mut mock = Mock::new();
            match case {
                0 => mock.state.registration_allowed = false,
                1 => mock.state.has_password = true,
                _ => mock.state.password_hints_allowed = false,
            }
            rejected(&mut mock, &request(false), 400);
            assert_eq!(mock.calls, ["verify", "state"]);
        }
    }

    #[test]
    fn adapter_email_validity_rejects_before_commit_after_proof_policy_and_kdf_checks() {
        for case in 0..5 {
            let mut mock = Mock::new();
            mock.state.email_valid = false;
            let mut input = request(false);
            let expected_field = match case {
                0 => "email",
                1 => {
                    let RegistrationCredentials::Legacy { kdf, .. } = &mut input.credentials else {
                        unreachable!()
                    };
                    kdf.kdf_iterations = 99_999;
                    "kdfIterations"
                }
                2 => {
                    input.email_verification_token = None;
                    "emailVerificationToken"
                }
                3 => {
                    mock.state.has_password = true;
                    "registration"
                }
                _ => {
                    mock.state.password_hints_allowed = false;
                    "masterPasswordHint"
                }
            };
            let error = VaultService::new(&mut mock)
                .finish_registration(&input, &email())
                .unwrap_err();
            let RegistrationError::Api(error) = error else {
                panic!("Unexpected format error")
            };
            assert_eq!(error.status_code(), 400);
            assert_eq!(error.field, Some(expected_field));
            assert!(!mock.calls.contains(&"commit"));
            mock.unchanged();
        }
    }

    #[test]
    fn opaque_legacy_and_nested_material_is_preserved_and_validated_plans_are_redacted() {
        for nested in [false, true] {
            let mut mock = Mock::new();
            mock.claims.verified = true;
            let response = VaultService::new(&mut mock)
                .finish_registration(&request(nested), &email())
                .unwrap();
            assert_eq!(
                serde_json::to_value(response).unwrap(),
                serde_json::json!({"object":"registerFinish"})
            );
            let saved = mock.saved.as_ref().unwrap();
            assert!(saved.hash == "opaque-client-hash" && saved.key == "future-key\0雪");
            assert!(
                saved
                    .keys
                    .as_ref()
                    .is_some_and(|(private, public)| private == "future-private\0雪"
                        && public == "future-public\0雪")
            );
            assert!(saved.verified);
            assert_eq!(mock.calls, ["verify", "state", "commit"]);
            assert!(!mock.plan_debug.contains("future") && !mock.plan_debug.contains(EMAIL));
            assert_eq!(mock.unrelated, (7, true));
        }
        let mut input = request(false);
        input.credentials = RegistrationCredentials::Legacy {
            kdf: kdf(),
            master_password_hash: Secret::new(""),
            key: Secret::new(""),
        };
        input.keys = Some(AccountKeys {
            encrypted_private_key: "",
            public_key: "",
        });
        let mut mock = Mock::new();
        VaultService::new(&mut mock)
            .finish_registration(&input, &email())
            .unwrap();
        assert!(mock.saved.as_ref().is_some_and(|saved| {
            saved.hash.is_empty()
                && saved.key.is_empty()
                && saved
                    .keys
                    .as_ref()
                    .is_some_and(|(private, public)| private.is_empty() && public.is_empty())
        }));
        assert!(!std::format!("{input:?}{:?}", email()).contains(EMAIL));
    }

    #[test]
    fn provider_failures_roll_back_and_use_shared_error_mapping_without_exposing_state() {
        for kind in [ErrorKind::Storage, ErrorKind::Conflict] {
            for fail in [
                Fail::Allowed,
                Fail::Issue,
                Fail::Verify,
                Fail::State,
                Fail::Commit,
            ] {
                let mut mock = Mock::new();
                mock.fail = Some(fail);
                mock.error = kind;
                let error = if matches!(fail, Fail::Allowed | Fail::Issue) {
                    VaultService::new(&mut mock)
                        .request_registration_verification(&RegistrationVerificationRequest {
                            email: EMAIL,
                            name: None,
                        })
                        .unwrap_err()
                } else {
                    let RegistrationError::Api(error) = VaultService::new(&mut mock)
                        .finish_registration(&request(false), &email())
                        .unwrap_err()
                    else {
                        unreachable!()
                    };
                    error
                };
                assert_eq!(error.kind, kind);
                assert_eq!(error.message, "Static provider failure");
                assert!(mock.issued.is_none());
                mock.unchanged();
            }
        }
    }
}
