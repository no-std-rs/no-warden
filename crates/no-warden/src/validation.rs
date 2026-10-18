//! Input validation and configurable policy. Validation never decrypts client data.
use crate::{
    ApiError,
    wire::{CipherRequest, FolderRequest, PreloginResponse, RegisterRequest},
};

pub const MAX_ENCRYPTED_FIELD_BYTES: usize = 1_048_576;

/// Folder-name validation selected by the embedding application.
///
/// Existing callers retain encrypted-envelope validation. A protocol adapter that must
/// preserve arbitrary upstream folder names can explicitly choose `Opaque`; transport
/// and storage limits then belong to that adapter rather than this name validator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FolderNamePolicy {
    #[default]
    Encrypted,
    Opaque,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfPolicy {
    pub minimum_pbkdf2_iterations: u32,
    pub maximum_pbkdf2_iterations: u32,
    pub minimum_argon2_iterations: u32,
    pub maximum_argon2_iterations: u32,
    pub minimum_argon2_memory_mib: u32,
    pub maximum_argon2_memory_mib: u32,
    pub maximum_argon2_parallelism: u32,
}

impl Default for KdfPolicy {
    fn default() -> Self {
        Self {
            minimum_pbkdf2_iterations: 600_000,
            maximum_pbkdf2_iterations: 10_000_000,
            minimum_argon2_iterations: 2,
            maximum_argon2_iterations: 10,
            minimum_argon2_memory_mib: 16,
            maximum_argon2_memory_mib: 1024,
            maximum_argon2_parallelism: 16,
        }
    }
}

impl KdfPolicy {
    pub fn validate(self, kdf: PreloginResponse) -> Result<(), ApiError> {
        match kdf.kdf {
            0 => {
                if !(self.minimum_pbkdf2_iterations..=self.maximum_pbkdf2_iterations)
                    .contains(&kdf.kdf_iterations)
                {
                    return Err(ApiError::invalid(
                        "kdfIterations",
                        "PBKDF2 iterations are outside policy limits.",
                    ));
                }
            }
            1 => {
                if !(self.minimum_argon2_iterations..=self.maximum_argon2_iterations)
                    .contains(&kdf.kdf_iterations)
                {
                    return Err(ApiError::invalid(
                        "kdfIterations",
                        "Argon2 iterations are outside policy limits.",
                    ));
                }
                if !kdf.kdf_memory.is_some_and(|value| {
                    (self.minimum_argon2_memory_mib..=self.maximum_argon2_memory_mib)
                        .contains(&value)
                }) {
                    return Err(ApiError::invalid(
                        "kdfMemory",
                        "Argon2 memory is outside policy limits.",
                    ));
                }
                if !kdf
                    .kdf_parallelism
                    .is_some_and(|value| (1..=self.maximum_argon2_parallelism).contains(&value))
                {
                    return Err(ApiError::invalid(
                        "kdfParallelism",
                        "Argon2 parallelism is outside policy limits.",
                    ));
                }
            }
            _ => {
                return Err(ApiError::invalid(
                    "kdf",
                    "Unsupported key derivation function.",
                ));
            }
        }
        Ok(())
    }
}

/// Optional policy for applications that handle plaintext passwords locally.
/// Registration requests contain a client-derived hash, so the server cannot enforce this.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordPolicy {
    pub minimum_characters: usize,
    pub maximum_bytes: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_symbol: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            minimum_characters: 12,
            maximum_bytes: 1024,
            require_uppercase: false,
            require_lowercase: false,
            require_digit: false,
            require_symbol: false,
        }
    }
}

impl PasswordPolicy {
    pub fn validate(self, password: &str) -> Result<(), ApiError> {
        if password.len() > self.maximum_bytes || password.chars().count() < self.minimum_characters
        {
            return Err(ApiError::invalid(
                "password",
                "Password length is outside policy limits.",
            ));
        }
        let bytes = password.as_bytes();
        if (self.require_uppercase && !bytes.iter().any(u8::is_ascii_uppercase))
            || (self.require_lowercase && !bytes.iter().any(u8::is_ascii_lowercase))
            || (self.require_digit && !bytes.iter().any(u8::is_ascii_digit))
            || (self.require_symbol && !bytes.iter().any(u8::is_ascii_punctuation))
        {
            return Err(ApiError::invalid(
                "password",
                "Password does not meet character requirements.",
            ));
        }
        Ok(())
    }
}

pub fn validate_email(email: &str) -> Result<(), ApiError> {
    let valid = email.len() <= 254
        && email.is_ascii()
        && !email
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && local.len() <= 64
                && !domain.is_empty()
                && !domain.contains('@')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        });
    if valid {
        Ok(())
    } else {
        Err(ApiError::invalid(
            "email",
            "A valid email address is required.",
        ))
    }
}

pub fn validate_registration(
    request: &RegisterRequest<'_>,
    policy: KdfPolicy,
) -> Result<(), ApiError> {
    validate_email(request.email)?;
    policy.validate(request.prelogin())?;
    if decoded_base64_len(request.master_password_hash) != Some(32) {
        return Err(ApiError::invalid(
            "masterPasswordHash",
            "A base64-encoded 32-byte password hash is required.",
        ));
    }
    validate_encrypted_string(request.key)
        .map_err(|_| ApiError::invalid("key", "An encrypted account key is required."))?;
    if request.name.is_some_and(|name| name.len() > 128) {
        return Err(ApiError::invalid("name", "Account name is too long."));
    }
    if request
        .master_password_hint
        .is_some_and(|hint| hint.len() > 256)
    {
        return Err(ApiError::invalid(
            "masterPasswordHint",
            "Password hint is too long.",
        ));
    }
    if let Some(keys) = request.keys {
        if !decoded_base64_len(keys.public_key).is_some_and(|length| (128..=8192).contains(&length))
        {
            return Err(ApiError::invalid(
                "keys.publicKey",
                "A base64-encoded public key is required.",
            ));
        }
        validate_encrypted_string(keys.encrypted_private_key)?;
    }
    Ok(())
}

pub fn validate_folder(request: &FolderRequest<'_>) -> Result<(), ApiError> {
    validate_folder_with_policy(request, FolderNamePolicy::Encrypted)
}

/// Validate a folder name without decrypting or modifying it.
///
/// `Opaque` accepts every string, including empty strings and future encrypted formats,
/// without an intrinsic byte limit. It does not change cipher or import validation.
pub fn validate_folder_with_policy(
    request: &FolderRequest<'_>,
    policy: FolderNamePolicy,
) -> Result<(), ApiError> {
    match policy {
        FolderNamePolicy::Encrypted => validate_encrypted_string(request.name)
            .map_err(|_| ApiError::invalid("name", "An encrypted folder name is required.")),
        FolderNamePolicy::Opaque => Ok(()),
    }
}

pub fn validate_cipher(request: &CipherRequest<'_>) -> Result<(), ApiError> {
    if request.organization_id.is_some() {
        return Err(ApiError::invalid(
            "organizationId",
            "Organization vaults are not supported by the personal-vault service.",
        ));
    }
    if request.reprompt > 1 {
        return Err(ApiError::invalid(
            "reprompt",
            "Unsupported reprompt policy.",
        ));
    }
    if let Some(key) = request.key {
        validate_encrypted_string(key)
            .map_err(|_| ApiError::invalid("key", "An encrypted cipher key is required."))?;
    }
    if let Some(data) = request.data {
        if data.is_empty() || data.len() > MAX_ENCRYPTED_FIELD_BYTES {
            return Err(ApiError::invalid(
                "data",
                "An opaque cipher blob within size limits is required.",
            ));
        }
        if !(1..=8).contains(&request.kind) {
            return Err(ApiError::invalid("type", "Unsupported cipher type."));
        }
        return Ok(());
    }
    validate_encrypted_string(request.name.ok_or(ApiError::invalid(
        "name",
        "An encrypted cipher name is required.",
    ))?)
    .map_err(|_| ApiError::invalid("name", "An encrypted cipher name is required."))?;
    optional_encrypted(request.notes)?;
    match request.kind {
        1 => {
            let login = request
                .login
                .as_ref()
                .ok_or(ApiError::invalid("login", "Login data is required."))?;
            for value in [login.username, login.password, login.totp] {
                optional_encrypted(value)?;
            }
            if let Some(uris) = &login.uris {
                for uri in uris.iter() {
                    optional_encrypted(uri.uri)?;
                    optional_encrypted(uri.uri_checksum)?;
                    if uri.match_type.is_some_and(|value| value > 5) {
                        return Err(ApiError::invalid(
                            "login.uris.match",
                            "Unsupported URI match type.",
                        ));
                    }
                }
            }
            if let Some(credentials) = &login.fido2_credentials {
                for credential in credentials.iter() {
                    for value in [
                        credential.credential_id,
                        credential.key_type,
                        credential.key_algorithm,
                        credential.key_curve,
                        credential.key_value,
                        credential.rp_id,
                        credential.rp_name,
                        credential.counter,
                        credential.user_handle,
                        credential.user_name,
                        credential.user_display_name,
                        credential.discoverable,
                    ] {
                        optional_encrypted(value)?;
                    }
                }
            }
        }
        2 => {
            if request.secure_note.is_none_or(|note| note.kind != 0) {
                return Err(ApiError::invalid(
                    "secureNote",
                    "Generic secure note data is required.",
                ));
            }
        }
        3 => {
            let card = request
                .card
                .ok_or(ApiError::invalid("card", "Card data is required."))?;
            for value in [
                card.cardholder_name,
                card.brand,
                card.number,
                card.exp_month,
                card.exp_year,
                card.code,
            ] {
                optional_encrypted(value)?;
            }
        }
        4 => {
            let identity = request
                .identity
                .ok_or(ApiError::invalid("identity", "Identity data is required."))?;
            for value in [
                identity.title,
                identity.first_name,
                identity.middle_name,
                identity.last_name,
                identity.address1,
                identity.address2,
                identity.address3,
                identity.city,
                identity.state,
                identity.postal_code,
                identity.country,
                identity.company,
                identity.email,
                identity.phone,
                identity.ssn,
                identity.username,
                identity.passport_number,
                identity.license_number,
            ] {
                optional_encrypted(value)?;
            }
        }
        5 => {
            let ssh = request
                .ssh_key
                .ok_or(ApiError::invalid("sshKey", "SSH key data is required."))?;
            for value in [ssh.private_key, ssh.public_key, ssh.key_fingerprint] {
                validate_encrypted_string(value)?;
            }
        }
        _ => return Err(ApiError::invalid("type", "Unsupported cipher type.")),
    }
    if let Some(fields) = &request.fields {
        for field in fields.iter() {
            if field.kind > 3 {
                return Err(ApiError::invalid(
                    "fields.type",
                    "Unsupported custom field type.",
                ));
            }
            optional_encrypted(field.name)?;
            optional_encrypted(field.value)?;
        }
    }
    if let Some(history) = &request.password_history {
        for entry in history.iter() {
            validate_encrypted_string(entry.password)?;
        }
    }
    Ok(())
}

fn optional_encrypted(value: Option<&str>) -> Result<(), ApiError> {
    match value {
        Some("") | None => Ok(()),
        Some(value) => validate_encrypted_string(value),
    }
}

/// Validate an EncString envelope, never its authenticity or plaintext.
/// Supports AES/RSA 0 through 6, opaque COSE type 7, and headerless AES-256.
pub fn validate_encrypted_string(value: &str) -> Result<(), ApiError> {
    let invalid = || ApiError::invalid("encryptedValue", "Invalid encrypted value envelope.");
    if value.len() > MAX_ENCRYPTED_FIELD_BYTES {
        return Err(invalid());
    }
    // Legacy clients omit the type prefix for AES-256-CBC (`iv|ciphertext`).
    let (kind, payload) = value.split_once('.').unwrap_or(("0", value));
    let mut parts = payload.split('|');
    let first = decoded_base64_len(parts.next().ok_or_else(invalid)?).ok_or_else(invalid)?;
    match kind {
        "0" | "1" | "2" => {
            if first != 16 {
                return Err(invalid());
            }
            let data = decoded_base64_len(parts.next().ok_or_else(invalid)?).ok_or_else(invalid)?;
            if data == 0 || data % 16 != 0 {
                return Err(invalid());
            }
            if kind != "0" && decoded_base64_len(parts.next().ok_or_else(invalid)?) != Some(32) {
                return Err(invalid());
            }
        }
        "3" | "4" => {
            if first < 128 {
                return Err(invalid());
            }
        }
        "5" | "6" => {
            if first < 128 || decoded_base64_len(parts.next().ok_or_else(invalid)?) != Some(32) {
                return Err(invalid());
            }
        }
        "7" => {
            if first == 0 {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    if parts.next().is_some() {
        return Err(invalid());
    }
    Ok(())
}

/// Return the decoded byte length for canonical, padded standard base64.
pub fn decoded_base64_len(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let padding = if bytes.ends_with(b"==") {
        2
    } else if bytes.ends_with(b"=") {
        1
    } else {
        0
    };
    let data = &bytes[..bytes.len() - padding];
    if data.iter().any(|byte| base64_digit(*byte).is_none()) {
        return None;
    }
    let last = base64_digit(*data.last()?)?;
    if (padding == 2 && last & 15 != 0) || (padding == 1 && last & 3 != 0) {
        return None;
    }
    Some(bytes.len() / 4 * 3 - padding)
}

fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    pub(crate) const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn opaque_folder_names_are_opt_in_and_have_no_encrypted_field_limit() {
        assert_eq!(FolderNamePolicy::default(), FolderNamePolicy::Encrypted);
        assert!(validate_folder(&FolderRequest { name: ENCRYPTED }).is_ok());
        let oversized = "x".repeat(MAX_ENCRYPTED_FIELD_BYTES + 1);
        for name in ["", "café 🔐", "future-envelope:v42:anything", &oversized] {
            let request = FolderRequest { name };
            assert_eq!(validate_folder(&request).unwrap_err().field, Some("name"));
            assert!(validate_folder_with_policy(&request, FolderNamePolicy::Opaque).is_ok());
        }
    }

    #[test]
    fn encrypted_values_require_well_formed_envelopes() {
        assert!(validate_encrypted_string(ENCRYPTED).is_ok());
        assert!(
            validate_encrypted_string("AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==").is_ok()
        );
        // A headerless value has no MAC: current clients interpret it as type 0.
        assert!(validate_encrypted_string("AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err());
        for invalid in [
            "plaintext",
            "2.a|b|c",
            "2.AAAA|AAAA|AAAA",
            "9.AAAA",
            "0.AAAA|AAAA",
            "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|extra",
        ] {
            assert!(validate_encrypted_string(invalid).is_err(), "{invalid}");
        }
        assert_eq!(decoded_base64_len("AA=="), Some(1));
        assert_eq!(decoded_base64_len("AB=="), None);
        assert_eq!(decoded_base64_len("AA=A"), None);
        assert_eq!(decoded_base64_len("===="), None);
    }

    #[test]
    fn policies_reject_weak_or_excessive_work_factors() {
        let policy = KdfPolicy::default();
        assert!(policy.validate(PreloginResponse::default()).is_ok());
        assert!(
            policy
                .validate(PreloginResponse {
                    kdf_iterations: 1,
                    ..Default::default()
                })
                .is_err()
        );
        assert!(
            policy
                .validate(PreloginResponse {
                    kdf: 1,
                    kdf_iterations: 3,
                    kdf_memory: Some(64),
                    kdf_parallelism: Some(4)
                })
                .is_ok()
        );
        assert!(
            policy
                .validate(PreloginResponse {
                    kdf: 1,
                    kdf_iterations: 3,
                    kdf_memory: Some(u32::MAX),
                    kdf_parallelism: Some(4)
                })
                .is_err()
        );
        assert!(
            PasswordPolicy::default()
                .validate("a long passphrase")
                .is_ok()
        );
        assert!(PasswordPolicy::default().validate("short").is_err());
    }

    #[test]
    fn optional_cipher_keys_require_valid_envelopes() {
        for key in [Some(""), Some("plaintext"), Some("2.a|b|c")] {
            let input = std::format!(
                r#"{{"type":2,"name":"{ENCRYPTED}","secureNote":{{"type":0}},"key":{}}}"#,
                serde_json::to_string(&key).unwrap(),
            );
            let request: CipherRequest<'_> = serde_json::from_str(&input).unwrap();
            assert_eq!(validate_cipher(&request).unwrap_err().field, Some("key"));
        }
        for key in [None, Some(ENCRYPTED)] {
            let input = std::format!(
                r#"{{"type":2,"name":"{ENCRYPTED}","secureNote":{{"type":0}},"key":{}}}"#,
                serde_json::to_string(&key).unwrap(),
            );
            let request: CipherRequest<'_> = serde_json::from_str(&input).unwrap();
            assert!(validate_cipher(&request).is_ok());
        }
    }

    #[test]
    fn opaque_blobs_cose_keys_and_passkey_envelopes_validate_without_decryption() {
        assert!(validate_encrypted_string("7.AAECAw==").is_ok());
        for value in ["7.", "7.invalid", "7.AAECAw==|extra"] {
            assert!(validate_encrypted_string(value).is_err());
        }
        let mut document =
            serde_json::json!({"type":1,"data":"opaque sealed JSON","key":"7.AAECAw=="});
        assert!(validate_cipher(&CipherRequest::deserialize(&document).unwrap()).is_ok());
        document["data"] = serde_json::json!("");
        assert_eq!(
            validate_cipher(&CipherRequest::deserialize(&document).unwrap())
                .unwrap_err()
                .field,
            Some("data")
        );
        document = serde_json::json!({"type":1,"name":ENCRYPTED,"login":{"fido2Credentials":[{"keyValue":"plaintext"}]}});
        assert!(validate_cipher(&CipherRequest::deserialize(&document).unwrap()).is_err());
        document["login"]["fido2Credentials"][0]["keyValue"] = serde_json::json!(ENCRYPTED);
        assert!(validate_cipher(&CipherRequest::deserialize(&document).unwrap()).is_ok());
    }

    #[test]
    fn email_and_type_validation() {
        assert!(validate_email("a@example.com").is_ok());
        for email in [
            "",
            "a",
            "@example.com",
            "a@@example.com",
            "a@",
            "a @example.com",
            "a@.com",
        ] {
            assert!(validate_email(email).is_err());
        }
        let json = std::format!(r#"{{"type":1,"name":"{ENCRYPTED}"}}"#);
        let request: CipherRequest<'_> = serde_json::from_str(&json).unwrap();
        assert!(validate_cipher(&request).is_err());
        let organization = std::format!(
            r#"{{"type":2,"name":"{ENCRYPTED}","secureNote":{{"type":0}},"organizationID":"unsupported-org"}}"#
        );
        let request: CipherRequest<'_> = serde_json::from_str(&organization).unwrap();
        assert_eq!(
            validate_cipher(&request).unwrap_err().field,
            Some("organizationId")
        );
    }
}
