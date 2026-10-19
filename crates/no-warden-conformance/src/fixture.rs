//! Password-account fixtures using the same key derivation and encrypted-key
//! formats as an ordinary Bitwarden registration.
//!
//! OpenSSL supplies RSA key generation and public-key wrapping. Password hashing, HKDF expansion,
//! and authenticated encryption are implemented here in Rust. Private keys,
//! symmetric keys and server bodies never enter diagnostics or temporary files.
//! RSA wrapping uses a private temporary file containing only public SPKI bytes.

use std::{
    fmt,
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use reqwest::{StatusCode, blocking::Client};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const REGISTRATION_ITERATIONS: u32 = 600_000;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// A fixture failure whose formatting never exposes credentials, key material,
/// verification tokens, server bodies, or command output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FixtureError(Failure);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    InvalidIterations,
    Randomness,
    Rsa,
    HttpClient,
    RegistrationRequest,
    RegistrationRejected,
    VerificationRequest,
    VerificationUnavailable,
    VerificationToken,
    RegistrationDocument,
    CredentialRewrap,
    FixtureKdf,
}

impl FixtureError {
    fn message(self) -> &'static str {
        match self.0 {
            Failure::InvalidIterations => "Registration requires a nonzero PBKDF2 iteration count.",
            Failure::Randomness => "Fixture generation could not obtain secure randomness.",
            Failure::Rsa => "Fixture RSA key generation failed.",
            Failure::HttpClient => "Registration HTTP client initialization failed.",
            Failure::RegistrationRequest => "Account registration request failed.",
            Failure::RegistrationRejected => "The server rejected account registration.",
            Failure::VerificationRequest => "Registration verification request failed.",
            Failure::VerificationUnavailable => {
                "Registration verification requires a test server with email verification disabled."
            }
            Failure::VerificationToken => "Registration verification did not return a token.",
            Failure::RegistrationDocument => "The registration fixture is invalid.",
            Failure::CredentialRewrap => "The PBKDF2 credential rewrap fixture is invalid.",
            Failure::FixtureKdf => "The fixture KDF configuration is invalid.",
        }
    }
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl fmt::Debug for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FixtureError")
            .field(&self.message())
            .finish()
    }
}

impl std::error::Error for FixtureError {}

fn master_key(email: &str, password: &str, iterations: u32) -> [u8; 32] {
    let mut result = [0; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        email.trim().to_lowercase().as_bytes(),
        iterations,
        &mut result,
    );
    result
}

// Standard Argon2id v1.3 with the protocol's SHA-256 email salt and MiB input.
// This is independently authored fixture glue around the RustCrypto primitive.
fn argon2_master_key(
    email: &str,
    password: &str,
    iterations: u32,
    memory_mib: u32,
    parallelism: u32,
) -> Result<[u8; 32], FixtureError> {
    let invalid = || FixtureError(Failure::FixtureKdf);
    let memory_kib = memory_mib.checked_mul(1024).ok_or_else(invalid)?;
    let params = argon2::Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|_| invalid())?;
    let algorithm =
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let salt = Sha256::digest(email.trim().to_lowercase().as_bytes());
    let mut result = [0; 32];
    algorithm
        .hash_password_into(password.as_bytes(), &salt, &mut result)
        .map_err(|_| invalid())?;
    Ok(result)
}

fn password_hash(master_key: &[u8; 32], password: &str) -> String {
    let mut result = [0; 32];
    pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, &mut result);
    STANDARD.encode(result)
}

/// Derive the ordinary password-login hash without generating RSA keys.
///
/// # Panics
///
/// Panics if `iterations` is zero, which is not a valid PBKDF2 configuration.
pub fn master_password_hash(email: &str, password: &str, iterations: u32) -> String {
    assert_ne!(iterations, 0, "PBKDF2 requires a nonzero iteration count");
    password_hash(&master_key(email, password, iterations), password)
}

fn authenticate(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC accepts keys of any length, including this fixed 256-bit key.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of every length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn stretch_key(master_key: &[u8; 32]) -> [u8; 64] {
    // Bitwarden uses HKDF-Expand directly: the PBKDF2 output is already the
    // pseudorandom key. Adding HKDF-Extract here would derive a different key.
    let mut result = [0; 64];
    result[..32].copy_from_slice(&authenticate(master_key, &[b"enc", &[1]]));
    result[32..].copy_from_slice(&authenticate(master_key, &[b"mac", &[1]]));
    result
}

fn encrypt_with_iv(plaintext: &[u8], key: &[u8; 64], iv: &[u8; 16]) -> String {
    let ciphertext = cbc::Encryptor::<aes::Aes256>::new(key[..32].into(), iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    let mac = authenticate(&key[32..], &[iv, &ciphertext]);
    format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(ciphertext),
        STANDARD.encode(mac),
    )
}

pub(crate) fn encrypt(plaintext: &[u8], key: &[u8; 64]) -> Result<String, FixtureError> {
    let mut iv = [0; 16];
    OsRng
        .try_fill_bytes(&mut iv)
        .map_err(|_| FixtureError(Failure::Randomness))?;
    Ok(encrypt_with_iv(plaintext, key, &iv))
}

pub(crate) fn decrypt(cipher_string: &str, key: &[u8; 64]) -> Result<Vec<u8>, &'static str> {
    let encoded = cipher_string
        .strip_prefix("2.")
        .ok_or("wrong encryption type")?;
    let parts: Vec<_> = encoded.split('|').collect();
    if parts.len() != 3 {
        return Err("wrong component count");
    }
    let iv = STANDARD.decode(parts[0]).map_err(|_| "invalid IV")?;
    let ciphertext = STANDARD
        .decode(parts[1])
        .map_err(|_| "invalid ciphertext")?;
    let mac = STANDARD.decode(parts[2]).map_err(|_| "invalid MAC")?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|_| "invalid MAC key")?;
    verifier.update(&iv);
    verifier.update(&ciphertext);
    verifier.verify_slice(&mac).map_err(|_| "MAC mismatch")?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| "invalid IV length")?;
    cbc::Decryptor::<aes::Aes256>::new(key[..32].into(), (&iv).into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|_| "invalid padding")
}

/// Standard HKDF-SHA256 Send derivation from the 16-byte URL-fragment seed.
pub(crate) fn send_key(seed: &[u8; 16]) -> [u8; 64] {
    let prk = authenticate(b"bitwarden-send", &[seed]);
    let first = authenticate(&prk, &[b"send", &[1]]);
    let second = authenticate(&prk, &[&first, b"send", &[2]]);
    let mut key = [0; 64];
    key[..32].copy_from_slice(&first);
    key[32..].copy_from_slice(&second);
    key
}

/// EncArrayBuffer: type byte, IV, MAC, then CBC ciphertext. This differs from
/// the textual EncString order; no file plaintext is returned before MAC checks.
pub(crate) fn encrypt_file(plaintext: &[u8], key: &[u8; 64]) -> Result<Vec<u8>, FixtureError> {
    let encoded = encrypt(plaintext, key)?;
    let fields = encoded[2..].split('|').collect::<Vec<_>>();
    let mut bytes = vec![2];
    for index in [0, 2, 1] {
        bytes.extend(
            STANDARD
                .decode(fields[index])
                .map_err(|_| FixtureError(Failure::CredentialRewrap))?,
        );
    }
    Ok(bytes)
}

pub(crate) fn decrypt_file(bytes: &[u8], key: &[u8; 64]) -> Result<Vec<u8>, &'static str> {
    if bytes.len() < 65 || bytes[0] != 2 || !(bytes.len() - 49).is_multiple_of(16) {
        return Err("invalid encrypted file format");
    }
    let encoded = format!(
        "2.{}|{}|{}",
        STANDARD.encode(&bytes[1..17]),
        STANDARD.encode(&bytes[49..]),
        STANDARD.encode(&bytes[17..49])
    );
    decrypt(&encoded, key)
}

fn openssl(arguments: &[&str], input: Option<&[u8]>) -> Result<Vec<u8>, FixtureError> {
    let mut child = Command::new("openssl")
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| FixtureError(Failure::Rsa))?;
    if let Some(input) = input {
        let written = child
            .stdin
            .take()
            .is_some_and(|mut stdin| stdin.write_all(input).is_ok());
        if !written {
            let _ = child.kill();
            let _ = child.wait();
            return Err(FixtureError(Failure::Rsa));
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|_| FixtureError(Failure::Rsa))?;
    if !output.status.success() || output.stdout.is_empty() {
        return Err(FixtureError(Failure::Rsa));
    }
    Ok(output.stdout)
}

fn rsa_key_pair() -> Result<(Vec<u8>, Vec<u8>), FixtureError> {
    let generated = openssl(
        &[
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-outform",
            "DER",
        ],
        None,
    )?;
    // genpkey's DER encoding differs between OpenSSL versions. Convert
    // explicitly to unencrypted PKCS#8 PrivateKeyInfo, as the clients expect.
    let private_key = openssl(
        &[
            "pkcs8", "-topk8", "-nocrypt", "-inform", "DER", "-outform", "DER",
        ],
        Some(&generated),
    )?;
    let public_key = openssl(
        &["pkey", "-pubout", "-inform", "DER", "-outform", "DER"],
        Some(&private_key),
    )?;
    Ok((public_key, private_key))
}

/// Standard RSA-OAEP-SHA1/MGF1-SHA1 encapsulation of a legacy 64-byte org key.
/// Only public SPKI bytes use a 0600 file within a 0700 disposable directory.
/// Symmetric plaintext goes through stdin; encrypted output remains in memory.
pub(crate) fn organization_key_for_account(
    account: &Value,
    key: &[u8; 64],
) -> Result<String, FixtureError> {
    let fail = || FixtureError(Failure::Rsa);
    let public = account["keys"]["publicKey"].as_str().ok_or_else(fail)?;
    let public = STANDARD.decode(public).map_err(|_| fail())?;
    let directory = tempfile::Builder::new()
        .prefix("no-warden-public-spki-")
        .tempdir()
        .map_err(|_| fail())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|_| fail())?;
    }
    let path = directory.path().join("public.der");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|_| fail())?;
    file.write_all(&public).map_err(|_| fail())?;
    drop(file);
    let output = openssl(
        &[
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-keyform",
            "DER",
            "-inkey",
            path.to_str().ok_or_else(fail)?,
            "-pkeyopt",
            "rsa_padding_mode:oaep",
            "-pkeyopt",
            "rsa_oaep_md:sha1",
            "-pkeyopt",
            "rsa_mgf1_md:sha1",
        ],
        Some(key),
    )?;
    if output.len() != 256 {
        return Err(fail());
    }
    Ok(format!("4.{}", STANDARD.encode(output)))
}

/// Generate a password-account registration with a random user key and RSA
/// key pair. Returned values contain encrypted credentials and must stay private.
pub fn registration(email: &str, password: &str, iterations: u32) -> Result<Value, FixtureError> {
    if iterations == 0 {
        return Err(FixtureError(Failure::InvalidIterations));
    }
    let normalized_email = email.trim().to_lowercase();
    let master_key = master_key(&normalized_email, password, iterations);
    registration_document(
        &normalized_email,
        password,
        &master_key,
        0,
        iterations,
        None,
        None,
    )
}

/// Generate a real client-compatible Argon2id registration. This function is
/// fixture-only; the no-alloc API and server never derive these client keys.
pub fn registration_argon2(
    email: &str,
    password: &str,
    iterations: u32,
    memory_mib: u32,
    parallelism: u32,
) -> Result<Value, FixtureError> {
    let email = email.trim().to_lowercase();
    let master = argon2_master_key(&email, password, iterations, memory_mib, parallelism)?;
    registration_document(
        &email,
        password,
        &master,
        1,
        iterations,
        Some(memory_mib),
        Some(parallelism),
    )
}
fn registration_document(
    normalized_email: &str,
    password: &str,
    master_key: &[u8; 32],
    kdf: u8,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<Value, FixtureError> {
    let stretched_key = stretch_key(master_key);
    let mut user_key = [0; 64];
    OsRng
        .try_fill_bytes(&mut user_key)
        .map_err(|_| FixtureError(Failure::Randomness))?;
    let (public_key, private_key) = rsa_key_pair()?;
    Ok(json!({
        "email": normalized_email,
        "name": "no-warden compatibility test",
        "masterPasswordHash": password_hash(master_key, password),
        "masterPasswordHint": null,
        "key": encrypt(&user_key, &stretched_key)?,
        "keys": {
            "publicKey": STANDARD.encode(public_key),
            "encryptedPrivateKey": encrypt(&private_key, &user_key)?,
        },
        "kdf": kdf,
        "kdfIterations": iterations,
        "kdfMemory": memory,
        "kdfParallelism": parallelism,
        "organizationUserId": null,
        "referenceData": null,
    }))
}

pub(crate) fn pbkdf2_fixture_user_key(
    fixture: &Value,
    password: &str,
) -> Result<[u8; 64], FixtureError> {
    let invalid = || FixtureError(Failure::CredentialRewrap);
    if fixture["kdf"].as_i64() != Some(0) {
        return Err(invalid());
    }
    fixture_user_key(fixture, password).map_err(|_| invalid())
}

pub(crate) fn fixture_user_key(fixture: &Value, password: &str) -> Result<[u8; 64], FixtureError> {
    let invalid = || FixtureError(Failure::FixtureKdf);
    let email = fixture["email"].as_str().ok_or_else(invalid)?;
    let old_iterations = fixture["kdfIterations"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(invalid)?;
    let old_master_key = match fixture["kdf"].as_i64() {
        Some(0) => master_key(email, password, old_iterations),
        Some(1) => {
            let memory = fixture["kdfMemory"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(invalid)?;
            let parallelism = fixture["kdfParallelism"]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(invalid)?;
            argon2_master_key(email, password, old_iterations, memory, parallelism)?
        }
        _ => return Err(invalid()),
    };
    if fixture["masterPasswordHash"].as_str()
        != Some(password_hash(&old_master_key, password).as_str())
    {
        return Err(invalid());
    }
    let wrapped = fixture["key"].as_str().ok_or_else(invalid)?;
    decrypt(wrapped, &stretch_key(&old_master_key))
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())
}

/// Encrypt one fixture vault field with its authenticated user key. The key
/// stays private inside this helper; clients must decrypt the returned envelope.
pub fn encrypted_pbkdf2_value(
    fixture: &Value,
    password: &str,
    plaintext: &[u8],
) -> Result<String, FixtureError> {
    encrypt(plaintext, &pbkdf2_fixture_user_key(fixture, password)?)
}

pub(crate) fn encrypted_fixture_value(
    fixture: &Value,
    password: &str,
    plaintext: &[u8],
) -> Result<String, FixtureError> {
    encrypt(plaintext, &fixture_user_key(fixture, password)?)
}

/// Rewrap the same fixture user key after changing PBKDF2 iterations. Returned
/// credentials are private; the server and core never perform this client crypto.
/// Existing RSA keys, encrypted vault contents and unrelated fixture fields survive.
pub fn rewrap_pbkdf2(
    fixture: &Value,
    password: &str,
    new_iterations: u32,
) -> Result<Value, FixtureError> {
    if new_iterations == 0 {
        return Err(FixtureError(Failure::InvalidIterations));
    }
    let user_key = pbkdf2_fixture_user_key(fixture, password)?;
    let email = fixture["email"]
        .as_str()
        .ok_or(FixtureError(Failure::CredentialRewrap))?;
    let new_master_key = master_key(email, password, new_iterations);
    let mut updated = fixture.clone();
    updated["masterPasswordHash"] = json!(password_hash(&new_master_key, password));
    updated["key"] = json!(encrypt(&user_key, &stretch_key(&new_master_key))?);
    updated["kdf"] = json!(0);
    updated["kdfIterations"] = json!(new_iterations);
    updated["kdfMemory"] = Value::Null;
    updated["kdfParallelism"] = Value::Null;
    Ok(updated)
}

/// Rewrap the same fixture user key for a new master password. Client KDF
/// settings, RSA keys and existing encrypted vault fields remain unchanged.
/// Returned credentials are private and belong only to disposable test accounts.
pub fn rewrap_pbkdf2_password(
    fixture: &Value,
    old_password: &str,
    new_password: &str,
) -> Result<Value, FixtureError> {
    let user_key = pbkdf2_fixture_user_key(fixture, old_password)?;
    let invalid = || FixtureError(Failure::CredentialRewrap);
    let email = fixture["email"].as_str().ok_or_else(invalid)?;
    let iterations = fixture["kdfIterations"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(invalid)?;
    let new_master_key = master_key(email, new_password, iterations);
    let mut updated = fixture.clone();
    updated["masterPasswordHash"] = json!(password_hash(&new_master_key, new_password));
    updated["key"] = json!(encrypt(&user_key, &stretch_key(&new_master_key))?);
    Ok(updated)
}

fn registration_client() -> Result<Client, FixtureError> {
    // Registration bodies include password hashes, wrapped keys, and, in the
    // finish phase, verification tokens. Own the transport policy so callers
    // cannot enable redirects that replay those bodies at another origin.
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| FixtureError(Failure::HttpClient))
}

fn post_registration(server: &str, body: &Value) -> Result<(), FixtureError> {
    let client = registration_client()?;
    let server = server.trim_end_matches('/');
    let response = client
        .post(format!("{server}/api/accounts/register"))
        .timeout(REQUEST_TIMEOUT)
        .json(body)
        .send()
        .map_err(|_| FixtureError(Failure::RegistrationRequest))?;
    if response.status() != StatusCode::NOT_FOUND {
        return if response.status().is_success() {
            Ok(())
        } else {
            Err(FixtureError(Failure::RegistrationRejected))
        };
    }

    post_modern_registration(&client, server, body)
}

/// Explicit modern setup for fixtures whose supported input deliberately falls
/// outside the adapter's separately retained strict legacy embedding API.
pub(crate) fn register_modern_fixture(server: &str, body: &Value) -> Result<(), FixtureError> {
    post_modern_registration(&registration_client()?, server.trim_end_matches('/'), body)
}

// The only callers pass a client built by registration_client; callers cannot
// supply redirect or proxy policy. Keep credentials and tokens in memory only.
fn post_modern_registration(
    client: &Client,
    server: &str,
    body: &Value,
) -> Result<(), FixtureError> {
    // Newer upstream versions use a verification/finish registration pair.
    // Disposable instances with email verification disabled return the token
    // directly. The token never appears in logs or the returned fixture.
    let verification = client
        .post(format!(
            "{server}/identity/accounts/register/send-verification-email"
        ))
        .timeout(REQUEST_TIMEOUT)
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&json!({
            "email": body["email"],
            "name": body["name"],
            "receiveMarketingEmails": false,
        }))
        .send()
        .map_err(|_| FixtureError(Failure::VerificationRequest))?;
    if !verification.status().is_success() || verification.status() == StatusCode::NO_CONTENT {
        return Err(FixtureError(Failure::VerificationUnavailable));
    }
    let token = verification
        .json::<String>()
        .map_err(|_| FixtureError(Failure::VerificationToken))?;
    let mut finish = body.clone();
    finish
        .as_object_mut()
        .ok_or(FixtureError(Failure::RegistrationDocument))?
        .insert("emailVerificationToken".to_owned(), Value::String(token));
    let response = client
        .post(format!("{server}/identity/accounts/register/finish"))
        .timeout(REQUEST_TIMEOUT)
        .json(&finish)
        .send()
        .map_err(|_| FixtureError(Failure::RegistrationRequest))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(FixtureError(Failure::RegistrationRejected))
    }
}

/// Register an ordinary password account and return its registration document.
///
/// This supports both the legacy registration route and newer upstream's
/// verification-token/finish flow; it requires email verification to be disabled
/// on a disposable test server. Redirects and environment proxies are disabled
/// for every registration phase. Returned values contain credentials.
pub fn seed_account(server: &str, email: &str, password: &str) -> Result<Value, FixtureError> {
    let body = registration(email, password, REGISTRATION_ITERATIONS)?;
    post_registration(server, &body)?;
    Ok(body)
}

/// Register an Argon2id account using the same redirect-safe modern fallback.
pub fn seed_account_argon2(
    server: &str,
    email: &str,
    password: &str,
    iterations: u32,
    memory_mib: u32,
    parallelism: u32,
) -> Result<Value, FixtureError> {
    let body = registration_argon2(email, password, iterations, memory_mib, parallelism)?;
    post_registration(server, &body)?;
    Ok(body)
}

/// Register a password account without submitting its generated RSA key pair.
///
/// Fixture-only distinction: the returned private registration document retains
/// `keys`, encrypted for this account's generated user key, so a later account-key
/// initialization can submit that matching pair. The actual registration request
/// omits `keys` entirely. Transport and verification behavior are identical to
/// [`seed_account`]; returned values contain credentials and must stay private.
pub fn seed_account_without_keys(
    server: &str,
    email: &str,
    password: &str,
) -> Result<Value, FixtureError> {
    let body = registration(email, password, REGISTRATION_ITERATIONS)?;
    let mut submitted = body.clone();
    submitted
        .as_object_mut()
        .ok_or(FixtureError(Failure::RegistrationDocument))?
        .remove("keys");
    post_registration(server, &submitted)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_rsa_oaep_wrapping_roundtrips_the_full_key_without_private_key_files() {
        let password = "synthetic-organization-password";
        let account = registration("organization-fixture@example.test", password, 1000).unwrap();
        let key = [0x62; 64];
        let wrapped = organization_key_for_account(&account, &key).unwrap();
        assert!(wrapped.starts_with("4."));
        let ciphertext = STANDARD.decode(&wrapped[2..]).unwrap();
        assert!(ciphertext.len() == 256);
        let user_key = pbkdf2_fixture_user_key(&account, password).unwrap();
        let private_key = decrypt(
            account["keys"]["encryptedPrivateKey"].as_str().unwrap(),
            &user_key,
        )
        .unwrap();
        // The test-only second input file contains ciphertext, never key material.
        let mut encrypted_file = tempfile::NamedTempFile::new().unwrap();
        encrypted_file.write_all(&ciphertext).unwrap();
        let plaintext = openssl(
            &[
                "pkeyutl",
                "-decrypt",
                "-keyform",
                "DER",
                "-inkey",
                "/dev/stdin",
                "-in",
                encrypted_file.path().to_str().unwrap(),
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_oaep_md:sha1",
                "-pkeyopt",
                "rsa_mgf1_md:sha1",
            ],
            Some(&private_key),
        )
        .unwrap();
        assert!(plaintext == key);
    }

    #[test]
    fn organization_rsa_wrapping_rejects_bad_public_input_without_secret_diagnostics() {
        for public in [
            "invalid-base64".to_owned(),
            STANDARD.encode(b"synthetic-private-marker"),
        ] {
            let account = json!({"keys":{"publicKey":public,"encryptedPrivateKey":"private-value-must-not-be-used"}});
            let error = organization_key_for_account(&account, &[0x17; 64])
                .err()
                .unwrap();
            let output = format!("{error} {error:?}");
            assert!(
                !output.contains("synthetic-private-marker")
                    && !output.contains("private-value-must-not-be-used")
            );
        }
    }

    #[test]
    fn argon2_fixture_matches_public_client_proof_vector_and_normalized_salt() {
        // Public deterministic client protocol vector (SDK master_key.rs).
        // The test validates our independent standard-primitive assembly.
        let master = argon2_master_key(" TEST_SALT ", "asdfasdf", 4, 32, 2).unwrap();
        assert!(
            password_hash(&master, "asdfasdf") == "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ="
        );
    }

    #[test]
    fn argon2_fixture_unwraps_authenticated_fields_and_keeps_pbkdf_helpers_strict() {
        let password = "synthetic-Argon-fixture-password";
        let account = registration_argon2(" Fixture-É@EXAMPLE.TEST ", password, 1, 16, 1).unwrap();
        assert!(
            account["email"] == "fixture-é@example.test"
                && account["kdf"] == 1
                && account["kdfIterations"] == 1
                && account["kdfMemory"] == 16
                && account["kdfParallelism"] == 1
        );
        let key = fixture_user_key(&account, password).unwrap();
        let encrypted = encrypted_fixture_value(
            &account,
            password,
            "authenticated Argon fixture\0雪".as_bytes(),
        )
        .unwrap();
        assert!(
            decrypt(&encrypted, &key)
                .is_ok_and(|p| p == "authenticated Argon fixture\0雪".as_bytes())
        );
        assert!(pbkdf2_fixture_user_key(&account, password).is_err());
        assert!(fixture_user_key(&account, "wrong synthetic fixture password").is_err());
    }

    #[test]
    fn argon2_fixture_parameter_failures_are_bounded_and_redacted() {
        for (iterations, memory, parallelism) in
            [(0, 16, 1), (1, 0, 1), (1, 16, 0), (1, u32::MAX, 1)]
        {
            let error = argon2_master_key(
                "private-fixture@example.test",
                "private-fixture-password",
                iterations,
                memory,
                parallelism,
            )
            .err()
            .unwrap();
            let output = format!("{error} {error:?}");
            assert!(!output.contains("private-fixture") && !output.contains("password"));
        }
    }
    use std::{
        error::Error as _,
        io::{BufRead, BufReader, Read},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
    };

    fn hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn key_derivation_matches_the_original_node_crypto_fixture() {
        // Synthetic public test credentials, compared with Node's independent
        // PBKDF2/HMAC implementations. These are not a server account.
        let email = " Alice@Example.Test ";
        let password = "synthetic-fixture-password";
        let master = master_key(email, password, 1_000);
        assert_eq!(
            hex(&master),
            "21c7d7143c4974c9727e5cb444058784342e38964c9b860d19bf4436d012559c"
        );
        let hash = STANDARD
            .decode(master_password_hash(email, password, 1_000))
            .unwrap();
        assert_eq!(
            hex(&hash),
            "94ee0fd9e76199d196ba268ddef73ccd983c5f4b85ca8ff6ffb0d46b47ca20d3"
        );
        let stretched = stretch_key(&master);
        assert_eq!(
            hex(&stretched[..32]),
            "5c03c91b676698a0cff2277e1b61c412c870b9b7f2a7307c60921acbccb9ba54"
        );
        assert_eq!(
            hex(&stretched[32..]),
            "8f0336a7b0914d548ad9d3c2c43ec12c7c2debbd75c7f1671e36df47be821c17"
        );
    }

    #[test]
    fn authenticated_encryption_matches_node_and_rejects_tampering() {
        let key = [0x42; 64];
        let iv = [0x17; 16];
        assert_eq!(
            encrypt_with_iv(b"synthetic fixture payload", &key, &iv),
            "2.FxcXFxcXFxcXFxcXFxcXFw==|v2inTszFHv7DkkpD/6pGgA2foY77dXSP+IkUGs0NTrk=|OS1Ic2SRVyahVEu1loFkaelClbm/kmeXjP30ZlV7aus=",
        );
        for plaintext in [b"".as_slice(), b"one", &[0x56; 64], &[0x78; 73]] {
            let encrypted = encrypt_with_iv(plaintext, &key, &iv);
            assert!(decrypt(&encrypted, &key).is_ok_and(|decrypted| decrypted == plaintext));
            let mut components: Vec<_> = encrypted[2..].split('|').map(str::to_owned).collect();
            let mut ciphertext = STANDARD.decode(&components[1]).unwrap();
            ciphertext[0] ^= 1;
            components[1] = STANDARD.encode(ciphertext);
            assert_eq!(
                decrypt(&format!("2.{}", components.join("|")), &key),
                Err("MAC mismatch")
            );
            assert_eq!(decrypt(&encrypted, &[0x43; 64]), Err("MAC mismatch"));
        }
    }

    #[test]
    fn pbkdf2_rewrap_preserves_the_user_key_rsa_pair_and_original_fixture() {
        let email = " Alice@Example.Test ";
        let password = "synthetic-rewrap-password";
        let user_key = [0x63; 64];
        let old_key = stretch_key(&master_key(email, password, 1_000));
        let fixture = json!({"email":email,"kdf":0,"kdfIterations":1000,
            "masterPasswordHash":master_password_hash(email,password,1000),
            "key":encrypt_with_iv(&user_key,&old_key,&[0x17;16]),
            "keys":{"publicKey":"preserved-public","encryptedPrivateKey":"preserved-private"},
            "extension":{"opaque":"unchanged"}});
        let before = fixture.clone();
        let updated = rewrap_pbkdf2(&fixture, password, 2_000).unwrap();
        assert!(fixture == before && updated["keys"] == fixture["keys"]);
        assert!(
            updated["extension"] == fixture["extension"] && updated["email"] == fixture["email"]
        );
        assert!(updated["masterPasswordHash"] == master_password_hash(email, password, 2_000));
        assert!(updated["kdf"] == 0 && updated["kdfIterations"] == 2_000);
        assert!(updated["kdfMemory"].is_null() && updated["kdfParallelism"].is_null());
        let wrapped = updated["key"].as_str().unwrap();
        let new_key = stretch_key(&master_key(email, password, 2_000));
        assert!(decrypt(wrapped, &new_key).is_ok_and(|key| key == user_key));
        assert!(decrypt(wrapped, &old_key).is_err());
        let encrypted =
            encrypted_pbkdf2_value(&fixture, password, b"existing encrypted item").unwrap();
        let recovered = pbkdf2_fixture_user_key(&updated, password).unwrap();
        assert!(
            decrypt(&encrypted, &recovered).is_ok_and(|value| value == b"existing encrypted item")
        );
        assert!(encrypted_pbkdf2_value(&fixture, "wrong password", b"private").is_err());
    }

    #[test]
    fn password_rewrap_keeps_existing_cipher_decryptable_and_rejects_old_password() {
        let email = " Alice@Example.Test ";
        let old_password = "synthetic-old-password";
        let new_password = "synthetic-new-password";
        let user_key = [0x63; 64];
        let old_key = stretch_key(&master_key(email, old_password, 1_000));
        let fixture = json!({"email":email,"kdf":0,"kdfIterations":1000,
            "kdfMemory":null,"kdfParallelism":null,
            "masterPasswordHash":master_password_hash(email,old_password,1000),
            "key":encrypt_with_iv(&user_key,&old_key,&[0x17;16]),
            "keys":{"publicKey":"preserved-public","encryptedPrivateKey":"preserved-private"},
            "extension":{"opaque":"unchanged"}});
        let before = fixture.clone();
        let encrypted = encrypted_pbkdf2_value(&fixture, old_password, b"existing item").unwrap();
        let updated = rewrap_pbkdf2_password(&fixture, old_password, new_password).unwrap();
        assert!(fixture == before);
        for field in [
            "email",
            "kdf",
            "kdfIterations",
            "kdfMemory",
            "kdfParallelism",
            "keys",
            "extension",
        ] {
            assert!(updated[field] == fixture[field]);
        }
        assert!(updated["masterPasswordHash"] == master_password_hash(email, new_password, 1_000));
        let recovered = pbkdf2_fixture_user_key(&updated, new_password).unwrap();
        assert!(recovered == user_key);
        assert!(decrypt(&encrypted, &recovered).is_ok_and(|value| value == b"existing item"));
        assert!(pbkdf2_fixture_user_key(&updated, old_password).is_err());
        for (value, password) in [(&fixture, "wrong password"), (&Value::Null, old_password)] {
            let Err(error) = rewrap_pbkdf2_password(value, password, new_password) else {
                panic!("Invalid password rewrap accepted.")
            };
            for message in [error.to_string(), format!("{error:?}")] {
                assert!(!message.contains(old_password) && !message.contains(new_password));
                assert!(!message.contains(fixture["key"].as_str().unwrap()));
            }
        }
    }

    #[test]
    fn pbkdf2_rewrap_rejects_bad_proof_tampered_keys_and_invalid_metadata_without_disclosure() {
        let email = "rewrap@example.test";
        let password = "synthetic-private-rewrap-password";
        let key = stretch_key(&master_key(email, password, 1_000));
        let fixture = json!({"email":email,"kdf":0,"kdfIterations":1000,
            "masterPasswordHash":master_password_hash(email,password,1000),
            "key":encrypt_with_iv(&[0x63;64],&key,&[0x17;16])});
        assert!(rewrap_pbkdf2(&fixture, password, 0).is_err());
        assert!(rewrap_pbkdf2(&fixture, "wrong password", 2_000).is_err());
        let mut invalid = Vec::new();
        for (field, value) in [
            ("email", Value::Null),
            ("kdf", json!(1)),
            ("kdfIterations", json!(0)),
            ("kdfIterations", json!(-1)),
            ("kdfIterations", json!(u64::MAX)),
            ("masterPasswordHash", json!("forged-proof")),
            ("key", json!("2.invalid|invalid|invalid")),
            (
                "key",
                json!(encrypt_with_iv(&[0x63; 63], &key, &[0x17; 16])),
            ),
        ] {
            let mut value_fixture = fixture.clone();
            value_fixture[field] = value;
            invalid.push(value_fixture);
        }
        invalid.push(Value::Null);
        for value in invalid {
            let Err(error) = rewrap_pbkdf2(&value, password, 2_000) else {
                panic!("Invalid rewrap fixture accepted.")
            };
            for message in [error.to_string(), format!("{error:?}")] {
                assert!(!message.contains(password) && !message.contains("forged-proof"));
                assert!(!message.contains(fixture["key"].as_str().unwrap()));
            }
        }
    }

    fn tlv<'a>(input: &mut &'a [u8], expected_tag: u8) -> &'a [u8] {
        assert_eq!(input[0], expected_tag);
        let first = input[1];
        let (length, header) = if first < 128 {
            (usize::from(first), 2)
        } else {
            let count = usize::from(first & 0x7f);
            let length = input[2..2 + count]
                .iter()
                .fold(0_usize, |value, byte| (value << 8) | usize::from(*byte));
            (length, 2 + count)
        };
        let value = &input[header..header + length];
        *input = &input[header + length..];
        value
    }

    #[test]
    fn registration_wraps_a_valid_pkcs8_rsa_key_and_matching_spki_public_key() {
        let email = " Alice@Example.Test ";
        let password = "synthetic-fixture-password";
        let body = registration(email, password, 1_000).unwrap();
        assert_eq!(body["email"], "alice@example.test");
        assert_eq!(body["kdf"], 0);
        assert_eq!(body["kdfIterations"], 1_000);
        assert_eq!(
            body["masterPasswordHash"],
            master_password_hash(email, password, 1_000)
        );
        assert!(body["masterPasswordHint"].is_null());
        assert!(body["kdfMemory"].is_null());
        assert!(body["kdfParallelism"].is_null());
        let wrapped_user_key = body["key"].as_str().unwrap();
        let user_key: [u8; 64] = decrypt(
            wrapped_user_key,
            &stretch_key(&master_key(email, password, 1_000)),
        )
        .unwrap()
        .try_into()
        .unwrap_or_else(|_| panic!("The wrapped user key must contain exactly 64 bytes."));
        let private_key = decrypt(
            body["keys"]["encryptedPrivateKey"].as_str().unwrap(),
            &user_key,
        )
        .unwrap();
        let public_key = STANDARD
            .decode(body["keys"]["publicKey"].as_str().unwrap())
            .unwrap();
        let mut top = private_key.as_slice();
        let mut pkcs8 = tlv(&mut top, 0x30);
        assert!(top.is_empty());
        assert_eq!(tlv(&mut pkcs8, 0x02), [0]);
        let algorithm = tlv(&mut pkcs8, 0x30);
        // rsaEncryption OID followed by its NULL parameter.
        assert_eq!(
            algorithm,
            [
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
            ]
        );
        let rsa_private = tlv(&mut pkcs8, 0x04);
        assert!(pkcs8.is_empty());
        let mut rsa_private_slice = rsa_private;
        let mut rsa_fields = tlv(&mut rsa_private_slice, 0x30);
        assert!(rsa_private_slice.is_empty());
        assert_eq!(tlv(&mut rsa_fields, 0x02), [0]);
        let modulus = tlv(&mut rsa_fields, 0x02);
        assert_eq!(modulus.len(), 257); // 2048 bits plus DER sign padding.
        assert_eq!(modulus[0], 0);
        let derived_public = openssl(
            &["pkey", "-pubout", "-inform", "DER", "-outform", "DER"],
            Some(&private_key),
        )
        .unwrap();
        assert!(derived_public == public_key);
        let mut public_slice = public_key.as_slice();
        let mut spki = tlv(&mut public_slice, 0x30);
        assert!(public_slice.is_empty());
        assert_eq!(tlv(&mut spki, 0x30), algorithm);
        assert!(!tlv(&mut spki, 0x03).is_empty());
        assert!(spki.is_empty());
    }

    #[test]
    fn invalid_iterations_and_all_fixture_error_formats_are_redacted() {
        assert!(matches!(
            registration("unused@example.test", "unused-secret", 0),
            Err(FixtureError(Failure::InvalidIterations))
        ));
        for failure in [
            Failure::InvalidIterations,
            Failure::Randomness,
            Failure::Rsa,
            Failure::HttpClient,
            Failure::RegistrationRequest,
            Failure::RegistrationRejected,
            Failure::VerificationRequest,
            Failure::VerificationUnavailable,
            Failure::VerificationToken,
            Failure::RegistrationDocument,
        ] {
            let error = FixtureError(failure);
            assert!(!format!("{error} {error:?}").contains("unused-secret"));
            assert!(error.source().is_none());
        }
        // Command failure output is discarded rather than attached to errors.
        assert!(matches!(
            openssl(&["not-a-real-openssl-operation"], None),
            Err(FixtureError(Failure::Rsa))
        ));
    }

    struct Reply {
        path: &'static str,
        status: u16,
        body: &'static str,
    }

    fn server(replies: Vec<Reply>) -> (String, thread::JoinHandle<Vec<(String, Value)>>) {
        server_with_redirect(replies, None)
    }

    fn server_with_redirect(
        replies: Vec<Reply>,
        location: Option<String>,
    ) -> (String, thread::JoinHandle<Vec<(String, Value)>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                // Public seeding helpers derive a full-strength password fixture
                // before connecting; allow that CPU work on slower CI machines.
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "Fixture origin request timed out."
                            );
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => panic!("Fixture origin listener failed."),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first_line = String::new();
                assert!(reader.read_line(&mut first_line).unwrap() > 0);
                assert_eq!(first_line.split_whitespace().next(), Some("POST"));
                let path = first_line.split_whitespace().nth(1).unwrap().to_owned();
                assert_eq!(path, reply.path);
                let mut length = None;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap();
                    if name.eq_ignore_ascii_case("content-length") {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let mut body = vec![0; length.unwrap()];
                reader.read_exact(&mut body).unwrap();
                requests.push((path, serde_json::from_slice(&body).unwrap()));
                let location_header = location
                    .as_ref()
                    .filter(|_| matches!(reply.status, 307 | 308))
                    .map(|location| format!("Location: {location}\r\n"))
                    .unwrap_or_default();
                write!(stream, "HTTP/1.1 {} Test\r\n{location_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.status, reply.body.len(), reply.body).unwrap();
            }
            requests
        });
        (format!("http://{address}"), handle)
    }

    fn request_fixture() -> Value {
        json!({"email":"fixture@example.test", "name":"fixture", "key":"synthetic-encrypted-key"})
    }

    #[test]
    fn legacy_registration_accepts_success_without_consuming_response_bodies() {
        let (server, handle) = server(vec![Reply {
            path: "/api/accounts/register",
            status: 200,
            body: "not-json",
        }]);
        let body = request_fixture();
        post_registration(&format!("{server}/"), &body).unwrap();
        let requests = handle.join().unwrap();
        assert!(requests[0].1 == body);
    }

    #[test]
    fn keyless_seed_omits_keys_on_wire_and_retains_matching_fixture_material() {
        let (server, handle) = server(vec![Reply {
            path: "/api/accounts/register",
            status: 200,
            body: "not-json",
        }]);
        let body = seed_account_without_keys(&server, "keyless@example.test", "synthetic-password")
            .unwrap();
        let requests = handle.join().unwrap();
        let mut expected = body.clone();
        let keys = expected.as_object_mut().unwrap().remove("keys").unwrap();
        assert!(keys["publicKey"].is_string() && keys["encryptedPrivateKey"].is_string());
        assert!(requests.len() == 1 && requests[0].1 == expected);
        assert!(requests[0].1.get("keys").is_none());
    }

    #[test]
    fn keyless_seed_uses_existing_modern_verification_flow_without_submitting_keys() {
        let (server, handle) = server(vec![
            Reply {
                path: "/api/accounts/register",
                status: 404,
                body: "{}",
            },
            Reply {
                path: "/identity/accounts/register/send-verification-email",
                status: 200,
                body: "\"synthetic-verification-secret\"",
            },
            Reply {
                path: "/identity/accounts/register/finish",
                status: 204,
                body: "",
            },
        ]);
        let body =
            seed_account_without_keys(&server, "keyless-modern@example.test", "synthetic-password")
                .unwrap();
        let requests = handle.join().unwrap();
        assert!(requests.len() == 3 && requests.iter().all(|(_, body)| body.get("keys").is_none()));
        let mut expected = body.clone();
        expected.as_object_mut().unwrap().remove("keys");
        assert!(requests[0].1 == expected);
        expected["emailVerificationToken"] = json!("synthetic-verification-secret");
        assert!(requests[2].1 == expected);
        assert!(body.get("emailVerificationToken").is_none() && body["keys"].is_object());
    }

    #[test]
    fn modern_registration_forwards_the_verification_token_only_to_finish() {
        let (server, handle) = server(vec![
            Reply {
                path: "/api/accounts/register",
                status: 404,
                body: "{}",
            },
            Reply {
                path: "/identity/accounts/register/send-verification-email",
                status: 200,
                body: "\"synthetic-verification-secret\"",
            },
            Reply {
                path: "/identity/accounts/register/finish",
                status: 204,
                body: "",
            },
        ]);
        let body = request_fixture();
        post_registration(&server, &body).unwrap();
        let requests = handle.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].1 == body);
        assert_eq!(
            requests[1].1,
            json!({"email":"fixture@example.test", "name":"fixture", "receiveMarketingEmails":false})
        );
        assert!(requests[2].1["emailVerificationToken"] == "synthetic-verification-secret");
        assert!(body.get("emailVerificationToken").is_none());
    }

    #[test]
    fn explicit_modern_registration_skips_legacy_and_limits_token_to_finish() {
        let (server, handle) = server(vec![
            Reply {
                path: "/identity/accounts/register/send-verification-email",
                status: 200,
                body: "\"synthetic-verification-secret\"",
            },
            Reply {
                path: "/identity/accounts/register/finish",
                status: 200,
                body: "{\"object\":\"registerFinish\"}",
            },
        ]);
        let mut body = request_fixture();
        body["email"] = json!("fixture-café@example.test");
        register_modern_fixture(&server, &body).unwrap();
        let requests = handle.join().unwrap();
        assert!(
            requests.len() == 2
                && requests[0].1["email"] == body["email"]
                && requests[0].1.get("masterPasswordHash").is_none()
        );
        let mut expected = body.clone();
        expected["emailVerificationToken"] = json!("synthetic-verification-secret");
        assert!(requests[1].1 == expected && body.get("emailVerificationToken").is_none());
    }

    #[test]
    fn registration_rejections_and_verification_errors_never_expose_server_bodies() {
        for (replies, expected) in [
            (
                vec![Reply {
                    path: "/api/accounts/register",
                    status: 400,
                    body: "server-secret-marker",
                }],
                Failure::RegistrationRejected,
            ),
            (
                vec![
                    Reply {
                        path: "/api/accounts/register",
                        status: 404,
                        body: "{}",
                    },
                    Reply {
                        path: "/identity/accounts/register/send-verification-email",
                        status: 204,
                        body: "",
                    },
                ],
                Failure::VerificationUnavailable,
            ),
            (
                vec![
                    Reply {
                        path: "/api/accounts/register",
                        status: 404,
                        body: "{}",
                    },
                    Reply {
                        path: "/identity/accounts/register/send-verification-email",
                        status: 403,
                        body: "server-secret-marker",
                    },
                ],
                Failure::VerificationUnavailable,
            ),
            (
                vec![
                    Reply {
                        path: "/api/accounts/register",
                        status: 404,
                        body: "{}",
                    },
                    Reply {
                        path: "/identity/accounts/register/send-verification-email",
                        status: 200,
                        body: "{\"token\":\"server-secret-marker\"}",
                    },
                ],
                Failure::VerificationToken,
            ),
            (
                vec![
                    Reply {
                        path: "/api/accounts/register",
                        status: 404,
                        body: "{}",
                    },
                    Reply {
                        path: "/identity/accounts/register/send-verification-email",
                        status: 200,
                        body: "\"synthetic-verification-secret\"",
                    },
                    Reply {
                        path: "/identity/accounts/register/finish",
                        status: 400,
                        body: "server-secret-marker",
                    },
                ],
                Failure::RegistrationRejected,
            ),
        ] {
            let (server, handle) = server(replies);
            let error = post_registration(&server, &request_fixture()).unwrap_err();
            assert!(error.0 == expected);
            assert!(!format!("{error} {error:?}").contains("server-secret-marker"));
            assert!(!format!("{error} {error:?}").contains("synthetic-verification-secret"));
            handle.join().unwrap();
        }
    }

    #[test]
    fn transport_failures_are_static_and_do_not_echo_the_server_url() {
        let error =
            post_registration("not-a-url-with-secret-marker", &request_fixture()).unwrap_err();
        assert!(error.0 == Failure::RegistrationRequest);
        assert!(!format!("{error} {error:?}").contains("secret-marker"));
    }

    fn redirect_destination() -> (String, Arc<AtomicBool>, thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            let mut requests = 0;
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            while !thread_stop.load(Ordering::Acquire) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "Redirect destination observation timed out."
                );
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        requests += 1;
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut length = 0;
                        loop {
                            let mut line = String::new();
                            assert!(reader.read_line(&mut line).unwrap() > 0);
                            if line == "\r\n" {
                                break;
                            }
                            if let Some((name, value)) = line.split_once(':')
                                && name.eq_ignore_ascii_case("content-length")
                            {
                                length = value.trim().parse::<usize>().unwrap();
                            }
                        }
                        // Drain any replayed body without exposing its contents.
                        let mut discarded = vec![0; length];
                        reader.read_exact(&mut discarded).unwrap();
                        let body = "\"synthetic-verification-secret\"";
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => panic!("Redirect destination listener failed."),
                }
            }
            requests
        });
        (format!("http://{address}/redirected"), stop, handle)
    }

    fn rejects_cross_origin_redirects(phase: usize) {
        let paths = [
            "/api/accounts/register",
            "/identity/accounts/register/send-verification-email",
            "/identity/accounts/register/finish",
        ];
        let mut forwarded_statuses = Vec::new();
        let mut accepted_statuses = Vec::new();
        for status in [307, 308] {
            let (destination, stop, destination_handle) = redirect_destination();
            let mut replies = Vec::new();
            if phase > 0 {
                replies.push(Reply {
                    path: paths[0],
                    status: 404,
                    body: "{}",
                });
            }
            if phase > 1 {
                replies.push(Reply {
                    path: paths[1],
                    status: 200,
                    body: "\"synthetic-verification-secret\"",
                });
            }
            replies.push(Reply {
                path: paths[phase],
                status,
                body: "",
            });
            let (origin, origin_handle) = server_with_redirect(replies, Some(destination));
            let body = json!({
                "email":"fixture@example.test",
                "name":"fixture",
                "masterPasswordHash":"synthetic-password-hash",
                "key":"synthetic-encrypted-key",
            });
            let result = post_registration(&origin, &body);
            origin_handle.join().unwrap();
            stop.store(true, Ordering::Release);
            if destination_handle.join().unwrap() != 0 {
                forwarded_statuses.push(status);
            }
            if result.is_ok() {
                accepted_statuses.push(status);
            }
        }
        assert!(
            forwarded_statuses.is_empty(),
            "Registration forwarded cross-origin requests for HTTP {forwarded_statuses:?}."
        );
        assert!(
            accepted_statuses.is_empty(),
            "Registration accepted redirect responses for HTTP {accepted_statuses:?}."
        );
    }

    #[test]
    fn legacy_registration_rejects_cross_origin_307_and_308_redirects() {
        rejects_cross_origin_redirects(0);
    }

    #[test]
    fn keyless_seed_rejects_redirects_without_replaying_registration_material() {
        for status in [307, 308] {
            let (destination, stop, destination_handle) = redirect_destination();
            let (origin, origin_handle) = server_with_redirect(
                vec![Reply {
                    path: "/api/accounts/register",
                    status,
                    body: "",
                }],
                Some(destination),
            );
            let result = seed_account_without_keys(
                &origin,
                "keyless-redirect@example.test",
                "synthetic-password",
            );
            let requests = origin_handle.join().unwrap();
            stop.store(true, Ordering::Release);
            assert!(destination_handle.join().unwrap() == 0);
            assert!(requests.len() == 1 && requests[0].1.get("keys").is_none());
            let error = result.err().unwrap();
            assert!(error.0 == Failure::RegistrationRejected);
            assert!(!format!("{error} {error:?}").contains("synthetic-password"));
        }
    }

    #[test]
    fn verification_registration_rejects_cross_origin_307_and_308_redirects() {
        rejects_cross_origin_redirects(1);
    }

    #[test]
    fn finish_registration_rejects_cross_origin_307_and_308_redirects() {
        rejects_cross_origin_redirects(2);
    }
}
