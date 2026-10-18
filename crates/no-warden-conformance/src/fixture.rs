//! Password-account fixtures using the same key derivation and encrypted-key
//! formats as an ordinary Bitwarden registration.
//!
//! OpenSSL supplies RSA key generation only. Password hashing, HKDF expansion,
//! and authenticated encryption are implemented here in Rust. Keys and server
//! response bodies are never included in errors or written to temporary files.

use std::{
    fmt,
    io::Write,
    process::{Command, Stdio},
    time::Duration,
};

use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use reqwest::{StatusCode, blocking::Client};
use serde_json::{Value, json};
use sha2::Sha256;

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

fn encrypt(plaintext: &[u8], key: &[u8; 64]) -> Result<String, FixtureError> {
    let mut iv = [0; 16];
    OsRng
        .try_fill_bytes(&mut iv)
        .map_err(|_| FixtureError(Failure::Randomness))?;
    Ok(encrypt_with_iv(plaintext, key, &iv))
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

/// Generate a password-account registration with a random user key and RSA
/// key pair. Returned values contain encrypted credentials and must stay private.
pub fn registration(email: &str, password: &str, iterations: u32) -> Result<Value, FixtureError> {
    if iterations == 0 {
        return Err(FixtureError(Failure::InvalidIterations));
    }
    let normalized_email = email.trim().to_lowercase();
    let master_key = master_key(&normalized_email, password, iterations);
    let stretched_key = stretch_key(&master_key);
    let mut user_key = [0; 64];
    OsRng
        .try_fill_bytes(&mut user_key)
        .map_err(|_| FixtureError(Failure::Randomness))?;
    let (public_key, private_key) = rsa_key_pair()?;
    Ok(json!({
        "email": normalized_email,
        "name": "no-warden compatibility test",
        "masterPasswordHash": password_hash(&master_key, password),
        "masterPasswordHint": null,
        "key": encrypt(&user_key, &stretched_key)?,
        "keys": {
            "publicKey": STANDARD.encode(public_key),
            "encryptedPrivateKey": encrypt(&private_key, &user_key)?,
        },
        "kdf": 0,
        "kdfIterations": iterations,
        "kdfMemory": null,
        "kdfParallelism": null,
        "organizationUserId": null,
        "referenceData": null,
    }))
}

fn post_registration(server: &str, body: &Value) -> Result<(), FixtureError> {
    // Registration bodies include password hashes, wrapped keys, and, in the
    // finish phase, verification tokens. Own the transport policy so callers
    // cannot enable redirects that replay those bodies at another origin.
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| FixtureError(Failure::HttpClient))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockDecryptMut;
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

    fn decrypt(cipher_string: &str, key: &[u8; 64]) -> Result<Vec<u8>, &'static str> {
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
        let mut verifier =
            Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|_| "invalid MAC key")?;
        verifier.update(&iv);
        verifier.update(&ciphertext);
        verifier.verify_slice(&mac).map_err(|_| "MAC mismatch")?;
        let iv: [u8; 16] = iv.try_into().map_err(|_| "invalid IV length")?;
        cbc::Decryptor::<aes::Aes256>::new(key[..32].into(), (&iv).into())
            .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
            .map_err(|_| "invalid padding")
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
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
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
    fn verification_registration_rejects_cross_origin_307_and_308_redirects() {
        rejects_cross_origin_redirects(1);
    }

    #[test]
    fn finish_registration_rejects_cross_origin_307_and_308_redirects() {
        rejects_cross_origin_redirects(2);
    }
}
