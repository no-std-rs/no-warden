//! Portable ordinary registration with email delivery disabled.
//!
//! Vaultwarden58a980f850464f7d9cdc99a765df36f0a3308b91 and release1.37.4
//! (7c188967e7a467b19b2757bc3326f9cf3ccae327) have identical verification,
//! registration DTO/handler, and verification-claim semantics for this flow.
//! Sources: identity.rs1037–1104, accounts.rs83–446, auth.rs130–147/451–475;
//! Rocket0.5.1 Accept::preferred and MediaType equality. Legacy BODY means the
//! old DTO on the modern finish route, not a legacy registration-route claim.
//! SMTP, invitations/emergency access, signup restrictions, token expiry beyond
//! decoded claims, arbitrary email syntax and exhaustive KDF variants are separate.
//! All diagnostics and private receipts exclude credentials, bodies and tokens.

use crate::fixture;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Method, blocking::Client};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    time::Duration,
};
use uuid::Uuid;

type Case = fn(&mut Suite) -> Result<(), RegistrationError>;
const CASES: [(&str, Case); 8] = [
    (
        "registration_verification_accept_and_claims",
        registration_verification_accept_and_claims,
    ),
    (
        "registration_legacy_finish_and_account_authority",
        registration_legacy_finish_and_account_authority,
    ),
    (
        "registration_current_nested_aliases_and_legacy_precedence",
        registration_current_nested_aliases_and_legacy_precedence,
    ),
    (
        "registration_name_authority_and_utf8_boundaries",
        registration_name_authority_and_utf8_boundaries,
    ),
    (
        "registration_verification_schema_and_syntax_guards",
        registration_verification_schema_and_syntax_guards,
    ),
    (
        "registration_finish_schema_and_proof_guards",
        registration_finish_schema_and_proof_guards,
    ),
    (
        "registration_kdf_validation_and_retry",
        registration_kdf_validation_and_retry,
    ),
    (
        "registration_duplicate_finish_and_account_isolation",
        registration_duplicate_finish_and_account_isolation,
    ),
];
const VERIFY: &str = "/identity/accounts/register/send-verification-email";
const FINISH: &str = "/identity/accounts/register/finish";
const PRELOGIN: &str = "/identity/accounts/prelogin";
const MAX_REPLY_BYTES: u64 = 16 * 1024 * 1024;

/// Static errors retain no account identifiers, passwords, tokens, keys or bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationError(&'static str);
impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for RegistrationError {}
fn require(condition: bool, message: &'static str) -> Result<(), RegistrationError> {
    if condition {
        Ok(())
    } else {
        Err(RegistrationError(message))
    }
}
fn text(value: &Value) -> Result<&str, RegistrationError> {
    value
        .as_str()
        .ok_or(RegistrationError("Required registration string missing"))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
    content_type: String,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, RegistrationError> {
        if self.status != expected {
            eprintln!(
                "Registration HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Registration HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, RegistrationError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| RegistrationError("Registration response was not valid JSON"))
    }
    fn token(self, json_response: bool) -> Result<String, RegistrationError> {
        let json_type = self
            .content_type
            .split(';')
            .next()
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json"));
        require(
            json_type == json_response,
            "Verification response media type did not follow Accept preference",
        )?;
        if json_response {
            serde_json::from_slice(&self.bytes)
                .map_err(|_| RegistrationError("Verification response was not a JSON token string"))
        } else {
            String::from_utf8(self.bytes)
                .map_err(|_| RegistrationError("Verification response was not a UTF-8 token"))
        }
    }
    fn rejected(self, expected: u16) -> Result<(), RegistrationError> {
        let reply = self.status(expected)?;
        // Rocket's JSON guards may return non-JSON catchers. Their status is the
        // assertion; any JSON error still must not expose successful authority.
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                value.get("access_token").is_none()
                    && value.get("refresh_token").is_none()
                    && value.get("emailVerificationToken").is_none(),
                "Rejected registration returned credential authority",
            )?;
        }
        Ok(())
    }
}
#[derive(Clone, PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
    keys: Value,
    devices: Value,
    revision: i64,
}
#[derive(Clone)]
struct Account {
    fixture: Value,
    token: String,
    verification: String,
    baseline: Snapshot,
}
#[derive(Default)]
struct PeerCounts {
    public: usize,
    identity: usize,
}
#[derive(Clone, Copy, Default)]
enum BodyType<'a> {
    #[default]
    Json,
    Missing,
    Other(&'a str),
}
#[derive(Clone, Copy, Default)]
struct Headers<'a> {
    bearer: Option<&'a str>,
    accept: Option<&'a str>,
    body_type: BodyType<'a>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt<'a> {
    schema_version: u8,
    status: &'static str,
    cases: &'a [&'static str],
    passed_cases: usize,
    expected_cases: usize,
    http_requests: usize,
    verification_requests: usize,
    finish_requests: usize,
    prelogin_requests: usize,
    identity_requests: usize,
    successful_logins: usize,
    max_public_requests_per_peer: usize,
    max_identity_requests_per_peer: usize,
}
struct Suite {
    server: String,
    origin: String,
    clients: BTreeMap<u8, Client>,
    peers: BTreeMap<u8, PeerCounts>,
    peer: u8,
    accounts: Vec<Account>,
    requests: usize,
    verifications: usize,
    finishes: usize,
    prelogins: usize,
    identity_requests: usize,
    logins: usize,
    passed: Vec<&'static str>,
    receipt: Option<fs::File>,
    finished: bool,
}
impl Drop for Suite {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.write_receipt("failed");
        }
    }
}
impl Suite {
    fn write_receipt(&mut self, status: &'static str) -> Result<(), RegistrationError> {
        if let Some(file) = &mut self.receipt {
            let receipt = Receipt {
                schema_version: 1,
                status,
                cases: &self.passed,
                passed_cases: self.passed.len(),
                expected_cases: CASES.len(),
                http_requests: self.requests,
                verification_requests: self.verifications,
                finish_requests: self.finishes,
                prelogin_requests: self.prelogins,
                identity_requests: self.identity_requests,
                successful_logins: self.logins,
                max_public_requests_per_peer: self
                    .peers
                    .values()
                    .map(|p| p.public)
                    .max()
                    .unwrap_or(0),
                max_identity_requests_per_peer: self
                    .peers
                    .values()
                    .map(|p| p.identity)
                    .max()
                    .unwrap_or(0),
            };
            let bytes = serde_json::to_vec(&receipt)
                .map_err(|_| RegistrationError("Registration receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| RegistrationError("Registration receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| RegistrationError("Registration receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| RegistrationError("Registration receipt write failed"))?;
            file.sync_all()
                .map_err(|_| RegistrationError("Registration receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, RegistrationError> {
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|s| s.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RegistrationError("Registration response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY_BYTES,
            "Registration response exceeded capture limit",
        )?;
        Ok(Reply {
            status,
            bytes,
            content_type,
        })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        headers: Headers<'_>,
        body: Option<&[u8]>,
    ) -> Result<Reply, RegistrationError> {
        self.requests += 1;
        let mut request = self
            .clients
            .get(&self.peer)
            .ok_or(RegistrationError("Registration peer fixture unavailable"))?
            .request(method, format!("{}{path}", self.server));
        if let Some(token) = headers.bearer {
            request = request.bearer_auth(token);
        }
        if let Some(accept) = headers.accept {
            request = request.header(reqwest::header::ACCEPT, accept);
        }
        if let Some(body) = body {
            let content_type = match headers.body_type {
                BodyType::Json => Some("application/json"),
                BodyType::Missing => None,
                BodyType::Other(value) => Some(value),
            };
            if let Some(content_type) = content_type {
                request = request.header(reqwest::header::CONTENT_TYPE, content_type);
            }
            request = request.body(body.to_vec());
        }
        Self::read(
            request
                .send()
                .map_err(|_| RegistrationError("Registration HTTP request failed"))?,
        )
    }
    fn json(&mut self, path: &str, token: Option<&str>) -> Result<Value, RegistrationError> {
        self.request(
            Method::GET,
            path,
            Headers {
                bearer: token,
                ..Headers::default()
            },
            None,
        )?
        .status(200)?
        .json()
    }
    fn public(
        &mut self,
        path: &str,
        body: &[u8],
        headers: Headers<'_>,
    ) -> Result<Reply, RegistrationError> {
        let count = &mut self.peers.entry(self.peer).or_default().public;
        *count += 1;
        // Count guard rejections as well: the conservative bound does not rely
        // on guessing which raw fixture enters upstream's public handler.
        require(
            *count <= 50,
            "Registration per-peer public request budget exceeded",
        )?;
        match path {
            VERIFY => self.verifications += 1,
            FINISH => self.finishes += 1,
            PRELOGIN => self.prelogins += 1,
            _ => {
                return Err(RegistrationError(
                    "Unclassified public registration fixture route",
                ));
            }
        }
        self.request(Method::POST, path, headers, Some(body))
    }
    fn verify(
        &mut self,
        email: &str,
        name: Option<&Value>,
        accept: Option<&str>,
        json_response: bool,
    ) -> Result<String, RegistrationError> {
        let mut body = json!({"email":email,"receiveMarketingEmails":false,"ignored":true});
        if let Some(name) = name {
            body["name"] = name.clone();
        }
        let token = self
            .public(
                VERIFY,
                body.to_string().as_bytes(),
                Headers {
                    accept,
                    bearer: Some("ignored-verification-bearer"),
                    ..Headers::default()
                },
            )?
            .status(200)?
            .token(json_response)?;
        self.check_claims(&token, email, name.unwrap_or(&Value::Null))?;
        Ok(token)
    }
    fn verify_without_accept(
        &mut self,
        email: &str,
        name: &Value,
    ) -> Result<String, RegistrationError> {
        // Reqwest injects Accept:*/* even when no request header was supplied.
        // Use one bounded direct HTTP request to actually omit that header.
        let url = reqwest::Url::parse(&self.server)
            .map_err(|_| RegistrationError("Registration direct HTTP configuration invalid"))?;
        let address = SocketAddr::from((
            [127, 0, 0, 1],
            url.port_or_known_default()
                .ok_or(RegistrationError("Registration test port missing"))?,
        ));
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(15))
            .map_err(|_| RegistrationError("Direct verification connection failed"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|_| RegistrationError("Direct verification read timeout failed"))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|_| RegistrationError("Direct verification write timeout failed"))?;
        let body = json!({"email":email,"name":name}).to_string();
        let header = format!(
            "POST {VERIFY} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        self.requests += 1;
        self.verifications += 1;
        let count = &mut self.peers.entry(1).or_default().public;
        *count += 1;
        require(
            *count <= 50,
            "Registration direct peer public budget exceeded",
        )?;
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(body.as_bytes()))
            .map_err(|_| RegistrationError("Direct verification write failed"))?;
        let mut bytes = Vec::new();
        stream
            .take(MAX_REPLY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RegistrationError("Direct verification read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY_BYTES,
            "Direct verification reply exceeded capture limit",
        )?;
        let token = raw_http_reply(&bytes)?.status(200)?.token(false)?;
        self.check_claims(&token, email, name)?;
        Ok(token)
    }
    fn check_claims(
        &self,
        token: &str,
        email: &str,
        name: &Value,
    ) -> Result<(), RegistrationError> {
        let claims = jwt_claims(token)?;
        require(
            claims["sub"] == email
                && claims["name"] == *name
                && claims["verified"] == false
                && claims["iss"] == format!("{}|register_verify", self.origin)
                && claims["exp"]
                    .as_i64()
                    .zip(claims["nbf"].as_i64())
                    .is_some_and(|(exp, nbf)| exp - nbf == 1800),
            "Verification claims changed raw email, name, purpose, delivery state or thirty-minute lifetime",
        )
    }
    fn finish_raw(&mut self, body: &[u8], status: u16) -> Result<(), RegistrationError> {
        let reply = self.public(
            FINISH,
            body,
            Headers {
                accept: Some("application/json"),
                bearer: Some("ignored-finish-bearer"),
                ..Headers::default()
            },
        )?;
        if status == 200 {
            require(
                reply.status(200)?.json()? == json!({"object":"registerFinish"}),
                "Registration finish response differed from its exact one-field projection",
            )
        } else {
            reply.rejected(status)
        }
    }
    fn finish(&mut self, body: &Value, status: u16) -> Result<(), RegistrationError> {
        self.finish_raw(body.to_string().as_bytes(), status)
    }
    fn login(&mut self, fixture: &Value) -> Result<Value, RegistrationError> {
        let count = &mut self.peers.entry(1).or_default().identity;
        *count += 1;
        require(
            *count <= 10,
            "Registration identity request budget exceeded",
        )?;
        self.identity_requests += 1;
        self.requests += 1;
        let device = format!("Registration-Login-{}", Uuid::new_v4());
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&fixture["email"])?),
            ("password", text(&fixture["masterPasswordHash"])?),
            ("deviceIdentifier", device.as_str()),
            ("deviceName", "Registration comparison"),
            ("deviceType", "25"),
        ];
        let client = self
            .clients
            .get(&1)
            .ok_or(RegistrationError("Registration login peer unavailable"))?;
        let response = Self::read(
            client
                .post(format!("{}/identity/connect/token", self.server))
                .form(&form)
                .send()
                .map_err(|_| RegistrationError("Registration account login request failed"))?,
        )?
        .status(200)?
        .json()?;
        self.logins += 1;
        require(
            response["Key"] == fixture["key"]
                && response["PrivateKey"] == fixture["keys"]["encryptedPrivateKey"]
                && response["scope"] == "api offline_access"
                && response["refresh_token"].is_string(),
            "New account login lost its encrypted keys or password authority",
        )?;
        Ok(response)
    }
    fn snapshot(&mut self, token: &str) -> Result<Snapshot, RegistrationError> {
        let profile = self.json("/api/accounts/profile", Some(token))?;
        let sync = self.json("/api/sync", Some(token))?;
        let keys = self.json("/api/accounts/keys", Some(token))?;
        let devices = self.json("/api/devices", Some(token))?;
        let revision = self
            .json("/api/accounts/revision-date", Some(token))?
            .as_i64()
            .ok_or(RegistrationError("Registration account revision missing"))?;
        Ok(Snapshot {
            profile,
            sync,
            keys,
            devices,
            revision,
        })
    }
    fn register(
        &mut self,
        fixture: &Value,
        mut body: Value,
        token: &str,
        name: &str,
    ) -> Result<(), RegistrationError> {
        body["emailVerificationToken"] = json!(token);
        self.finish(&body, 200)?;
        let tokens = self.login(fixture)?;
        let bearer = text(&tokens["access_token"])?.to_owned();
        let baseline = self.snapshot(&bearer)?;
        require(
            Uuid::parse_str(text(&baseline.profile["id"])?).is_ok()
                && baseline.profile["email"] == text(&fixture["email"])?.to_lowercase()
                && baseline.profile["name"] == name
                && baseline.profile["emailVerified"] == true
                && baseline.profile["key"] == fixture["key"]
                && baseline.profile["privateKey"] == fixture["keys"]["encryptedPrivateKey"]
                && baseline.keys["publicKey"] == fixture["keys"]["publicKey"]
                && baseline.keys["privateKey"] == fixture["keys"]["encryptedPrivateKey"]
                && baseline.sync["profile"] == baseline.profile
                && baseline.sync["folders"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
                && baseline.sync["ciphers"]
                    .as_array()
                    .is_some_and(Vec::is_empty),
            "New account did not preserve token name, normalized email, keys or empty personal vault",
        )?;
        self.accounts.push(Account {
            fixture: fixture.clone(),
            token: bearer,
            verification: token.to_owned(),
            baseline,
        });
        Ok(())
    }
    fn check_accounts(&mut self) -> Result<(), RegistrationError> {
        for account in self.accounts.clone() {
            require(
                self.snapshot(&account.token)? == account.baseline,
                "Registration read or rejection changed an existing account, vault, keys, session, device or revision",
            )?;
        }
        Ok(())
    }
}

fn new_fixture(iterations: u32) -> Result<Value, RegistrationError> {
    let email = format!("registration-{}@example.test", Uuid::new_v4());
    let password = format!("Nw!{}", Uuid::new_v4());
    fixture::registration(&email, &password, iterations)
        .map_err(|_| RegistrationError("Private registration fixture generation failed"))
}
fn jwt_claims(token: &str) -> Result<Value, RegistrationError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or(RegistrationError("Verification token was not a JWT"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| RegistrationError("Verification JWT payload could not be decoded"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| RegistrationError("Verification JWT payload was not valid JSON"))
}
fn raw_http_reply(bytes: &[u8]) -> Result<Reply, RegistrationError> {
    let split = bytes
        .windows(4)
        .position(|p| p == b"\r\n\r\n")
        .ok_or(RegistrationError(
            "Direct verification HTTP headers incomplete",
        ))?;
    let headers = std::str::from_utf8(&bytes[..split])
        .map_err(|_| RegistrationError("Direct verification HTTP headers invalid"))?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(RegistrationError("Direct verification HTTP status invalid"))?;
    let mut content_type = String::new();
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-type") {
                content_type = value.trim().to_owned();
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value
                    .split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("chunked"));
            }
            if name.eq_ignore_ascii_case("content-length") {
                length =
                    Some(value.trim().parse::<usize>().map_err(|_| {
                        RegistrationError("Direct verification HTTP length invalid")
                    })?);
            }
        }
    }
    let body = &bytes[split + 4..];
    let mut output = Vec::new();
    if chunked {
        let mut remaining = body;
        loop {
            let split =
                remaining
                    .windows(2)
                    .position(|p| p == b"\r\n")
                    .ok_or(RegistrationError(
                        "Direct verification HTTP chunk incomplete",
                    ))?;
            let line = std::str::from_utf8(&remaining[..split])
                .map_err(|_| RegistrationError("Direct verification HTTP chunk invalid"))?;
            let size = usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|_| RegistrationError("Direct verification HTTP chunk length invalid"))?;
            if size == 0 {
                break;
            }
            remaining = &remaining[split + 2..];
            require(
                size <= remaining.len()
                    && remaining.get(size..size.saturating_add(2)) == Some(b"\r\n"),
                "Direct verification HTTP chunk body incomplete",
            )?;
            output.extend_from_slice(&remaining[..size]);
            remaining = &remaining[size + 2..];
        }
    } else {
        let size = length.unwrap_or(body.len());
        require(
            size == body.len(),
            "Direct verification HTTP body length differed",
        )?;
        output.extend_from_slice(body);
    }
    Ok(Reply {
        status,
        bytes: output,
        content_type,
    })
}
fn current_body(fixture: &Value, aliases: bool) -> Result<Value, RegistrationError> {
    let salt = text(&fixture["email"])?.trim().to_lowercase();
    if aliases {
        let kdf = json!({"kdfType":fixture["kdf"],"iterations":fixture["kdfIterations"],"memory":null,"parallelism":null});
        Ok(
            json!({"email":fixture["email"],"userAsymmetricKeys":fixture["keys"],
            "MasterPasswordAuthentication":{"Kdf":kdf,"Salt":salt,"MasterPasswordAuthenticationHash":fixture["masterPasswordHash"]},
            "MasterPasswordUnlock":{"kdf":kdf,"salt":salt,"masterKeyWrappedUserKey":fixture["key"]}}),
        )
    } else {
        let kdf = json!({"kdf":fixture["kdf"],"kdfIterations":fixture["kdfIterations"],"kdfMemory":null,"kdfParallelism":null});
        Ok(json!({"email":fixture["email"],"keys":fixture["keys"],
            "masterPasswordAuthentication":{"kdf":kdf,"salt":salt,"hash":fixture["masterPasswordHash"]},
            "masterPasswordUnlock":{"kdf":kdf,"salt":salt,"key":fixture["key"]}}))
    }
}
fn with_token(mut body: Value, token: &str) -> Value {
    body["emailVerificationToken"] = json!(token);
    body
}

fn registration_verification_accept_and_claims(s: &mut Suite) -> Result<(), RegistrationError> {
    let email = format!("Registration-Accept-{}@example.test", Uuid::new_v4());
    let name = json!("  raw token name\0雪  ");
    let cases = [
        (None, false),
        (Some("application/json"), true),
        (Some("text/plain"), false),
        (Some("*/*"), false),
        (Some("application/*"), false),
        (Some("application/*+json"), false),
        (Some("application/problem+json"), false),
        (Some("application/json; charset=utf-8"), true),
        (Some("APPLICATION/JSON"), true),
        (Some("text/plain, application/json"), false),
        (Some("application/json, text/plain"), true),
        (Some("application/json;q=0.1, text/plain;q=0.9"), false),
        (Some("text/plain;q=0.1, application/json;q=0.9"), true),
        (Some("application/json;q=1, text/plain"), false),
        (Some("*/*;q=1, application/json;q=0"), true),
        (Some("application/json;q=0"), true),
        // Rocket's quoted-string parser keeps separators and escaped quotes
        // inside a parameter. MediaType equality still compares only essence.
        (Some(r#"application/json; a=";,;""#), true),
        (Some(r#"application/json; a="a\";,b""#), true),
        (Some(r#"application/json; a=""; b=c"#), true),
        // Only the first parameter supplies q, and values longer than five
        // bytes are unweighted, even when nonnumeric or outside 0..=1.
        (Some("application/json;a=b;q=0.1, text/plain;q=0.9"), true),
        (
            Some("application/json;a=b;q=invalid, text/plain;q=0.9"),
            true,
        ),
        (Some("application/json;q=0.1234, text/plain;q=0.9"), true),
        (Some("application/json;q=xxxxxx, text/plain;q=0.9"), true),
        (Some("application/json;q=2.0000, text/plain;q=0.9"), true),
        (Some(r#"application/json;q="0.1", text/plain;q=0.9"#), false),
        (
            Some("application/json;q=0.1;q=0.9, text/plain;q=0.5"),
            false,
        ),
        // Invalid short q values invalidate Accept, so the optional guard is
        // absent and verification returns its plain-string representation.
        (Some("application/json;q=1.1"), false),
        (Some("application/json;q=oops"), false),
    ];
    for (index, (accept, json_response)) in cases.into_iter().enumerate() {
        let result = if accept.is_none() {
            s.verify_without_accept(&email, &name)
        } else {
            s.verify(&email, Some(&name), accept, json_response)
        };
        if result.is_err() {
            eprintln!("Registration Accept fixture index {index}, method POST");
        }
        let token = result?;
        s.request(
            Method::GET,
            "/api/accounts/profile",
            Headers {
                bearer: Some(&token),
                ..Headers::default()
            },
            None,
        )?
        .status(401)?;
    }
    Ok(())
}
fn registration_legacy_finish_and_account_authority(
    s: &mut Suite,
) -> Result<(), RegistrationError> {
    let fixture = new_fixture(600_000)?;
    let raw_email = text(&fixture["email"])?.to_uppercase();
    let name = "Token-owned registration name";
    let token = s.verify(
        &raw_email,
        Some(&json!(name)),
        Some("application/json"),
        true,
    )?;
    let mut body = fixture.clone();
    body["email"] = json!(raw_email);
    body["name"] = json!({"untrusted":"ignored"});
    body["id"] = json!(Uuid::new_v4().to_string());
    body["enabled"] = json!(false);
    body["emailVerified"] = json!(true);
    body["futureRegistrationField"] = json!(["ignored", null]);
    s.register(&fixture, body, &token, name)
}
fn registration_current_nested_aliases_and_legacy_precedence(
    s: &mut Suite,
) -> Result<(), RegistrationError> {
    for aliases in [false, true] {
        let fixture = new_fixture(600_000)?;
        let name = "Nested registration";
        let token = s.verify(
            text(&fixture["email"])?,
            Some(&json!(name)),
            Some("application/json"),
            true,
        )?;
        s.register(&fixture, current_body(&fixture, aliases)?, &token, name)?;
    }
    let fixture = new_fixture(600_000)?;
    let name = "Legacy variant wins";
    let token = s.verify(
        text(&fixture["email"])?,
        Some(&json!(name)),
        Some("application/json"),
        true,
    )?;
    let mut body = fixture.clone();
    let object = body
        .as_object_mut()
        .ok_or(RegistrationError("Legacy fixture object missing"))?;
    for (old, new) in [
        ("kdf", "kdfType"),
        ("kdfIterations", "iterations"),
        ("key", "userSymmetricKey"),
        ("masterPasswordHash", "master_password_hash"),
        ("keys", "userAsymmetricKeys"),
    ] {
        let value = object
            .remove(old)
            .ok_or(RegistrationError("Legacy alias fixture field missing"))?;
        object.insert(new.into(), value);
    }
    body["masterPasswordAuthentication"] = json!({"kdf":{"kdf":1,"kdfIterations":1,"kdfMemory":64,"kdfParallelism":4},"salt":"wrong-salt","hash":"wrong-proof"});
    body["masterPasswordUnlock"] =
        json!({"kdf":{"kdf":0,"kdfIterations":100000},"salt":"different-salt","key":"wrong-key"});
    s.register(&fixture, body, &token, name)
}
fn registration_name_authority_and_utf8_boundaries(s: &mut Suite) -> Result<(), RegistrationError> {
    let fixture = new_fixture(600_000)?;
    let email = text(&fixture["email"])?;
    s.verify(email, None, Some("application/json"), true)?;
    let token = s.verify(email, Some(&Value::Null), Some("application/json"), true)?;
    s.register(&fixture, fixture.clone(), &token, email)?;
    let fixture = new_fixture(600_000)?;
    let token = s.verify(
        text(&fixture["email"])?,
        Some(&json!("")),
        Some("application/json"),
        true,
    )?;
    s.register(&fixture, fixture.clone(), &token, "")?;
    let fixture = new_fixture(600_000)?;
    let oversized = "雪".repeat(17);
    let valid = format!("{}\0x", "雪".repeat(16));
    require(
        oversized.len() == 51 && valid.len() == 50,
        "UTF-8 name boundary fixture invalid",
    )?;
    let token = s.verify(
        text(&fixture["email"])?,
        Some(&json!(oversized)),
        Some("application/json"),
        true,
    )?;
    s.finish(&with_token(fixture.clone(), &token), 400)?;
    let token = s.verify(
        text(&fixture["email"])?,
        Some(&json!(valid)),
        Some("application/json"),
        true,
    )?;
    s.register(&fixture, fixture.clone(), &token, &valid)
}
fn registration_verification_schema_and_syntax_guards(
    s: &mut Suite,
) -> Result<(), RegistrationError> {
    let email = format!("registration-schema-{}@example.test", Uuid::new_v4());
    let base = json!({"email":email,"name":null});
    let mut bodies = vec![
        json!(null),
        json!(false),
        json!("string"),
        json!([]),
        json!({}),
        json!({"Email":email}),
        json!([email]),
    ];
    for field in ["email", "name"] {
        for value in [json!(0), json!([]), json!({}), json!(false)] {
            let mut body = base.clone();
            body[field] = value;
            bodies.push(body);
        }
    }
    let mut null_email = base.clone();
    null_email["email"] = Value::Null;
    bodies.push(null_email);
    let mut raw: Vec<String> = bodies.iter().map(Value::to_string).collect();
    raw.push(
        base.to_string()
            .replacen('{', &format!("{{\"email\":{},", json!(email)), 1),
    );
    raw.push(base.to_string().replacen('{', "{\"na\\u006de\":null,", 1));
    for (index, body) in raw.iter().enumerate() {
        let result = s
            .public(
                VERIFY,
                body.as_bytes(),
                Headers {
                    accept: Some("application/json"),
                    ..Headers::default()
                },
            )?
            .rejected(422);
        if result.is_err() {
            eprintln!("Registration verification schema fixture index {index}, method POST");
        }
        result?;
    }
    for body in ["{".to_owned(), json!([email, null, 0]).to_string()] {
        s.public(VERIFY, body.as_bytes(), Headers::default())?
            .rejected(400)?;
    }
    let token = s
        .public(
            VERIFY,
            json!([email, null]).to_string().as_bytes(),
            Headers {
                accept: Some("application/json"),
                ..Headers::default()
            },
        )?
        .status(200)?
        .token(true)?;
    s.check_claims(&token, &email, &Value::Null)?;
    // Verification deliberately signs raw emails. Finish validates them before
    // persistence. A distinctive valid KDF makes an erroneously created account
    // observable in prelogin; compare each server's own unknown-email response,
    // since upstream selects deterministic decoy KDFs for unknown addresses.
    let fixture = new_fixture(600_000)?;
    let invalid_emails = [
        String::new(),
        format!("missing-at-{}", Uuid::new_v4()),
        format!(" {} ", text(&fixture["email"])?),
        format!("invalid-{}@example.test/path", Uuid::new_v4()),
        format!("invalid-{}@example.test?query", Uuid::new_v4()),
    ];
    for (index, email) in invalid_emails.iter().enumerate() {
        let query = json!({"email":email}).to_string();
        let before = s
            .public(PRELOGIN, query.as_bytes(), Headers::default())?
            .status(200)?
            .json()?;
        let token = s.verify(email, None, Some("application/json"), true)?;
        let mut body = with_token(fixture.clone(), &token);
        body["email"] = json!(email);
        body["kdfIterations"] = json!(123456);
        let result = s.finish(&body, 400);
        if result.is_err() {
            eprintln!("Registration invalid-email fixture index {index}, method POST");
        }
        result?;
        let after = s
            .public(PRELOGIN, query.as_bytes(), Headers::default())?
            .status(200)?
            .json()?;
        require(
            after == before,
            "Rejected invalid email changed observable prelogin metadata",
        )?;
    }
    // These routes have no format="json" filter. Rocket Json::from_data
    // decodes the body independently of the Content-Type header.
    for body_type in [
        BodyType::Missing,
        BodyType::Other("text/plain"),
        BodyType::Other("application/problem+json"),
    ] {
        let token = s
            .public(
                VERIFY,
                base.to_string().as_bytes(),
                Headers {
                    accept: Some("application/json"),
                    body_type,
                    ..Headers::default()
                },
            )?
            .status(200)?
            .token(true)?;
        s.check_claims(&token, &email, &Value::Null)?;
    }
    Ok(())
}
fn registration_finish_schema_and_proof_guards(s: &mut Suite) -> Result<(), RegistrationError> {
    let fixture = new_fixture(600_000)?;
    let name = "Retriable registration";
    let token = s.verify(
        text(&fixture["email"])?,
        Some(&json!(name)),
        Some("application/json"),
        true,
    )?;
    let base = with_token(fixture.clone(), &token);
    let mut invalid = vec![
        json!(null),
        json!(false),
        json!("string"),
        json!([]),
        json!({}),
    ];
    for field in ["email", "key", "masterPasswordHash", "kdf", "kdfIterations"] {
        let mut body = base.clone();
        body.as_object_mut()
            .ok_or(RegistrationError("Finish fixture object missing"))?
            .remove(field);
        invalid.push(body);
    }
    for (field, value) in [
        ("email", Value::Null),
        ("key", Value::Null),
        ("masterPasswordHash", json!(0)),
        ("kdf", json!("0")),
        ("kdfIterations", json!(1.5)),
        ("keys", json!("not-keys")),
        ("masterPasswordHint", json!(false)),
    ] {
        let mut body = base.clone();
        body[field] = value;
        invalid.push(body);
    }
    let mut raw: Vec<String> = invalid.iter().map(Value::to_string).collect();
    raw.push(
        base.to_string()
            .replacen('{', &format!("{{\"email\":{},", fixture["email"]), 1),
    );
    raw.push(base.to_string().replacen(
        '{',
        &format!("{{\"userAsymmetricKeys\":{},", fixture["keys"]),
        1,
    ));
    raw.push(base.to_string().replacen(
        '{',
        &format!(
            "{{\"masterPasswordHash\":{},",
            fixture["masterPasswordHash"]
        ),
        1,
    ));
    raw.push(
        base.to_string()
            .replacen('{', &format!("{{\"key\":{},", fixture["key"]), 1),
    );
    for (index, body) in raw.iter().enumerate() {
        let result = s.finish_raw(body.as_bytes(), 422);
        if result.is_err() {
            eprintln!("Registration finish schema fixture index {index}, method POST");
        }
        result?;
    }
    for body in ["{".to_owned(), format!("{base},")] {
        s.finish_raw(body.as_bytes(), 400)?;
    }
    let mut missing = base.clone();
    missing
        .as_object_mut()
        .ok_or(RegistrationError("Finish fixture object missing"))?
        .remove("emailVerificationToken");
    s.finish(&missing, 400)?;
    let mut bad_proof = base.clone();
    bad_proof["emailVerificationToken"] = json!("forged-verification-token");
    for body_type in [
        BodyType::Missing,
        BodyType::Other("text/plain"),
        BodyType::Other("application/problem+json"),
    ] {
        s.public(
            FINISH,
            bad_proof.to_string().as_bytes(),
            Headers {
                accept: Some("application/json"),
                body_type,
                ..Headers::default()
            },
        )?
        .rejected(400)?;
    }
    for value in [
        Value::Null,
        json!(""),
        json!("forged-verification-token"),
        json!(s.accounts[0].token),
    ] {
        let mut body = base.clone();
        body["emailVerificationToken"] = value;
        s.finish(&body, 400)?;
    }
    let mut mismatch = base.clone();
    mismatch["email"] = json!(text(&fixture["email"])?.to_uppercase());
    s.finish(&mismatch, 400)?;
    for field in [
        "organizationUserId",
        "orgInviteToken",
        "acceptEmergencyAccessId",
        "acceptEmergencyAccessInviteToken",
    ] {
        let mut body = base.clone();
        body[field] = json!(Uuid::new_v4().to_string());
        s.finish(&body, 400)?;
    }
    for field in ["masterPasswordAuthentication", "masterPasswordUnlock"] {
        let mut body = with_token(current_body(&fixture, false)?, &token);
        body[field]["salt"] = json!("wrong-salt");
        s.finish(&body, 422)?;
    }
    let mut body = with_token(current_body(&fixture, false)?, &token);
    body["masterPasswordUnlock"]["kdf"]["kdfIterations"] = json!(600001);
    s.finish(&body, 422)?;
    // Both versions remove Unicode whitespace before JWT verification.
    let decorated = format!("\u{2003} {} \n", token.replace('.', ".\t"));
    s.register(&fixture, fixture.clone(), &decorated, name)
}
fn registration_kdf_validation_and_retry(s: &mut Suite) -> Result<(), RegistrationError> {
    let fixture = new_fixture(100_000)?;
    let name = "KDF boundary registration";
    let token = s.verify(
        text(&fixture["email"])?,
        Some(&json!(name)),
        Some("application/json"),
        true,
    )?;
    let base = with_token(fixture.clone(), &token);
    let mut pbkdf = base.clone();
    pbkdf["kdfIterations"] = json!(99999);
    s.finish(&pbkdf, 400)?;
    let argon = json!({"kdf":1,"kdfIterations":1,"kdfMemory":64,"kdfParallelism":4});
    for (field, value) in [
        ("kdfIterations", json!(0)),
        ("kdfMemory", Value::Null),
        ("kdfMemory", json!(14)),
        ("kdfMemory", json!(1025)),
        ("kdfParallelism", Value::Null),
        ("kdfParallelism", json!(0)),
        ("kdfParallelism", json!(17)),
    ] {
        let mut body = base.clone();
        for (key, value) in argon
            .as_object()
            .ok_or(RegistrationError("KDF fixture object missing"))?
        {
            body[key] = value.clone();
        }
        body[field] = value;
        s.finish(&body, 400)?;
    }
    s.register(&fixture, fixture.clone(), &token, name)
}
fn registration_duplicate_finish_and_account_isolation(
    s: &mut Suite,
) -> Result<(), RegistrationError> {
    let account = s
        .accounts
        .first()
        .cloned()
        .ok_or(RegistrationError("Duplicate registration fixture missing"))?;
    let mut body = with_token(account.fixture.clone(), &account.verification);
    // The first fixture used an upper-case raw token subject.
    body["email"] = json!(text(&jwt_claims(&account.verification)?["sub"])?);
    s.finish(&body, 400)?;
    s.check_accounts()?;
    let token = s.verify(
        text(&account.fixture["email"])?,
        Some(&json!("must-not-replace-name")),
        Some("application/json"),
        true,
    )?;
    let mut replacement = with_token(account.fixture, &token);
    replacement["key"] = json!("must-not-replace-key");
    replacement["masterPasswordHash"] = json!("must-not-replace-password");
    s.finish(&replacement, 400)?;
    s.check_accounts()
}

fn receipt() -> Result<Option<fs::File>, RegistrationError> {
    let Some(path) = std::env::var_os("BW_REGISTRATION_RECEIPT") else {
        return Ok(None);
    };
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|_| RegistrationError("Private registration receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| RegistrationError("Private registration receipt permissions failed"))?;
    }
    Ok(Some(file))
}
fn peer_client(peer: u8) -> Result<Client, RegistrationError> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, peer)))
        .build()
        .map_err(|_| RegistrationError("Registration HTTP client initialization failed"))
}
/// Nine password logins share peer1, below the unchanged default burst10.
/// Cases use direct peers2–9; every verification/finish request, including guard
/// rejections, conservatively counts toward a limit50 for that peer. Neither
/// forwarded headers nor altered server rate settings are used. No retries.
pub fn run() -> Result<(), RegistrationError> {
    let server = std::env::var("BW_E2E_SERVER")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".into())
        .trim_end_matches('/')
        .to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| RegistrationError("Invalid registration test server configuration"))?;
    require(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Registration direct-peer suite requires an IPv4-loopback test server",
    )?;
    let mut clients = BTreeMap::new();
    for peer in 1..=9 {
        clients.insert(peer, peer_client(peer)?);
    }
    let mut s = Suite {
        server,
        origin: String::new(),
        clients,
        peers: BTreeMap::new(),
        peer: 1,
        accounts: Vec::new(),
        requests: 0,
        verifications: 0,
        finishes: 0,
        prelogins: 0,
        identity_requests: 0,
        logins: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    s.write_receipt("running")?;
    let config = s.json("/api/config", None)?;
    s.origin = reqwest::Url::parse(text(&config["environment"]["vault"])?)
        .map_err(|_| RegistrationError("Configured registration origin invalid"))?
        .origin()
        .ascii_serialization();
    for (index, (name, case)) in CASES.into_iter().enumerate() {
        s.peer = index as u8 + 2;
        case(&mut s)?;
        s.check_accounts()?;
        s.passed.push(name);
        s.write_receipt("running")?;
        println!("PASS {name}");
    }
    require(
        s.identity_requests == 9 && s.logins == 9 && s.accounts.len() == 9,
        "Registration successful-login budget differed",
    )?;
    s.write_receipt("passed")?;
    s.finished = true;
    println!(
        "PASS registration: {} cases, {} HTTP requests, {} verification requests, {} finish requests, {} prelogin requests, {} successful logins, max{} public requests per peer",
        s.passed.len(),
        s.requests,
        s.verifications,
        s.finishes,
        s.prelogins,
        s.logins,
        s.peers.values().map(|p| p.public).max().unwrap_or(0)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Deserialize)]
    struct VerificationShape {
        email: String,
        name: Option<String>,
    }
    #[test]
    fn optional_verification_name_still_requires_its_sequence_slot() {
        let shape: VerificationShape = serde_json::from_str(r#"["e",null]"#).unwrap();
        assert!(shape.email == "e" && shape.name.is_none());
        let shape: VerificationShape = serde_json::from_str(r#"{"email":"e"}"#).unwrap();
        assert!(shape.name.is_none());
        for body in [r#"["e"]"#, r#"{"email":"e","name":null,"na\u006de":null}"#] {
            assert!(
                serde_json::from_str::<VerificationShape>(body)
                    .err()
                    .unwrap()
                    .classify()
                    == serde_json::error::Category::Data
            );
        }
        assert!(
            serde_json::from_str::<VerificationShape>(r#"["e",null,0]"#)
                .err()
                .unwrap()
                .classify()
                == serde_json::error::Category::Syntax
        );
    }
    #[test]
    fn current_alias_builder_retains_distinct_authentication_and_unlock_fields() {
        let fixture = json!({"email":"E@example.test","kdf":0,"kdfIterations":600000,"masterPasswordHash":"private-hash","key":"wrapped-key","keys":{"publicKey":"public","encryptedPrivateKey":"private"}});
        let body = current_body(&fixture, true).unwrap();
        assert!(body["MasterPasswordAuthentication"]["Salt"] == "e@example.test");
        assert!(
            body["MasterPasswordAuthentication"]["MasterPasswordAuthenticationHash"]
                == fixture["masterPasswordHash"]
        );
        assert!(
            body["MasterPasswordUnlock"]["masterKeyWrappedUserKey"] == fixture["key"]
                && body.get("masterPasswordHash").is_none()
        );
    }
    #[test]
    fn diagnostics_and_receipts_exclude_private_server_response_data() {
        let marker = "private-registration-marker";
        let reply = Reply {
            status: 500,
            bytes: marker.as_bytes().to_vec(),
            content_type: String::new(),
        };
        let error = reply.status(200).err().unwrap();
        assert!(!format!("{error} {error:?}").contains(marker));
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{marker}",
            marker.len()
        );
        assert!(
            raw_http_reply(raw.as_bytes())
                .unwrap()
                .token(false)
                .unwrap()
                == marker
        );
        let raw = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{marker}\r\n0\r\n\r\n",
            marker.len()
        );
        assert!(
            raw_http_reply(raw.as_bytes())
                .unwrap()
                .token(false)
                .unwrap()
                == marker
        );
        let error = jwt_claims(marker).err().unwrap();
        assert!(!format!("{error} {error:?}").contains(marker));
        let receipt = Receipt {
            schema_version: 1,
            status: "passed",
            cases: &[CASES[0].0],
            passed_cases: 1,
            expected_cases: 8,
            http_requests: 1,
            verification_requests: 1,
            finish_requests: 1,
            prelogin_requests: 0,
            identity_requests: 9,
            successful_logins: 9,
            max_public_requests_per_peer: 40,
            max_identity_requests_per_peer: 9,
        };
        let value = serde_json::to_value(receipt).unwrap();
        assert!(value["successfulLogins"] == 9 && !value.to_string().contains(marker));
    }
}
