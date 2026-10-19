//! Ordinary password grants, ordered forms and source-accurate guard errors.
//!
//! Vaultwarden pin/release1.37.4 identity.rs65-80,370-498,auth.rs1259-1267,
//! error.rs223-257 and Rocket0.5.1 NameView/FromForm define these contracts.
//! Thirty-nine guard POSTs precede the login limiter; six further requests reach
//! credential evaluation, including one existing auth-request selector canary.
//! Required grant_type is lenient/first-wins; duplicate Option fields become None.
//! This is a default personal/no-SMTP/no-2FA configuration comparison. Disabled
//! policy/provider effects, server throttling, complete token models and timed
//! client refresh are separate proofs. No claimed CLI route trace is added.

use crate::fixture;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Method, blocking::Client};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use uuid::Uuid;

type Form = Vec<(String, String)>;
type Case = fn(&mut Suite) -> Result<(), PasswordGrantsError>;
const TOKEN: &str = "/identity/connect/token";
const MAX_REPLY: u64 = 16 * 1024 * 1024;
const PROOF_ERROR: &str = "Username or password is incorrect. Try again";
const REQUIRED: [(&str, &str); 7] = [
    ("client_id", "client_id cannot be blank"),
    ("password", "password cannot be blank"),
    ("scope", "scope cannot be blank"),
    ("username", "username cannot be blank"),
    ("deviceIdentifier", "device_identifier cannot be blank"),
    ("deviceName", "device_name cannot be blank"),
    ("deviceType", "device_type cannot be blank"),
];
const CASES: [(&str, Case); 6] = [
    (
        "password_grants_required_presence_and_order",
        required_presence_and_order,
    ),
    (
        "password_grants_scope_and_empty_presence",
        scope_and_empty_presence,
    ),
    (
        "password_grants_first_root_aliases_and_duplicates",
        first_root_aliases_and_duplicates,
    ),
    (
        "password_grants_raw_proof_and_missing_user",
        raw_proof_and_missing_user,
    ),
    (
        "password_grants_alias_success_and_token_authority",
        alias_success_and_token_authority,
    ),
    (
        "password_grants_empty_device_values_and_authrequest_selection",
        empty_device_values_and_authrequest_selection,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordGrantsError(&'static str);
impl fmt::Display for PasswordGrantsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for PasswordGrantsError {}
fn require(value: bool, message: &'static str) -> Result<(), PasswordGrantsError> {
    if value {
        Ok(())
    } else {
        Err(PasswordGrantsError(message))
    }
}
fn text(value: &Value) -> Result<&str, PasswordGrantsError> {
    value.as_str().ok_or(PasswordGrantsError(
        "Required password-grant fixture string missing",
    ))
}
fn array(value: &Value) -> Result<&[Value], PasswordGrantsError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(PasswordGrantsError(
            "Required password-grant fixture array missing",
        ))
}
fn set(form: &mut Form, key: &str, value: impl Into<String>) {
    form.iter_mut()
        .find(|(name, _)| name == key)
        .expect("Authored form field exists")
        .1 = value.into();
}
fn ordinary_error(message: &str) -> Value {
    json!({"message":message,"validationErrors":{"": [message]},"errorModel":{"message":message,"object":"error"},
        "error":"","error_description":"","exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"})
}
fn scope_error(scope: &str) -> String {
    format!("Scope ({}) not supported", scope.escape_debug())
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, PasswordGrantsError> {
        if self.status != expected {
            eprintln!(
                "Password grant HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Password grant HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, PasswordGrantsError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| PasswordGrantsError("Password grant response was not JSON"))
    }
    fn ordinary_error(self, message: &str) -> Result<(), PasswordGrantsError> {
        require(
            self.status(400)?.json()? == ordinary_error(message),
            "Password grant source error envelope differed",
        )
    }
    fn rejected(self, expected: u16) -> Result<(), PasswordGrantsError> {
        let reply = self.status(expected)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                [
                    "access_token",
                    "refresh_token",
                    "Key",
                    "PrivateKey",
                    "AccountKeys",
                    "UserDecryptionOptions",
                ]
                .iter()
                .all(|field| value.get(field).is_none()),
                "Rejected password grant exposed token or account key authority",
            )?;
        }
        Ok(())
    }
}
struct Http {
    server: String,
    client: Client,
    requests: usize,
    token_requests: usize,
    guard_requests: usize,
    credential_attempts: usize,
    successful_logins: usize,
}
impl Http {
    fn new() -> Result<Self, PasswordGrantsError> {
        let server = std::env::var("BW_E2E_SERVER")
            .unwrap_or_else(|_| "http://127.0.0.1:8000".into())
            .trim_end_matches('/')
            .to_owned();
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| PasswordGrantsError("Password grant client initialization failed"))?;
        Ok(Self {
            server,
            client,
            requests: 0,
            token_requests: 0,
            guard_requests: 0,
            credential_attempts: 0,
            successful_logins: 0,
        })
    }
    fn capture(response: reqwest::blocking::Response) -> Result<Reply, PasswordGrantsError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PasswordGrantsError("Password grant response capture failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "Password grant response exceeded private capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn token(&mut self, form: &Form, reaches_limiter: bool) -> Result<Reply, PasswordGrantsError> {
        self.requests += 1;
        self.token_requests += 1;
        if reaches_limiter {
            self.credential_attempts += 1;
        } else {
            self.guard_requests += 1;
        }
        require(
            self.credential_attempts <= 6,
            "Password grant credential peer budget exceeded",
        )?;
        // Vec serialization preserves field order and duplicate names on the wire.
        let reply = Self::capture(
            self.client
                .post(format!("{}{TOKEN}", self.server))
                .form(form)
                .send()
                .map_err(|_| PasswordGrantsError("Password grant token request failed"))?,
        )?;
        if reply.status == 200 {
            self.successful_logins += 1;
        }
        Ok(reply)
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, PasswordGrantsError> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server))
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(body);
        }
        Self::capture(
            request
                .send()
                .map_err(|_| PasswordGrantsError("Password grant authority request failed"))?,
        )?
        .status(200)?
        .json()
    }
    fn known(&mut self, email: &str, device: &str) -> Result<bool, PasswordGrantsError> {
        self.requests += 1;
        let response = self
            .client
            .get(format!("{}/api/devices/knowndevice", self.server))
            .header("X-Request-Email", URL_SAFE_NO_PAD.encode(email))
            .header("X-Device-Identifier", device)
            .send()
            .map_err(|_| PasswordGrantsError("Password grant known-device request failed"))?;
        Self::capture(response)?
            .status(200)?
            .json()?
            .as_bool()
            .ok_or(PasswordGrantsError(
                "Password grant known-device response was not boolean",
            ))
    }
}
#[derive(Clone, PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
    keys: Value,
    domains: Value,
    devices: Value,
    revision: Value,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt<'a> {
    schema_version: u8,
    status: &'static str,
    cases: &'a [&'static str],
    expected_cases: usize,
    passed_cases: usize,
    http_requests: usize,
    token_http_requests: usize,
    pre_limiter_guard_requests: usize,
    credential_evaluated_attempts: usize,
    successful_logins: usize,
    max_credential_attempts_per_peer: usize,
    fixture_registrations: usize,
}
struct Suite {
    http: Http,
    fixture: Value,
    encrypted_field: String,
    device: String,
    failed_devices: [String; 3],
    access: Option<String>,
    passed: Vec<&'static str>,
    receipt: Option<fs::File>,
    finished: bool,
}
impl Drop for Suite {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Suite {
    fn form(&self) -> Result<Form, PasswordGrantsError> {
        Ok(vec![
            ("grant_type".into(), "password".into()),
            ("client_id".into(), "cli".into()),
            (
                "password".into(),
                text(&self.fixture["masterPasswordHash"])?.into(),
            ),
            ("scope".into(), "api offline_access".into()),
            ("username".into(), text(&self.fixture["email"])?.into()),
            ("deviceIdentifier".into(), self.device.clone()),
            ("deviceName".into(), "Ordered password grant fixture".into()),
            ("deviceType".into(), "8".into()),
        ])
    }
    fn receipt(&mut self, status: &'static str) -> Result<(), PasswordGrantsError> {
        if let Some(file) = &mut self.receipt {
            let record = Receipt {
                schema_version: 1,
                status,
                cases: &self.passed,
                expected_cases: CASES.len(),
                passed_cases: self.passed.len(),
                http_requests: self.http.requests,
                token_http_requests: self.http.token_requests,
                pre_limiter_guard_requests: self.http.guard_requests,
                credential_evaluated_attempts: self.http.credential_attempts,
                successful_logins: self.http.successful_logins,
                max_credential_attempts_per_peer: self.http.credential_attempts,
                fixture_registrations: usize::from(!self.fixture.is_null()),
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| PasswordGrantsError("Password grant receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| PasswordGrantsError("Password grant receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| PasswordGrantsError("Password grant receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| PasswordGrantsError("Password grant receipt write failed"))?;
            file.sync_all()
                .map_err(|_| PasswordGrantsError("Password grant receipt persistence failed"))?;
        }
        Ok(())
    }
    fn snapshot(&mut self, token: &str) -> Result<Snapshot, PasswordGrantsError> {
        Ok(Snapshot {
            profile: self
                .http
                .json(Method::GET, "/api/accounts/profile", token, None)?,
            sync: self.http.json(Method::GET, "/api/sync", token, None)?,
            keys: self
                .http
                .json(Method::GET, "/api/accounts/keys", token, None)?,
            domains: self
                .http
                .json(Method::GET, "/api/settings/domains", token, None)?,
            devices: self.http.json(Method::GET, "/api/devices", token, None)?,
            revision: self
                .http
                .json(Method::GET, "/api/accounts/revision-date", token, None)?,
        })
    }
    fn check_tokens(
        &mut self,
        tokens: &Value,
        client: &str,
        device: &str,
        label: &str,
    ) -> Result<Snapshot, PasswordGrantsError> {
        let access = text(&tokens["access_token"])?;
        let refresh = text(&tokens["refresh_token"])?;
        require(
            !access.is_empty()
                && !refresh.is_empty()
                && tokens["scope"] == "api offline_access"
                && tokens["token_type"] == "Bearer"
                && tokens["expires_in"]
                    .as_i64()
                    .is_some_and(|seconds| (7195..=7200).contains(&seconds)),
            "Password grant access/refresh scope or lifetime differed",
        )?;
        require(
            tokens["Key"] == self.fixture["key"]
                && tokens["PrivateKey"] == self.fixture["keys"]["encryptedPrivateKey"]
                && tokens["Kdf"] == self.fixture["kdf"]
                && tokens["KdfIterations"] == self.fixture["kdfIterations"],
            "Password grant substituted account keys or KDF metadata",
        )?;
        let unlock = &tokens["UserDecryptionOptions"]["MasterPasswordUnlock"];
        require(
            tokens["UserDecryptionOptions"]["HasMasterPassword"] == true
                && unlock["MasterKeyWrappedUserKey"] == self.fixture["key"]
                && unlock["MasterKeyEncryptedUserKey"] == self.fixture["key"]
                && unlock["Salt"] == self.fixture["email"],
            "Password grant decryption options differed",
        )?;
        let pair = &tokens["AccountKeys"]["publicKeyEncryptionKeyPair"];
        require(
            pair["wrappedPrivateKey"] == self.fixture["keys"]["encryptedPrivateKey"]
                && pair["publicKey"] == self.fixture["keys"]["publicKey"],
            "Password grant account key pair differed",
        )?;
        let snapshot = self.snapshot(access)?;
        let claims = jwt_claims(access)?;
        require(
            claims["sub"] == snapshot.profile["id"]
                && claims["device"] == device
                && claims["client_id"] == client
                && claims["devicetype"] == label
                && claims["scope"] == json!(["api", "offline_access"])
                && claims["amr"] == json!(["Application"])
                && claims["sstamp"] == snapshot.profile["securityStamp"]
                && claims["exp"]
                    .as_i64()
                    .zip(claims["nbf"].as_i64())
                    .is_some_and(|(exp, nbf)| exp - nbf == 7200),
            "Signed password grant owner/device/client/scope/stamp/lifetime differed",
        )?;
        Ok(snapshot)
    }
}
fn jwt_claims(token: &str) -> Result<Value, PasswordGrantsError> {
    let mut parts = token.split('.');
    let _header = parts
        .next()
        .ok_or(PasswordGrantsError("Password grant JWT shape invalid"))?;
    let body = parts
        .next()
        .ok_or(PasswordGrantsError("Password grant JWT shape invalid"))?;
    require(
        parts.next().is_some() && parts.next().is_none(),
        "Password grant JWT shape invalid",
    )?;
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| PasswordGrantsError("Password grant JWT encoding invalid"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| PasswordGrantsError("Password grant JWT claims invalid"))
}
fn required_presence_and_order(s: &mut Suite) -> Result<(), PasswordGrantsError> {
    let mut missing_grant = s.form()?;
    missing_grant.retain(|(key, _)| key != "grant_type");
    s.http.token(&missing_grant, false)?.rejected(422)?;
    for (index, (field, message)) in REQUIRED.iter().enumerate() {
        let mut individual = s.form()?;
        individual.retain(|(key, _)| key != field);
        s.http.token(&individual, false)?.ordinary_error(message)?;
        let mut ordered = s.form()?;
        ordered.retain(|(key, _)| !REQUIRED[index..].iter().any(|(missing, _)| key == missing));
        s.http.token(&ordered, false)?.ordinary_error(message)?;
    }
    Ok(())
}
fn scope_and_empty_presence(s: &mut Suite) -> Result<(), PasswordGrantsError> {
    for scope in [
        "",
        "api",
        "offline_access api",
        "api offline_access ",
        "api  offline_access",
        "API offline_access",
        "\0雪\n",
    ] {
        let mut form = s.form()?;
        set(&mut form, "scope", scope);
        s.http
            .token(&form, false)?
            .ordinary_error(&scope_error(scope))?;
    }
    let mut form = s.form()?;
    for (key, _) in REQUIRED {
        set(&mut form, key, "");
    }
    set(&mut form, "scope", "invalid");
    s.http
        .token(&form, false)?
        .ordinary_error(&scope_error("invalid"))
}
fn first_root_aliases_and_duplicates(s: &mut Suite) -> Result<(), PasswordGrantsError> {
    for root in [
        "SCOPE",
        "scope.nested",
        "scope[nested]",
        "[scope]",
        ".scope",
        "[scope",
    ] {
        let mut form = s.form()?;
        form.retain(|(key, _)| key != "scope");
        form.insert(0, (root.into(), "first".into()));
        form.push(("scope".into(), "ignored-later".into()));
        s.http
            .token(&form, false)?
            .ordinary_error("scope cannot be blank")?;
    }
    // Rocket Option<T> initializes T strictly and converts its duplicate error
    // into None, unlike the required grant_type String's lenient first value.
    for ((_, message), alias) in REQUIRED.iter().zip([
        "[CLIENTID]",
        ".PASSWORD",
        "ScOpE[nested]",
        "USERNAME.foo",
        "[DEVICE_IDENTIFIER]",
        ".DEVICENAME",
        "DEVICE_TYPE.nested",
    ]) {
        let mut form = s.form()?;
        form.insert(0, (alias.into(), "ignored-first".into()));
        s.http.token(&form, false)?.ordinary_error(message)?;
    }
    let mut form = s.form()?;
    form.retain(|(key, _)| key != "grant_type");
    form.insert(0, ("GRANTTYPE.nested".into(), "password".into()));
    form.push(("grant_type".into(), "client_credentials".into()));
    set(&mut form, "scope", "first");
    s.http
        .token(&form, false)?
        .ordinary_error(&scope_error("first"))?;
    for ignored in ["scope_", "..scope"] {
        let mut form = s.form()?;
        form.retain(|(key, _)| key != "scope");
        form.push((ignored.into(), "api offline_access".into()));
        s.http
            .token(&form, false)?
            .ordinary_error("scope cannot be blank")?;
    }
    Ok(())
}
fn raw_proof_and_missing_user(s: &mut Suite) -> Result<(), PasswordGrantsError> {
    for index in 0..3 {
        let mut form = s.form()?;
        set(
            &mut form,
            "deviceIdentifier",
            s.failed_devices[index].clone(),
        );
        match index {
            0 => set(
                &mut form,
                "password",
                format!(" {} ", text(&s.fixture["masterPasswordHash"])?),
            ),
            1 => set(
                &mut form,
                "username",
                format!("missing-password-login-{}@example.test", Uuid::new_v4()),
            ),
            _ => set(&mut form, "password", ""),
        }
        s.http.token(&form, true)?.ordinary_error(PROOF_ERROR)?;
        require(
            !s.http
                .known(text(&s.fixture["email"])?, &s.failed_devices[index])?,
            "Rejected password grant registered a device",
        )?;
    }
    Ok(())
}
fn alias_success_and_token_authority(s: &mut Suite) -> Result<(), PasswordGrantsError> {
    let username = format!(
        "\u{2003}{}\u{00a0}",
        text(&s.fixture["email"])?.to_uppercase()
    );
    let form = vec![
        ("GRANTTYPE.nested".into(), "password".into()),
        ("grant_type".into(), "client_credentials".into()),
        ("[CLIENTID]".into(), "cli".into()),
        (
            ".PASSWORD".into(),
            text(&s.fixture["masterPasswordHash"])?.into(),
        ),
        ("ScOpE[suffix]".into(), "api offline_access".into()),
        ("USERNAME.foo".into(), username),
        ("[DEVICEIDENTIFIER]".into(), s.device.clone()),
        (
            ".DEVICENAME".into(),
            "Ordered password grant fixture".into(),
        ),
        ("DEVICE_TYPE.nested".into(), "8".into()),
        ("auth_request".into(), "ignored-underscore-name".into()),
        ("ownerId".into(), "ignored-owner".into()),
    ];
    let tokens = s.http.token(&form, true)?.status(200)?.json()?;
    let device = s.device.clone();
    let snapshot = s.check_tokens(&tokens, "cli", &device, "Linux")?;
    let rows = array(&snapshot.devices["data"])?;
    require(
        rows.len() == 1
            && rows[0]["identifier"] == s.device
            && rows[0]["name"] == "Ordered password grant fixture"
            && rows[0]["type"] == 8,
        "Password grant first-root device metadata differed",
    )?;
    let access = text(&tokens["access_token"])?.to_owned();
    s.http.json(Method::POST,"/api/ciphers",&access,Some(&json!({"encryptedFor":snapshot.profile["id"],"type":2,"name":s.encrypted_field,"notes":s.encrypted_field,"secureNote":{"type":0}})))?;
    s.access = Some(access);
    Ok(())
}
fn empty_device_values_and_authrequest_selection(s: &mut Suite) -> Result<(), PasswordGrantsError> {
    let original = s.access.clone().ok_or(PasswordGrantsError(
        "Password grant authority fixture missing",
    ))?;
    let before = s.snapshot(&original)?;
    let mut form = s.form()?;
    for key in ["client_id", "deviceIdentifier", "deviceName", "deviceType"] {
        set(&mut form, key, "");
    }
    let tokens = s.http.token(&form, true)?.status(200)?.json()?;
    let after = s.check_tokens(&tokens, "", "", "Unknown Browser")?;
    let rows = array(&after.devices["data"])?;
    require(
        rows.len() == 2
            && rows
                .iter()
                .any(|row| row["identifier"] == "" && row["name"] == "" && row["type"] == 14),
        "Present-empty password grant device fields were rejected or rewritten",
    )?;
    let mut expected = before;
    expected.devices = after.devices.clone();
    require(
        after == expected && s.snapshot(&original)? == after,
        "Successful password grant changed existing vault/account authority",
    )?;
    let mut form = s.form()?;
    form.push(("authRequest.x".into(), "".into()));
    let before = s.snapshot(&original)?;
    s.http.token(&form, true)?.rejected(400)?;
    require(
        s.snapshot(&original)? == before,
        "Recognized empty auth-request field fell back to password or mutated authority",
    )?;
    require(
        s.http.token_requests == 45
            && s.http.guard_requests == 39
            && s.http.credential_attempts == 6
            && s.http.successful_logins == 2,
        "Password grant token/guard/credential counts differed",
    )
}
fn private_receipt() -> Result<Option<fs::File>, PasswordGrantsError> {
    let Some(path) = std::env::var_os("BW_PASSWORD_GRANTS_RECEIPT") else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| PasswordGrantsError("Password grant private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| PasswordGrantsError("Password grant receipt permissions failed"))?;
    Ok(Some(file))
}
/// Six opt-in cases: 45 token POSTs, of which six reach credential evaluation.
/// Admission counts follow source order; no claim of adapter throttling is made.
pub fn run() -> Result<(), PasswordGrantsError> {
    let mut s = Suite {
        http: Http::new()?,
        fixture: Value::Null,
        encrypted_field: String::new(),
        device: Uuid::new_v4().to_string(),
        failed_devices: std::array::from_fn(|_| Uuid::new_v4().to_string()),
        access: None,
        passed: Vec::new(),
        receipt: private_receipt()?,
        finished: false,
    };
    s.receipt("running")?;
    let email = format!("password-grant-{}@example.test", Uuid::new_v4());
    let password = format!("Private-password-grant-fixture-{}", Uuid::new_v4());
    s.fixture = fixture::seed_account(&s.http.server, &email, &password)
        .map_err(|_| PasswordGrantsError("Password grant fixture registration failed"))?;
    s.encrypted_field = fixture::encrypted_pbkdf2_value(
        &s.fixture,
        &password,
        b"Retained password grant vault payload",
    )
    .map_err(|_| PasswordGrantsError("Password grant encrypted field fixture failed"))?;
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    s.receipt("passed")?;
    s.finished = true;
    println!("PASS password-grants HTTP cases: {}", s.passed.len());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordered_form_serialization_retains_duplicates_and_escapes_opaque_values() {
        let form = vec![
            ("Scope.nested".to_owned(), "first + value".to_owned()),
            ("scope".to_owned(), "second\0雪".to_owned()),
        ];
        let request = Client::new()
            .post("http://127.0.0.1/")
            .form(&form)
            .build()
            .unwrap();
        let body = request
            .body()
            .and_then(reqwest::blocking::Body::as_bytes)
            .unwrap();
        assert!(body == b"Scope.nested=first+%2B+value&scope=second%00%E9%9B%AA");
    }
    #[test]
    fn ordinary_errors_have_nine_source_fields_and_diagnostics_discard_private_material() {
        let value = ordinary_error(PROOF_ERROR);
        assert!(value.as_object().is_some_and(|object| object.len() == 9));
        assert!(
            value["error"] == ""
                && value["error_description"] == ""
                && value["errorModel"]["message"] == PROOF_ERROR
        );
        assert!(scope_error("\0雪\n") == "Scope (\\0雪\\n) not supported");
        let error = Reply {
            status: 200,
            bytes: b"private-password-token-key".to_vec(),
        }
        .json()
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-password"));
    }
}
