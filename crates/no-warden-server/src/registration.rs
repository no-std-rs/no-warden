//! No-SMTP registration adapter. Protocol facts follow Vaultwarden
//! 58a980f850464f7d9cdc99a765df36f0a3308b91 accounts.rs:88-478,
//! identity.rs:1031-1103 and auth.rs:66-67,130-147,451-478.
//! Tokens, verifier input and private keys never enter diagnostics or stored JSON.

use crate::Failure;
use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use no_warden::identity::Secret;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS registration_signing_key(singleton INTEGER PRIMARY KEY CHECK(singleton=1),secret BLOB NOT NULL CHECK(length(secret)=32));
    CREATE TABLE IF NOT EXISTS registration_metadata(owner TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,email_verified INTEGER NOT NULL CHECK(email_verified IN(0,1)));";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationInput {
    pub email: String,
    pub name: Option<String>,
}
impl VerificationInput {
    pub fn request(&self) -> no_warden::wire::RegistrationVerificationRequest<'_> {
        no_warden::wire::RegistrationVerificationRequest {
            email: &self.email,
            name: self.name.as_deref(),
        }
    }
}
pub fn parse_verification(body: &[u8]) -> Result<VerificationInput, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}

// User::save calls util::is_valid_email. Match its mailbox parser and URL
// domain checks; verification issuance intentionally does not call this helper.
// <https://github.com/dani-garcia/vaultwarden/blob/58a980f850464f7d9cdc99a765df36f0a3308b91/src/util.rs#L533-L541>
pub fn valid_storage_email(email: &str) -> bool {
    use std::str::FromStr;
    let Ok(email) = email_address::EmailAddress::from_str(email) else {
        return false;
    };
    let Ok(url) = url::Url::parse(&format!("https://{}", email.domain())) else {
        return false;
    };
    url.domain().is_some() && url.path() == "/" && url.query().is_none()
}

// Mirror the upstream Serde declarations: flattening and Old-first untagged
// selection matter for mixed payloads, aliases, known duplicates and sequences.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishInput {
    pub email: String,
    #[serde(flatten)]
    credentials: Credentials,
    #[serde(alias = "userAsymmetricKeys")]
    keys: Option<Keys>,
    master_password_hint: Option<String>,
    organization_user_id: Option<String>,
    email_verification_token: Option<String>,
    accept_emergency_access_id: Option<String>,
    accept_emergency_access_invite_token: Option<String>,
    #[serde(alias = "token")]
    org_invite_token: Option<String>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Credentials {
    Legacy(Legacy),
    Nested(Nested),
}
#[derive(Deserialize)]
struct Legacy {
    #[serde(flatten)]
    kdf: Kdf,
    #[serde(alias = "userSymmetricKey")]
    key: String,
    #[serde(alias = "masterPasswordHash")]
    master_password_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Nested {
    #[serde(alias = "MasterPasswordAuthentication")]
    master_password_authentication: Authentication,
    #[serde(alias = "MasterPasswordUnlock")]
    master_password_unlock: Unlock,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Kdf {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Authentication {
    #[serde(alias = "Kdf")]
    kdf: Kdf,
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(
        alias = "masterPasswordAuthenticationHash",
        alias = "MasterPasswordAuthenticationHash"
    )]
    hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Unlock {
    kdf: Kdf,
    salt: String,
    #[serde(alias = "masterKeyWrappedUserKey")]
    key: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Keys {
    encrypted_private_key: String,
    public_key: String,
}
pub fn parse_finish(body: &[u8]) -> Result<FinishInput, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}
impl Kdf {
    fn view(&self) -> no_warden::wire::RegistrationKdf {
        no_warden::wire::RegistrationKdf {
            kdf: self.kdf,
            kdf_iterations: self.kdf_iterations,
            kdf_memory: self.kdf_memory,
            kdf_parallelism: self.kdf_parallelism,
        }
    }
}
impl FinishInput {
    pub fn request(&self) -> no_warden::wire::RegistrationFinishRequest<'_> {
        use no_warden::wire::{
            RegistrationAuthentication, RegistrationCredentials, RegistrationUnlock,
        };
        let credentials = match &self.credentials {
            Credentials::Legacy(old) => RegistrationCredentials::Legacy {
                kdf: old.kdf.view(),
                master_password_hash: Secret::new(&old.master_password_hash),
                key: Secret::new(&old.key),
            },
            Credentials::Nested(current) => RegistrationCredentials::Nested {
                authentication: RegistrationAuthentication {
                    kdf: current.master_password_authentication.kdf.view(),
                    salt: &current.master_password_authentication.salt,
                    hash: Secret::new(&current.master_password_authentication.hash),
                },
                unlock: RegistrationUnlock {
                    kdf: current.master_password_unlock.kdf.view(),
                    salt: &current.master_password_unlock.salt,
                    key: Secret::new(&current.master_password_unlock.key),
                },
            },
        };
        // This host models ordinary token registration. Preserve upstream's
        // nested-format check before rejecting unsupported/mixed invitation proof.
        let ordinary = self.organization_user_id.is_none()
            && self.accept_emergency_access_id.is_none()
            && self.accept_emergency_access_invite_token.is_none()
            && self.org_invite_token.is_none();
        no_warden::wire::RegistrationFinishRequest {
            email: &self.email,
            credentials,
            email_verification_token: ordinary
                .then_some(self.email_verification_token.as_deref())
                .flatten()
                .map(Secret::new),
            keys: self.keys.as_ref().map(|keys| no_warden::wire::AccountKeys {
                encrypted_private_key: &keys.encrypted_private_key,
                public_key: &keys.public_key,
            }),
            master_password_hint: self.master_password_hint.as_deref(),
        }
    }
}

// Fixed no-SMTP adapter policy. Request JSON never supplies these switches.
pub struct Policy {
    pub signups_allowed: bool,
    pub password_hints_allowed: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            signups_allowed: true,
            password_hints_allowed: true,
        }
    }
}

// Registration signing authority persists independently of the existing access
// JWT key. Concurrent first callers read the winning key after INSERT OR IGNORE.
pub fn signing_key(db: &rusqlite::Connection) -> rusqlite::Result<[u8; 32]> {
    use rusqlite::OptionalExtension;
    let read = || {
        db.query_row(
            "SELECT secret FROM registration_signing_key WHERE singleton=1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
    };
    let secret = match read()? {
        Some(secret) => secret,
        None => {
            let mut candidate = [0u8; 32];
            OsRng.fill_bytes(&mut candidate);
            db.execute(
                "INSERT OR IGNORE INTO registration_signing_key(singleton,secret) VALUES(1,?1)",
                [candidate.as_slice()],
            )?;
            read()?.ok_or(rusqlite::Error::InvalidQuery)?
        }
    };
    secret.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

#[derive(Deserialize, Serialize)]
pub struct Claims {
    nbf: i64,
    exp: i64,
    iss: String,
    sub: String,
    name: Option<String>,
    verified: bool,
}
impl std::fmt::Debug for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationClaims").finish_non_exhaustive()
    }
}
impl no_warden::registration::RegistrationClaims for Claims {
    fn subject(&self) -> &str {
        &self.sub
    }
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    fn verified(&self) -> bool {
        self.verified
    }
}
pub fn issuer(base: &str) -> Result<String, Failure> {
    Ok(format!(
        "{}|register_verify",
        crate::auth_requests::origin(base)?
    ))
}
fn sign_claims(key: &[u8; 32], claims: &Claims) -> Result<String, Failure> {
    let encoded = serde_json::to_vec(claims).map_err(|_| {
        Failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Registration token failed",
        )
    })?;
    let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"HS256"}"#);
    let unsigned = format!("{header}.{}", URL_SAFE_NO_PAD.encode(encoded));
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key size");
    mac.update(unsigned.as_bytes());
    Ok(format!(
        "{unsigned}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}
pub fn issue_token(
    key: &[u8; 32],
    issuer: &str,
    email: &str,
    name: Option<&str>,
    now: i64,
) -> Result<String, Failure> {
    sign_claims(
        key,
        &Claims {
            nbf: now,
            exp: now.checked_add(1800).ok_or(Failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Registration token failed",
            ))?,
            iss: issuer.into(),
            sub: email.into(),
            name: name.map(str::to_owned),
            verified: false,
        },
    )
}
pub fn verify_token(key: &[u8; 32], issuer: &str, token: &Secret<'_>, now: i64) -> Option<Claims> {
    #[derive(Deserialize)]
    struct Header {
        alg: String,
    }
    let token: String = token
        .expose_secret()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut parts = token.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let header_value: Header =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header_value.alg != "HS256" {
        return None;
    }
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(format!("{header}.{payload}").as_bytes());
    mac.verify_slice(&signature).ok()?;
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    // jsonwebtoken 11.1 validates floor-second NumericDates with 30s leeway:
    // exp < now-30 rejects, nbf > now+30 rejects. Keep issuer purpose exact.
    if claims.iss != issuer
        || claims.exp < 0
        || claims.nbf < 0
        || claims.exp < now.saturating_sub(30)
        || claims.nbf > now.saturating_add(30)
    {
        return None;
    }
    Some(claims)
}

// Rocket 0.5.1 Accept::preferred has ordered weighting/specificity rules.
// Keep parsing/selection here rather than treating every +json or wildcard as JSON.
pub fn accepts_json(headers: &HeaderMap) -> bool {
    let Some(raw) = headers
        .get("accept")
        .and_then(|h| std::str::from_utf8(h.as_bytes()).ok())
    else {
        return false;
    };
    preferred_json(raw).unwrap_or(false)
}
struct Media<'a> {
    kind: &'a str,
    subtype: &'a str,
    weight: Option<f32>,
    parameters: usize,
}
impl Media<'_> {
    fn specificity(&self) -> u8 {
        u8::from(self.kind != "*") + u8::from(self.subtype != "*")
    }
}

// Independently implement the pinned observable grammar. Tokens/OWS follow
// Rocket 0.5.1 parse/checkers.rs; quoted extents retain escaped bytes verbatim.
// <https://github.com/rwf2/Rocket/blob/v0.5.1/core/http/src/parse/media_type.rs>
fn accept_token<'a>(remaining: &mut &'a str) -> Option<&'a str> {
    let length=remaining.bytes().take_while(|byte|matches!(*byte,b'0'..=b'9'|b'A'..=b'Z'|b'^'..=b'~'|b'#'..=b'\''|b'!'|b'*'|b'+'|b'-'|b'.')).count();
    if length == 0 {
        return None;
    }
    let token = &remaining[..length];
    *remaining = &remaining[length..];
    Some(token)
}
fn accept_value<'a>(remaining: &mut &'a str) -> Option<&'a str> {
    let Some(quoted) = remaining.strip_prefix('"') else {
        return accept_token(remaining);
    };
    let mut escaped = false;
    for (index, character) in quoted.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if character == '"' {
            let value = &quoted[..index];
            *remaining = &quoted[index + 1..];
            return Some(value);
        }
    }
    None
}
fn accept_media<'a>(remaining: &mut &'a str) -> Option<Media<'a>> {
    let kind = accept_token(remaining)?;
    *remaining = remaining.strip_prefix('/')?;
    let subtype = accept_token(remaining)?;
    let mut media = Media {
        kind,
        subtype,
        weight: None,
        parameters: 0,
    };
    while let Some(next) = remaining.strip_prefix(';') {
        *remaining = next.trim_start_matches([' ', '\t']);
        let key = accept_token(remaining)?;
        *remaining = remaining.strip_prefix('=')?;
        let value = accept_value(remaining)?;
        media.parameters += 1;
        // Rocket's weight comes only from the first parameter. A long q is
        // unweighted, and quoted q text is not escape-decoded before parsing.
        // parse/accept.rs:12-29 also accepts f32 NaN because neither bound holds.
        if media.parameters == 1 && key.eq_ignore_ascii_case("q") && value.len() <= 5 {
            let weight = value.parse::<f32>().ok()?;
            if weight > 1.0 {
                return None;
            }
            if weight < 0.0 {
                return None;
            }
            media.weight = Some(weight);
        }
        *remaining = remaining.trim_start_matches([' ', '\t']);
    }
    Some(media)
}
fn preferred_json(raw: &str) -> Option<bool> {
    let mut remaining = raw;
    let mut preferred: Option<Media<'_>> = None;
    loop {
        remaining = remaining.trim_start_matches([' ', '\t']);
        let current = accept_media(&mut remaining)?;
        let replace = preferred.as_ref().is_none_or(|previous| {
            current.weight.is_none() && previous.weight.is_some()
                || current.weight.unwrap_or(0.0) > previous.weight.unwrap_or(1.0)
                || current.specificity() > previous.specificity()
                || (current.kind.eq_ignore_ascii_case(previous.kind)
                    && current.subtype.eq_ignore_ascii_case(previous.subtype)
                    && current.weight == previous.weight
                    && current.parameters > previous.parameters)
        });
        if replace {
            preferred = Some(current)
        }
        remaining = remaining.trim_start_matches([' ', '\t']);
        if remaining.is_empty() {
            break;
        }
        remaining = remaining.strip_prefix(',')?;
    }
    preferred.map(|media| {
        media.kind.eq_ignore_ascii_case("application") && media.subtype.eq_ignore_ascii_case("json")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_email_uses_upstream_mailbox_and_url_domain_rules() {
        for email in [
            "person@example.test",
            "person+tag@example.test",
            "用户@例子.测试",
            "Name <person@example.test>",
        ] {
            assert!(
                valid_storage_email(email),
                "Valid upstream mailbox was rejected."
            );
        }
        for email in [
            "",
            "not-an-email",
            " person@example.test",
            "person@example.test ",
            "person@127.0.0.1",
            "person@[127.0.0.1]",
            "person@example.test/path",
            "person@example.test?query",
            "person@example.test\0",
        ] {
            assert!(
                !valid_storage_email(email),
                "Invalid upstream mailbox was accepted."
            );
        }
    }
    #[test]
    fn registration_jwt_is_purpose_bound_signed_and_uses_exact_leeway() {
        let key = [7; 32];
        let origin = issuer("https://ORIGIN.example.test:443/path")
            .unwrap_or_else(|_| panic!("Origin fixture failed."));
        assert!(origin == "https://origin.example.test|register_verify");
        let token = issue_token(&key, &origin, " Raw@EMAIL ", Some("NUL\0雪"), 1000)
            .unwrap_or_else(|_| panic!("Token fixture failed."));
        let claims = verify_token(&key, &origin, &Secret::new(&token), 1000).unwrap();
        assert!(
            claims.sub == " Raw@EMAIL "
                && claims.name.as_deref() == Some("NUL\0雪")
                && !claims.verified
                && claims.exp - claims.nbf == 1800
        );
        assert!(!format!("{claims:?}").contains("Raw@EMAIL"));
        assert!(
            verify_token(
                &key,
                &origin,
                &Secret::new(&format!("\n\t{} \u{2003}", token)),
                2830
            )
            .is_some()
        );
        assert!(verify_token(&key, &origin, &Secret::new(&token), 2831).is_none());
        assert!(verify_token(&key, &origin, &Secret::new(&token), 970).is_some());
        assert!(verify_token(&key, &origin, &Secret::new(&token), 969).is_none());
        assert!(verify_token(&[8; 32], &origin, &Secret::new(&token), 1000).is_none());
        assert!(
            verify_token(
                &key,
                "https://origin.example.test|login",
                &Secret::new(&token),
                1000
            )
            .is_none()
        );
        assert!(
            verify_token(&key, &origin, &Secret::new(&format!("{token}.extra")), 1000).is_none()
        );
        let mut tampered = token.into_bytes();
        let index = tampered.iter().position(|b| *b == b'.').unwrap() + 1;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        assert!(
            verify_token(
                &key,
                &origin,
                &Secret::new(std::str::from_utf8(&tampered).unwrap()),
                1000
            )
            .is_none()
        );
    }
    #[test]
    fn registration_accept_preserves_quotes_and_only_first_short_quality_parameter() {
        for (header, json) in [
            (r#"application/json;a=";,;""#, true),
            (r#"application/json;profile="a,b""#, true),
            (r#"application/json;profile="a;b""#, true),
            (r#"application/json;profile="a\",b;c";charset=utf8"#, true),
            ("application/json;level=1;q=0,text/plain;q=0.9", true),
            ("application/json;q=0.0000,text/plain;q=0.9", true),
            ("application/json;level=1;q=wrong,text/plain;q=0.9", true),
            (r#"application/json;q="0.5",text/plain;q=0.9"#, false),
            (r#"application/json;q="0\.5""#, false),
            ("application/json;q=NaN", true),
            ("application/json;q=0.2;q=0.9,text/plain;q=0.8", false),
            (r#"application/json;empty="""#, true),
            ("application/json;{field}=value", true),
            ("application/json;a= b", false),
            ("application/json ;a=b", false),
            (r#"application/json;a="unterminated"#, false),
            (r#"application/json;a="escaped\""#, false),
            ("application/json;a=bad/value", false),
            ("application/json,", false),
            ("application/json;;a=b", false),
            ("application/json;q=1.1", false),
            ("application/json;q=2.0000,text/plain;q=0.9", true),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("accept", header.parse().unwrap());
            assert!(
                accepts_json(&headers) == json,
                "Quoted/quality Accept behavior differed."
            );
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            axum::http::HeaderValue::from_bytes("application/json;profile=\"雪;,\"".as_bytes())
                .unwrap(),
        );
        assert!(accepts_json(&headers), "Quoted UTF-8 parameter rejected.");
    }
    #[test]
    fn registration_accept_selection_matches_rocket_common_quality_and_specificity_rules() {
        for (header, json) in [
            ("application/json", true),
            ("APPLICATION/JSON;charset=utf8", true),
            ("*/*", false),
            ("application/*", false),
            ("application/problem+json", false),
            ("application/json;q=0", true),
            ("*/*;q=1,application/json;q=0", true),
            ("text/plain,application/json", false),
            ("application/json,text/plain", true),
            ("application/json;q=1,text/plain", false),
            ("text/plain;q=0.3,application/json;q=0.9", true),
            ("application/json;q=0.9,text/plain;q=0.3", true),
            ("text/plain;q=0.5,application/json", true),
            ("not a media type", false),
            ("application/json;q=wrong", false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("accept", header.parse().unwrap());
            assert!(accepts_json(&headers) == json, "Accept selection differed.");
        }
        assert!(!accepts_json(&HeaderMap::new()));
    }
    #[test]
    fn registration_owned_guards_preserve_schema_aliases_and_old_first_precedence() {
        for body in [
            br#"{"email":"","name":null}"#.as_slice(),
            br#"["email",null]"#,
            br#"{"email":"NUL\u0000\u96ea","name":""}"#,
        ] {
            assert!(parse_verification(body).is_ok());
        }
        for body in [
            b"{}".as_slice(),
            b"[]",
            br#"["email"]"#,
            br#"{"email":"x","email":"y"}"#,
            br#"{"email":null}"#,
        ] {
            let Err(error) = parse_verification(body) else {
                panic!("Invalid verification schema accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
        let flat=br#"{"email":"","kdfType":-7,"iterations":-8,"memory":-1,"parallelism":0,"userSymmetricKey":"NUL\u0000","master_password_hash":"","userAsymmetricKeys":{"publicKey":"","encryptedPrivateKey":""},"ignored":true}"#;
        let parsed = parse_finish(flat).unwrap_or_else(|_| panic!("Legacy fixture rejected."));
        assert!(matches!(parsed.credentials, Credentials::Legacy(_)));
        let mixed=br#"{"email":"e","kdf":0,"kdfIterations":100000,"key":"old","masterPasswordHash":"old","masterPasswordAuthentication":{"kdf":{"kdfType":-2,"iterations":-3},"salt":"wrong","hash":"new"},"masterPasswordUnlock":{"kdf":{"kdfType":-2,"iterations":-3},"salt":"wrong","key":"new"}}"#;
        assert!(matches!(
            parse_finish(mixed)
                .unwrap_or_else(|_| panic!("Mixed fixture rejected."))
                .credentials,
            Credentials::Legacy(_)
        ));
        for body in [b"{}".as_slice(),b"[]",br#"{"email":"e","kdf":0,"kdfIterations":100000,"key":"k","masterPasswordHash":"h","keys":{"publicKey":null,"encryptedPrivateKey":""}}"#,br#"{"email":"e","email":"x","kdf":0,"kdfIterations":100000,"key":"k","masterPasswordHash":"h"}"#] {
            let Err(error)=parse_finish(body) else{panic!("Invalid finish schema accepted.")};assert_eq!(error.0,StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
}
