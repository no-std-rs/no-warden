//! Adapter parsing and persistence for pending authentication-request discovery.
//! Pinned Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91:
//! accounts.rs:1650-1900, auth.rs:610-636 and models/auth_request.rs.
//! Access codes are stored privately and never enter wire projections or diagnostics.

use crate::Failure;
use axum::http::HeaderMap;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    pub access_code: String,
    pub device_identifier: String,
    pub email: String,
    pub public_key: String,
}
pub fn parse_input(body: &[u8]) -> Result<Input, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}
// The optional slot has no explicit default: omitted object fields are None,
// while positional input still requires the third slot before the bool.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInput {
    pub device_identifier: String,
    pub key: String,
    pub master_password_hash: Option<String>,
    pub request_approved: bool,
}
pub fn parse_update(body: &[u8]) -> Result<UpdateInput, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}

pub fn device_type(headers: &HeaderMap) -> i32 {
    headers
        .get("device-type")
        .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(14)
}

// Keep nanosecond precision without chrono's i64 timestamp_nanos limitation.
pub fn unix_nanos(value: chrono::DateTime<chrono::Utc>) -> i128 {
    i128::from(value.timestamp()) * 1_000_000_000 + i128::from(value.timestamp_subsec_nanos())
}

pub struct LoginRecord {
    id: String,
    owner: String,
    request_ip: String,
    approved: Option<bool>,
    used: bool,
    created_at_unix_nanos: i128,
    account_enabled: bool,
}
impl LoginRecord {
    pub fn view(&self) -> no_warden::auth_login::AuthRequestLoginRecord<'_> {
        no_warden::auth_login::AuthRequestLoginRecord {
            id: &self.id,
            owner_id: &self.owner,
            request_ip: &self.request_ip,
            approved: self.approved,
            used: self.used,
            created_at_unix_nanos: self.created_at_unix_nanos,
            account_enabled: self.account_enabled,
        }
    }
}

pub fn login_record(
    db: &rusqlite::Connection,
    owner: &str,
    id: &str,
    code: &no_warden::identity::Secret<'_>,
) -> rusqlite::Result<Option<LoginRecord>> {
    let Some(record) = load(db, owner, id)? else {
        return Ok(None);
    };
    if !verify_code(&record.access_code, code) {
        return Ok(None);
    }
    let (used, enabled): (bool, bool) = db.query_row(
        "SELECT authentication_date IS NOT NULL,COALESCE((SELECT enabled FROM account_auth_policy WHERE owner=?1),1) FROM auth_requests WHERE owner=?1 AND id=?2",
        rusqlite::params![owner,id], |row| Ok((row.get(0)?,row.get(1)?)),
    )?;
    let created = chrono::DateTime::parse_from_rfc3339(&record.created)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(Some(LoginRecord {
        id: record.id,
        owner: record.owner,
        request_ip: record.request_ip,
        approved: record.approved,
        used,
        created_at_unix_nanos: unix_nanos(created.with_timezone(&chrono::Utc)),
        account_enabled: enabled,
    }))
}

pub fn consume_login(
    db: &mut rusqlite::Connection,
    owner: &str,
    id: &str,
    now_unix_nanos: i128,
) -> rusqlite::Result<bool> {
    let seconds = i64::try_from(now_unix_nanos.div_euclid(1_000_000_000))
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let nanos = now_unix_nanos.rem_euclid(1_000_000_000) as u32;
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(seconds, nanos)
        .ok_or(rusqlite::Error::InvalidQuery)?
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let transaction = db.savepoint()?;
    let changed = transaction.execute(
        "UPDATE auth_requests SET authentication_date=?1 WHERE owner=?2 AND id=?3 AND approved=1 AND authentication_date IS NULL",
        rusqlite::params![date,owner,id],
    )?;
    transaction.commit()?;
    Ok(changed == 1)
}
pub fn origin(base: &str) -> Result<String, Failure> {
    let url = url::Url::parse(base).map_err(|_| {
        Failure(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid configured origin",
        )
    })?;
    Ok(url.origin().ascii_serialization())
}

pub struct Record {
    pub id: String,
    pub owner: String,
    pub device_identifier: String,
    pub device_type: i32,
    pub request_ip: String,
    access_code: String,
    pub public_key: String,
    pub key: Option<String>,
    pub master_password_hash: Option<String>,
    pub approved: Option<bool>,
    pub created: String,
    pub responded: Option<String>,
}
impl Record {
    pub fn view(&self) -> no_warden::auth_requests::AuthRequestRecord<'_> {
        no_warden::auth_requests::AuthRequestRecord {
            id: &self.id,
            owner_id: &self.owner,
            request_device_identifier: &self.device_identifier,
            device_type: self.device_type,
            request_ip: &self.request_ip,
            access_code: &self.access_code,
            public_key: &self.public_key,
            key: self.key.as_deref(),
            master_password_hash: self.master_password_hash.as_deref(),
            approved: self.approved,
            creation_date: &self.created,
            response_date: self.responded.as_deref(),
        }
    }
}
#[derive(Default)]
pub struct Requests(pub Vec<Record>);
impl no_warden::auth_requests::AuthRequestListData for Requests {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<no_warden::auth_requests::AuthRequestRecord<'_>> {
        self.0.get(index).map(Record::view)
    }
}
fn row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok(Record {
        id: row.get(0)?,
        owner: row.get(1)?,
        device_identifier: row.get(2)?,
        device_type: row.get(3)?,
        request_ip: row.get(4)?,
        access_code: row.get(5)?,
        public_key: row.get(6)?,
        key: row.get(7)?,
        master_password_hash: row.get(8)?,
        approved: row.get(9)?,
        created: row.get(10)?,
        responded: row.get(11)?,
    })
}
pub fn load(db: &rusqlite::Connection, owner: &str, id: &str) -> rusqlite::Result<Option<Record>> {
    use rusqlite::OptionalExtension;
    db.query_row("SELECT id,owner,request_device_identifier,device_type,request_ip,access_code,public_key,encrypted_key,master_password_hash,approved,creation_date,response_date FROM auth_requests WHERE owner=?1 AND id=?2",rusqlite::params![owner,id],row).optional()
}
pub fn list(db: &rusqlite::Connection, owner: &str) -> rusqlite::Result<Requests> {
    let mut statement=db.prepare("SELECT id,owner,request_device_identifier,device_type,request_ip,access_code,public_key,encrypted_key,master_password_hash,approved,creation_date,response_date FROM auth_requests WHERE owner=?1 ORDER BY rowid")?;
    Ok(Requests(
        statement
            .query_map([owner], row)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    ))
}
pub fn create(
    db: &mut rusqlite::Connection,
    owner: &str,
    request: &no_warden::wire::AuthRequestCreateRequest<'_>,
    context: &no_warden::auth_requests::AuthRequestContext<'_>,
) -> rusqlite::Result<Record> {
    let record = Record {
        id: uuid::Uuid::new_v4().to_string(),
        owner: owner.into(),
        device_identifier: request.device_identifier.into(),
        device_type: context.device_type,
        request_ip: context.request_ip.into(),
        access_code: request.access_code.into(),
        public_key: request.public_key.into(),
        key: None,
        master_password_hash: None,
        approved: None,
        created: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        responded: None,
    };
    let tx = db.savepoint()?;
    tx.execute("INSERT INTO auth_requests(id,owner,request_device_identifier,device_type,request_ip,access_code,public_key,creation_date) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",rusqlite::params![record.id,record.owner,record.device_identifier,record.device_type,record.request_ip,record.access_code,record.public_key,record.created])?;
    tx.commit()?;
    Ok(record)
}

// A fixed-size HMAC-SHA256 fingerprint makes the comparison independent of
// code contents and avoids prefix/length short-circuit string equality. This
// domain separator is public; the fingerprints are neither stored nor exposed.
// Mac::verify_slice performs the constant-time tag comparison.
pub fn verify_code(stored: &str, supplied: &no_warden::identity::Secret<'_>) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let fingerprint = |value: &str| {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"no-warden/auth-request/access-code/v1")
            .expect("HMAC key size");
        mac.update(value.as_bytes());
        mac
    };
    let expected = fingerprint(stored).finalize().into_bytes();
    fingerprint(supplied.expose_secret())
        .verify_slice(&expected)
        .is_ok()
}
pub fn by_code(
    db: &rusqlite::Connection,
    id: &str,
    code: &no_warden::identity::Secret<'_>,
) -> rusqlite::Result<Option<Record>> {
    use rusqlite::OptionalExtension;
    let record = db.query_row("SELECT id,owner,request_device_identifier,device_type,request_ip,access_code,public_key,encrypted_key,master_password_hash,approved,creation_date,response_date FROM auth_requests WHERE id=?1", [id], row).optional()?;
    Ok(record.filter(|record| verify_code(&record.access_code, code)))
}
pub fn respond(
    db: &mut rusqlite::Connection,
    owner: &str,
    id: &str,
    request: &no_warden::wire::AuthRequestUpdateRequest<'_>,
) -> rusqlite::Result<Record> {
    let tx = db.savepoint()?;
    let mut record = load(&tx, owner, id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    if record.approved.is_some() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let date = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let changed = if request.request_approved {
        tx.execute("UPDATE auth_requests SET encrypted_key=?1,master_password_hash=?2,approved=1,response_device_id=?3,response_date=?4 WHERE owner=?5 AND id=?6 AND approved IS NULL", rusqlite::params![request.key,request.master_password_hash,request.device_identifier,date,owner,id])?
    } else {
        tx.execute(
            "DELETE FROM auth_requests WHERE owner=?1 AND id=?2 AND approved IS NULL",
            rusqlite::params![owner, id],
        )?
    };
    if changed != 1 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    if request.request_approved {
        record.key = Some(request.key.into());
        record.master_password_hash = request.master_password_hash.map(str::to_owned);
        record.approved = Some(true);
    }
    record.responded = Some(date);
    tx.commit()?;
    Ok(record)
}

// Root extraction follows the same pinned Rocket NameView rules used for the
// verified sync query: leading dot/bracket and scalar nested suffixes are valid.
fn query_root(name: &str) -> &str {
    if name.starts_with('=') {
        return "";
    }
    if let Some(bracketed) = name.strip_prefix('[') {
        return bracketed.split(']').next().unwrap_or_default();
    }
    name.strip_prefix('.')
        .unwrap_or(name)
        .split(['.', '['])
        .next()
        .unwrap_or_default()
}

// Rocket's ConnectData matches the first name segment before handing scalar
// AuthRequestId its shifted field. Keep this compact selector separate from
// the adapter's other inherited form-field parsing policies.
pub fn auth_request_field(
    form: &std::collections::BTreeMap<String, String>,
) -> Result<Option<&str>, Failure> {
    let mut matches = form
        .iter()
        .filter(|(name, _)| query_root(name).eq_ignore_ascii_case("authrequest"));
    let value = matches.next().map(|(_, value)| value.as_str());
    if matches.next().is_some() {
        return Err(crate::invalid());
    }
    Ok(value)
}
pub fn query_code(query: Option<&str>) -> Result<String, Failure> {
    let missing = || {
        Failure(
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid auth request query",
        )
    };
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(query.unwrap_or_default()).map_err(|_| missing())?;
    pairs
        .into_iter()
        .find(|(name, _)| query_root(name) == "code")
        .map(|(_, value)| value)
        .ok_or_else(missing)
}

// Rocket percent-decodes a raw path parameter once before UuidFromParam. Retain
// the decoded spelling, including UUID case, braces and URN forms.
pub fn path_id(raw: &str) -> Result<String, Failure> {
    let fail = || {
        Failure(
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid auth request ID",
        )
    };
    let bytes = raw.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let high = (bytes[i + 1] as char).to_digit(16);
            let low = (bytes[i + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                output.push((high * 16 + low) as u8);
                i += 3;
                continue;
            }
        }
        output.push(bytes[i]);
        i += 1;
    }
    let decoded = String::from_utf8(output).map_err(|_| fail())?;
    uuid::Uuid::parse_str(&decoded).map_err(|_| fail())?;
    Ok(decoded)
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn auth_response_update_schema_preserves_optional_slot_and_opaque_strings() {
        for body in [br#"{"deviceIdentifier":"","key":"","requestApproved":true}"#.as_slice(),br#"["opaque","key",null,false]"#,br#"{"deviceIdentifier":"NUL\u0000\u96ea","key":"future","masterPasswordHash":"","requestApproved":false,"ignored":1}"#] {
            assert!(parse_update(body).is_ok());
        }
        for body in [b"{}".as_slice(),b"null",b"[]",br#"["d","k",true]"#,br#"["d","k",null]"#,br#"{"deviceIdentifier":"d","key":null,"requestApproved":true}"#,br#"{"deviceIdentifier":"d","key":"k","masterPasswordHash":false,"requestApproved":true}"#,br#"{"deviceIdentifier":"d","key":"k","requestApproved":1}"#,br#"{"deviceIdentifier":"d","key":"k","requestApproved":true,"requestApproved":false}"#] {
            let Err(error)=parse_update(body) else{panic!("Invalid auth-response schema accepted.")};assert_eq!(error.0,StatusCode::UNPROCESSABLE_ENTITY);
        }
        for body in [b"".as_slice(), b"{", br#"["d","k",null,true,null]"#] {
            let Err(error) = parse_update(body) else {
                panic!("Invalid auth-response syntax accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
    }
    #[test]
    fn auth_response_code_query_uses_rocket_first_root_and_form_decoding() {
        for (query, expected) in [
            ("code", ""),
            ("code=", ""),
            ("ignored=x&code=NUL%00caf%C3%A9", "NUL\0café"),
            ("code=a+b", "a b"),
            ("code=a%2Bb", "a+b"),
            ("code=%252B", "%2B"),
            ("code=first&code=second", "first"),
            ("Code=ignored&code=second", "second"),
            ("code.foo=first", "first"),
            ("[code]=first", "first"),
            (".code=first", "first"),
            ("[code=first", "first"),
            ("code=%FF", "�"),
            ("code=%GG", "%GG"),
        ] {
            let parsed =
                query_code(Some(query)).unwrap_or_else(|_| panic!("Valid code query rejected."));
            assert!(parsed == expected);
        }
        for query in [None, Some(""), Some("other=code"), Some("Code=ignored")] {
            let Err(error) = query_code(query) else {
                panic!("Missing required code query accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
    #[test]
    fn auth_response_code_comparison_checks_fixed_size_tags_without_plaintext_equality() {
        use no_warden::identity::Secret;
        for code in [
            "",
            "a",
            "NUL\0café 雪",
            "a reasonably long opaque access code",
        ] {
            assert!(verify_code(code, &Secret::new(code)));
            assert!(!verify_code(code, &Secret::new(&format!("{code}x"))));
            assert!(!verify_code(&format!("{code}x"), &Secret::new(code)));
        }
        assert!(!verify_code("prefix-a", &Secret::new("prefix-b")));
        assert!(!verify_code("prefix-a", &Secret::new("different")));
    }

    #[test]
    fn auth_request_json_schema_retains_opaque_fields_and_error_categories() {
        for body in [
            br#"{"accessCode":"","deviceIdentifier":"","email":"","publicKey":""}"#.as_slice(),
            br#"["code","device","mail","public"]"#,
            br#"{"accessCode":"NUL\u0000caf\u00e9","deviceIdentifier":"opaque_/+","email":"\u96ea@EXAMPLE.TEST","publicKey":"\r\n","unknown":1,"unknown":2}"#,
        ] { assert!(parse_input(body).is_ok()); }
        let parsed = parse_input(br#"["NUL\u0000caf\u00e9","device","mail","public"]"#)
            .unwrap_or_else(|_| panic!("Valid opaque auth-request JSON rejected."));
        assert!(
            parsed.access_code == "NUL\0café"
                && parsed.device_identifier == "device"
                && parsed.email == "mail"
                && parsed.public_key == "public"
        );
        for body in [b"{}".as_slice(),b"null",b"[]",br#"["code","device","mail"]"#,br#"{"accessCode":null,"deviceIdentifier":"d","email":"e","publicKey":"p"}"#,br#"{"accessCode":"c","deviceIdentifier":1,"email":"e","publicKey":"p"}"#,br#"{"accessCode":"c","deviceIdentifier":"d","email":[],"publicKey":"p"}"#,br#"{"accessCode":"c","deviceIdentifier":"d","email":"e","publicKey":{}}"#,br#"{"accessCode":"c","deviceIdentifier":"d","email":"e","publicKey":"p","publicKey":"duplicate"}"#] {
            let Err(error)=parse_input(body) else{panic!("Invalid auth-request schema accepted.")};
            assert_eq!(error.0,StatusCode::UNPROCESSABLE_ENTITY);
        }
        for body in [
            b"".as_slice(),
            b"{",
            br#"["c","d","e","p",null]"#,
            br#"{"accessCode":"c","deviceIdentifier":"d","email":"e","publicKey":"p"} {}"#,
        ] {
            let Err(error) = parse_input(body) else {
                panic!("Invalid auth-request syntax accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
    }
    #[test]
    fn auth_request_header_type_is_optional_raw_i32_and_origin_is_canonical() {
        let mut headers = HeaderMap::new();
        assert_eq!(device_type(&headers), 14);
        for (value, expected) in [
            ("", 14),
            (" 1", 14),
            ("iOS", 14),
            ("-7", -7),
            ("+1", 1),
            ("2147483648", 14),
            ("2147483647", i32::MAX),
        ] {
            headers.insert("device-type", value.parse().unwrap());
            assert_eq!(device_type(&headers), expected);
        }
        for (base, expected) in [
            (
                "https://EXAMPLE.test:443/sub/path?query",
                "https://example.test",
            ),
            ("http://example.test:8080/sub", "http://example.test:8080"),
            ("https://[::1]:8443/sub", "https://[::1]:8443"),
            ("http://user:pass@example.test/path", "http://example.test"),
        ] {
            let parsed =
                origin(base).unwrap_or_else(|_| panic!("Valid configured origin rejected."));
            assert!(parsed == expected);
        }
    }
    #[test]
    fn auth_request_uuid_guard_percent_decodes_once_and_preserves_spelling() {
        let uuid = "10000000-0000-4000-8000-0000000000ab";
        for (raw, expected) in [
            (uuid, uuid),
            (
                "10000000-0000-4000-8000-0000000000AB",
                "10000000-0000-4000-8000-0000000000AB",
            ),
            (
                "%7B10000000-0000-4000-8000-0000000000ab%7D",
                "{10000000-0000-4000-8000-0000000000ab}",
            ),
            (
                "urn%3Auuid%3A10000000-0000-4000-8000-0000000000ab",
                "urn:uuid:10000000-0000-4000-8000-0000000000ab",
            ),
            (
                "100000000000400080000000000000ab",
                "100000000000400080000000000000ab",
            ),
        ] {
            let decoded = path_id(raw).unwrap_or_else(|_| panic!("Valid UUID spelling rejected."));
            assert!(decoded == expected);
        }
        for raw in [
            "not-a-uuid",
            "%FF",
            "%257B10000000-0000-4000-8000-0000000000ab%257D",
            "10000000-0000-4000-8000-0000000000a%",
            "+10000000-0000-4000-8000-0000000000ab",
        ] {
            let Err(error) = path_id(raw) else {
                panic!("Invalid auth-request UUID accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
    }
}
