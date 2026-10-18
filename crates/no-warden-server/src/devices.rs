//! Adapter-owned discovery registry and disabled-relay push-token storage.
//! Source: vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91,
//! accounts.rs:1504-1641, push.rs:87-151, device.rs:23-130, identity.rs:776-797 and
//! macros/src/lib.rs:40-58. Device IDs are opaque in headers/login forms;
//! authenticated path IDs use the upstream ASCII alphanumeric/hyphen guard.

use crate::{Failure, connect_field, digest};
use axum::http::{HeaderMap, StatusCode};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use no_warden::{
    devices::{DeviceListData, DeviceRecord, DeviceRegistration},
    wire::KnownDeviceRequest,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use std::collections::BTreeMap;

// Decode strings before borrowing the core request. Parsing the original body
// preserves known duplicate-field errors and Serde's positional struct schema.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushInput {
    pub push_token: String,
}
pub fn parse_push_input(body: &[u8]) -> Result<PushInput, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}

pub struct KnownHeaders {
    email: String,
    identifier: String,
}
impl KnownHeaders {
    pub fn request(&self) -> KnownDeviceRequest<'_> {
        KnownDeviceRequest {
            email: &self.email,
            identifier: &self.identifier,
        }
    }
}

fn bad(message: &'static str) -> Failure {
    Failure(StatusCode::BAD_REQUEST, message)
}

pub fn known_headers(headers: &HeaderMap) -> Result<KnownHeaders, Failure> {
    let encoded = headers
        .get("x-request-email")
        .ok_or_else(|| bad("X-Request-Email value is required"))?;
    let encoded = std::str::from_utf8(encoded.as_bytes())
        .map_err(|_| bad("X-Request-Email value failed to decode as base64url"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.trim_end_matches('='))
        .map_err(|_| bad("X-Request-Email value failed to decode as base64url"))?;
    let email = String::from_utf8(bytes)
        .map_err(|_| bad("X-Request-Email value failed to decode as UTF-8"))?;
    let identifier = headers
        .get("x-device-identifier")
        .ok_or_else(|| bad("X-Device-Identifier value is required"))?;
    // Rocket reads UTF-8 header bytes, including non-ASCII identifiers.
    let identifier = std::str::from_utf8(identifier.as_bytes())
        .map_err(|_| bad("Invalid device identifier"))?
        .to_owned();
    Ok(KnownHeaders { email, identifier })
}

// Decode only bytes admitted by IdFromParam. A literal '+' is never form-decoded.
// Rejecting any other byte also rejects malformed escapes and invalid UTF-8.
pub fn path_identifier(segment: &str) -> Result<String, Failure> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let fail = || Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid device ID");
    let bytes = segment.as_bytes();
    let mut result = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let byte = if bytes[i] == b'%' {
            let high = bytes.get(i + 1).copied().and_then(hex).ok_or_else(fail)?;
            let low = bytes.get(i + 2).copied().and_then(hex).ok_or_else(fail)?;
            i += 3;
            high * 16 + low
        } else {
            let byte = bytes[i];
            i += 1;
            byte
        };
        if !byte.is_ascii_alphanumeric() && byte != b'-' {
            return Err(fail());
        }
        result.push(char::from(byte));
    }
    Ok(result)
}

pub fn login_registration(
    form: &BTreeMap<String, String>,
) -> Result<DeviceRegistration<'_>, Failure> {
    let identifier = connect_field(form, &["device_identifier", "deviceidentifier"])?
        .ok_or_else(|| bad("Device identifier is required"))?;
    let name = connect_field(form, &["device_name", "devicename"])?
        .ok_or_else(|| bad("Device name is required"))?;
    let device_type = connect_field(form, &["device_type", "devicetype"])?
        .ok_or_else(|| bad("Device type is required"))?;
    Ok(DeviceRegistration {
        identifier,
        name,
        device_type: device_type.parse().unwrap_or(14),
    })
}

pub struct Record {
    pub owner: String,
    pub identifier: String,
    pub name: String,
    pub device_type: i32,
    pub created: String,
}
impl Record {
    pub fn view(&self) -> DeviceRecord<'_> {
        DeviceRecord {
            owner_id: &self.owner,
            identifier: &self.identifier,
            name: &self.name,
            device_type: self.device_type,
            creation_date: &self.created,
            pending_auth_request: None,
        }
    }
}
#[derive(Default)]
pub struct Registry(pub Vec<Record>);
impl DeviceListData for Registry {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<DeviceRecord<'_>> {
        self.0.get(index).map(Record::view)
    }
}
fn record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok(Record {
        owner: row.get(0)?,
        identifier: row.get(1)?,
        name: row.get(2)?,
        device_type: row.get(3)?,
        created: row.get(4)?,
    })
}
pub fn list(db: &Connection, owner: &str) -> rusqlite::Result<Registry> {
    let mut statement = db.prepare("SELECT owner,identifier,name,device_type,created FROM device_registry WHERE owner=?1 ORDER BY rowid")?;
    Ok(Registry(
        statement
            .query_map([owner], record)?
            .collect::<rusqlite::Result<Vec<_>>>()?,
    ))
}
pub fn load(db: &Connection, owner: &str, identifier: &str) -> rusqlite::Result<Option<Record>> {
    db.query_row("SELECT owner,identifier,name,device_type,created FROM device_registry WHERE owner=?1 AND identifier=?2", params![owner,identifier], record).optional()
}
fn activity_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}
pub fn register(
    db: &mut Connection,
    owner: &str,
    registration: &DeviceRegistration<'_>,
) -> rusqlite::Result<()> {
    let tx = db.savepoint()?;
    let now = activity_now();
    tx.execute("INSERT INTO device_registry(owner,identifier,name,device_type,created,updated) VALUES(?1,?2,?3,?4,?5,?5) ON CONFLICT(owner,identifier) DO UPDATE SET updated=excluded.updated", params![owner,registration.identifier,registration.name,registration.device_type,now])?;
    tx.commit()
}
pub fn touch(db: &Connection, owner: &str, identifier: &str) -> rusqlite::Result<()> {
    let changed = db.execute(
        "UPDATE device_registry SET updated=?1 WHERE owner=?2 AND identifier=?3",
        params![activity_now(), owner, identifier],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(rusqlite::Error::QueryReturnedNoRows)
    }
}
pub fn bind(db: &Connection, owner: &str, identifier: &str, access: &str) -> rusqlite::Result<()> {
    let changed = db.execute("INSERT INTO session_devices(access,owner,identifier) SELECT access,owner,?1 FROM sessions WHERE access=?2 AND owner=?3", params![identifier,digest(access),owner])?;
    if changed == 1 {
        Ok(())
    } else {
        Err(rusqlite::Error::QueryReturnedNoRows)
    }
}
pub fn refresh_binding(
    db: &Connection,
    refresh_digest: &str,
    owner: &str,
) -> rusqlite::Result<Option<String>> {
    db.query_row("SELECT d.identifier FROM session_devices d JOIN sessions s ON s.access=d.access AND s.owner=d.owner WHERE s.refresh=?1 AND s.owner=?2", params![refresh_digest,owner], |row| row.get(0)).optional()
}

// This lookup accepts only the session whose access digest was authenticated by
// dispatch. Request headers, a path ID and decoded-but-unverified JWT claims
// cannot select the target device.
pub fn access_binding(
    db: &Connection,
    access_digest: &str,
    owner: &str,
) -> rusqlite::Result<Option<String>> {
    db.query_row("SELECT d.identifier FROM session_devices d JOIN sessions s ON s.access=d.access AND s.owner=d.owner JOIN device_registry r ON r.owner=d.owner AND r.identifier=d.identifier WHERE s.access=?1 AND s.owner=?2", params![access_digest,owner], |row| row.get(0)).optional()
}
pub fn push_token(
    db: &Connection,
    owner: &str,
    identifier: &str,
) -> rusqlite::Result<Option<String>> {
    db.query_row(
        "SELECT token FROM device_push_tokens WHERE owner=?1 AND identifier=?2",
        params![owner, identifier],
        |row| row.get(0),
    )
    .optional()
}
pub fn save_push_token(
    db: &mut Connection,
    owner: &str,
    identifier: &str,
    token: &str,
) -> rusqlite::Result<()> {
    let tx = db.savepoint()?;
    if push_token(&tx, owner, identifier)?.as_deref() != Some(token) {
        tx.execute("INSERT INTO device_push_tokens(owner,identifier,token) VALUES(?1,?2,?3) ON CONFLICT(owner,identifier) DO UPDATE SET token=excluded.token", params![owner,identifier,token])?;
        touch(&tx, owner, identifier)?;
    }
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn push_input_matches_required_string_schema_sequence_and_error_categories() {
        for body in [
            br#"{"pushToken":""}"#.as_slice(),
            br#"{"pushToken":"NUL\u0000caf\u00e9\u96ea","untrusted":{"id":"foreign"}}"#,
            br#"["opaque"]"#,
            br#"{"pushToken":"first","unknown":1,"unknown":2}"#,
        ] {
            assert!(parse_push_input(body).is_ok());
        }
        let parsed = parse_push_input(br#"{"pushToken":"NUL\u0000caf\u00e9"}"#)
            .unwrap_or_else(|_| panic!("Valid opaque push token rejected."));
        assert!(parsed.push_token == "NUL\0café");
        for body in [
            b"{}".as_slice(),
            b"null",
            b"false",
            b"17",
            br#"{"pushToken":null}"#,
            br#"{"pushToken":true}"#,
            br#"{"pushToken":4}"#,
            br#"{"pushToken":[]}"#,
            br#"{"pushToken":{}}"#,
            br#"{"pushToken":"one","pushToken":"two"}"#,
            b"[]",
            b"[null]",
        ] {
            let Err(error) = parse_push_input(body) else {
                panic!("Invalid push token schema accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
        for body in [
            b"".as_slice(),
            b"{",
            br#"{"pushToken":"truncated""#,
            br#"["first","extra"]"#,
            br#"{"pushToken":"one"} {}"#,
        ] {
            let Err(error) = parse_push_input(body) else {
                panic!("Invalid push token syntax accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn known_header_guard_preserves_utf8_opaque_ids_and_strict_email_decoding() {
        let mut headers = HeaderMap::new();
        for value in [
            None,
            Some("a"),
            Some("/w"),
            Some("YQ==x"),
            Some("YR"),
            Some("_w"),
        ] {
            if let Some(value) = value {
                headers.insert("x-request-email", value.parse().unwrap());
            } else {
                headers.remove("x-request-email");
            }
            let Err(error) = known_headers(&headers) else {
                panic!("Invalid email header accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        for email in ["", " Alice@Example.test ", "雪@example.test"] {
            headers.insert(
                "x-request-email",
                format!("{}=====", URL_SAFE_NO_PAD.encode(email))
                    .parse()
                    .unwrap(),
            );
            for identifier in ["", "opaque:_/+", "opaque-雪"] {
                headers.insert(
                    "x-device-identifier",
                    HeaderValue::from_bytes(identifier.as_bytes()).unwrap(),
                );
                let parsed = known_headers(&headers)
                    .unwrap_or_else(|_| panic!("Valid opaque headers rejected."));
                assert!(parsed.email == email && parsed.identifier == identifier);
            }
        }
        headers.remove("x-device-identifier");
        assert!(known_headers(&headers).is_err());
    }

    #[test]
    fn device_path_guard_decodes_percent_bytes_without_uuid_or_form_rules() {
        for (raw, expected) in [
            ("not-a-UUID", "not-a-UUID"),
            ("%41bc%2D9", "Abc-9"),
            ("UPPER", "UPPER"),
        ] {
            let parsed =
                path_identifier(raw).unwrap_or_else(|_| panic!("Valid device path rejected."));
            assert!(parsed == expected);
        }
        for raw in [
            "a+b",
            "a%2Bb",
            "a_b",
            "%5F",
            "%2F",
            "%00",
            "%E9%9B%AA",
            "%",
            "%0",
            "%GG",
            "雪",
        ] {
            let Err(error) = path_identifier(raw) else {
                panic!("Invalid device path accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
    }

    #[test]
    fn login_metadata_requires_presence_retains_opaque_values_and_parses_i32_only() {
        let mut form = BTreeMap::new();
        for (name, value) in [("DeviceIdentifier", ""), ("DEVICE_NAME", "NUL\0雪")] {
            form.insert(name.into(), value.into());
            assert!(login_registration(&form).is_err());
        }
        for (value, expected) in [
            ("-1", -1),
            ("+4", 4),
            ("2147483647", i32::MAX),
            ("-2147483648", i32::MIN),
            ("2147483648", 14),
            ("iOS", 14),
            ("", 14),
            (" 1", 14),
        ] {
            form.insert("deviceType".into(), value.into());
            let parsed = login_registration(&form)
                .unwrap_or_else(|_| panic!("Present device fields rejected."));
            assert!(parsed.identifier.is_empty() && parsed.name == "NUL\0雪");
            assert_eq!(parsed.device_type, expected);
        }
        form.insert("device_type".into(), "1".into());
        assert!(login_registration(&form).is_err());
    }
}
