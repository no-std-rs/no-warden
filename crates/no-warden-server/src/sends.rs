//! Personal text Sends. Ciphertext stays opaque; storage, clocks and proof
//! cryptography implement the reusable allocation-free Send provider contract.

use crate::{Failure, store::Store};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use hmac::{Hmac, Mac, digest::CtOutput};
use no_warden::{
    VaultService,
    identity::Secret,
    sends::{
        SendAccessError, SendContext, SendListData, SendNumber, SendPasswordChange, SendPolicy,
        SendRecord, SendState, SendStorage, ValidatedSendAccess, ValidatedTextSend,
    },
    wire::{SendAccessTokenRequest, TextSendRequest},
};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS personal_sends(
 id TEXT PRIMARY KEY,
 owner TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 kind INTEGER NOT NULL,
 name TEXT NOT NULL, notes TEXT, key TEXT NOT NULL, data TEXT NOT NULL,
 password_hash BLOB, password_salt BLOB,
 max_access_count INTEGER, access_count INTEGER NOT NULL DEFAULT 0,
 disabled INTEGER NOT NULL, hide_email INTEGER,
 created TEXT NOT NULL, revision TEXT NOT NULL, expiration TEXT, deletion TEXT NOT NULL,
 CHECK((password_hash IS NULL AND password_salt IS NULL) OR
       (length(password_hash)=32 AND length(password_salt)=64))
);
CREATE INDEX IF NOT EXISTS personal_sends_owner ON personal_sends(owner);
CREATE TABLE IF NOT EXISTS send_signing_key(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 secret BLOB NOT NULL CHECK(length(secret)=32)
);";

#[derive(Deserialize)]
#[serde(untagged)]
enum Number {
    Integer(i64),
    String(String),
}
impl Number {
    fn view(&self) -> SendNumber<'_> {
        match self {
            Self::Integer(value) => SendNumber::Integer(*value),
            Self::String(value) => SendNumber::String(value),
        }
    }
}

struct Date(DateTime<Utc>);
impl<'de> Deserialize<'de> for Date {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        DateTime::<Utc>::deserialize(deserializer).map(Self)
    }
}
fn nanos(value: DateTime<Utc>) -> i128 {
    i128::from(value.timestamp()) * 1_000_000_000 + i128::from(value.timestamp_subsec_nanos())
}
fn date(value: i128) -> rusqlite::Result<String> {
    let seconds = i64::try_from(value.div_euclid(1_000_000_000))
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    DateTime::from_timestamp(seconds, value.rem_euclid(1_000_000_000) as u32)
        .map(|date| date.to_rfc3339_opts(SecondsFormat::Micros, true))
        .ok_or(rusqlite::Error::InvalidQuery)
}
fn parse_date(value: &str) -> rusqlite::Result<i128> {
    value
        .parse::<DateTime<Utc>>()
        .map(nanos)
        .map_err(|_| rusqlite::Error::InvalidQuery)
}
pub fn context() -> SendContext {
    SendContext {
        now_unix_nanos: nanos(Utc::now()),
    }
}

// Parsed source dates keep their display representation alongside semantic time.
// A leap second is representable by Chrono but not by a plain Unix nanosecond count.
// Only adapter-decoded dates matching the validated request can be used for a write.
pub(crate) struct Dates {
    deletion_ns: i128,
    expiration_ns: Option<i128>,
    deletion: String,
    expiration: Option<String>,
}

// Keep all fifteen source fields in declaration order. Besides duplicate-field
// guards this preserves Serde's accepted positional-array representation.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    #[serde(rename = "type")]
    kind: i32,
    key: String,
    password: Option<String>,
    max_access_count: Option<Number>,
    expiration_date: Option<Date>,
    deletion_date: Date,
    disabled: bool,
    hide_email: Option<bool>,
    emails: Option<String>,
    name: String,
    notes: Option<String>,
    text: Option<Value>,
    #[serde(rename = "file")]
    _file: Option<Value>,
    #[serde(rename = "fileLength")]
    _file_length: Option<Number>,
    #[serde(rename = "id")]
    _id: Option<String>,
}
impl Input {
    pub fn parse(body: &[u8]) -> Result<Self, Failure> {
        serde_json::from_slice(body).map_err(crate::json_guard_error)
    }
    pub fn request(&self) -> TextSendRequest<'_, Value> {
        TextSendRequest {
            kind: self.kind,
            key: &self.key,
            password: self.password.as_deref().map(Secret::new),
            max_access_count: self.max_access_count.as_ref().map(Number::view),
            expiration_ns: self.expiration_date.as_ref().map(|date| nanos(date.0)),
            deletion_ns: nanos(self.deletion_date.0),
            disabled: self.disabled,
            hide_email: self.hide_email,
            emails: self.emails.as_deref(),
            name: &self.name,
            notes: self.notes.as_deref(),
            text: self.text.as_ref(),
        }
    }
    pub fn stage_dates(&self, store: &mut Store) {
        store.send_dates = Some(Dates {
            deletion_ns: nanos(self.deletion_date.0),
            expiration_ns: self.expiration_date.as_ref().map(|date| nanos(date.0)),
            deletion: self
                .deletion_date
                .0
                .to_rfc3339_opts(SecondsFormat::Micros, true),
            expiration: self
                .expiration_date
                .as_ref()
                .map(|date| date.0.to_rfc3339_opts(SecondsFormat::Micros, true)),
        });
    }
}

pub(crate) struct Record {
    id: String,
    owner: String,
    kind: i32,
    access_id: String,
    name: String,
    notes: Option<String>,
    key: String,
    text: Value,
    password_hash: Option<String>,
    max_access_count: Option<i32>,
    access_count: i32,
    disabled: bool,
    hide_email: Option<bool>,
    revision: String,
    expiration: Option<String>,
    deletion: String,
    email: String,
}

// Match upstream's object projection, including normalization of future nested
// field names. Encrypted string VALUES are never decoded or transformed.
fn lower_keys(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let key = if key.eq_ignore_ascii_case("ssn") {
                        "ssn".to_owned()
                    } else {
                        let mut chars = key.chars();
                        match chars.next() {
                            Some(first) => first.to_lowercase().chain(chars).collect(),
                            None => key,
                        }
                    };
                    (key, lower_keys(value))
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(lower_keys).collect()),
        value => value,
    }
}
fn projected_text(value: Value) -> Value {
    if !value.is_object() {
        return Value::Null;
    }
    let mut value = lower_keys(value);
    if let Some(size) = value.get("size").and_then(Value::as_i64) {
        value["size"] = json!(size.to_string());
    }
    value
}
fn stored_text<P: Serialize + ?Sized>(payload: &P) -> rusqlite::Result<String> {
    let mut value = serde_json::to_value(payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("response");
    }
    serde_json::to_string(&value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn load(db: &Connection, id: &str) -> rusqlite::Result<Option<Record>> {
    db.query_row(
        "SELECT s.id,s.owner,s.kind,s.name,s.notes,s.key,s.data,s.password_hash,
         s.max_access_count,s.access_count,s.disabled,s.hide_email,s.revision,
         s.expiration,s.deletion,a.email FROM personal_sends s JOIN accounts a
         ON a.id=s.owner WHERE s.id=?1",
        [id],
        |row| {
            let id: String = row.get(0)?;
            let uuid = uuid::Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let data: String = row.get(6)?;
            let data: Value =
                serde_json::from_str(&data).map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(Record {
                access_id: URL_SAFE_NO_PAD.encode(uuid.as_bytes()),
                id,
                owner: row.get(1)?,
                kind: row.get(2)?,
                name: row.get(3)?,
                notes: row.get(4)?,
                key: row.get(5)?,
                text: projected_text(data),
                password_hash: row
                    .get::<_, Option<Vec<u8>>>(7)?
                    .map(|hash| URL_SAFE_NO_PAD.encode(hash)),
                max_access_count: row.get(8)?,
                access_count: row.get(9)?,
                disabled: row.get(10)?,
                hide_email: row.get(11)?,
                revision: row.get(12)?,
                expiration: row.get(13)?,
                deletion: row.get(14)?,
                email: row.get(15)?,
            })
        },
    )
    .optional()
}

fn password(proof: &Secret<'_>) -> ([u8; 32], [u8; 64]) {
    let mut salt = [0; 64];
    OsRng.fill_bytes(&mut salt);
    let mut hash = [0; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(proof.expose_secret().as_bytes(), &salt, 100_000, &mut hash);
    (hash, salt)
}
type StoredVerifier = (Option<Vec<u8>>, Option<Vec<u8>>);

pub fn signing_key(db: &Connection) -> rusqlite::Result<[u8; 32]> {
    if let Some(key) = db
        .query_row(
            "SELECT secret FROM send_signing_key WHERE singleton=1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
    {
        return key.try_into().map_err(|_| rusqlite::Error::InvalidQuery);
    }
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    db.execute(
        "INSERT OR IGNORE INTO send_signing_key(singleton,secret) VALUES(1,?1)",
        [key.as_slice()],
    )?;
    signing_key(db)
}
fn issuer(base: &str) -> rusqlite::Result<String> {
    let url = url::Url::parse(base).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(format!("{}|send", url.origin().ascii_serialization()))
}

#[derive(Serialize, Deserialize)]
struct Claims {
    nbf: i64,
    exp: i64,
    iss: String,
    sub: String,
}
fn token(key: &[u8; 32], claims: &Claims) -> rusqlite::Result<String> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(claims).map_err(|_| rusqlite::Error::InvalidQuery)?);
    let unsigned = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| rusqlite::Error::InvalidQuery)?;
    mac.update(unsigned.as_bytes());
    Ok(format!(
        "{unsigned}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}
fn verify_token(key: &[u8; 32], issuer: &str, proof: &Secret<'_>, now: i64) -> Option<String> {
    #[derive(Deserialize)]
    struct Header {
        alg: String,
    }
    let normalized: String = proof
        .expose_secret()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut parts = normalized.split('.');
    let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header_value: Header =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    if header_value.alg != "HS256" {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(format!("{header}.{payload}").as_bytes());
    mac.verify_slice(&URL_SAFE_NO_PAD.decode(signature).ok()?)
        .ok()?;
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    if claims.iss != issuer
        || claims.exp < 0
        || claims.nbf < 0
        || claims.exp < now.saturating_sub(30)
        || claims.nbf > now.saturating_add(30)
    {
        return None;
    }
    Some(claims.sub)
}

pub fn path_id(raw: &str) -> Result<String, Failure> {
    crate::auth_requests::path_id(raw)
        .map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid Send ID"))
}

impl Record {
    fn state(&self) -> rusqlite::Result<SendState<'_>> {
        Ok(SendState {
            id: &self.id,
            owner_id: &self.owner,
            kind: self.kind,
            disabled: self.disabled,
            max_access_count: self.max_access_count,
            access_count: self.access_count,
            expiration_ns: self.expiration.as_deref().map(parse_date).transpose()?,
            deletion_ns: parse_date(&self.deletion)?,
            password_protected: self.password_hash.is_some(),
        })
    }
    fn view(&self) -> SendRecord<'_, &Value> {
        SendRecord {
            id: &self.id,
            owner_id: &self.owner,
            access_id: &self.access_id,
            name: &self.name,
            notes: self.notes.as_deref(),
            text: &self.text,
            key: &self.key,
            max_access_count: self.max_access_count,
            access_count: self.access_count,
            password_hash: self.password_hash.as_deref(),
            disabled: self.disabled,
            hide_email: self.hide_email,
            revision_date: &self.revision,
            expiration_date: self.expiration.as_deref(),
            deletion_date: &self.deletion,
            creator_identifier: (self.hide_email != Some(true)).then_some(self.email.as_str()),
        }
    }
}
pub struct List<'a>(&'a [Record]);
impl<'a> SendListData<'a> for List<'a> {
    type Payload = &'a Value;
    fn len(&self) -> usize {
        self.0.len()
    }
    fn get(&self, index: usize) -> Option<SendRecord<'a, Self::Payload>> {
        self.0.get(index).map(Record::view)
    }
}

fn save<P: Serialize + ?Sized>(
    db: &mut Connection,
    owner: &str,
    id: &str,
    plan: &ValidatedTextSend<'_, '_, P>,
    creating: bool,
    staged_dates: Option<Dates>,
) -> rusqlite::Result<()> {
    let request = plan.request();
    let data = stored_text(request.text.ok_or(rusqlite::Error::InvalidQuery)?)?;
    let (deletion, expiration) = match staged_dates.filter(|dates| {
        dates.deletion_ns == request.deletion_ns && dates.expiration_ns == request.expiration_ns
    }) {
        Some(dates) => (dates.deletion, dates.expiration),
        None => (
            date(request.deletion_ns)?,
            request.expiration_ns.map(date).transpose()?,
        ),
    };
    let changed_password = match plan.password_change() {
        SendPasswordChange::Set(proof) => Some(password(proof)),
        _ => None,
    };
    let tx = db.savepoint()?;
    let (hash, salt): StoredVerifier = match plan.password_change() {
        SendPasswordChange::Set(_) => {
            let (hash, salt) = changed_password.ok_or(rusqlite::Error::InvalidQuery)?;
            (Some(hash.to_vec()), Some(salt.to_vec()))
        }
        SendPasswordChange::Clear => (None, None),
        SendPasswordChange::Preserve => tx.query_row(
            "SELECT password_hash,password_salt FROM personal_sends WHERE id=?1 AND owner=?2",
            params![id, owner],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?,
    };
    let revision = crate::store::next_revision(&tx, owner)?;
    let send_revision = date(parse_date(&revision)?)?;
    let changed = if creating {
        tx.execute("INSERT INTO personal_sends(id,owner,kind,name,notes,key,data,password_hash,password_salt,
            max_access_count,access_count,disabled,hide_email,created,revision,expiration,deletion)
            VALUES(?1,?2,0,?3,?4,?5,?6,?7,?8,?9,0,?10,?11,?12,?12,?13,?14)",
            params![id,owner,request.name,request.notes,request.key,data,hash,salt,plan.max_access_count(),
                request.disabled,request.hide_email,send_revision,expiration,deletion])?
    } else {
        tx.execute(
            "UPDATE personal_sends SET name=?3,notes=?4,key=?5,data=?6,password_hash=?7,
            password_salt=?8,max_access_count=?9,disabled=?10,hide_email=?11,revision=?12,
            expiration=?13,deletion=?14 WHERE id=?1 AND owner=?2",
            params![
                id,
                owner,
                request.name,
                request.notes,
                request.key,
                data,
                hash,
                salt,
                plan.max_access_count(),
                request.disabled,
                request.hide_email,
                send_revision,
                expiration,
                deletion
            ],
        )?
    };
    if changed != 1 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    crate::store::bump(&tx, owner, &revision)?;
    tx.commit()
}

impl SendStorage for Store {
    type SendId = String;
    type Payload<'a> = &'a Value;
    type Sends<'a> = List<'a>;

    fn send_policy(&mut self, _owner: &str) -> rusqlite::Result<SendPolicy> {
        // This conformance host has no organizations or global Send restrictions.
        Ok(SendPolicy {
            can_modify: true,
            can_hide_email: true,
        })
    }
    fn send_state(&mut self, id: &str) -> rusqlite::Result<Option<SendState<'_>>> {
        self.send_record_cache = load(&self.db, id)?;
        self.send_record_cache
            .as_ref()
            .map(Record::state)
            .transpose()
    }
    fn send(&mut self, id: &str) -> rusqlite::Result<Option<SendRecord<'_, Self::Payload<'_>>>> {
        self.send_record_cache = load(&self.db, id)?;
        Ok(self.send_record_cache.as_ref().map(Record::view))
    }
    fn sends(&mut self, owner: &str) -> rusqlite::Result<Self::Sends<'_>> {
        let ids = self
            .db
            .prepare("SELECT id FROM personal_sends WHERE owner=?1 ORDER BY id")?
            .query_map([owner], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        self.send_records_cache = ids
            .iter()
            .map(|id| load(&self.db, id)?.ok_or(rusqlite::Error::QueryReturnedNoRows))
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(List(&self.send_records_cache))
    }
    fn create_text_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedTextSend<'_, '_, P>,
    ) -> rusqlite::Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        save(&mut self.db, owner, &id, plan, true, self.send_dates.take())?;
        Ok(id)
    }
    fn update_text_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        plan: &ValidatedTextSend<'_, '_, P>,
    ) -> rusqlite::Result<()> {
        save(&mut self.db, owner, id, plan, false, self.send_dates.take())
    }
    fn delete_send(&mut self, owner: &str, id: &str) -> rusqlite::Result<()> {
        let tx = self.db.savepoint()?;
        let revision = crate::store::next_revision(&tx, owner)?;
        if tx.execute(
            "DELETE FROM personal_sends WHERE id=?1 AND owner=?2",
            params![id, owner],
        )? != 1
        {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        crate::store::bump(&tx, owner, &revision)?;
        tx.commit()
    }
    fn remove_send_password(&mut self, owner: &str, id: &str) -> rusqlite::Result<()> {
        let tx = self.db.savepoint()?;
        let revision = crate::store::next_revision(&tx, owner)?;
        let send_revision = date(parse_date(&revision)?)?;
        if tx.execute("UPDATE personal_sends SET password_hash=NULL,password_salt=NULL,revision=?1 WHERE id=?2 AND owner=?3",
            params![send_revision,id,owner])? != 1 { return Err(rusqlite::Error::QueryReturnedNoRows); }
        crate::store::bump(&tx, owner, &revision)?;
        tx.commit()
    }
    fn resolve_send_access_id(&mut self, access_id: &str) -> rusqlite::Result<Option<String>> {
        Ok(URL_SAFE_NO_PAD
            .decode(access_id)
            .ok()
            .and_then(|bytes| uuid::Uuid::from_slice(&bytes).ok())
            .map(|uuid| uuid.to_string()))
    }
    fn verify_send_password(&mut self, id: &str, proof: &Secret<'_>) -> rusqlite::Result<bool> {
        let verifier: Option<StoredVerifier> = self
            .db
            .query_row(
                "SELECT password_hash,password_salt FROM personal_sends WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((Some(expected), Some(salt))) = verifier else {
            return Ok(false);
        };
        let expected: [u8; 32] = expected
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut actual = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            proof.expose_secret().as_bytes(),
            &salt,
            100_000,
            &mut actual,
        );
        Ok(CtOutput::<Sha256>::new(expected.into()) == CtOutput::<Sha256>::new(actual.into()))
    }
    fn verify_send_access_token(&mut self, proof: &Secret<'_>) -> rusqlite::Result<Option<String>> {
        Ok(verify_token(
            &signing_key(&self.db)?,
            &issuer(&self.download_base)?,
            proof,
            Utc::now().timestamp(),
        ))
    }
    fn register_send_access(&mut self, plan: &ValidatedSendAccess<'_>) -> rusqlite::Result<bool> {
        let tx = self.db.savepoint()?;
        let owner: String = tx.query_row(
            "SELECT owner FROM personal_sends WHERE id=?1",
            [plan.id()],
            |row| row.get(0),
        )?;
        let revision = crate::store::next_revision(&tx, &owner)?;
        // Upstream advances the owner even if the conditional counter update loses.
        crate::store::bump(&tx, &owner, &revision)?;
        let send_revision = date(parse_date(&revision)?)?;
        let changed = tx.execute(
            "UPDATE personal_sends SET access_count=access_count+1,revision=?1
            WHERE id=?2 AND (max_access_count IS NULL OR access_count<max_access_count)",
            params![send_revision, plan.id()],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }
}

pub struct TokenInput(Vec<(String, String)>);
impl TokenInput {
    pub fn selected(body: &[u8]) -> Result<Option<Self>, Failure> {
        let fields = Self(serde_urlencoded::from_bytes(body).map_err(|_| crate::invalid())?);
        Ok((fields.first(&["grant_type", "granttype"]) == Some("send_access")).then_some(fields))
    }
    fn first(&self, aliases: &[&str]) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| {
                aliases
                    .iter()
                    .any(|alias| crate::auth_requests::query_root(name).eq_ignore_ascii_case(alias))
            })
            .map(|(_, value)| value.as_str())
    }
    fn optional(&self, aliases: &[&str]) -> Option<&str> {
        let mut fields = self.0.iter().filter(|(name, _)| {
            aliases
                .iter()
                .any(|alias| crate::auth_requests::query_root(name).eq_ignore_ascii_case(alias))
        });
        let value = fields.next().map(|(_, value)| value.as_str());
        if fields.next().is_some() { None } else { value }
    }
    fn optional_exact(&self, name: &str) -> Option<&str> {
        // These two fields have no uncased/compact ConnectData annotations.
        let mut fields = self
            .0
            .iter()
            .filter(|(field, _)| crate::auth_requests::query_root(field) == name);
        let value = fields.next().map(|(_, value)| value.as_str());
        if fields.next().is_some() { None } else { value }
    }
    fn request(&self) -> SendAccessTokenRequest<'_> {
        SendAccessTokenRequest {
            grant_type: self.first(&["grant_type", "granttype"]),
            client_id: self.optional(&["client_id", "clientid"]),
            send_id: self.optional_exact("send_id"),
            password_hash_b64: self.optional_exact("password_hash_b64").map(Secret::new),
        }
    }
}
pub fn grant(store: &mut Store, input: &TokenInput) -> Result<Response, Failure> {
    let grant = match VaultService::new(&mut *store)
        .authenticate_send_access(&input.request(), &context())
    {
        Ok(grant) => grant,
        Err(SendAccessError::Api(error)) => {
            return Ok(crate::password_login::error_response(
                StatusCode::from_u16(error.status_code()).unwrap(),
                error.message,
            ));
        }
        Err(error) => {
            let (status, kind, code) = match error {
                SendAccessError::PasswordRequired => (
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "password_hash_b64_required",
                ),
                SendAccessError::InvalidPassword => (
                    StatusCode::NOT_FOUND,
                    "invalid_grant",
                    "password_hash_b64_invalid",
                ),
                _ => (StatusCode::NOT_FOUND, "invalid_grant", "send_id_invalid"),
            };
            return Ok((
                status,
                axum::Json(
                    json!({"kind":"expected_server","error":kind,"send_access_error_type":code}),
                ),
            )
                .into_response());
        }
    };
    let now = Utc::now().timestamp();
    let proof = token(
        &signing_key(&store.db)?,
        &Claims {
            nbf: now,
            exp: now + i64::from(grant.expires_in()),
            iss: issuer(&store.download_base)?,
            sub: grant.id().to_owned(),
        },
    )?;
    Ok(crate::json_response(
        json!({"access_token":proof,"expires_in":grant.expires_in(),"token_type":"Bearer","scope":grant.scope()}),
    ))
}
pub fn access(store: &mut Store, headers: &axum::http::HeaderMap) -> Result<Response, Failure> {
    let proof = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit("Bearer ").next())
        .ok_or_else(crate::unauthorized)?;
    let mut service = VaultService::new(store);
    let response = service.access_text_send(&Secret::new(proof), &context())?;
    Ok(axum::Json(response).into_response())
}
pub fn sync(store: &mut Store, owner: &str) -> Result<Value, Failure> {
    let mut service = VaultService::new(store);
    let response = service.list_sends(owner)?;
    let mut value = serde_json::to_value(response)
        .map_err(|_| Failure(StatusCode::INTERNAL_SERVER_ERROR, "Send response failed"))?;
    Ok(value["data"].take())
}

pub fn is_send_error(message: &str) -> bool {
    message.starts_with("Send ")
        || message.starts_with("Sends ")
        || message.starts_with("File sends ")
        || message.starts_with("You cannot have a Send ")
        || message.starts_with("Due to an Enterprise Policy, ")
        || matches!(
            message,
            "Number does not fit in i32" | "Can't convert to number"
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use no_warden::ApiError;

    fn fixture_at(path: &str) -> Store {
        let mut store = Store::open(path).unwrap();
        store.download_base = "http://127.0.0.1:18600/base".into();
        for owner in ["alice", "bob"] {
            store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'unused-verifier','2000-01-01T00:00:00.000Z')",
                params![owner,format!("{owner}@example.test"),json!({"id":owner,"key":"opaque-account-key","revisionDate":"2000-01-01T00:00:00.000Z"}).to_string()]).unwrap();
        }
        store
    }
    fn input() -> Input {
        let deletion = (Utc::now() + chrono::TimeDelta::days(1)).to_rfc3339();
        Input::parse(
            &serde_json::to_vec(
                &json!({"type":0,"key":"opaque-wrapped-seed","name":"opaque-name",
            "notes":"opaque-notes","text":{"text":"opaque-ciphertext","hidden":false},
            "deletionDate":deletion,"disabled":false,"password":"opaque-proof"}),
            )
            .unwrap(),
        )
        .unwrap_or_else(|_| panic!("Fixture input invalid"))
    }
    fn create(store: &mut Store, owner: &str, input: &Input) -> String {
        input.stage_dates(store);
        let request = input.request();
        let mut service = VaultService::new(store);
        let response = service
            .create_text_send(owner, &request, &context())
            .unwrap();
        let document = serde_json::to_value(response).unwrap();
        document["id"].as_str().unwrap().to_owned()
    }
    fn capability(store: &mut Store, id: &str) -> String {
        let now = Utc::now().timestamp();
        token(
            &signing_key(&store.db).unwrap(),
            &Claims {
                nbf: now,
                exp: now + 120,
                iss: issuer(&store.download_base).unwrap(),
                sub: id.into(),
            },
        )
        .unwrap()
    }
    fn snapshot(store: &Store) -> Vec<Vec<String>> {
        use rusqlite::types::ValueRef;
        let mut snapshot = Vec::new();
        for sql in [
            "SELECT * FROM accounts ORDER BY id",
            "SELECT * FROM personal_sends ORDER BY id",
            "SELECT * FROM send_signing_key ORDER BY singleton",
        ] {
            let mut statement = store.db.prepare(sql).unwrap();
            let columns = statement.column_count();
            snapshot.extend(
                statement
                    .query_map([], |row| {
                        (0..columns)
                            .map(|column| {
                                Ok(match row.get_ref(column)? {
                                    ValueRef::Null => "null".into(),
                                    ValueRef::Integer(value) => format!("i{value}"),
                                    ValueRef::Real(value) => format!("r{}", value.to_bits()),
                                    ValueRef::Text(value) => {
                                        format!("s{}", URL_SAFE_NO_PAD.encode(value))
                                    }
                                    ValueRef::Blob(value) => {
                                        format!("b{}", URL_SAFE_NO_PAD.encode(value))
                                    }
                                })
                            })
                            .collect::<rusqlite::Result<Vec<_>>>()
                    })
                    .unwrap()
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .unwrap(),
            );
        }
        snapshot
    }

    #[test]
    fn send_input_matches_source_field_order_and_does_not_narrow_opaque_values() {
        let bytes = br#"{"type":0,"key":"","deletionDate":"2026-01-01T01:00:00.123456789+01:00","disabled":false,"name":"","text":{"text":"escaped\u0000opaque"},"maxAccessCount":"-1","id":"ignored","owner":"forged"}"#;
        let input = Input::parse(bytes).unwrap_or_else(|_| panic!("Valid Send rejected"));
        let request = input.request();
        assert!(request.key.is_empty() && request.name.is_empty());
        assert!(request.max_access_count.unwrap().into_i32().unwrap() == -1);
        assert!(date(request.deletion_ns).unwrap() == "2026-01-01T00:00:00.123456Z");
        assert!(request.text.unwrap()["text"] == "escaped\0opaque");
        let array = br#"[0,"",null,null,null,"2026-01-01T00:00:00Z",false,null,null,"",null,{"text":"opaque"},null,null,"ignored"]"#;
        assert!(Input::parse(array).is_ok());
        for invalid in [
            br#"{"Type":0,"key":"","deletionDate":"2026-01-01T00:00:00Z","disabled":false,"name":"","text":{}}"#.as_slice(),
            br#"{"type":0,"key":"","deletionDate":"2026-01-01T00:00:00Z","disabled":false,"name":"","text":{},"text":{}}"#,
            br#"{"type":0,"key":"","deletionDate":"2026-01-01T00:00:00Z","disabled":false,"name":"","text":{},"id":{}}"#,
            br#"{"type":0,"key":"","deletionDate":"2026-01-01T00:00:00Z","disabled":false,"name":"","text":{},"fileLength":false}"#,
        ] {
            let Err(error) = Input::parse(invalid) else { panic!("Malformed Send accepted") };
            assert!(error.0 == StatusCode::UNPROCESSABLE_ENTITY);
        }
        let canonical = TokenInput::selected(b"GRANTTYPE=send_access&CLIENTID=send&[send_id].x=opaque-id&password_hash_b64.x=opaque-proof&SEND_ID=ignored&passwordhashb64=ignored")
            .unwrap_or_else(|_| panic!("Valid form rejected")).unwrap_or_else(|| panic!("Send grant not selected"));
        let request = canonical.request();
        assert!(
            request.send_id == Some("opaque-id")
                && request.client_id == Some("send")
                && request.password_hash_b64.as_ref().unwrap().expose_secret() == "opaque-proof"
        );
        let ignored = TokenInput::selected(b"grant_type=send_access&client_id=send&sendid=ignored&SEND_ID=ignored&passwordhashb64=ignored&PASSWORD_HASH_B64=ignored")
            .unwrap_or_else(|_| panic!("Valid form rejected")).unwrap_or_else(|| panic!("Send grant not selected"));
        assert!(
            ignored.request().send_id.is_none() && ignored.request().password_hash_b64.is_none()
        );
        let duplicate = TokenInput::selected(b"grant_type=send_access&send_id=first&send_id.x=second&password_hash_b64=first&password_hash_b64[x]=second")
            .unwrap_or_else(|_| panic!("Valid form rejected")).unwrap_or_else(|| panic!("Send grant not selected"));
        assert!(
            duplicate.request().send_id.is_none()
                && duplicate.request().password_hash_b64.is_none()
        );
    }

    #[test]
    fn send_projection_removes_only_exact_response_and_preserves_encrypted_values() {
        let payload = json!({"Text":"opaque\0ciphertext","Hidden":false,"response":"remove",
            "Response":"retained","Size":17,"SSN":"opaque-suffix","Future":[{"NestedKey":"opaque-value","response":"nested-retained"}]});
        let stored: Value = serde_json::from_str(&stored_text(&payload).unwrap()).unwrap();
        assert!(stored.get("response").is_none() && stored["Response"] == "retained");
        let projected = projected_text(stored);
        assert!(
            projected["text"] == "opaque\0ciphertext"
                && projected["response"] == "retained"
                && projected["size"] == "17"
                && projected["ssn"] == "opaque-suffix"
                && projected["future"][0]["nestedKey"] == "opaque-value"
                && projected["future"][0]["response"] == "nested-retained"
        );
        for value in [
            Value::Null,
            json!("opaque"),
            json!([{"text":"opaque"}]),
            json!(123),
            json!(true),
        ] {
            assert!(projected_text(value).is_null());
        }
    }

    #[test]
    fn send_native_date_grammar_and_leap_second_projection_survive_writes() {
        let mut store = fixture_at(":memory:");
        for (encoded, expected) in [
            ("2000-01-01 00:00:00+0000", "2000-01-01T00:00:00.000000Z"),
            ("2016-12-31T23:59:60Z", "2016-12-31T23:59:60.000000Z"),
            ("-0001-01-01T00:00:00Z", "-0001-01-01T00:00:00.000000Z"),
        ] {
            let mut input = input();
            input.password = None;
            input.deletion_date = serde_json::from_value(json!(encoded)).unwrap();
            input.expiration_date = Some(serde_json::from_value(json!(encoded)).unwrap());
            let id = create(&mut store, "alice", &input);
            let record = load(&store.db, &id).unwrap().unwrap();
            assert!(record.deletion == expected && record.expiration.as_deref() == Some(expected));
            assert!(record.state().is_ok());
            let request = input.request();
            input.stage_dates(&mut store);
            let mut service = VaultService::new(&mut store);
            let response = service
                .update_text_send("alice", &id, &request, &context())
                .unwrap();
            let response = serde_json::to_value(response).unwrap();
            assert!(response["deletionDate"] == expected && response["expirationDate"] == expected);
        }
    }

    #[test]
    fn send_capability_checks_signature_purpose_and_exact_leeway_with_unicode_whitespace() {
        let key = [41u8; 32];
        let claims = Claims {
            nbf: 1000,
            exp: 1120,
            iss: "https://example.test|send".into(),
            sub: "send-id".into(),
        };
        let encoded = token(&key, &claims).unwrap();
        let spaced = format!("\u{2003}{}\n\u{a0}", encoded.replace('.', ".\t"));
        for now in [970, 1000, 1120, 1150] {
            assert!(
                verify_token(&key, &claims.iss, &Secret::new(&spaced), now).as_deref()
                    == Some("send-id")
            );
        }
        for now in [969, 1151] {
            assert!(verify_token(&key, &claims.iss, &Secret::new(&encoded), now).is_none());
        }
        assert!(verify_token(&[42; 32], &claims.iss, &Secret::new(&encoded), 1000).is_none());
        assert!(
            verify_token(
                &key,
                "https://example.test|login",
                &Secret::new(&encoded),
                1000
            )
            .is_none()
        );
        assert!(
            verify_token(&key, &claims.iss, &Secret::new(&(encoded + ".extra")), 1000).is_none()
        );
        assert!(
            issuer("https://example.test:444/prefix/").unwrap() == "https://example.test:444|send"
        );
    }

    fn operation(
        store: &mut Store,
        operation: usize,
        id: &str,
        input: &Input,
        proof: &str,
    ) -> Result<(), ApiError> {
        if operation <= 1 {
            input.stage_dates(store);
        }
        let request = input.request();
        let mut service = VaultService::new(store);
        match operation {
            0 => service
                .create_text_send("alice", &request, &context())
                .map(|_| ()),
            1 => service
                .update_text_send("alice", id, &request, &context())
                .map(|_| ()),
            2 => service.remove_send_password("alice", id).map(|_| ()),
            3 => service.delete_send("alice", id),
            _ => service
                .access_text_send(&Secret::new(proof), &context())
                .map(|_| ()),
        }
    }

    #[test]
    fn send_mutations_roll_back_rows_revision_and_deferred_commit_then_retry() {
        for operation_id in 0..5 {
            for fault in 0..3 {
                let mut store = fixture_at(":memory:");
                let original = input();
                let id = create(&mut store, "alice", &original);
                let foreign = create(&mut store, "bob", &original);
                let proof = capability(&mut store, &id);
                let mut changed = input();
                changed.name = "changed-opaque-name".into();
                changed.password = Some("changed-opaque-proof".into());
                let event = match operation_id {
                    0 => "INSERT",
                    3 => "DELETE",
                    _ => "UPDATE",
                };
                let trigger = match fault {
                    0 => format!("CREATE TRIGGER reject_send BEFORE {event} ON personal_sends BEGIN SELECT RAISE(ABORT,'injected send fault'); END;"),
                    1 => "CREATE TRIGGER reject_send BEFORE UPDATE OF revision ON accounts WHEN NEW.id='alice' BEGIN SELECT RAISE(ABORT,'injected revision fault'); END;".into(),
                    _ => format!("CREATE TABLE failed_send_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_send AFTER {event} ON personal_sends BEGIN INSERT INTO failed_send_commit(owner) VALUES('missing-owner'); END;"),
                };
                store.db.execute_batch(&trigger).unwrap();
                let before = snapshot(&store);
                assert!(operation(&mut store, operation_id, &id, &changed, &proof).is_err());
                assert!(store.db.is_autocommit() && snapshot(&store) == before);
                store.db.execute_batch("DROP TRIGGER reject_send").unwrap();
                if fault == 2 {
                    store
                        .db
                        .execute_batch("DROP TABLE failed_send_commit")
                        .unwrap();
                }
                assert!(operation(&mut store, operation_id, &id, &changed, &proof).is_ok());
                assert!(load(&store.db, &foreign).unwrap().is_some());
            }
        }
    }

    #[test]
    fn send_limit_denial_advances_only_owner_revision_and_token_mint_does_not_write() {
        let mut store = fixture_at(":memory:");
        let mut input = input();
        input.password = None;
        input.max_access_count = Some(Number::Integer(1));
        let id = create(&mut store, "alice", &input);
        let record = load(&store.db, &id).unwrap().unwrap();
        let access_id = record.access_id.clone();
        let before = snapshot(&store);
        let request = SendAccessTokenRequest {
            grant_type: Some("send_access"),
            client_id: Some("send"),
            send_id: Some(&access_id),
            password_hash_b64: None,
        };
        assert!(
            VaultService::new(&mut store)
                .authenticate_send_access(&request, &context())
                .is_ok()
        );
        assert!(snapshot(&store) == before);
        let proof = capability(&mut store, &id);
        assert!(operation(&mut store, 4, &id, &input, &proof).is_ok());
        let before = load(&store.db, &id).unwrap().unwrap();
        let revision: String = store
            .db
            .query_row(
                "SELECT revision FROM accounts WHERE id='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let error = operation(&mut store, 4, &id, &input, &proof).unwrap_err();
        assert!(error.status_code() == 404);
        let after = load(&store.db, &id).unwrap().unwrap();
        let next_revision: String = store
            .db
            .query_row(
                "SELECT revision FROM accounts WHERE id='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            after.access_count == 1
                && before.revision == after.revision
                && next_revision > revision
        );
        let before = snapshot(&store);
        assert!(matches!(
            VaultService::new(&mut store).authenticate_send_access(&request, &context()),
            Err(SendAccessError::InvalidSend)
        ));
        assert!(snapshot(&store) == before);
    }

    #[test]
    fn sends_and_signing_authority_survive_reopen_purge_preserves_and_account_delete_cascades() {
        let path = std::env::temp_dir().join(format!(
            "no-warden-send-durable-{}.db",
            uuid::Uuid::new_v4()
        ));
        let mut store = fixture_at(path.to_str().unwrap());
        let input = input();
        let id = create(&mut store, "alice", &input);
        let foreign = create(&mut store, "bob", &input);
        let proof = capability(&mut store, &id);
        let signer = signing_key(&store.db).unwrap();
        let before = snapshot(&store);
        drop(store);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store.download_base = "http://127.0.0.1:18600/base".into();
        assert!(snapshot(&store) == before && signing_key(&store.db).unwrap() == signer);
        assert!(operation(&mut store, 4, &id, &input, &proof).is_ok());
        let before = load(&store.db, &id).unwrap().unwrap().revision;
        crate::purge::personal(&mut store.db, "alice").unwrap();
        assert!(load(&store.db, &id).unwrap().unwrap().revision == before);
        crate::account_deletion::delete(&mut store.db, "alice").unwrap();
        assert!(load(&store.db, &id).unwrap().is_none());
        assert!(
            operation(&mut store, 4, &id, &input, &proof)
                .unwrap_err()
                .status_code()
                == 404
        );
        assert!(
            load(&store.db, &foreign).unwrap().is_some()
                && signing_key(&store.db).unwrap() == signer
        );
        drop(store);
        std::fs::remove_file(&path).unwrap();
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
