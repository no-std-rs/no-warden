//! Independently authored MIT OR Apache-2.0 shared attachment READ contracts.
//! Direct HTTP only; client execution, shared attachment writes and JWT internals
//! are not implied. Capability URL values stay private and are never receipted.
use crate::{
    fixture,
    organization_collections::create_organization,
    organization_owner::{self, Account, Http as OwnerHttp, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
};
use rand::{RngCore, rngs::OsRng};
use reqwest::{Method, Url, blocking::Client};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
// Measured on the pinned native six-case READ suite; eight legitimate grants.
// Excludes12 modern registration calls performed by the fixture helper.
pub const HTTP_REQUEST_COUNT: usize = 2168;
const NOTE: &str = "Attachment read preserves opaque secure note Ω\0";
const FILE_NAME: &str = "Opaque attachment \"quoted\" café 🔐.bin";
const LABELS: [&str; 6] = [
    "Owner",
    "ReadonlyManage",
    "Readonly",
    "NoGrant",
    "AcceptedAdmin",
    "RevokedAdmin",
];
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_attachment_read_current_roles_and_exact_metadata",
        roles,
    ),
    (
        "organization_attachment_read_metadata_auth_identity_body_and_head_guards",
        guards,
    ),
    (
        "organization_attachment_read_capability_query_scope_bytes_and_headers",
        capability,
    ),
    (
        "organization_attachment_read_old_capability_survives_canonical_revoke",
        revoke,
    ),
    (
        "organization_attachment_read_real_clock_capability_age_65_and_95",
        expiry,
    ),
    (
        "organization_attachment_read_keys_folders_personal_vault_and_sessions",
        preservation,
    ),
];
struct Reply {
    status: u16,
    bytes: Vec<u8>,
    media: Option<String>,
    length: Option<u64>,
    disposition: bool,
    started: Instant,
    completed: Instant,
}
impl Reply {
    fn expect(&self, expected: u16) -> Result<(), Error> {
        if self.status != expected {
            eprintln!(
                "Attachment READ status expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Attachment READ status differed")
    }
    fn value(&self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Attachment private JSON capture failed"))
    }
    fn rejection(&self, status: u16) -> Result<(), Error> {
        self.expect(status)?;
        let v = self.value()?;
        require(
            [
                "access_token",
                "refresh_token",
                "key",
                "privateKey",
                "publicKey",
            ]
            .iter()
            .all(|k| v.get(k).is_none()),
            "Attachment denial exposed authority",
        )?;
        if status == 400 {
            let keys = BTreeSet::from([
                "error",
                "errorModel",
                "error_description",
                "exceptionMessage",
                "exceptionStackTrace",
                "innerExceptionMessage",
                "message",
                "object",
                "validationErrors",
            ]);
            require(
                v.as_object()
                    .is_some_and(|o| o.keys().map(String::as_str).collect::<BTreeSet<_>>() == keys)
                    && v["object"] == "error",
                "Attachment business error envelope differed",
            )
        } else {
            require(
                v.as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
                "Attachment guard error envelope differed",
            )
        }
    }
}
struct Http {
    client: Client,
    base: String,
    requests: usize,
    logins: usize,
}
impl Http {
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&[u8]>,
        media: Option<&str>,
    ) -> Result<Reply, Error> {
        self.requests += 1;
        let url = if path.starts_with("http://") || path.starts_with("https://") {
            path.to_owned()
        } else {
            format!("{}{path}", self.base)
        };
        let mut q = self
            .client
            .request(method, url)
            .header("Accept", "application/json");
        if !token.is_empty() {
            q = q.bearer_auth(token);
        }
        if let Some(body) = body {
            q = q.body(body.to_vec());
            if let Some(media) = media {
                q = q.header("Content-Type", media);
            }
        }
        let started = Instant::now();
        let response = q
            .send()
            .map_err(|_| Error("Attachment private HTTP request failed"))?;
        let status = response.status().as_u16();
        let media = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let length = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        let disposition = response.headers().contains_key("content-disposition");
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Attachment private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Attachment response exceeded private bound",
        )?;
        Ok(Reply {
            status,
            bytes,
            media,
            length,
            disposition,
            started,
            completed: Instant::now(),
        })
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        let encoded = body.map(Value::to_string);
        let r = self.raw(
            method,
            path,
            token,
            encoded.as_deref().map(str::as_bytes),
            Some("application/json"),
        )?;
        r.expect(200)?;
        if r.bytes.is_empty() {
            Ok(Value::Null)
        } else {
            r.value()
        }
    }
    fn device_grant(&mut self, account: &Account, identifier: &str) -> Result<String, Error> {
        self.logins += 1;
        require(self.logins <= 8, "Attachment extra grant budget exceeded")?;
        let mut form = Url::parse("http://private-form.invalid")
            .map_err(|_| Error("Attachment form construction failed"))?;
        form.query_pairs_mut().extend_pairs([
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&account.fixture["email"])?),
            ("password", text(&account.fixture["masterPasswordHash"])?),
            ("deviceIdentifier", identifier),
            ("deviceName", "Private attachment guard fixture"),
            ("deviceType", "8"),
        ]);
        let body = form
            .query()
            .ok_or(Error("Attachment password form missing"))?;
        let r = self.raw(
            Method::POST,
            "/identity/connect/token",
            "",
            Some(body.as_bytes()),
            Some("application/x-www-form-urlencoded"),
        )?;
        r.expect(200)?;
        let v = r.value()?;
        Ok(text(&v["access_token"])?.to_owned())
    }
}
struct Snapshot {
    views: Vec<Option<Value>>,
    revisions: Vec<Value>,
    keys: Vec<Value>,
}
struct Trial {
    reply: Reply,
    before: Snapshot,
    after: Snapshot,
}
impl Trial {
    fn unchanged(&self) -> Result<(), Error> {
        require(
            self.before.views == self.after.views
                && self.before.revisions == self.after.revisions
                && self.before.keys == self.after.keys,
            "Attachment READ altered opaque/private/archive/account/key state",
        )
    }
    fn denied(self, status: u16) -> Result<(), Error> {
        self.unchanged()?;
        self.reply.rejection(status)
    }
}
struct File {
    id: String,
    bytes: Vec<u8>,
    name: String,
    key: String,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    org: Organization,
    members: Vec<String>,
    folders: Vec<String>,
    key: [u8; 64],
    cipher: String,
    file: Option<File>,
    controls: Vec<Value>,
    keys: Vec<Value>,
    folder_controls: Vec<Value>,
    passed: Vec<&'static str>,
    receipt: Option<fs::File>,
    finished: bool,
    expiry_samples: Vec<Value>,
    device_bearers: Vec<String>,
}
impl Drop for Suite {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Suite {
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed,"cases":self.passed.len(),"expectedCases":CASE_COUNT,"httpRequests":self.http.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"fixtureRegistrationHttpRequests":12,"httpRequestsIncludingFixtureRegistration":self.http.requests+12,"fixtureAccounts":6,"directPasswordLogins":self.http.logins,"eachAccountUsesFreshOwnerHttp":true,"existingOwnerHttpLoginBudgetUnchanged":true,"normalDeviceBoundPasswordFixtures":true,"negativeDeviceBindingProbeClaimed":false,"additionalRealDeviceGrantRequests":2,"metadataNonUuidAndEmptyDeviceBearerAsserted":self.passed.len()>=2,"metadataExact7FieldsOpaqueIdentityAsserted":!self.passed.is_empty(),"metadataUuidAuthCaseBodyQueryHeadGuardsAsserted":self.passed.len()>=2,"firstLowercaseTokenAndCapabilityScopeAsserted":self.passed.len()>=3,"exact257EncryptedBytesAbsentContentTypeDispositionAsserted":self.passed.len()>=3,"oldCapabilityAfterRevokeAndNewMetadataDeniedAsserted":self.passed.len()>=4,"realClockCapabilitySamples":self.expiry_samples,"noJwtDecodeOrClockChange":true,"wholeViewsOnlyCapabilityUrlValuesNormalized":true,"allSixAccountRevisionsKeysAndPrivateViewsAsserted":self.finished,"accountKeysPrivateFoldersPersonalControlsAndSessionsPreserved":self.finished,"actualCliExecuted":false,"actualBrowserExecuted":false,"capturedRouteTrace":false,"decodedSecretTraceClaimed":false,"attachmentWriteAuthorityClaimed":false,"setupAttachmentUploadedByDirectHttp":true,"setupPersonalUploadBeforeDirectHttpMove":true,"historicalAssociationTested":false,"configuredPolicies":false,"groupsConfigured":false,"smtpEnabled":false,"rawDatabaseChecked":false,"nativeConcurrencyClaimed":false,"fullParityClaimed":false}),
        )
    }
    fn token(&self, i: usize) -> String {
        self.accounts[i].token.clone()
    }
    fn path(&self) -> Result<String, Error> {
        Ok(format!(
            "/api/ciphers/{}/attachment/{}",
            self.cipher,
            self.file
                .as_ref()
                .ok_or(Error("Attachment fixture absent"))?
                .id
        ))
    }
    fn stable(&self, v: &Value) -> Result<Value, Error> {
        let mut value = v.clone();
        if let Some(rows) = value["attachments"].as_array_mut() {
            for row in rows {
                if let Some(url) = row["url"].as_str() {
                    let mut url =
                        Url::parse(url).map_err(|_| Error("Attachment capability URL invalid"))?;
                    let query: Vec<_> = url
                        .query_pairs()
                        .map(|(k, _)| (k.into_owned(), "private-capability-value".to_owned()))
                        .collect();
                    url.set_query(None);
                    if !query.is_empty() {
                        url.query_pairs_mut().extend_pairs(query);
                    }
                    row["url"] = json!(url.as_str());
                }
            }
        }
        Ok(value)
    }
    fn snapshot(&mut self) -> Result<Snapshot, Error> {
        let mut views = Vec::new();
        let mut revisions = Vec::new();
        let mut keys = Vec::new();
        for i in 0..self.accounts.len() {
            let token = self.token(i);
            let r = self.http.raw(
                Method::GET,
                &format!("/api/ciphers/{}", self.cipher),
                &token,
                None,
                None,
            )?;
            if r.status == 200 {
                views.push(Some(self.stable(&r.value()?)?));
            } else {
                r.rejection(400)?;
                views.push(None);
            }
            revisions.push(self.http.json(
                Method::GET,
                "/api/accounts/revision-date",
                &token,
                None,
            )?);
            keys.push(
                self.http
                    .json(Method::GET, "/api/accounts/keys", &token, None)?,
            );
        }
        Ok(Snapshot {
            views,
            revisions,
            keys,
        })
    }
    fn trial(
        &mut self,
        method: Method,
        path: &str,
        actor: Option<usize>,
        body: Option<&[u8]>,
    ) -> Result<Trial, Error> {
        let token = actor.map(|i| self.token(i)).unwrap_or_default();
        self.trial_bearer(method, path, &token, body)
    }
    fn trial_bearer(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&[u8]>,
    ) -> Result<Trial, Error> {
        let before = self.snapshot()?;
        let reply = self.http.raw(method, path, token, body, None)?;
        let after = self.snapshot()?;
        let trial = Trial {
            reply,
            before,
            after,
        };
        trial.unchanged()?;
        Ok(trial)
    }
    fn metadata(&mut self, actor: usize) -> Result<(Reply, Url), Error> {
        let t = self.trial(Method::GET, &self.path()?, Some(actor), None)?;
        let url = self.check_metadata(&t.reply)?;
        Ok((t.reply, url))
    }
    fn check_metadata(&self, r: &Reply) -> Result<Url, Error> {
        r.expect(200)?;
        let v = r.value()?;
        let f = self
            .file
            .as_ref()
            .ok_or(Error("Attachment fixture absent"))?;
        let fields = BTreeSet::from(["fileName", "id", "key", "object", "size", "sizeName", "url"]);
        require(
            v.as_object().is_some_and(|o| {
                o.keys().map(String::as_str).collect::<BTreeSet<_>>() == fields
                    && o.values().all(Value::is_string)
            }),
            "Attachment exact7string model differed",
        )?;
        let expected_size = f.bytes.len().to_string();
        require(
            v["object"] == "attachment"
                && v["id"] == f.id
                && v["fileName"] == f.name
                && v["key"] == f.key
                && v["size"].as_str() == Some(expected_size.as_str()),
            "Attachment opaque identity/size changed",
        )?;
        require(
            r.media.as_deref() == Some("application/json") && !r.disposition,
            "Attachment metadata headers differed",
        )?;
        let url =
            Url::parse(text(&v["url"])?).map_err(|_| Error("Attachment capability URL invalid"))?;
        let base =
            Url::parse(&self.http.base).map_err(|_| Error("Attachment server URL invalid"))?;
        require(
            url.origin() == base.origin()
                && url.path() == format!("/attachments/{}/{}", self.cipher, f.id)
                && url
                    .query_pairs()
                    .any(|(k, v)| k == "token" && !v.is_empty()),
            "Attachment capability scope differed",
        )?;
        Ok(url)
    }
    fn bytes(&self, r: &Reply) -> Result<(), Error> {
        r.expect(200)?;
        let f = self
            .file
            .as_ref()
            .ok_or(Error("Attachment fixture absent"))?;
        require(
            r.bytes == f.bytes
                && r.media.is_none()
                && !r.disposition
                && r.length == Some(f.bytes.len() as u64),
            "Attachment encrypted bytes or headers differed",
        )
    }
    fn change_grant(&mut self, read_only: bool, manage: bool) -> Result<(), Error> {
        let body = json!({"name":self.org.body["collectionName"],"users":[{"id":self.members[1],"readOnly":read_only,"hidePasswords":false,"manage":manage},{"id":self.members[2],"readOnly":true,"hidePasswords":false,"manage":false}],"groups":[],"externalId":null});
        self.http.json(
            Method::PUT,
            &format!(
                "/api/organizations/{}/collections/{}",
                self.org.id, self.org.collection_id
            ),
            &self.token(0),
            Some(&body),
        )?;
        Ok(())
    }
}
fn roles(s: &mut Suite) -> Result<(), Error> {
    let baseline = s.snapshot()?;
    require(
        baseline
            .views
            .iter()
            .enumerate()
            .all(|(i, v)| v.is_some() == (i < 3)),
        "Attachment fixture read roles differed",
    )?;
    require(
        baseline.views[1]
            .as_ref()
            .is_some_and(|v| v["edit"] == false)
            && baseline.views[2]
                .as_ref()
                .is_some_and(|v| v["edit"] == false),
        "Attachment readonly fixture advertised edit",
    )?;
    for i in 0..6 {
        if i < 3 {
            s.metadata(i)?;
        } else {
            s.trial(Method::GET, &s.path()?, Some(i), None)?
                .denied(400)?;
        }
    }
    s.change_grant(false, false)?;
    let writable = s.snapshot()?;
    require(
        writable.views[1]
            .as_ref()
            .is_some_and(|v| v["edit"] == true),
        "Attachment writable control did not advertise edit",
    )?;
    s.metadata(1)?;
    s.change_grant(true, true)?;
    Ok(())
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let path = s.path()?;
    s.trial(Method::GET, &path, None, None)?.denied(401)?;
    let malformed = "/api/ciphers/not-a-uuid/attachment/not-an-attachment";
    s.trial(Method::GET, malformed, None, None)?.denied(401)?;
    s.trial(Method::GET, malformed, Some(0), None)?
        .denied(422)?;
    let f = s.file.as_ref().ok_or(Error("Attachment fixture absent"))?;
    let id = f.id.clone();
    let uppercase = s.cipher.to_uppercase();
    require(
        uppercase != s.cipher,
        "Uppercase source fixture had no case distinction",
    )?;
    for path in [
        format!("/api/ciphers/{uppercase}/attachment/{id}"),
        format!("/api/ciphers/{}/attachment/{id}", s.accounts[0].cipher_id),
        format!("/api/ciphers/{}/attachment/not-an-attachment", s.cipher),
        format!(
            "/api/ciphers/{}/attachment/{}",
            s.cipher,
            Uuid::new_v4().simple().to_string()[..20].to_owned()
        ),
    ] {
        s.trial(Method::GET, &path, Some(0), None)?.denied(400)?;
    }
    for alternate in [
        s.cipher.replace('-', ""),
        format!("{{{}}}", s.cipher),
        format!("urn:uuid:{}", s.cipher),
    ] {
        s.trial(
            Method::GET,
            &format!("/api/ciphers/{alternate}/attachment/{id}"),
            Some(0),
            None,
        )?
        .denied(400)?;
    }
    require(
        s.device_bearers.len() == 2,
        "Attachment real device grant controls missing",
    )?;
    for token in s.device_bearers.clone() {
        let t = s.trial_bearer(Method::GET, &path, &token, None)?;
        s.check_metadata(&t.reply)?;
    }
    let upper = id.to_uppercase();
    require(
        upper != id,
        "Uppercase attachment fixture had no case distinction",
    )?;
    let t = s.trial(
        Method::GET,
        &format!("/api/ciphers/{}/attachment/{upper}", s.cipher),
        Some(0),
        None,
    )?;
    s.check_metadata(&t.reply)?;
    let t = s.trial(
        Method::GET,
        &format!("{path}?unknown=ignored"),
        Some(0),
        Some(b"\xff\0"),
    )?;
    s.check_metadata(&t.reply)?;
    let (get, _) = s.metadata(0)?;
    let head = s.trial(Method::HEAD, &path, Some(0), None)?;
    head.reply.expect(200)?;
    require(
        head.reply.bytes.is_empty()
            && head.reply.length == Some(get.bytes.len() as u64)
            && head.reply.media.as_deref() == Some("application/json")
            && !head.reply.disposition,
        "Attachment metadata HEAD representation differed",
    )?;
    s.trial(Method::PUT, &path, Some(0), Some(b"{}"))?
        .denied(404)
}
fn capability(s: &mut Suite) -> Result<(), Error> {
    let (_, url) = s.metadata(0)?;
    let valid = url
        .query_pairs()
        .find(|(k, _)| k == "token")
        .ok_or(Error("Attachment token missing"))?
        .1
        .into_owned();
    let t = s.trial(Method::GET, url.as_str(), None, None)?;
    s.bytes(&t.reply)?;
    let t = s.trial(Method::GET, url.as_str(), Some(3), None)?;
    s.bytes(&t.reply)?;
    let mut missing = url.clone();
    missing.set_query(None);
    s.trial(Method::GET, missing.as_str(), None, None)?
        .denied(422)?;
    s.trial(Method::GET, missing.as_str(), Some(0), None)?
        .denied(422)?;
    for first in ["", "forged"] {
        let mut bad = missing.clone();
        bad.query_pairs_mut().append_pair("token", first);
        s.trial(Method::GET, bad.as_str(), None, None)?
            .denied(404)?;
    }
    for (values, status) in [
        (vec![valid.as_str(), "forged"], 200),
        (vec!["forged", valid.as_str()], 404),
        (vec!["", valid.as_str()], 404),
        (vec![valid.as_str(), ""], 200),
    ] {
        let mut query = missing.clone();
        query
            .query_pairs_mut()
            .extend_pairs(values.iter().map(|v| ("token", *v)));
        let t = s.trial(Method::GET, query.as_str(), None, None)?;
        if status == 200 {
            s.bytes(&t.reply)?;
        } else {
            t.denied(status)?;
        }
    }
    let mut mixed = missing.clone();
    mixed
        .query_pairs_mut()
        .append_pair("Token", "forged")
        .append_pair("token", &valid)
        .append_pair("unknown", "ignored");
    let t = s.trial(Method::GET, mixed.as_str(), None, Some(b"\xff\0"))?;
    s.bytes(&t.reply)?;
    let mut upper_key = missing.clone();
    upper_key.query_pairs_mut().append_pair("Token", &valid);
    s.trial(Method::GET, upper_key.as_str(), None, None)?
        .denied(422)?;
    let file = s
        .file
        .as_ref()
        .ok_or(Error("Attachment fixture absent"))?
        .id
        .clone();
    for path in [
        format!("/attachments/{}/{}", s.cipher.to_uppercase(), file),
        format!("/attachments/{}/{}", s.cipher, file.to_uppercase()),
        format!("/attachments/{}/{file}", s.accounts[0].cipher_id),
        format!(
            "/attachments/{}/{}",
            s.cipher,
            Uuid::new_v4().simple().to_string()[..20].to_owned()
        ),
    ] {
        let mut wrong = url.clone();
        wrong.set_path(&path);
        s.trial(Method::GET, wrong.as_str(), None, None)?
            .denied(404)?;
    }
    for has_token in [true, false] {
        let mut bad = url.clone();
        bad.set_path(&format!("/attachments/not-a-uuid/{file}"));
        if !has_token {
            bad.set_query(None);
        }
        s.trial(Method::GET, bad.as_str(), None, None)?
            .denied(422)?;
    }
    let mut bad_file = url.clone();
    bad_file.set_path(&format!("/attachments/{}/not-an-attachment", s.cipher));
    s.trial(Method::GET, bad_file.as_str(), None, None)?
        .denied(404)?;
    let head = s.trial(Method::HEAD, url.as_str(), None, None)?;
    head.reply.expect(200)?;
    require(
        head.reply.bytes.is_empty()
            && head.reply.length == Some(257)
            && head.reply.media.is_none()
            && !head.reply.disposition,
        "Attachment capability HEAD headers/body differed",
    )?;
    s.trial(Method::PUT, url.as_str(), None, Some(b"{}"))?
        .denied(404)
}
fn revoke(s: &mut Suite) -> Result<(), Error> {
    let (_, url) = s.metadata(1)?;
    let before = s.snapshot()?;
    s.http.json(
        Method::PUT,
        &format!(
            "/api/organizations/{}/users/{}/revoke",
            s.org.id, s.members[1]
        ),
        &s.token(0),
        None,
    )?;
    s.trial(Method::GET, &s.path()?, Some(1), None)?
        .denied(400)?;
    let t = s.trial(Method::GET, url.as_str(), None, None)?;
    s.bytes(&t.reply)?;
    s.http.json(
        Method::PUT,
        &format!(
            "/api/organizations/{}/users/{}/restore",
            s.org.id, s.members[1]
        ),
        &s.token(0),
        None,
    )?;
    let after = s.snapshot()?;
    require(
        before.views == after.views && before.keys == after.keys,
        "Membership restore lost private/common/key state",
    )?;
    s.metadata(1)?;
    Ok(())
}
fn wait_age(issued: Instant, seconds: u64) {
    while issued.elapsed() < Duration::from_secs(seconds) {
        std::thread::sleep(
            Duration::from_secs(seconds)
                .saturating_sub(issued.elapsed())
                .min(Duration::from_secs(15)),
        );
    }
}
fn expiry(s: &mut Suite) -> Result<(), Error> {
    let (mint, url) = s.metadata(0)?;
    for (age, status) in [(65, 200), (95, 404)] {
        wait_age(mint.completed, age);
        let t = s.trial(Method::GET, url.as_str(), None, None)?;
        let sent = t.reply.started.duration_since(mint.completed).as_millis();
        let received = t.reply.completed.duration_since(mint.completed).as_millis();
        require(
            sent >= u128::from(age) * 1000 && sent < u128::from(age + 3) * 1000,
            "Attachment real-clock sample missed its bounded window",
        )?;
        if status == 200 {
            s.bytes(&t.reply)?;
        } else {
            t.reply.rejection(status)?;
        }
        s.expiry_samples.push(json!({"requestedAgeSeconds":age,"requestMillisecondsSinceMetadataResponse":sent,"responseMillisecondsSinceMetadataResponse":received,"status":status,"exactEncryptedBytes":status==200,"allViewsPrivateKeysAndRevisionsUnchanged":true}));
        s.receipt("running")?;
    }
    Ok(())
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..6 {
        let token = s.token(i);
        require(
            s.http
                .json(Method::GET, "/api/accounts/keys", &token, None)?
                == s.keys[i],
            "Attachment reads changed account keys",
        )?;
        require(
            s.http.json(
                Method::GET,
                &format!("/api/folders/{}", s.folders[i]),
                &token,
                None,
            )? == s.folder_controls[i],
            "Attachment reads changed private folder",
        )?;
        require(
            s.http.json(
                Method::GET,
                &format!("/api/ciphers/{}", s.accounts[i].cipher_id),
                &token,
                None,
            )? == s.controls[i],
            "Attachment reads changed unrelated personal note",
        )?;
        let profile = s
            .http
            .json(Method::GET, "/api/accounts/profile", &token, None)?;
        require(
            profile["id"] == s.accounts[i].user_id,
            "Attachment fixture bearer session ceased working",
        )?;
    }
    let views = s.snapshot()?;
    for i in 0..3 {
        let v = views.views[i]
            .as_ref()
            .ok_or(Error("Attachment reader disappeared"))?;
        require(
            v["folderId"] == s.folders[i]
                && v["favorite"] == (i != 1)
                && v["archivedDate"].is_string()
                && fixture::decrypt(text(&v["name"])?, &s.key)
                    .map_err(|_| Error("Attachment source decrypt failed"))?
                    == NOTE.as_bytes(),
            "Attachment reads lost private archive or encrypted source",
        )?;
    }
    Ok(())
}
fn setup() -> Result<Suite, Error> {
    let mut accounts = Vec::new();
    let mut requests = 0;
    let mut logins = 0;
    for _ in 0..6 {
        let mut owner = OwnerHttp::new()?;
        accounts.push(organization_owner::seed(&mut owner)?);
        requests += owner.requests;
        logins += owner.logins;
    }
    require(
        logins == 6,
        "Attachment fixture password login count differed",
    )?;
    let mut owner = OwnerHttp::new()?;
    let org = create_organization(&mut owner, &accounts[0])?;
    requests += owner.requests;
    let http = Http {
        client: http_client()?,
        base: owner.server,
        requests,
        logins,
    };
    let mut s = Suite {
        http,
        accounts,
        org,
        members: vec![String::new(); 6],
        folders: Vec::new(),
        key: [0; 64],
        cipher: String::new(),
        file: None,
        controls: Vec::new(),
        keys: Vec::new(),
        folder_controls: Vec::new(),
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_ATTACHMENT_READ_RECEIPT")?,
        finished: false,
        expiry_samples: Vec::new(),
        device_bearers: Vec::new(),
    };
    for i in 1..6 {
        let role = if i < 4 { 2 } else { 1 };
        let grants = if i < 3 {
            json!([{"id":s.org.collection_id,"readOnly":true,"hidePasswords":false,"manage":i==1}])
        } else {
            json!([])
        };
        s.http.json(Method::POST,&format!("/api/organizations/{}/users/invite",s.org.id),&s.token(0),Some(&json!({"emails":[s.accounts[i].fixture["email"]],"type":role,"collections":grants,"groups":[],"permissions":{}})))?;
        let rows = s.http.json(
            Method::GET,
            &format!(
                "/api/organizations/{}/users?includeCollections=true&includeGroups=true",
                s.org.id
            ),
            &s.token(0),
            None,
        )?;
        let row = rows["data"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["userId"] == s.accounts[i].user_id))
            .ok_or(Error("Attachment membership absent"))?;
        require(
            row["status"] == 1,
            "Attachment invite acceptance fixture differed",
        )?;
        s.members[i] = text(&row["id"])?.to_owned();
        if i != 4 {
            let key = fixture::organization_key_for_account(&s.accounts[i].fixture, &s.org.key)
                .map_err(|_| Error("Attachment member organization wrap failed"))?;
            s.http.json(
                Method::POST,
                &format!(
                    "/api/organizations/{}/users/{}/confirm",
                    s.org.id, s.members[i]
                ),
                &s.token(0),
                Some(&json!({"key":key})),
            )?;
        }
        if i == 5 {
            s.http.json(
                Method::PUT,
                &format!(
                    "/api/organizations/{}/users/{}/revoke",
                    s.org.id, s.members[i]
                ),
                &s.token(0),
                None,
            )?;
        }
    }
    let mut user_keys = Vec::new();
    for (i, label) in LABELS.iter().enumerate() {
        let user_key = fixture::fixture_user_key(&s.accounts[i].fixture, &s.accounts[i].password)
            .map_err(|_| Error("Attachment private fixture key failed"))?;
        user_keys.push(user_key);
        let encrypted = fixture::encrypt(format!("Private folder {label}").as_bytes(), &user_key)
            .map_err(|_| Error("Attachment folder encryption failed"))?;
        let folder = s.http.json(
            Method::POST,
            "/api/folders",
            &s.token(i),
            Some(&json!({"name":encrypted})),
        )?;
        s.folders.push(text(&folder["id"])?.to_owned());
        s.folder_controls.push(s.http.json(
            Method::GET,
            &format!("/api/folders/{}", s.folders[i]),
            &s.token(i),
            None,
        )?);
        s.keys.push(
            s.http
                .json(Method::GET, "/api/accounts/keys", &s.token(i), None)?,
        );
        s.controls.push(s.http.json(
            Method::GET,
            &format!("/api/ciphers/{}", s.accounts[i].cipher_id),
            &s.token(i),
            None,
        )?);
    }
    OsRng
        .try_fill_bytes(&mut s.key)
        .map_err(|_| Error("Attachment source key randomness failed"))?;
    let sealed = fixture::encrypt(NOTE.as_bytes(), &s.key)
        .map_err(|_| Error("Attachment source encryption failed"))?;
    let wrapped = fixture::encrypt(&s.key, &s.org.key)
        .map_err(|_| Error("Attachment source wrapping failed"))?;
    let personal_key = fixture::encrypt(&s.key, &user_keys[0])
        .map_err(|_| Error("Attachment personal key wrapping failed"))?;
    let personal=s.http.json(Method::POST,"/api/ciphers",&s.token(0),Some(&json!({"type":2,"encryptedFor":s.accounts[0].user_id,"name":sealed,"notes":sealed,"key":personal_key,"secureNote":{"type":0}})))?;
    s.cipher = text(&personal["id"])?.to_owned();
    let mut file_key = [0; 64];
    OsRng
        .try_fill_bytes(&mut file_key)
        .map_err(|_| Error("Attachment file key randomness failed"))?;
    let mut plaintext = [0; 193];
    OsRng
        .try_fill_bytes(&mut plaintext)
        .map_err(|_| Error("Attachment plaintext fixture randomness failed"))?;
    let bytes = fixture::encrypt_file(&plaintext, &file_key)
        .map_err(|_| Error("Attachment file encryption failed"))?;
    require(
        bytes.len() == 257,
        "Attachment encrypted fixture size differed",
    )?;
    let name = fixture::encrypt(FILE_NAME.as_bytes(), &s.key)
        .map_err(|_| Error("Attachment filename encryption failed"))?;
    let key =
        fixture::encrypt(&file_key, &s.key).map_err(|_| Error("Attachment key wrapping failed"))?;
    let reserved = s.http.json(
        Method::POST,
        &format!("/api/ciphers/{}/attachment/v2", s.cipher),
        &s.token(0),
        Some(&json!({"fileName":name,"key":key,"fileSize":bytes.len()})),
    )?;
    require(
        reserved["object"] == "attachment-fileUpload" && reserved["fileUploadType"] == 0,
        "Attachment direct upload reservation differed",
    )?;
    let id = text(&reserved["attachmentId"])?.to_owned();
    let boundary = format!("----IndependentAttachment{}", Uuid::new_v4());
    let mut raw=format!("--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"opaque-encrypted-file\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    raw.extend_from_slice(&bytes);
    raw.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let upload = s.http.raw(
        Method::POST,
        &format!("/api/ciphers/{}/attachment/{id}", s.cipher),
        &s.token(0),
        Some(&raw),
        Some(&format!("multipart/form-data; boundary={boundary}")),
    )?;
    upload.expect(200)?;
    require(
        upload.bytes.is_empty(),
        "Attachment upload setup response not empty",
    )?;
    // Portable setup uploads only while personal; shared attachment writes stay
    // unimplemented. Move carries opaque keyed metadata through the existing rewrap.
    let mut rewrap = serde_json::Map::new();
    rewrap.insert(id.clone(), json!({"fileName":name,"key":key}));
    s.http.json(Method::PUT,&format!("/api/ciphers/{}/share",s.cipher),&s.token(0),Some(&json!({"collectionIds":[s.org.collection_id],"cipher":{"type":2,"encryptedFor":s.accounts[0].user_id,"organizationId":s.org.id,"name":sealed,"notes":sealed,"key":wrapped,"attachments2":rewrap,"secureNote":{"type":0},"fields":[{"name":sealed,"value":sealed,"type":0,"linkedId":null}],"passwordHistory":[{"password":sealed,"lastUsedDate":"2024-01-01T00:00:00.000000Z"}],"favorite":true,"folderId":s.folders[0]}})))?;
    for i in 0..3 {
        s.http.json(
            Method::PUT,
            &format!("/api/ciphers/{}/partial", s.cipher),
            &s.token(i),
            Some(&json!({"favorite":i!=1,"folderId":s.folders[i]})),
        )?;
        s.http.json(
            Method::PUT,
            &format!("/api/ciphers/{}/archive", s.cipher),
            &s.token(i),
            None,
        )?;
        std::thread::sleep(Duration::from_millis(3));
    }
    s.file = Some(File {
        id,
        bytes,
        name,
        key,
    });
    let views = s.snapshot()?;
    let dates: BTreeSet<_> = views.views[..3]
        .iter()
        .filter_map(|v| v.as_ref().and_then(|v| v["archivedDate"].as_str()))
        .collect();
    require(
        dates.len() == 3,
        "Attachment fixture private archive dates not distinct",
    )?;
    // Extra legitimate grants are setup, outside all READ snapshots. Each seed
    // still used its own OwnerHttp and unchanged two-login budget.
    for identifier in ["read-guard-device-not-uuid", ""] {
        s.device_bearers
            .push(s.http.device_grant(&s.accounts[0], identifier)?);
    }
    s.receipt("running")?;
    Ok(s)
}
pub fn run() -> Result<(), Error> {
    let mut s = setup()?;
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    if s.http.requests != HTTP_REQUEST_COUNT {
        eprintln!(
            "Attachment READ measured HTTP requests {}, expected {}",
            s.http.requests, HTTP_REQUEST_COUNT
        );
    }
    require(
        s.http.requests == HTTP_REQUEST_COUNT && s.http.logins == 8 && s.passed.len() == CASE_COUNT,
        "Attachment READ fixed request budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")?;
    println!("PASS organization-attachment-read: {CASE_COUNT} cases");
    Ok(())
}
