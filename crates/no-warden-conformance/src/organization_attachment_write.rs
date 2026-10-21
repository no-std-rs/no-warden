//! Independently authored shared attachment WRITE black-box observations.
//! Uses our opaque READ fixture; no native implementation or JWT code is used.
use crate::{
    fixture,
    organization_attachment_read::{self as reads, Snapshot, Suite as Fixture},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
};
use reqwest::{Method, Url};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
type Case = fn(&mut Suite) -> Result<(), Error>;
// Deliberate sentinel: freeze only after actual pinned native execution.
pub const HTTP_REQUEST_COUNT: usize = 0;
const CASE_NAMES: [&str; CASE_COUNT] = [
    "organization_attachment_write_reservation_current_roles_and_metadata_only",
    "organization_attachment_write_upload_current_roles_and_reader_revisions",
    "organization_attachment_write_delete_current_roles_and_reader_revisions",
    "organization_attachment_write_owner_manage_delete_aliases_and_admin_read",
    "organization_attachment_write_auth_uuid_json_schema_guards",
    "organization_attachment_write_opaque_vault_private_keys_and_controls_preserved",
];
struct File {
    id: String,
    name: String,
    key: String,
    bytes: Vec<u8>,
}
struct Suite {
    fixture: Fixture,
    passed: Vec<&'static str>,
    mutations: usize,
    rejected: usize,
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
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({
                "schemaVersion":1,"status":status,"passedCases":self.passed,
                "cases":self.passed.len(),"expectedCases":CASE_COUNT,
                "httpRequests":self.fixture.http.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,
                "fixtureRegistrationHttpRequests":12,"directPasswordLogins":self.fixture.http.logins,
                "successfulSharedMutationObservations":self.mutations,"rejectedGuardObservations":self.rejected,
                "accountReaderFanoutAndCipherRevisionAsserted":self.passed.len()>=3,
                "wholeProtectedCommonPrivateKeysAndControlStateAsserted":self.finished,
                "actualCliExecuted":false,"actualBrowserExecuted":false,
                "capturedRouteTrace":false,"databaseImplementationInspected":false,
                "concurrentNativeMutationClaimed":false,"nativeQuotaClaimed":false,
                "configuredPolicies":false,"groupsConfigured":false,"smtpEnabled":false,
                "fullParityClaimed":false
            }),
        )
    }
    fn path(&self, file: &str) -> String {
        format!("/api/ciphers/{}/attachment/{file}", self.fixture.cipher)
    }
    fn request(&self) -> Result<(Value, File), Error> {
        let original = self
            .fixture
            .file
            .as_ref()
            .ok_or(Error("WRITE file fixture missing"))?;
        Ok((
            json!({"fileName":original.name,"key":original.key,"fileSize":original.bytes.len()}),
            File {
                id: String::new(),
                name: original.name.clone(),
                key: original.key.clone(),
                bytes: original.bytes.clone(),
            },
        ))
    }
    fn unchanged(&self, before: &Snapshot, after: &Snapshot) -> Result<(), Error> {
        require(
            before.views == after.views
                && before.revisions == after.revisions
                && before.keys == after.keys,
            "Rejected attachment WRITE changed protected state",
        )
    }
    fn changed(
        &self,
        before: &Snapshot,
        after: &Snapshot,
        readers_bumped: bool,
        metadata_changed: bool,
    ) -> Result<(), Error> {
        require(
            before.keys == after.keys && before.views.len() == 6 && after.views.len() == 6,
            "Attachment WRITE changed keys or actor scope",
        )?;
        for i in 0..6 {
            require(
                (before.revisions[i] != after.revisions[i]) == (readers_bumped && i < 3),
                "Attachment WRITE reader account revision fanout differed",
            )?;
            match (&before.views[i], &after.views[i]) {
                (Some(a), Some(b)) => {
                    require(i < 3, "Attachment WRITE revealed a foreign view")?;
                    let mut common_a = a.clone();
                    let mut common_b = b.clone();
                    common_a
                        .as_object_mut()
                        .ok_or(Error("WRITE view model missing"))?
                        .remove("attachments");
                    common_b
                        .as_object_mut()
                        .ok_or(Error("WRITE view model missing"))?
                        .remove("attachments");
                    require(
                        common_a == common_b,
                        "Attachment WRITE changed common cipher/private state or cipher revision",
                    )?;
                    require(
                        (a["attachments"] != b["attachments"]) == metadata_changed,
                        "Attachment WRITE metadata transition differed",
                    )?;
                }
                (None, None) => require(i >= 3, "Attachment WRITE lost a current reader")?,
                _ => return Err(Error("Attachment WRITE changed current read scope")),
            }
        }
        Ok(())
    }
    fn error(&self, reply: &reads::Reply, status: u16, business: bool) -> Result<(), Error> {
        reply.expect(status)?;
        let v = reply.value()?;
        let object = v
            .as_object()
            .ok_or(Error("WRITE rejection model missing"))?;
        if business {
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
                object.keys().map(String::as_str).collect::<BTreeSet<_>>() == keys,
                "WRITE business error keys differed",
            )?;
            require(
                ["error", "error_description", "message", "object"]
                    .iter()
                    .all(|k| v[k].is_string())
                    && ["errorModel", "validationErrors"]
                        .iter()
                        .all(|k| v[k].is_object())
                    && [
                        "exceptionMessage",
                        "exceptionStackTrace",
                        "innerExceptionMessage",
                    ]
                    .iter()
                    .all(|k| v[k].is_null())
                    && v["object"] == "error",
                "WRITE business error types differed",
            )
        } else {
            require(
                object.len() == 1 && v["error"].is_object(),
                "WRITE guard error outer model differed",
            )
        }
    }
    fn reserve(&mut self, actor: usize, expected: u16) -> Result<Option<File>, Error> {
        let (body, mut file) = self.request()?;
        let before = self.fixture.snapshot()?;
        let path = self.path("v2");
        let token = self.fixture.token(actor);
        let encoded = body.to_string();
        let r = self.fixture.http.raw(
            Method::POST,
            &path,
            &token,
            Some(encoded.as_bytes()),
            Some("application/json"),
        )?;
        let after = self.fixture.snapshot()?;
        if expected != 200 {
            self.unchanged(&before, &after)?;
            self.error(&r, expected, true)?;
            self.rejected += 1;
            return Ok(None);
        }
        r.expect(200)?;
        let value = r.value()?;
        let keys = BTreeSet::from([
            "attachmentId",
            "cipherResponse",
            "fileUploadType",
            "object",
            "url",
        ]);
        require(
            value
                .as_object()
                .is_some_and(|v| v.keys().map(String::as_str).collect::<BTreeSet<_>>() == keys)
                && value["object"] == "attachment-fileUpload"
                && value["fileUploadType"] == 0,
            "WRITE reservation exact five-field model differed",
        )?;
        file.id = text(&value["attachmentId"])?.to_owned();
        require(
            value["url"] == format!("/ciphers/{}/attachment/{}", self.fixture.cipher, file.id),
            "WRITE reservation upload URL scope differed",
        )?;
        let actor_view = after.views[actor]
            .as_ref()
            .ok_or(Error("WRITE reservation actor view absent"))?;
        require(
            value["cipherResponse"]
                .as_object()
                .is_some_and(|v| v.len() == 30)
                && self.fixture.stable(&value["cipherResponse"])? == *actor_view,
            "WRITE reservation cipher response differed from actor GET",
        )?;
        self.changed(&before, &after, false, true)?;
        let expected_size = file.bytes.len().to_string();
        for i in 0..3 {
            let old = before.views[i]
                .as_ref()
                .ok_or(Error("WRITE before reader absent"))?;
            let new = after.views[i]
                .as_ref()
                .ok_or(Error("WRITE after reader absent"))?;
            let rows = new["attachments"]
                .as_array()
                .ok_or(Error("WRITE reservation metadata absent"))?;
            require(
                rows.len() == old["attachments"].as_array().map_or(0, Vec::len) + 1,
                "WRITE reservation did not add exactly one metadata row",
            )?;
            let row = rows
                .iter()
                .find(|v| v["id"] == file.id)
                .ok_or(Error("WRITE reserved metadata absent"))?;
            require(
                row["fileName"] == file.name
                    && row["key"] == file.key
                    && row["size"].as_str() == Some(expected_size.as_str()),
                "WRITE reservation changed opaque attachment metadata",
            )?;
        }
        self.mutations += 1;
        Ok(Some(file))
    }
    fn metadata_url(&mut self, file: &File) -> Result<Url, Error> {
        let path = self.path(&file.id);
        let token = self.fixture.token(0);
        let value = self.fixture.http.json(Method::GET, &path, &token, None)?;
        require(
            value.as_object().is_some_and(|v| v.len() == 7)
                && value["id"] == file.id
                && value["key"] == file.key
                && value["fileName"] == file.name,
            "WRITE metadata lookup lost opaque file identity",
        )?;
        let url =
            Url::parse(text(&value["url"])?).map_err(|_| Error("WRITE capability URL invalid"))?;
        let base =
            Url::parse(&self.fixture.http.base).map_err(|_| Error("WRITE base URL invalid"))?;
        require(
            url.origin() == base.origin()
                && url.path() == format!("/attachments/{}/{}", self.fixture.cipher, file.id)
                && url
                    .query_pairs()
                    .any(|(k, v)| k == "token" && !v.is_empty()),
            "WRITE capability scope differed",
        )?;
        Ok(url)
    }
    fn capability(&mut self, url: &Url, file: &File, status: u16) -> Result<(), Error> {
        let before = self.fixture.snapshot()?;
        let reply = self
            .fixture
            .http
            .raw(Method::GET, url.as_str(), "", None, None)?;
        let after = self.fixture.snapshot()?;
        self.unchanged(&before, &after)?;
        reply.expect(status)?;
        if status == 200 {
            require(
                reply.bytes == file.bytes
                    && reply.media.is_none()
                    && !reply.disposition
                    && reply.length == Some(file.bytes.len() as u64),
                "WRITE capability encrypted bytes or headers differed",
            )?;
        }
        Ok(())
    }
    fn multipart(file: &File) -> (Vec<u8>, String) {
        let boundary = format!("----IndependentWrite{}", Uuid::new_v4());
        let mut bytes=format!("--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"opaque\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
        bytes.extend_from_slice(&file.bytes);
        bytes.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        (bytes, format!("multipart/form-data; boundary={boundary}"))
    }
    fn upload(&mut self, actor: usize, file: &File, status: u16) -> Result<(), Error> {
        let url = self.metadata_url(file)?;
        self.capability(&url, file, 404)?;
        let before = self.fixture.snapshot()?;
        let (bytes, media) = Self::multipart(file);
        let path = self.path(&file.id);
        let token = self.fixture.token(actor);
        let reply =
            self.fixture
                .http
                .raw(Method::POST, &path, &token, Some(&bytes), Some(&media))?;
        let after = self.fixture.snapshot()?;
        if status == 200 {
            reply.expect(200)?;
            require(
                reply.bytes.is_empty()
                    && reply.media.is_none()
                    && !reply.disposition
                    && reply.length == Some(0),
                "WRITE upload empty response headers differed",
            )?;
            self.changed(&before, &after, true, false)?;
            self.mutations += 1;
        } else {
            self.error(&reply, status, true)?;
            self.unchanged(&before, &after)?;
            self.rejected += 1;
        }
        self.capability(&url, file, if status == 200 { 200 } else { 404 })
    }
    fn delete(
        &mut self,
        actor: usize,
        file: &File,
        method: Method,
        suffix: &str,
        status: u16,
    ) -> Result<(), Error> {
        let url = self.metadata_url(file)?;
        let before = self.fixture.snapshot()?;
        let path = format!("{}{suffix}", self.path(&file.id));
        let token = self.fixture.token(actor);
        let reply = self.fixture.http.raw(method, &path, &token, None, None)?;
        let after = self.fixture.snapshot()?;
        if status == 200 {
            reply.expect(200)?;
            let value = reply.value()?;
            require(
                value
                    .as_object()
                    .is_some_and(|v| v.len() == 1 && v.contains_key("cipher"))
                    && value["cipher"].as_object().is_some_and(|v| v.len() == 30)
                    && Some(self.fixture.stable(&value["cipher"])?) == after.views[actor],
                "WRITE delete response differed from actor GET",
            )?;
            self.changed(&before, &after, true, true)?;
            for i in 0..3 {
                let view = after.views[i]
                    .as_ref()
                    .ok_or(Error("WRITE delete reader absent"))?;
                require(
                    view["attachments"]
                        .as_array()
                        .is_none_or(|rows| rows.iter().all(|r| r["id"] != file.id)),
                    "WRITE delete retained file metadata",
                )?;
            }
            self.mutations += 1;
        } else {
            self.error(&reply, status, true)?;
            self.unchanged(&before, &after)?;
            self.rejected += 1;
        }
        if status == 200 {
            self.capability(&url, file, 404)?;
        }
        Ok(())
    }
    fn guard(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&[u8]>,
        media: Option<&str>,
        expected: (u16, bool),
    ) -> Result<(), Error> {
        let (status, business) = expected;
        let before = self.fixture.snapshot()?;
        let reply = self.fixture.http.raw(method, path, token, body, media)?;
        let after = self.fixture.snapshot()?;
        self.error(&reply, status, business)?;
        self.unchanged(&before, &after)?;
        self.rejected += 1;
        Ok(())
    }
}

fn reservations(s: &mut Suite) -> Result<(), Error> {
    for actor in 0..6 {
        if let Some(file) = s.reserve(actor, if actor < 2 { 200 } else { 400 })? {
            s.delete(0, &file, Method::DELETE, "", 200)?;
        }
    }
    s.fixture.change_grant(false, false)?;
    let file = s
        .reserve(1, 200)?
        .ok_or(Error("Writable reservation absent"))?;
    s.delete(1, &file, Method::DELETE, "", 200)?;
    s.fixture.change_grant(true, true)
}
fn uploads(s: &mut Suite) -> Result<(), Error> {
    for actor in 0..6 {
        let file = s
            .reserve(0, 200)?
            .ok_or(Error("Upload reservation absent"))?;
        s.upload(actor, &file, if actor < 2 { 200 } else { 400 })?;
        s.delete(0, &file, Method::DELETE, "", 200)?;
    }
    s.fixture.change_grant(false, false)?;
    let file = s
        .reserve(1, 200)?
        .ok_or(Error("Writable upload reservation absent"))?;
    s.upload(1, &file, 200)?;
    s.delete(1, &file, Method::DELETE, "", 200)?;
    s.fixture.change_grant(true, true)
}
fn deletions(s: &mut Suite) -> Result<(), Error> {
    for actor in 0..6 {
        let file = s
            .reserve(0, 200)?
            .ok_or(Error("Delete reservation absent"))?;
        s.upload(0, &file, 200)?;
        s.delete(
            actor,
            &file,
            Method::DELETE,
            "",
            if actor < 2 { 200 } else { 400 },
        )?;
        if actor >= 2 {
            s.delete(0, &file, Method::DELETE, "", 200)?;
        }
    }
    s.fixture.change_grant(false, false)?;
    let file = s
        .reserve(1, 200)?
        .ok_or(Error("Writable delete reservation absent"))?;
    s.upload(1, &file, 200)?;
    s.delete(1, &file, Method::DELETE, "", 200)?;
    s.fixture.change_grant(true, true)
}
fn aliases(s: &mut Suite) -> Result<(), Error> {
    for actor in [0, 1] {
        for (method, suffix) in [
            (Method::DELETE, "/admin"),
            (Method::POST, "/delete"),
            (Method::POST, "/delete-admin"),
        ] {
            let file = s
                .reserve(0, 200)?
                .ok_or(Error("Alias reservation absent"))?;
            s.upload(0, &file, 200)?;
            let path = format!("{}/admin", s.path(&file.id));
            let token = s.fixture.token(actor);
            s.guard(Method::GET, &path, &token, None, None, (404, false))?;
            s.delete(actor, &file, method, suffix, 200)?;
        }
    }
    Ok(())
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let file = s
        .reserve(0, 200)?
        .ok_or(Error("Guard reservation absent"))?;
    let (request, _) = s.request()?;
    let encoded = request.to_string();
    let (multipart, media) = Suite::multipart(&file);
    let token = s.fixture.token(0);
    let random = Uuid::new_v4().to_string();
    for operation in [0, 1, 2] {
        let method = if operation == 2 {
            Method::DELETE
        } else {
            Method::POST
        };
        let tail = if operation == 0 { "v2" } else { &file.id };
        let path = s.path(tail);
        let body = if operation == 0 {
            Some(encoded.as_bytes())
        } else if operation == 1 {
            Some(multipart.as_slice())
        } else {
            None
        };
        let content = if operation == 1 {
            media.as_str()
        } else {
            "application/json"
        };
        for bearer in ["", "forged-attachment-bearer"] {
            s.guard(
                method.clone(),
                &path,
                bearer,
                body,
                Some(content),
                (401, false),
            )?;
        }
        let invalid = format!("/api/ciphers/not-a-uuid/attachment/{tail}");
        s.guard(
            method.clone(),
            &invalid,
            "",
            body,
            Some(content),
            (401, false),
        )?;
        s.guard(
            method.clone(),
            &invalid,
            &token,
            body,
            Some(content),
            (422, false),
        )?;
        let missing = format!("/api/ciphers/{random}/attachment/{tail}");
        s.guard(method, &missing, &token, body, Some(content), (400, true))?;
    }
    let path = s.path("v2");
    for field in ["fileName", "fileSize", "key"] {
        for invalid in [None, Some(Value::Null), Some(json!({"unexpected":true}))] {
            let mut body = request.clone();
            let obj = body.as_object_mut().ok_or(Error("Guard request missing"))?;
            if let Some(value) = invalid {
                obj.insert(field.to_owned(), value);
            } else {
                obj.remove(field);
            }
            let raw = body.to_string();
            s.guard(
                Method::POST,
                &path,
                &token,
                Some(raw.as_bytes()),
                Some("application/json"),
                (422, false),
            )?;
        }
    }
    for (raw, status) in [(b"{".as_slice(), 400), (b"[\"one-field\"]".as_slice(), 422)] {
        s.guard(
            Method::POST,
            &path,
            &token,
            Some(raw),
            Some("application/json"),
            (status, false),
        )?;
    }
    // The measured unknown field is ignored, and only reservation metadata changes.
    let mut body = request;
    body["independentUnknownField"] = json!({"ignored":true});
    let before = s.fixture.snapshot()?;
    let value = s
        .fixture
        .http
        .json(Method::POST, &path, &token, Some(&body))?;
    let after = s.fixture.snapshot()?;
    s.changed(&before, &after, false, true)?;
    s.mutations += 1;
    let id = text(&value["attachmentId"])?.to_owned();
    let (_, mut unknown) = s.request()?;
    unknown.id = id;
    s.delete(0, &unknown, Method::DELETE, "", 200)?;
    s.delete(0, &file, Method::DELETE, "", 200)
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let f = &mut s.fixture;
    for i in 0..6 {
        let token = f.token(i);
        require(
            f.http
                .json(Method::GET, "/api/accounts/keys", &token, None)?
                == f.keys[i],
            "WRITE changed account keys",
        )?;
        require(
            f.http.json(
                Method::GET,
                &format!("/api/folders/{}", f.folders[i]),
                &token,
                None,
            )? == f.folder_controls[i],
            "WRITE changed private folder",
        )?;
        require(
            f.http.json(
                Method::GET,
                &format!("/api/ciphers/{}", f.accounts[i].cipher_id),
                &token,
                None,
            )? == f.controls[i],
            "WRITE changed unrelated personal cipher",
        )?;
    }
    let state = f.snapshot()?;
    for i in 0..3 {
        let view = state.views[i]
            .as_ref()
            .ok_or(Error("WRITE current reader absent"))?;
        require(
            view["folderId"] == f.folders[i]
                && view["favorite"] == (i != 1)
                && view["archivedDate"].is_string()
                && fixture::decrypt(text(&view["name"])?, &f.key)
                    .map_err(|_| Error("WRITE opaque source decrypt failed"))?
                    == "Attachment read preserves opaque secure note Ω\0".as_bytes(),
            "WRITE lost encrypted or private vault state",
        )?;
    }
    Ok(())
}
pub fn run() -> Result<(), Error> {
    let fixture = reads::write_fixture()?;
    let mut s = Suite {
        fixture,
        passed: Vec::new(),
        mutations: 0,
        rejected: 0,
        receipt: receipt_file("BW_ORGANIZATION_ATTACHMENT_WRITE_RECEIPT")?,
        finished: false,
    };
    let cases: [Case; CASE_COUNT] = [
        reservations,
        uploads,
        deletions,
        aliases,
        guards,
        preservation,
    ];
    for (name, case) in CASE_NAMES.into_iter().zip(cases) {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    eprintln!(
        "Attachment WRITE measured HTTP requests {}",
        s.fixture.http.requests
    );
    require(
        s.fixture.http.requests == HTTP_REQUEST_COUNT && s.fixture.http.logins == 6,
        "WRITE fixed request budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")?;
    println!("PASS organization-attachment-write: {CASE_COUNT} cases");
    Ok(())
}
