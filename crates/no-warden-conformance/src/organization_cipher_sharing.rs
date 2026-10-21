//! Independently authored actual-server single-share contracts. MIT OR Apache-2.0.
//! Attachment, configured-policy, group, bulk and full sharing parity remain unverified.
use crate::{
    fixture,
    organization_collections::create_organization,
    organization_owner::{self, Account, Http as OwnerHttp, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, io::Read};
use uuid::Uuid;

pub const CASE_COUNT: usize = 7;
// Original6 cases423 + revision-phase case115 (12 fresh trials96 + alias reads15 + controls4).
pub const HTTP_REQUEST_COUNT: usize = 538;
const NOTE: &str = "Independent sharing contract Ω\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_cipher_sharing_schema_path_source_and_accepted_guards",
        guards,
    ),
    (
        "organization_cipher_sharing_confirmed_roles_grants_and_empty_duplicates",
        admission,
    ),
    (
        "organization_cipher_sharing_ordered_prefix_failure_effects",
        prefix_effects,
    ),
    (
        "organization_cipher_sharing_read_alias_permissions_and_private_annotations",
        projections,
    ),
    (
        "organization_cipher_sharing_wrapper_aliases_and_nested_scope",
        aliases,
    ),
    (
        "organization_cipher_sharing_revoke_restore_and_preserved_personal_authority",
        preservation,
    ),
    (
        "organization_cipher_sharing_revision_dates_follow_collection_effects",
        revision_phase,
    ),
];
const FIELDS: [&str; 30] = [
    "archivedDate",
    "attachments",
    "bankAccount",
    "card",
    "collectionIds",
    "creationDate",
    "deletedDate",
    "driversLicense",
    "edit",
    "favorite",
    "fields",
    "folderId",
    "id",
    "identity",
    "key",
    "login",
    "name",
    "notes",
    "object",
    "organizationId",
    "organizationUseTotp",
    "passport",
    "passwordHistory",
    "permissions",
    "reprompt",
    "revisionDate",
    "secureNote",
    "sshKey",
    "type",
    "viewPassword",
];
pub(crate) struct CipherExpectation<'a> {
    pub id: &'a str,
    pub organization: Option<&'a str>,
    pub collections: &'a [String],
    pub edit: bool,
    pub view_password: bool,
    pub favorite: bool,
    pub folder: Option<&'a str>,
}
pub(crate) fn check_cipher(value: &Value, expected: CipherExpectation<'_>) -> Result<(), Error> {
    let object = value
        .as_object()
        .ok_or(Error("Shared cipher projection was not an object"))?;
    require(
        object.keys().map(String::as_str).collect::<BTreeSet<_>>() == BTreeSet::from(FIELDS),
        "Shared cipher field set differed",
    )?;
    require(
        value["id"] == expected.id
            && value["organizationId"].as_str() == expected.organization
            && value["collectionIds"] == json!(expected.collections)
            && value["object"] == "cipherDetails"
            && value["type"] == 2
            && value["secureNote"] == json!({"type":0})
            && value["edit"] == expected.edit
            && value["viewPassword"] == expected.view_password
            && value["permissions"] == json!({"delete":expected.edit,"restore":expected.edit})
            && value["favorite"] == expected.favorite
            && value["folderId"].as_str() == expected.folder
            && value["key"].is_null()
            && value["attachments"].is_null()
            && value["name"].is_string()
            && value["notes"].is_string()
            && value["creationDate"].is_string()
            && value["revisionDate"].is_string()
            && value["deletedDate"].is_null()
            && value["archivedDate"].is_null()
            && value["organizationUseTotp"] == true,
        "Shared cipher metadata differed",
    )
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, Error> {
        if self.status != expected {
            eprintln!(
                "Sharing HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Sharing HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes).map_err(|_| Error("Sharing response was not JSON"))
    }
    fn rejected(self, expected: u16) -> Result<(), Error> {
        let value = self.status(expected)?.json()?;
        require(
            [
                "access_token",
                "refresh_token",
                "key",
                "privateKey",
                "publicKey",
            ]
            .iter()
            .all(|f| value.get(f).is_none()),
            "Sharing rejection exposed authority",
        )?;
        if expected == 422 {
            return require(
                value
                    .as_object()
                    .is_some_and(|o| o.len() == 1 && o.contains_key("error")),
                "Sharing schema envelope differed",
            );
        }
        if expected == 400 {
            let fields = [
                "error",
                "errorModel",
                "error_description",
                "exceptionMessage",
                "exceptionStackTrace",
                "innerExceptionMessage",
                "message",
                "object",
                "validationErrors",
            ];
            require(
                value.as_object().is_some_and(|o| {
                    o.keys().map(String::as_str).collect::<BTreeSet<_>>() == BTreeSet::from(fields)
                }) && value["object"] == "error"
                    && value["message"].is_string()
                    && value["validationErrors"].is_object(),
                "Sharing business error envelope differed",
            )?;
        }
        Ok(())
    }
}
struct Http {
    owner: OwnerHttp,
    client: Client,
    refreshes: usize,
}
impl Http {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            owner: OwnerHttp::new()?,
            client: http_client()?,
            refreshes: 0,
        })
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.owner.server))
            .bearer_auth(token)
            .header("Accept", "application/json");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .map_err(|_| Error("Sharing HTTP request failed"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Sharing private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Sharing response exceeded capture bound",
        )?;
        Ok(Reply { status, bytes })
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.raw(method, path, token, body)?.status(200)?.json()
    }
    fn refresh(&mut self, proof: &str) -> Result<Value, Error> {
        self.owner.requests += 1;
        self.refreshes += 1;
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.owner.server))
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", "cli"),
                ("refresh_token", proof),
            ])
            .send()
            .map_err(|_| Error("Sharing refresh failed"))?;
        require(
            response.status().as_u16() == 200,
            "Sharing refresh rejected",
        )?;
        response
            .json()
            .map_err(|_| Error("Sharing refresh response malformed"))
    }
}
#[derive(Clone, Copy)]
enum Form {
    Standard,
    MissingCollections,
    NullCollections,
    StringCollections,
    MissingCipher,
    NullCipher,
    Pascal,
    Mixed,
    MissingOrg,
    NullOrg,
    ForeignOrg,
    BodyId,
    OuterOrg,
    BadPath,
    ChangedAnnotations,
    RevisionOlder,
    RevisionFuture,
    RevisionMalformed,
    RevisionMissing,
    RevisionNull,
    NullOrgRevisionOlder,
    MissingOrgRevisionOlder,
    NullOrgRevisionEqual,
}
struct Trial {
    id: String,
    before: Value,
    after: Value,
    payload: Value,
    reply: Reply,
    before_revisions: [Value; 2],
    after_revisions: [Value; 2],
}
impl Trial {
    fn unchanged(self, status: u16) -> Result<(), Error> {
        self.reply.rejected(status)?;
        require(
            self.before == self.after && self.before_revisions == self.after_revisions,
            "Rejected sharing changed source or account revisions",
        )
    }
    fn success(
        self,
        org: Option<&str>,
        collections: &[String],
        folder: Option<&str>,
    ) -> Result<String, Error> {
        let response = self.reply.status(200)?.json()?;
        check_cipher(
            &response,
            CipherExpectation {
                id: &self.id,
                organization: org,
                collections,
                edit: true,
                view_password: true,
                favorite: true,
                folder,
            },
        )?;
        require(
            response["name"] == self.payload["name"] && response["notes"] == self.payload["notes"],
            "Sharing changed opaque submitted fields",
        )?;
        require(
            response == self.after,
            "Sharing write-return and source GET differed in full-access fixture",
        )?;
        Ok(self.id)
    }
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    collections: [String; 4],
    folders: [String; 2],
    member: String,
    controls: [Value; 2],
    keys: [Value; 2],
    personal_totp_before: [bool; 2],
    shared: Option<String>,
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
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"passedCases":self.passed.len(),"expectedCases":CASE_COUNT,"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"attachmentBearingMoveTested":false,"configuredPolicies":false,"groupsConfigured":false,"smtpEnabled":false,"browserTraceClaimed":false,"cliCallerClaimed":false,"capturedRouteTrace":false,"fullParityClaimed":false,"businessErrorTextAsserted":false,"personalOrganizationUseTotpBeforeOrganizations":self.personal_totp_before,"personalOrganizationUseTotpAfterOrganizations":[self.controls[0]["organizationUseTotp"],self.controls[1]["organizationUseTotp"]],"orderedPrefixSideEffectsAsserted":true,"aliasSpecificCollectionProjectionAsserted":true,"crossOrganizationRetryAsserted":true,"historicalIdsRetainedForOwnerAsserted":true,"oldGrantDoesNotAuthorizeRetryTargetAsserted":false,"canonicalConfirmedMemberHistoricalGrantAccessAsserted":true,"freshRestrictedManagerWithoutGrantDeniedAsserted":true,"retryOrdinaryUserHistoricalGrantPaired":true,"retryRevisionFanoutAsserted":true,"retryBOnlyRecipientPaired":false,"revisionDateGuardOlderOnlyAsserted":true,"revisionDateGuardAfterCollectionEffectsAsserted":true,"revisionDateGuardSelectionErrorPrecedenceAsserted":true,"revisionDateGuardPersonalNullOrganizationBranchAsserted":true}),
        )
    }
    fn token(&self, index: usize) -> String {
        self.accounts[index].token.clone()
    }
    fn get(&mut self, actor: usize, path: &str) -> Result<Value, Error> {
        let token = self.token(actor);
        self.http.json(Method::GET, path, &token, None)
    }
    fn revisions(&mut self) -> Result<[Value; 2], Error> {
        Ok([
            self.get(0, "/api/accounts/revision-date")?,
            self.get(1, "/api/accounts/revision-date")?,
        ])
    }
    fn trial(
        &mut self,
        source: usize,
        actor: usize,
        org: usize,
        ids: &[String],
        form: Form,
        folder: Option<String>,
    ) -> Result<Trial, Error> {
        let encrypted = fixture::encrypted_fixture_value(
            &self.accounts[source].fixture,
            &self.accounts[source].password,
            NOTE.as_bytes(),
        )
        .map_err(|_| Error("Sharing personal encryption failed"))?;
        let source_token = self.token(source);
        let actor_token = self.token(actor);
        let created=self.http.json(Method::POST,"/api/ciphers",&source_token,Some(&json!({"type":2,"encryptedFor":self.accounts[source].user_id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"favorite":true,"folderId":folder})))?;
        let id = text(&created["id"])?.to_owned();
        let path = format!("/api/ciphers/{id}");
        let before = self.http.json(Method::GET, &path, &source_token, None)?;
        let before_revisions = self.revisions()?;
        let encrypted = if matches!(
            form,
            Form::NullOrgRevisionOlder | Form::MissingOrgRevisionOlder | Form::NullOrgRevisionEqual
        ) {
            fixture::encrypted_fixture_value(
                &self.accounts[source].fixture,
                &self.accounts[source].password,
                NOTE.as_bytes(),
            )
            .map_err(|_| Error("Sharing personal-update encryption failed"))?
        } else {
            fixture::encrypt(NOTE.as_bytes(), &self.orgs[org].key)
                .map_err(|_| Error("Sharing target encryption failed"))?
        };
        let mut payload = json!({"type":2,"organizationId":self.orgs[org].id,"encryptedFor":self.accounts[source].user_id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"favorite":true,"folderId":folder,"key":null,"lastKnownRevisionDate":before["revisionDate"]});
        match form {
            Form::MissingOrg | Form::MissingOrgRevisionOlder => {
                payload.as_object_mut().unwrap().remove("organizationId");
            }
            Form::NullOrg | Form::NullOrgRevisionOlder | Form::NullOrgRevisionEqual => {
                payload["organizationId"] = Value::Null;
            }
            Form::ForeignOrg => payload["organizationId"] = json!(self.orgs[1].id),
            Form::BodyId => payload["id"] = json!(Uuid::new_v4().to_string()),
            Form::ChangedAnnotations => {
                payload["favorite"] = json!(false);
                payload["folderId"] = Value::Null;
            }
            _ => {}
        }
        match form {
            Form::RevisionOlder | Form::NullOrgRevisionOlder | Form::MissingOrgRevisionOlder => {
                payload["lastKnownRevisionDate"] = json!("2000-01-01T00:00:00.000Z");
            }
            Form::RevisionFuture => {
                payload["lastKnownRevisionDate"] = json!("2999-01-01T00:00:00.000Z");
            }
            Form::RevisionMalformed => payload["lastKnownRevisionDate"] = json!("not-a-date"),
            Form::RevisionMissing => {
                payload
                    .as_object_mut()
                    .unwrap()
                    .remove("lastKnownRevisionDate");
            }
            Form::RevisionNull => payload["lastKnownRevisionDate"] = Value::Null,
            _ => {}
        }
        let mut body = json!({"collectionIds":ids,"cipher":payload});
        match form {
            Form::MissingCollections => {
                body.as_object_mut().unwrap().remove("collectionIds");
            }
            Form::NullCollections => body["collectionIds"] = Value::Null,
            Form::StringCollections => body["collectionIds"] = json!("invalid"),
            Form::MissingCipher => {
                body.as_object_mut().unwrap().remove("cipher");
            }
            Form::NullCipher => body["cipher"] = Value::Null,
            Form::Pascal => body = json!({"CollectionIds":ids,"Cipher":payload}),
            Form::Mixed => body = json!({"CollectionIds":ids,"cipher":payload}),
            Form::OuterOrg => body["organizationId"] = json!(self.orgs[1].id),
            _ => {}
        }
        let share_path = if matches!(form, Form::BadPath) {
            "/api/ciphers/not-a-uuid/share".to_owned()
        } else {
            format!("{path}/share")
        };
        let reply = self
            .http
            .raw(Method::PUT, &share_path, &actor_token, Some(&body))?;
        let after = self.http.json(Method::GET, &path, &source_token, None)?;
        let after_revisions = self.revisions()?;
        Ok(Trial {
            id,
            before,
            after,
            payload,
            reply,
            before_revisions,
            after_revisions,
        })
    }
    fn confirm(&mut self, org: usize, member: &str) -> Result<(), Error> {
        let wrapped =
            fixture::organization_key_for_account(&self.accounts[1].fixture, &self.orgs[org].key)
                .map_err(|_| Error("Sharing RSA confirmation failed"))?;
        let token = self.token(0);
        self.http
            .raw(
                Method::POST,
                &format!(
                    "/api/organizations/{}/users/{member}/confirm",
                    self.orgs[org].id
                ),
                &token,
                Some(&json!({"key":wrapped})),
            )?
            .status(200)?;
        Ok(())
    }
    fn invite(
        &mut self,
        org: usize,
        role: i64,
        collections: Value,
        permissions: Value,
    ) -> Result<String, Error> {
        let token = self.token(0);
        let id = self.orgs[org].id.clone();
        self.http.raw(Method::POST,&format!("/api/organizations/{id}/users/invite"),&token,Some(&json!({"emails":[self.accounts[1].fixture["email"]],"type":role,"collections":collections,"groups":[],"permissions":permissions})))?.status(200)?;
        let rows = self.get(
            0,
            &format!("/api/organizations/{id}/users?includeCollections=true&includeGroups=true"),
        )?;
        let row = rows["data"]
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|v| v["email"] == self.accounts[1].fixture["email"])
            })
            .ok_or(Error("Sharing invitee missing"))?;
        require(
            row["status"] == 1,
            "Sharing registered invitee was not accepted",
        )?;
        Ok(text(&row["id"])?.to_owned())
    }
    fn check_views(
        &mut self,
        actor: usize,
        id: &str,
        collection: &str,
        mode: u8,
        folder: Option<String>,
    ) -> Result<(), Error> {
        let org = self.orgs[0].id.clone();
        let token = self.token(actor);
        let direct = self
            .http
            .json(Method::GET, &format!("/api/ciphers/{id}"), &token, None)?;
        let sync = self.http.json(Method::GET, "/api/sync", &token, None)?;
        let list = self.http.json(Method::GET, "/api/ciphers", &token, None)?;
        for (value, direct_get) in [
            (&direct, true),
            (unique_cipher(&sync["ciphers"], id)?, false),
            (unique_cipher(&list["data"], id)?, false),
        ] {
            let ids = if mode == 1 && direct_get {
                Vec::new()
            } else {
                vec![collection.to_owned()]
            };
            check_cipher(
                value,
                CipherExpectation {
                    id,
                    organization: Some(&org),
                    collections: &ids,
                    edit: mode != 1,
                    view_password: mode != 2,
                    favorite: actor == 0,
                    folder: folder.as_deref(),
                },
            )?;
        }
        Ok(())
    }
}
fn unique_cipher<'a>(rows: &'a Value, id: &str) -> Result<&'a Value, Error> {
    let found = rows
        .as_array()
        .ok_or(Error("Sharing cipher list missing"))?
        .iter()
        .filter(|v| v["id"] == id)
        .collect::<Vec<_>>();
    require(
        found.len() == 1,
        "Sharing list did not contain exactly one cipher",
    )?;
    Ok(found[0])
}
fn absent(rows: &Value, id: &str) -> Result<(), Error> {
    require(
        rows.as_array()
            .is_some_and(|a| a.iter().all(|v| v["id"] != id)),
        "Inaccessible shared cipher remained listed",
    )
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let ids = vec![s.orgs[0].collection_id.clone()];
    s.trial(1, 1, 0, &ids, Form::Standard, None)?
        .unchanged(400)?;
    let member = s.member.clone();
    s.confirm(0, &member)?;
    s.trial(0, 1, 0, &ids, Form::Standard, None)?
        .unchanged(400)?;
    let foreign = vec![s.orgs[1].collection_id.clone()];
    s.trial(0, 0, 1, &foreign, Form::Standard, None)?
        .unchanged(400)?;
    for form in [
        Form::MissingCollections,
        Form::NullCollections,
        Form::StringCollections,
        Form::MissingCipher,
        Form::NullCipher,
        Form::BadPath,
    ] {
        s.trial(0, 0, 0, &ids, form, None)?.unchanged(422)?;
    }
    Ok(())
}
fn admission(s: &mut Suite) -> Result<(), Error> {
    let main = s.orgs[0].id.clone();
    let writable = vec![s.orgs[0].collection_id.clone()];
    s.trial(1, 1, 0, &writable, Form::Standard, None)?
        .success(Some(&main), &writable, None)?;
    for col in [
        s.collections[0].clone(),
        s.collections[1].clone(),
        s.collections[2].clone(),
    ] {
        s.trial(1, 1, 0, &[col], Form::Standard, None)?
            .unchanged(400)?;
    }
    let hidden = vec![s.collections[3].clone()];
    let trial = s.trial(1, 1, 0, &hidden, Form::Standard, None)?;
    let value = trial.reply.status(200)?.json()?;
    require(
        value["id"] == trial.id && value["viewPassword"] == false && value["edit"] == true,
        "Writable hide-password sharing differed",
    )?;
    let restricted = vec![s.orgs[2].collection_id.clone()];
    s.trial(1, 1, 2, &restricted, Form::Standard, None)?
        .unchanged(400)?;
    let full = vec![s.orgs[3].collection_id.clone()];
    let full_org = s.orgs[3].id.clone();
    s.trial(1, 1, 3, &full, Form::Standard, None)?
        .success(Some(&full_org), &full, None)?;
    s.trial(1, 1, 0, &[], Form::Standard, None)?
        .unchanged(400)?;
    s.trial(0, 0, 0, &[], Form::Standard, None)?
        .success(Some(&main), &[], None)?;
    let duplicate = vec![writable[0].clone(), writable[0].clone()];
    s.trial(1, 1, 0, &duplicate, Form::Standard, None)?
        .success(Some(&main), &writable, None)?;
    Ok(())
}
fn prefix_effects(s: &mut Suite) -> Result<(), Error> {
    manager_fresh_probe(s)?;
    let valid = s.orgs[0].collection_id.clone();
    let foreign = s.orgs[1].collection_id.clone();
    for (index, (ids, changed)) in [
        (vec![valid.clone(), foreign.clone()], true),
        (vec![foreign, valid.clone()], false),
        (vec![valid.clone(), Uuid::new_v4().to_string()], true),
    ]
    .into_iter()
    .enumerate()
    {
        let folder = s.folders[0].clone();
        let mut trial = s.trial(0, 0, 0, &ids, Form::ChangedAnnotations, Some(folder))?;
        trial.reply.rejected(400)?;
        if changed {
            trial.before["collectionIds"] = json!([valid]);
            require(
                trial.before == trial.after
                    && trial.before_revisions[0] != trial.after_revisions[0]
                    && trial.before_revisions[1] != trial.after_revisions[1],
                "Late collection rejection lost its observed prefix/revision effects",
            )?;
        } else {
            require(
                trial.before == trial.after && trial.before_revisions == trial.after_revisions,
                "First invalid collection caused mutation",
            )?;
        }
        let owner_sync = s.get(0, "/api/sync")?;
        let owner_list = s.get(0, "/api/ciphers")?;
        require(
            unique_cipher(&owner_sync["ciphers"], &trial.id)? == &trial.after
                && unique_cipher(&owner_list["data"], &trial.id)? == &trial.after,
            "Personal prefix associations differed across Owner read aliases",
        )?;
        let token = s.token(1);
        s.http
            .raw(
                Method::GET,
                &format!("/api/ciphers/{}", trial.id),
                &token,
                None,
            )?
            .rejected(400)?;
        let sync = s.get(1, "/api/sync")?;
        let list = s.get(1, "/api/ciphers")?;
        absent(&sync["ciphers"], &trial.id)?;
        absent(&list["data"], &trial.id)?;
        if index != 1 {
            retry_prefix_in_another_org(
                s,
                &trial.id,
                &trial.after,
                &trial.after_revisions,
                &valid,
                if index == 0 { 2 } else { 4 },
            )?;
        }
    }
    Ok(())
}
// Actual Vaultwarden retains historical collection grants across a retry. A
// confirmed member of the new canonical organization can read through its old
// writable grant, even without a direct grant in the new organization.
fn retry_prefix_in_another_org(
    s: &mut Suite,
    id: &str,
    personal: &Value,
    before_revisions: &[Value; 2],
    old_collection: &str,
    target_index: usize,
) -> Result<(), Error> {
    let target = s.orgs[target_index].id.clone();
    let selected = s.orgs[target_index].collection_id.clone();
    let folder = s.folders[0].clone();
    let encrypted = fixture::encrypt(NOTE.as_bytes(), &s.orgs[target_index].key)
        .map_err(|_| Error("Sharing retry encryption failed"))?;
    let body = json!({"collectionIds":[selected],"cipher":{"type":2,"organizationId":target,"encryptedFor":s.accounts[0].user_id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"favorite":true,"folderId":folder,"key":null,"lastKnownRevisionDate":personal["revisionDate"]}});
    let token = s.token(0);
    let returned = s
        .http
        .raw(
            Method::PUT,
            &format!("/api/ciphers/{id}/share"),
            &token,
            Some(&body),
        )?
        .status(200)?
        .json()?;
    let direct = s.get(0, &format!("/api/ciphers/{id}"))?;
    let sync = s.get(0, "/api/sync")?;
    let list = s.get(0, "/api/ciphers")?;
    let mut expected_ids = vec![old_collection.to_owned(), selected.clone()];
    expected_ids.sort();
    for value in [
        &returned,
        &direct,
        unique_cipher(&sync["ciphers"], id)?,
        unique_cipher(&list["data"], id)?,
    ] {
        require(
            value["collectionIds"].as_array().is_some_and(|ids| {
                ids.len() == 2
                    && ids.contains(&json!(old_collection))
                    && ids.contains(&json!(selected))
            }),
            "Sharing retry pruned historical collection links",
        )?;
        // This bounded probe establishes membership of the ID set, not its order.
        let mut normalized = value.clone();
        normalized["collectionIds"] = json!(expected_ids);
        check_cipher(
            &normalized,
            CipherExpectation {
                id,
                organization: Some(&target),
                collections: &expected_ids,
                edit: true,
                view_password: true,
                favorite: true,
                folder: Some(&folder),
            },
        )?;
        require(
            value["name"] == encrypted
                && value["notes"] == encrypted
                && value["revisionDate"] != personal["revisionDate"],
            "Sharing retry lost replacement ciphertext or revision",
        )?;
    }
    let token = s.token(1);
    let reply = s
        .http
        .raw(Method::GET, &format!("/api/ciphers/{id}"), &token, None)?;
    let status = reply.status;
    let direct = if status == 200 {
        Some(reply.json()?)
    } else {
        reply.rejected(400)?;
        None
    };
    let sync = s.get(1, "/api/sync")?;
    let list = s.get(1, "/api/ciphers")?;
    let after = s.revisions()?;
    require(
        status == 200,
        "Historical collection grant did not authorize confirmed retry member",
    )?;
    for value in [
        direct
            .as_ref()
            .ok_or(Error("Historical grant GET projection missing"))?,
        unique_cipher(&sync["ciphers"], id)?,
        unique_cipher(&list["data"], id)?,
    ] {
        check_cipher(
            value,
            CipherExpectation {
                id,
                organization: Some(&target),
                collections: &[old_collection.to_owned()],
                edit: true,
                view_password: true,
                favorite: false,
                folder: None,
            },
        )?;
        require(
            value["name"] == encrypted && value["notes"] == encrypted,
            "Historical grant projection changed ciphertext",
        )?;
    }
    require(
        after[0] != before_revisions[0] && after[1] != before_revisions[1],
        "Sharing retry historical grant revision fanout differed",
    )
}
fn manager_fresh_probe(s: &mut Suite) -> Result<(), Error> {
    let target = s.orgs[2].id.clone();
    let selected = s.orgs[2].collection_id.clone();
    let trial = s.trial(
        0,
        0,
        2,
        std::slice::from_ref(&selected),
        Form::Standard,
        None,
    )?;
    let revision_changed = trial.before_revisions[1] != trial.after_revisions[1];
    let id = trial.success(Some(&target), std::slice::from_ref(&selected), None)?;
    let token = s.token(1);
    let reply = s
        .http
        .raw(Method::GET, &format!("/api/ciphers/{id}"), &token, None)?;
    let status = reply.status;
    let direct = if status == 200 {
        Some(reply.json()?)
    } else {
        reply.rejected(400)?;
        None
    };
    let sync = s.get(1, "/api/sync")?;
    let list = s.get(1, "/api/ciphers")?;
    require(
        status == 400 && direct.is_none() && !revision_changed,
        "Fresh restricted Manager read or revision fanout differed",
    )?;
    absent(&sync["ciphers"], &id)?;
    absent(&list["data"], &id)?;
    Ok(())
}
fn projections(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let cases = [
        (s.orgs[0].collection_id.clone(), 0),
        (s.collections[0].clone(), 1),
        (s.collections[3].clone(), 2),
    ];
    for (col, mode) in cases {
        let folder = s.folders[0].clone();
        let ids = vec![col.clone()];
        let id = s
            .trial(0, 0, 0, &ids, Form::Standard, Some(folder.clone()))?
            .success(Some(&org), &ids, Some(&folder))?;
        let revisions = s.revisions()?;
        s.check_views(0, &id, &col, 0, Some(folder))?;
        s.check_views(1, &id, &col, mode, None)?;
        require(
            revisions == s.revisions()?,
            "Shared reads changed account revisions",
        )?;
        if mode == 0 {
            s.shared = Some(id);
        }
    }
    let foreign = s.orgs[1].id.clone();
    let ids = vec![s.orgs[1].collection_id.clone()];
    let id = s
        .trial(1, 1, 1, &ids, Form::Standard, None)?
        .success(Some(&foreign), &ids, None)?;
    let token = s.token(0);
    s.http
        .raw(Method::GET, &format!("/api/ciphers/{id}"), &token, None)?
        .rejected(400)?;
    let sync = s.get(0, "/api/sync")?;
    let list = s.get(0, "/api/ciphers")?;
    absent(&sync["ciphers"], &id)?;
    absent(&list["data"], &id)?;
    Ok(())
}
fn aliases(s: &mut Suite) -> Result<(), Error> {
    let org = s.orgs[0].id.clone();
    let ids = vec![s.orgs[0].collection_id.clone()];
    for form in [Form::Pascal, Form::Mixed, Form::BodyId, Form::OuterOrg] {
        s.trial(0, 0, 0, &ids, form, None)?
            .success(Some(&org), &ids, None)?;
    }
    for form in [Form::MissingOrg, Form::NullOrg] {
        s.trial(0, 0, 0, &ids, form, None)?
            .success(None, &[], None)?;
    }
    s.trial(0, 0, 0, &ids, Form::ForeignOrg, None)?
        .unchanged(400)?;
    let foreign = vec![s.orgs[1].collection_id.clone()];
    s.trial(0, 0, 0, &foreign, Form::Standard, None)?
        .unchanged(400)?;
    s.trial(0, 0, 0, &[Uuid::new_v4().to_string()], Form::Standard, None)?
        .unchanged(400)?;
    Ok(())
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let id = s
        .shared
        .clone()
        .ok_or(Error("Shared read fixture missing"))?;
    let org = s.orgs[0].id.clone();
    let token = s.token(0);
    let before = s.get(
        0,
        &format!(
            "/api/organizations/{org}/users/{}?includeCollections=true",
            s.member
        ),
    )?;
    s.http
        .raw(
            Method::PUT,
            &format!("/api/organizations/{org}/users/{}/revoke", s.member),
            &token,
            None,
        )?
        .status(200)?;
    let recipient = s.token(1);
    s.http
        .raw(Method::GET, &format!("/api/ciphers/{id}"), &recipient, None)?
        .rejected(400)?;
    let sync = s.get(1, "/api/sync")?;
    let list = s.get(1, "/api/ciphers")?;
    absent(&sync["ciphers"], &id)?;
    absent(&list["data"], &id)?;
    let ids = vec![s.orgs[0].collection_id.clone()];
    s.trial(1, 1, 0, &ids, Form::Standard, None)?
        .unchanged(400)?;
    s.http
        .raw(
            Method::PUT,
            &format!("/api/organizations/{org}/users/{}/restore", s.member),
            &token,
            None,
        )?
        .status(200)?;
    let after = s.get(
        0,
        &format!(
            "/api/organizations/{org}/users/{}?includeCollections=true",
            s.member
        ),
    )?;
    require(
        before == after,
        "Sharing flow altered restored membership/grants",
    )?;
    s.check_views(1, &id, &ids[0], 0, None)?;
    for actor in 0..2 {
        let control = s.get(
            actor,
            &format!("/api/ciphers/{}", s.accounts[actor].cipher_id),
        )?;
        let keys = s.get(actor, "/api/accounts/keys")?;
        require(
            control == s.controls[actor] && keys == s.keys[actor],
            "Sharing changed personal control or keys",
        )?;
        let key =
            fixture::fixture_user_key(&s.accounts[actor].fixture, &s.accounts[actor].password)
                .map_err(|_| Error("Sharing control key unwrap failed"))?;
        require(
            fixture::decrypt(text(&control["notes"])?, &key)
                .map_err(|_| Error("Sharing control decryption failed"))?
                == organization_owner::NOTE.as_bytes(),
            "Sharing control plaintext differed",
        )?;
        let proof = s.accounts[actor].refresh.clone();
        let refreshed = s.http.refresh(&proof)?;
        let profile = s.http.json(
            Method::GET,
            "/api/accounts/profile",
            text(&refreshed["access_token"])?,
            None,
        )?;
        require(
            profile["id"] == s.accounts[actor].user_id,
            "Sharing retained session changed account",
        )?;
    }
    Ok(())
}

// Native older-only rejection is a final payload guard: prior successful links
// and account revision fanout remain durable, while cipher data stays personal.
// This is distinct from an adapter's live source-revision concurrency check.
fn revision_phase(s: &mut Suite) -> Result<(), Error> {
    let target = s.orgs[0].id.clone();
    let valid = s.orgs[0].collection_id.clone();
    let foreign = s.orgs[1].collection_id.clone();
    let folder = s.folders[0].clone();
    for form in [
        Form::Standard, // Exact current revision.
        Form::RevisionFuture,
        Form::RevisionMalformed,
        Form::RevisionMissing,
        Form::RevisionNull,
    ] {
        let trial = s.trial(
            0,
            0,
            0,
            std::slice::from_ref(&valid),
            form,
            Some(folder.clone()),
        )?;
        require(
            trial.before_revisions[0] != trial.after_revisions[0]
                && trial.before_revisions[1] != trial.after_revisions[1]
                && trial.before["revisionDate"] != trial.after["revisionDate"]
                && trial.before["creationDate"] == trial.after["creationDate"],
            "Accepted revision form lost payload or account revision effects",
        )?;
        let payload = trial.payload.clone();
        trial.success(Some(&target), std::slice::from_ref(&valid), Some(&folder))?;
        for field in ["name", "notes"] {
            require(
                fixture::decrypt(text(&payload[field])?, &s.orgs[0].key)
                    .map_err(|_| Error("Sharing revision ciphertext decryption failed"))?
                    == NOTE.as_bytes(),
                "Accepted revision form changed encrypted content",
            )?;
        }
    }
    let message = |reply: &Reply| -> Result<Value, Error> {
        let value: Value = serde_json::from_slice(&reply.bytes)
            .map_err(|_| Error("Sharing rejection category was not JSON"))?;
        require(
            value["message"].is_string(),
            "Sharing rejection category missing",
        )?;
        // Compare categories only within a target; never log native error text.
        Ok(value["message"].clone())
    };
    let mut older_message = None;
    let mut foreign_message = None;
    for (ids, form, freshness_error) in [
        (vec![valid.clone()], Form::RevisionOlder, true),
        (
            vec![valid.clone(), foreign.clone()],
            Form::RevisionOlder,
            false,
        ),
        (vec![valid.clone(), foreign.clone()], Form::Standard, false),
    ] {
        let mut trial = s.trial(0, 0, 0, &ids, form, Some(folder.clone()))?;
        let category = message(&trial.reply)?;
        if freshness_error {
            older_message = Some(category);
        } else if let Some(previous) = &foreign_message {
            require(
                previous == &category,
                "Freshness ran before collection rejection",
            )?;
        } else {
            foreign_message = Some(category);
        }
        trial.reply.rejected(400)?;
        trial.before["collectionIds"] = json!([valid]);
        require(
            trial.before == trial.after
                && trial.before_revisions[0] != trial.after_revisions[0]
                && trial.before_revisions[1] != trial.after_revisions[1],
            "Revision or selection rejection lost prior associations or rewrote cipher data",
        )?;
        let sync = s.get(0, "/api/sync")?;
        let list = s.get(0, "/api/ciphers")?;
        require(
            unique_cipher(&sync["ciphers"], &trial.id)? == &trial.after
                && unique_cipher(&list["data"], &trial.id)? == &trial.after,
            "Rejected sharing prefix changed Owner alias projection",
        )?;
        let recipient = s.token(1);
        s.http
            .raw(
                Method::GET,
                &format!("/api/ciphers/{}", trial.id),
                &recipient,
                None,
            )?
            .rejected(400)?;
        let sync = s.get(1, "/api/sync")?;
        let list = s.get(1, "/api/ciphers")?;
        absent(&sync["ciphers"], &trial.id)?;
        absent(&list["data"], &trial.id)?;
    }
    require(
        older_message != foreign_message,
        "Revision and collection rejection categories collapsed",
    )?;
    let trial = s.trial(
        0,
        0,
        0,
        &[foreign, valid.clone()],
        Form::RevisionOlder,
        Some(folder.clone()),
    )?;
    require(
        Some(message(&trial.reply)?) == foreign_message,
        "Older revision hid first collection rejection",
    )?;
    trial.unchanged(400)?;
    for form in [Form::NullOrgRevisionOlder, Form::MissingOrgRevisionOlder] {
        let trial = s.trial(
            0,
            0,
            0,
            std::slice::from_ref(&valid),
            form,
            Some(folder.clone()),
        )?;
        require(
            Some(message(&trial.reply)?) == older_message,
            "Personal branch older-date rejection category differed",
        )?;
        trial.unchanged(400)?;
    }
    let trial = s.trial(
        0,
        0,
        0,
        std::slice::from_ref(&valid),
        Form::NullOrgRevisionEqual,
        Some(folder.clone()),
    )?;
    require(
        trial.before_revisions[0] != trial.after_revisions[0]
            && trial.before_revisions[1] == trial.after_revisions[1]
            && trial.before["revisionDate"] != trial.after["revisionDate"]
            && trial.before["creationDate"] == trial.after["creationDate"],
        "Personal null-organization branch added target revision effects",
    )?;
    let payload = trial.payload.clone();
    trial.success(None, &[], Some(&folder))?;
    let key = fixture::fixture_user_key(&s.accounts[0].fixture, &s.accounts[0].password)
        .map_err(|_| Error("Sharing personal revision key unwrap failed"))?;
    require(
        fixture::decrypt(text(&payload["notes"])?, &key)
            .map_err(|_| Error("Sharing personal revision decryption failed"))?
            == NOTE.as_bytes(),
        "Personal null-organization revision path changed encrypted content",
    )?;
    for actor in 0..2 {
        let control = s.get(
            actor,
            &format!("/api/ciphers/{}", s.accounts[actor].cipher_id),
        )?;
        let keys = s.get(actor, "/api/accounts/keys")?;
        require(
            control == s.controls[actor] && keys == s.keys[actor],
            "Revision sharing changed personal controls or account keys",
        )?;
    }
    Ok(())
}

fn setup() -> Result<Suite, Error> {
    let mut http = Http::new()?;
    let accounts = vec![
        organization_owner::seed(&mut http.owner)?,
        organization_owner::seed(&mut http.owner)?,
    ];
    let mut personal_totp_before = [false; 2];
    for (actor, account) in accounts.iter().enumerate() {
        let value = http.json(
            Method::GET,
            &format!("/api/ciphers/{}", account.cipher_id),
            &account.token,
            None,
        )?;
        personal_totp_before[actor] = value["organizationUseTotp"].as_bool().ok_or(Error(
            "Personal TOTP flag missing before organization setup",
        ))?;
    }
    let orgs = vec![
        create_organization(&mut http.owner, &accounts[0])?,
        create_organization(&mut http.owner, &accounts[1])?,
        create_organization(&mut http.owner, &accounts[0])?,
        create_organization(&mut http.owner, &accounts[0])?,
        create_organization(&mut http.owner, &accounts[0])?,
    ];
    let mut folders = Vec::new();
    for account in &accounts {
        let name = fixture::encrypted_fixture_value(
            &account.fixture,
            &account.password,
            b"Private sharing folder",
        )
        .map_err(|_| Error("Sharing folder encryption failed"))?;
        let value = http.json(
            Method::POST,
            "/api/folders",
            &account.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&value["id"])?.to_owned());
    }
    let mut collections = Vec::new();
    for name in [
        "Read only",
        "Read only and manage",
        "Unassigned",
        "Hidden passwords",
    ] {
        let encrypted = fixture::encrypt(name.as_bytes(), &orgs[0].key)
            .map_err(|_| Error("Sharing collection encryption failed"))?;
        let value = http.json(
            Method::POST,
            &format!("/api/organizations/{}/collections", orgs[0].id),
            &accounts[0].token,
            Some(&json!({"name":encrypted,"users":[],"groups":[]})),
        )?;
        collections.push(text(&value["id"])?.to_owned());
    }
    let mut s = Suite {
        http,
        accounts,
        orgs,
        collections: collections
            .try_into()
            .map_err(|_| Error("Sharing collections incomplete"))?,
        folders: folders
            .try_into()
            .map_err(|_| Error("Sharing folders incomplete"))?,
        member: String::new(),
        controls: [Value::Null, Value::Null],
        keys: [Value::Null, Value::Null],
        personal_totp_before,
        shared: None,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_SHARING_RECEIPT")?,
        finished: false,
    };
    let selections = json!([{ "id":s.orgs[0].collection_id,"readOnly":false,"hidePasswords":false,"manage":false},{"id":s.collections[0],"readOnly":true,"hidePasswords":false,"manage":false},{"id":s.collections[1],"readOnly":true,"hidePasswords":false,"manage":true},{"id":s.collections[3],"readOnly":false,"hidePasswords":true,"manage":false}]);
    s.member = s.invite(0, 2, selections, json!({}))?;
    let restricted = s.invite(2, 3, json!([]), json!({}))?;
    s.confirm(2, &restricted)?;
    let full = s.invite(
        3,
        4,
        json!([]),
        json!({"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true}),
    )?;
    s.confirm(3, &full)?;
    let no_grant = s.invite(4, 2, json!([]), json!({}))?;
    s.confirm(4, &no_grant)?;
    for actor in 0..2 {
        s.controls[actor] = s.get(
            actor,
            &format!("/api/ciphers/{}", s.accounts[actor].cipher_id),
        )?;
        s.keys[actor] = s.get(actor, "/api/accounts/keys")?;
    }
    Ok(s)
}
pub fn run() -> Result<(), Error> {
    let mut s = setup()?;
    require(
        s.personal_totp_before == [true; 2]
            && s.controls
                .iter()
                .all(|value| value["organizationUseTotp"] == true),
        "Personal organization TOTP projection differed before or after organization creation",
    )?;
    s.receipt("running")?;
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    require(
        s.passed.len() == CASE_COUNT && s.http.owner.logins == 2 && s.http.refreshes == 2,
        "Sharing fixture budget differed",
    )?;
    if s.http.owner.requests != HTTP_REQUEST_COUNT {
        eprintln!(
            "Sharing HTTP request budget: expected {HTTP_REQUEST_COUNT}, actual {}",
            s.http.owner.requests
        );
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT,
        "Sharing HTTP request budget differed",
    )?;
    s.finished = true;
    s.receipt("passed")?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sharing_projection_rejects_cross_scope_private_annotations_and_read_alias_drift() {
        let mut row = json!({"archivedDate":null,"attachments":null,"bankAccount":null,"card":null,"collectionIds":[],"creationDate":"date","deletedDate":null,"driversLicense":null,"edit":false,"favorite":false,"fields":null,"folderId":null,"id":"cipher","identity":null,"key":null,"login":null,"name":"opaque","notes":"opaque","object":"cipherDetails","organizationId":"org","organizationUseTotp":true,"passport":null,"passwordHistory":null,"permissions":{"delete":false,"restore":false},"reprompt":0,"revisionDate":"date","secureNote":{"type":0},"sshKey":null,"type":2,"viewPassword":true});
        let check = |row: &Value| {
            check_cipher(
                row,
                CipherExpectation {
                    id: "cipher",
                    organization: Some("org"),
                    collections: &[],
                    edit: false,
                    view_password: true,
                    favorite: false,
                    folder: None,
                },
            )
        };
        assert!(check(&row).is_ok());
        row["folderId"] = json!("another-user-folder");
        assert!(check(&row).is_err());
        row["folderId"] = Value::Null;
        row["organizationId"] = json!("foreign");
        assert!(check(&row).is_err());
        row["organizationId"] = json!("org");
        row["collectionIds"] = json!(["readonly-id-visible-only-in-list"]);
        assert!(check(&row).is_err());
    }
}
