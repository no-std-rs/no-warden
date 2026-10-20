//! Independently authored MIT/Apache-2.0 default no-SMTP invitation contracts.
//! Invitation setup and modern registration use direct HTTP, not CLI invitation commands.
use crate::{
    fixture,
    organization_collections::{create_organization, path as collections_path},
    organization_owner::{self, Account, Http as OwnerHttp, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{fs, io::Read};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
pub const HTTP_REQUEST_COUNT: usize = 211;
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_invites_authentication_and_json_guards",
        guards,
    ),
    (
        "organization_invites_roles_and_reference_prevalidation",
        validation,
    ),
    (
        "organization_invites_existing_user_acceptance_and_duplicate",
        existing,
    ),
    (
        "organization_invites_ordered_per_email_partial_success",
        ordered,
    ),
    (
        "organization_invites_multi_org_placeholder_registration",
        completion,
    ),
    (
        "organization_invites_preserved_vault_keys_and_sessions",
        preservation,
    ),
];
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, Error> {
        if self.status != expected {
            eprintln!(
                "Organization members status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Organization member HTTP status differed",
        )?;
        Ok(self)
    }
    fn empty(self) -> Result<(), Error> {
        let reply = self.status(200)?;
        require(
            reply.bytes.is_empty(),
            "Invitation success response was not empty",
        )
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Organization member response was not JSON"))
    }
    fn rejected(self, expected: u16) -> Result<(), Error> {
        let response = self.status(expected)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "key", "privateKey"]
                    .iter()
                    .all(|k| value.get(k).is_none()),
                "Rejected member request exposed authority",
            )?;
        }
        Ok(())
    }
}
struct Http {
    owner: OwnerHttp,
    client: Client,
    refreshes: usize,
    bad_logins: usize,
}
impl Http {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            owner: OwnerHttp::new()?,
            client: http_client()?,
            refreshes: 0,
            bad_logins: 0,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, Error> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Member private response capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Member response exceeded private bound",
        )?;
        Ok(Reply { status, bytes })
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
        media: Option<&str>,
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.owner.server));
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        if let Some(media) = media {
            request = request.header("Content-Type", media);
        }
        Self::read(
            request
                .send()
                .map_err(|_| Error("Organization member request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.raw(
            method,
            path,
            Some(token),
            body.map(Value::to_string).as_deref().map(str::as_bytes),
            Some("application/json"),
        )?
        .status(200)?
        .json()
    }
    fn refresh(&mut self, proof: &str) -> Result<Value, Error> {
        self.owner.requests += 1;
        self.refreshes += 1;
        Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.owner.server))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", proof),
                    ("client_id", "cli"),
                ])
                .send()
                .map_err(|_| Error("Member refresh failed"))?,
        )?
        .status(200)?
        .json()
    }
    fn reject_placeholder_login(&mut self, email: &str) -> Result<(), Error> {
        self.owner.requests += 1;
        self.owner.logins += 1;
        self.bad_logins += 1;
        let value = Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.owner.server))
                .form(&[
                    ("grant_type", "password"),
                    ("client_id", "cli"),
                    ("scope", "api offline_access"),
                    ("username", email),
                    ("password", "incorrect-unregistered-placeholder-proof"),
                    ("deviceIdentifier", "Rejected-Invited-Placeholder"),
                    ("deviceName", "Rejected invitation fixture"),
                    ("deviceType", "8"),
                ])
                .send()
                .map_err(|_| Error("Placeholder negative login request failed"))?,
        )?
        .status(400)?
        .json()?;
        validate_bad_credentials(&value)
    }
}
fn validate_bad_credentials(value: &Value) -> Result<(), Error> {
    let message = "Username or password is incorrect. Try again";
    require(
        *value
            == json!({"message":message,"validationErrors":{"": [message]},"errorModel":{"message":message,"object":"error"},"error":"","error_description":"","exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"}),
        "Placeholder login did not return exact ordinary bad-credentials error",
    )
}
pub(crate) fn path(org: &str) -> String {
    format!("/api/organizations/{org}/users/invite")
}
pub(crate) fn member_path(org: &str) -> String {
    format!("/api/organizations/{org}/users?includeCollections=true&includeGroups=true")
}
pub(crate) fn member<'a>(value: &'a Value, email: &str) -> Result<&'a Value, Error> {
    let rows = crate::organization_members::rows(value)?;
    let found = rows
        .iter()
        .filter(|v| {
            v["email"]
                .as_str()
                .is_some_and(|s| s == email.to_lowercase())
        })
        .collect::<Vec<_>>();
    require(found.len() == 1, "Invitation member missing or duplicated")?;
    Ok(found[0])
}
pub(crate) fn basic_member(
    value: &Value,
    email: &str,
    status: i64,
    role: i64,
    name: &Value,
    password: bool,
) -> Result<(), Error> {
    require(
        value.as_object().is_some_and(|o| o.len() == 19)
            && value["email"] == email.to_lowercase()
            && value["status"] == status
            && value["type"] == role
            && value.get("name") == Some(name)
            && value.get("collections").is_some_and(Value::is_array)
            && value
                .get("permissions")
                .is_some_and(|v| v.is_null() || v.is_object())
            && value["hasMasterPassword"] == password
            && value["id"] != value["userId"]
            && value["id"]
                .as_str()
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
            && value["userId"]
                .as_str()
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
            && value["object"] == "organizationUserUserDetails",
        "Invitation member projection differed",
    )?;
    for field in ["externalId", "avatarColor"] {
        require(
            value.get(field).is_some_and(Value::is_null),
            "Invitation nullable metadata differed",
        )?;
    }
    for field in [
        "twoFactorEnabled",
        "resetPasswordEnrolled",
        "ssoBound",
        "claimedByOrganization",
        "usesKeyConnector",
        "accessSecretsManager",
    ] {
        require(value[field] == false, "Invitation account flag differed")?;
    }
    require(
        value["groups"] == json!([]),
        "Invitation unexpectedly gained group access",
    )
}
fn canonical_members(value: &Value) -> Result<Value, Error> {
    crate::organization_members::rows(value)?;
    let mut value = value.clone();
    value["data"]
        .as_array_mut()
        .ok_or(Error("Invitation list snapshot malformed"))?
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(value)
}
fn permissions(full: bool) -> Value {
    if !full {
        return Value::Null;
    }
    json!({"accessEventLogs":false,"accessImportExport":false,"accessReports":false,"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true,"manageGroups":false,"managePolicies":false,"manageSso":false,"manageUsers":false,"manageResetPassword":false,"manageScim":false})
}
pub(crate) fn ordinary_body(email: &str) -> Value {
    json!({"emails":[email],"groups":[],"type":2,"collections":[]})
}
pub(crate) fn invite_owner(
    http: &mut OwnerHttp,
    org: &str,
    token: &str,
    body: &Value,
) -> Result<(), Error> {
    http.requests += 1;
    let response = http_client()?
        .post(format!("{}{}", http.server, path(org)))
        .bearer_auth(token)
        .json(body)
        .send()
        .map_err(|_| Error("CLI invitation setup failed"))?;
    Http::read(response)?.empty()
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    organizations: Vec<Organization>,
    personal: Vec<Value>,
    revisions: Vec<Value>,
    authority: Value,
    known: Value,
    placeholder: Value,
    registrations: usize,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"rejectedPlaceholderLogins":self.http.bad_logins,"refreshRequests":self.http.refreshes,"modernRegistrations":self.registrations,"fixtureRegistrations":self.registrations,"registrationHttpRequests":self.registrations*2,"smtpEnabled":false,"successfulConfirmationClaimed":false}),
        )
    }
    fn members(&mut self, org: usize) -> Result<Value, Error> {
        let owner = usize::from(org == 1);
        self.http.json(
            Method::GET,
            &member_path(&self.organizations[org].id),
            &self.accounts[owner].token,
            None,
        )
    }
    fn authority_snapshot(&mut self) -> Result<Value, Error> {
        let mut profiles = Vec::new();
        for account in &self.accounts {
            let p = self
                .http
                .json(Method::GET, "/api/accounts/profile", &account.token, None)?;
            profiles.push(json!({"organizations":p["organizations"],"organizationsNew":p["organizationsNew"]}));
        }
        let mut collections = Vec::new();
        for i in 0..3 {
            collections.push(self.http.json(
                Method::GET,
                &collections_path(&self.organizations[i].id),
                &self.accounts[usize::from(i == 1)].token,
                None,
            )?);
        }
        let foreign = self.members(1)?;
        Ok(json!({"profiles":profiles,"collections":collections,"foreignMembers":foreign}))
    }
    fn readonly(&mut self) -> Result<(), Error> {
        for i in 0..2 {
            require(
                self.http.owner.personal(&self.accounts[i].token)? == self.personal[i]
                    && self.http.owner.revision(&self.accounts[i].token)? == self.revisions[i],
                "Invitations changed inviter/foreign credentials, vault, settings, sessions or revision",
            )?;
        }
        require(
            self.authority_snapshot()? == self.authority,
            "Invitations changed owner membership, collection or foreign organization",
        )
    }
    fn post(&mut self, org: usize, body: &Value) -> Result<(), Error> {
        self.http
            .raw(
                Method::POST,
                &path(&self.organizations[org].id),
                Some(&self.accounts[0].token),
                Some(body.to_string().as_bytes()),
                Some("application/json"),
            )?
            .empty()
    }
    fn error(&mut self, body: &Value, message: &str) -> Result<(), Error> {
        let error = self
            .http
            .raw(
                Method::POST,
                &path(&self.organizations[0].id),
                Some(&self.accounts[0].token),
                Some(body.to_string().as_bytes()),
                Some("application/json"),
            )?
            .status(400)?
            .json()?;
        require(
            error["message"] == message,
            "Invitation rejection message differed",
        )
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let org = s.organizations[0].id.clone();
    let token = s.accounts[0].token.clone();
    for bearer in [None, Some("invalid-invitation-bearer")] {
        s.http
            .raw(Method::POST, &path(&org), bearer, Some(b"{"), None)?
            .rejected(401)?;
    }
    for (p, bearer, status) in [
        (path(&org), s.accounts[1].token.as_str(), 401),
        (path("bad.id"), token.as_str(), 401),
        (
            format!("{}?organizationId={org}", path("bad.id")),
            token.as_str(),
            422,
        ),
    ] {
        s.http
            .raw(Method::POST, &p, Some(bearer), Some(b"{"), None)?
            .rejected(status)?;
    }
    let valid = json!({"emails":[],"groups":[],"type":2});
    let mut invalids = vec![
        (b"{".to_vec(), 400),
        (b"[]".to_vec(), 422),
        (b"[[],[],2]".to_vec(), 422),
        (b"[[],[],2,null,{},0]".to_vec(), 400),
        (
            br#"{"emails":[],"emails":[],"groups":[],"type":2}"#.to_vec(),
            422,
        ),
        (
            b"{\"emails\":[],\"groups\":[],\"type\":2,\"ignored\":\"\xff\"}".to_vec(),
            400,
        ),
    ];
    for field in ["emails", "groups", "type"] {
        let mut v = valid.clone();
        v.as_object_mut()
            .ok_or(Error("Invitation fixture invalid"))?
            .remove(field);
        invalids.push((v.to_string().into_bytes(), 422));
    }
    for (field, v) in [
        ("emails", json!("x")),
        ("emails", json!([null])),
        ("groups", Value::Null),
        ("type", json!(true)),
        ("type", json!(1.5)),
        ("permissions", Value::Null),
        ("collections", json!([{"id":"opaque"}])),
    ] {
        let mut body = valid.clone();
        body[field] = v;
        invalids.push((body.to_string().into_bytes(), 422));
    }
    for (body, status) in invalids {
        s.http
            .raw(
                Method::POST,
                &path(&org),
                Some(&token),
                Some(&body),
                Some("application/json"),
            )?
            .rejected(status)?;
    }
    let (first, tail) = org
        .split_at_checked(1)
        .ok_or(Error("Invitation UUID empty"))?;
    let encoded = format!("%{:02X}{tail}", first.as_bytes()[0]);
    s.http
        .raw(
            Method::POST,
            &path(&encoded),
            Some(&token),
            Some(valid.to_string().as_bytes()),
            Some("text/plain"),
        )?
        .empty()?;
    s.http
        .raw(Method::PATCH, &path(&org), Some(&token), None, None)?
        .rejected(404)?;
    require(
        crate::organization_members::rows(&s.members(0)?)?.len() == 1,
        "Rejected invitation inserted a membership",
    )?;
    s.readonly()
}
fn validation(s: &mut Suite) -> Result<(), Error> {
    let before = s.members(0)?;
    let email = format!("invalid-reference-{}@example.test", Uuid::new_v4());
    let bad_collection = json!({"id":s.organizations[1].collection_id,"readOnly":false,"hidePasswords":false,"manage":false});
    let own_collection = json!({"id":s.organizations[0].collection_id,"readOnly":false,"hidePasswords":false,"manage":false});
    for (collections, groups, message) in [
        (
            json!([bad_collection]),
            json!(["missing-group"]),
            "Invalid collection",
        ),
        (
            json!([own_collection]),
            json!(["missing-group"]),
            "Invalid group",
        ),
    ] {
        s.error(
            &json!({"emails":[email],"groups":groups,"type":2,"collections":collections}),
            message,
        )?;
    }
    for role in [json!("owner"), json!(9), json!(-1)] {
        s.error(
            &json!({"emails":[email],"groups":[],"type":role}),
            "Invalid type",
        )?;
    }
    for role in [
        json!(0),
        json!(1),
        json!(2),
        json!(3),
        json!(4),
        json!("Owner"),
        json!("Admin"),
        json!("User"),
        json!("Manager"),
        json!("Custom"),
    ] {
        s.post(0, &json!({"emails":[],"groups":[],"type":role}))?;
    }
    s.http
        .raw(
            Method::POST,
            &path(&s.organizations[0].id),
            Some(&s.accounts[0].token),
            Some(br#"[[],[],2,null]"#),
            None,
        )?
        .empty()?;
    require(
        s.members(0)? == before,
        "Reference/type failure or empty batch changed memberships",
    )?;
    s.readonly()
}
fn existing(s: &mut Suite) -> Result<(), Error> {
    let email = text(&s.known["email"])?.to_uppercase();
    let grant = json!({"id":s.organizations[0].collection_id,"readOnly":true,"hidePasswords":false,"manage":false});
    s.post(0,&json!({"emails":[email],"groups":[],"type":"User","collections":[grant],"accessAll":true,"ownerId":s.accounts[1].user_id}))?;
    let list = s.members(0)?;
    let row = member(&list, &email)?;
    basic_member(row, &email, 1, 2, &s.known["name"], true)?;
    require(
        row["permissions"].is_null() && row["collections"] == json!([grant]),
        "Registered invitee role/grants were not preserved",
    )?;
    let key = s.http.json(
        Method::GET,
        &format!("/api/users/{}/public-key", text(&row["userId"])?),
        &s.accounts[0].token,
        None,
    )?;
    require(
        key["publicKey"] == s.known["keys"]["publicKey"],
        "Inviting registered user replaced asymmetric key",
    )?;
    s.error(
        &ordinary_body(&email),
        &format!("User already in organization: {}", email.escape_debug()),
    )?;
    require(
        s.members(0)? == list,
        "Duplicate invitation changed existing member",
    )?;
    s.readonly()
}
fn ordered(s: &mut Suite) -> Result<(), Error> {
    let first = format!("prefix-{}@example.test", Uuid::new_v4());
    let last = format!("unprocessed-{}@example.test", Uuid::new_v4());
    let duplicate = text(&s.known["email"])?.to_owned();
    s.error(
        &json!({"emails":[first,duplicate,last],"groups":[],"type":2}),
        &format!("User already in organization: {}", duplicate.escape_debug()),
    )?;
    let list = s.members(0)?;
    basic_member(member(&list, &first)?, &first, 0, 2, &Value::Null, false)?;
    require(
        !crate::organization_members::rows(&list)?
            .iter()
            .any(|v| v["email"] == last),
        "Invitation batch processed a suffix after duplicate failure",
    )?;
    let next = format!("validation-prefix-{}@example.test", Uuid::new_v4());
    let skipped = format!("validation-suffix-{}@example.test", Uuid::new_v4());
    s.error(
        &json!({"emails":[next,"not-an-email",skipped],"groups":[],"type":2}),
        "Email domain not eligible for invitations",
    )?;
    s.error(
        &ordinary_body("bad space@example.test"),
        "Invitation email bad space@example.test is not a valid email address",
    )?;
    let list = s.members(0)?;
    basic_member(member(&list, &next)?, &next, 0, 2, &Value::Null, false)?;
    require(
        !crate::organization_members::rows(&list)?.iter().any(|v| {
            v["email"] == skipped
                || v["email"] == "not-an-email"
                || v["email"] == "bad space@example.test"
        }),
        "Invalid-email batch inserted failed or unprocessed memberships",
    )?;
    s.readonly()
}
fn completion(s: &mut Suite) -> Result<(), Error> {
    let email = text(&s.placeholder["email"])?.to_owned();
    let flags =
        json!({"editAnyCollection":true,"deleteAnyCollection":true,"createNewCollections":true});
    let grant = json!({"id":s.organizations[0].collection_id,"readOnly":true,"hidePasswords":false,"manage":false});
    s.post(0,&json!({"emails":[email],"groups":[],"type":"Custom","permissions":flags,"collections":[grant]}))?;
    let first_list = s.members(0)?;
    let first = member(&first_list, &email)?.clone();
    basic_member(&first, &email, 0, 4, &Value::Null, false)?;
    require(
        first["permissions"] == Value::Null && first["collections"] == json!([grant]),
        "Text custom role unexpectedly gained full collection access",
    )?;
    s.post(2,&json!({"emails":[email],"groups":[],"type":4,"permissions":flags,"collections":[{"id":s.organizations[2].collection_id,"readOnly":true,"hidePasswords":true,"manage":false}]}))?;
    let second_list = s.members(2)?;
    let second = member(&second_list, &email)?.clone();
    basic_member(&second, &email, 0, 4, &Value::Null, false)?;
    require(
        second["userId"] == first["userId"]
            && second["id"] != first["id"]
            && second["permissions"] == permissions(true)
            && second["collections"] == json!([]),
        "Multiple invitations failed to reuse account or numeric custom accessAll",
    )?;
    s.http
        .raw(
            Method::GET,
            &format!("/api/users/{}/public-key", text(&first["userId"])?),
            Some(&s.accounts[0].token),
            None,
            None,
        )?
        .rejected(404)?;
    s.http.reject_placeholder_login(&email)?;
    require(
        canonical_members(&s.members(0)?)? == canonical_members(&first_list)?
            && canonical_members(&s.members(2)?)? == canonical_members(&second_list)?,
        "Rejected placeholder login changed pending memberships",
    )?;
    s.readonly()?;
    fixture::register_modern_fixture(&s.http.owner.server, &s.placeholder)
        .map_err(|_| Error("Invited placeholder modern completion failed"))?;
    s.registrations += 1;
    for (org, before, before_list) in [(0, first, first_list), (2, second, second_list)] {
        let list = s.members(org)?;
        let after = member(&list, &email)?;
        let mut expected = before;
        expected["status"] = json!(1);
        expected["name"] = s.placeholder["name"].clone();
        expected["hasMasterPassword"] = json!(true);
        require(
            *after == expected,
            "Modern registration changed invited UUID/role/grants instead of accepting all pending memberships",
        )?;
        let mut expected_list = before_list;
        let expected_rows = expected_list["data"]
            .as_array_mut()
            .ok_or(Error("Invitation list snapshot malformed"))?;
        let expected_row = expected_rows
            .iter_mut()
            .find(|row| row["email"] == email)
            .ok_or(Error("Invitation list snapshot omitted placeholder"))?;
        *expected_row = expected;
        require(
            canonical_members(&list)? == canonical_members(&expected_list)?,
            "Placeholder completion changed another user's membership",
        )?;
    }
    let list = s.members(0)?;
    let row = member(&list, &email)?;
    let public = s.http.json(
        Method::GET,
        &format!("/api/users/{}/public-key", text(&row["userId"])?),
        &s.accounts[0].token,
        None,
    )?;
    require(
        public["publicKey"] == s.placeholder["keys"]["publicKey"],
        "Placeholder completion did not install registered asymmetric key",
    )?;
    s.readonly()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for account in &s.accounts {
        let fresh = s.http.refresh(&account.refresh)?;
        let profile = s.http.json(
            Method::GET,
            "/api/accounts/profile",
            text(&fresh["access_token"])?,
            None,
        )?;
        require(
            profile["id"] == account.user_id,
            "Invitations rebound existing refresh authority",
        )?;
        let cipher = s.http.json(
            Method::GET,
            &format!("/api/ciphers/{}", account.cipher_id),
            &account.token,
            None,
        )?;
        let key = fixture::fixture_user_key(&account.fixture, &account.password)
            .map_err(|_| Error("Invitation user-key unwrap failed"))?;
        require(
            fixture::decrypt(text(&cipher["notes"])?, &key)
                .is_ok_and(|p| p == organization_owner::NOTE.as_bytes()),
            "Invitations changed authenticated personal ciphertext",
        )?;
    }
    let list = s.members(0)?;
    require(
        crate::organization_members::rows(&list)?.len() == 5,
        "Invitation partial prefixes or accepted members disappeared",
    )?;
    s.readonly()
}
pub fn run() -> Result<(), Error> {
    let known_password = Uuid::new_v4().to_string();
    let placeholder_password = Uuid::new_v4().to_string();
    let known = fixture::registration(
        &format!("registered-invite-{}@example.test", Uuid::new_v4()),
        &known_password,
        600000,
    )
    .map_err(|_| Error("Known invitation fixture failed"))?;
    let placeholder = fixture::registration(
        &format!("placeholder-invite-{}@example.test", Uuid::new_v4()),
        &placeholder_password,
        600000,
    )
    .map_err(|_| Error("Placeholder invitation fixture failed"))?;
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        organizations: Vec::new(),
        personal: Vec::new(),
        revisions: Vec::new(),
        authority: Value::Null,
        known,
        placeholder,
        registrations: 0,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_INVITES_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for _ in 0..2 {
        let account = organization_owner::seed(&mut s.http.owner)?;
        s.registrations += 1;
        s.organizations
            .push(create_organization(&mut s.http.owner, &account)?);
        s.accounts.push(account);
    }
    s.organizations
        .push(create_organization(&mut s.http.owner, &s.accounts[0])?);
    fixture::register_modern_fixture(&s.http.owner.server, &s.known)
        .map_err(|_| Error("Known invitee registration failed"))?;
    s.registrations += 1;
    for account in &s.accounts {
        s.personal.push(s.http.owner.personal(&account.token)?);
        s.revisions.push(s.http.owner.revision(&account.token)?);
    }
    s.authority = s.authority_snapshot()?;
    for (name, case) in CASES {
        eprintln!("Organization invitation case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.logins == 3
            && s.http.bad_logins == 1
            && s.http.refreshes == 2
            && s.registrations == 4
            && s.passed.len() == CASE_COUNT
            && s.http.owner.requests == HTTP_REQUEST_COUNT,
        "Invitation fixture budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-invites: {CASE_COUNT} cases, {} HTTP requests, 3 password attempts (2 successful, 1 rejected), 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invitation_projection_distinguishes_pending_accepted_confirmed_and_account_identity() {
        let mut value = json!({"id":Uuid::new_v4().to_string(),"userId":Uuid::new_v4().to_string(),"name":null,"email":"invite@example.test","externalId":null,"avatarColor":null,"groups":[],"collections":[],"status":0,"type":2,"twoFactorEnabled":false,"resetPasswordEnrolled":false,"hasMasterPassword":false,"permissions":null,"ssoBound":false,"claimedByOrganization":false,"usesKeyConnector":false,"accessSecretsManager":false,"object":"organizationUserUserDetails"});
        assert!(basic_member(&value, "invite@example.test", 0, 2, &Value::Null, false).is_ok());
        value["status"] = json!(1);
        value["name"] = json!("registered");
        value["hasMasterPassword"] = json!(true);
        assert!(
            basic_member(
                &value,
                "invite@example.test",
                1,
                2,
                &json!("registered"),
                true
            )
            .is_ok()
        );
        assert!(
            basic_member(
                &value,
                "invite@example.test",
                2,
                2,
                &json!("registered"),
                true
            )
            .is_err()
        );
        value["id"] = value["userId"].clone();
        assert!(
            basic_member(
                &value,
                "invite@example.test",
                1,
                2,
                &json!("registered"),
                true
            )
            .is_err()
        );
    }
}
