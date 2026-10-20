//! Independently authored MIT/Apache-2.0 bulk organization-member public-key contracts.
//! Direct HTTP reads do not establish a CLI caller or a browser trace.
use crate::{
    fixture,
    organization_collections::{self, create_organization},
    organization_confirmations as confirmation, organization_invites as invites,
    organization_member_removal as removal, organization_member_status as status,
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
// Setup49 + guards34 + schema43 + ordered32 + states67 + actors176 + preservation30.
pub const HTTP_REQUEST_COUNT: usize = 431;
const OPAQUE_KEY: &str = "future-public-key 雪\0 exact ";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "organization_member_public_keys_authentication_and_scoped_admission",
        guards,
    ),
    (
        "organization_member_public_keys_required_schema_and_empty_positional_batches",
        schema,
    ),
    (
        "organization_member_public_keys_ordered_duplicates_and_scoped_missing_joins",
        ordered,
    ),
    (
        "organization_member_public_keys_unfiltered_states_roles_and_nullable_opaque_keys",
        states,
    ),
    (
        "organization_member_public_keys_confirmed_admin_and_revoked_actor_admission",
        actors,
    ),
    (
        "organization_member_public_keys_preserved_accounts_sessions_and_decryption",
        preservation,
    ),
];
pub(crate) fn path(org: &str) -> String {
    format!("/api/organizations/{org}/users/public-keys")
}
pub(crate) fn row(member: &Value, key: &Value) -> Value {
    json!({"object":"organizationUserPublicKeyResponseModel","id":member["id"],"userId":member["userId"],"key":key})
}
pub(crate) fn projection(value: &Value, expected: &[Value]) -> Result<(), Error> {
    require(
        *value == json!({"object":"list","data":expected,"continuationToken":null}),
        "Bulk public-key ordered exact projection differed",
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
                "Bulk public-key status expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Bulk public-key HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Bulk public-key private response was not JSON"))
    }
    fn rejected(self, status: u16) -> Result<(), Error> {
        let reply = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
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
                "Rejected public-key lookup exposed authority",
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
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
        media: Option<&str>,
    ) -> Result<Reply, Error> {
        self.owner.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.owner.server));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.body(body.to_vec());
        }
        if let Some(media) = media {
            request = request.header("Content-Type", media);
        }
        let response = request
            .send()
            .map_err(|_| Error("Bulk public-key HTTP request failed"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Bulk public-key private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Bulk public-key private capture exceeded bound",
        )?;
        Ok(Reply { status, bytes })
    }
    fn batch(&mut self, org: &str, token: &str, body: &Value) -> Result<Value, Error> {
        self.raw(
            Method::POST,
            &path(org),
            Some(token),
            Some(body.to_string().as_bytes()),
            Some("application/json"),
        )?
        .status(200)?
        .json()
    }
    fn get(&mut self, path: &str, token: &str) -> Result<Value, Error> {
        self.owner.json(Method::GET, path, token, None)
    }
    fn refresh(&mut self, proof: &str) -> Result<Value, Error> {
        self.owner.requests += 1;
        self.refreshes += 1;
        self.client
            .post(format!("{}/identity/connect/token", self.owner.server))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", proof),
                ("client_id", "cli"),
            ])
            .send()
            .map_err(|_| Error("Bulk public-key refresh failed"))?
            .json()
            .map_err(|_| Error("Bulk public-key private refresh malformed"))
    }
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    orgs: Vec<Organization>,
    members: Vec<Value>,
    documents: Vec<Value>,
    original: Value,
    side: Value,
    baseline: Value,
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
    fn receipt(&mut self, state: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":state,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.owner.requests,"expectedHttpRequests":HTTP_REQUEST_COUNT,"passwordCredentialAttempts":self.http.owner.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":5,"registrationHttpRequests":10,"nullableKeyRegistrationFixture":true,"emptyAndOpaqueKeyRegistrations":true,"danglingAccountHttpClaimed":false,"cliBulkPublicKeyCallerClaimed":false,"browserTraceClaimed":false,"capturedRouteTrace":false,"configuredPolicies":false,"smtpEnabled":false}),
        )
    }
    fn snapshot(&mut self) -> Result<Value, Error> {
        let mut accounts = Vec::new();
        for i in 0..2 {
            let token = &self.accounts[i].token;
            accounts.push(json!({"personal":self.http.owner.personal(token)?,"revision":self.http.owner.revision(token)?,"profile":self.http.get("/api/accounts/profile",token)?}));
        }
        let mut groups = Vec::new();
        for i in 0..4 {
            let token = &self.accounts[usize::from(i == 2)].token;
            groups.push(json!({"members":self.http.get(&invites::member_path(&self.orgs[i].id),token)?,"organization":self.http.get(&format!("/api/organizations/{}",self.orgs[i].id),token)?,"collections":self.http.get(&organization_collections::path(&self.orgs[i].id),token)?}));
        }
        Ok(json!({"accounts":accounts,"groups":groups}))
    }
    fn readonly(&mut self) -> Result<(), Error> {
        require(
            self.snapshot()? == self.baseline,
            "Bulk public-key read changed accounts, revisions, membership, keys, grants or sessions",
        )
    }
    fn query(
        &mut self,
        group: usize,
        actor: usize,
        ids: &[Value],
        expected: &[Value],
    ) -> Result<(), Error> {
        let value = self.http.batch(
            &self.orgs[group].id,
            &self.accounts[actor].token,
            &json!({"ids":ids}),
        )?;
        projection(&value, expected)
    }
    fn target_rows(&self) -> Vec<Value> {
        self.members
            .iter()
            .zip([
                self.accounts[0].fixture["keys"]["publicKey"].clone(),
                self.accounts[1].fixture["keys"]["publicKey"].clone(),
                Value::Null,
                json!(""),
                json!(OPAQUE_KEY),
                Value::Null,
            ])
            .map(|(member, key)| row(member, &key))
            .collect()
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[0].token.clone();
    let p = path(&s.orgs[0].id);
    for bearer in [
        None,
        Some("invalid-member-public-key-bearer"),
        Some(s.accounts[1].token.as_str()),
    ] {
        s.http
            .raw(Method::POST, &p, bearer, Some(b"{"), None)?
            .rejected(401)?;
    }
    for (p, bearer, expected) in [
        (path("bad.id"), token.as_str(), 401),
        (
            format!("{}?organizationId={}", path("bad.id"), s.orgs[0].id),
            token.as_str(),
            422,
        ),
        (path(&s.orgs[2].id), token.as_str(), 401),
        (path(&s.orgs[1].id), s.accounts[1].token.as_str(), 401),
        (path(&s.orgs[3].id), s.accounts[1].token.as_str(), 401),
    ] {
        s.http
            .raw(Method::POST, &p, Some(bearer), Some(b"{"), None)?
            .rejected(expected)?;
    }
    // Confirmed ordinary users and Managers cannot read membership-key batches.
    for group in [0, 3] {
        s.http
            .raw(
                Method::POST,
                &path(&s.orgs[group].id),
                Some(&s.accounts[1].token),
                Some(b"{}"),
                Some("application/json"),
            )?
            .rejected(401)?;
    }
    s.readonly()
}
fn schema(s: &mut Suite) -> Result<(), Error> {
    let p = path(&s.orgs[0].id);
    let token = s.accounts[0].token.clone();
    for (body, expected) in [
        (b"{}".as_slice(), 422),
        (br#"{"ids":null}"#, 422),
        (br#"{"Ids":[]}"#, 422),
        (br#"{"ids":true}"#, 422),
        (br#"{"ids":"value"}"#, 422),
        (br#"{"ids":{}}"#, 422),
        (br#"{"ids":[null]}"#, 422),
        (br#"{"ids":[1]}"#, 422),
        (br#"{"ids":[[]]}"#, 422),
        (br#"{"ids":[],"ids":[]}"#, 422),
        (b"[]", 422),
        (b"[[],0]", 400),
        (b"{", 400),
        (b"{\"ids\":[],\"ignored\":\"\xff\"}", 400),
        (b"{\"ids\":[]} true", 400),
    ] {
        s.http
            .raw(
                Method::POST,
                &p,
                Some(&token),
                Some(body),
                Some("application/json"),
            )?
            .rejected(expected)?;
    }
    for body in [
        b"{\"ids\":[]}".as_slice(),
        b"[[]]",
        b"{\"ids\":[],\"ignored\":42}",
    ] {
        let value = s
            .http
            .raw(Method::POST, &p, Some(&token), Some(body), None)?
            .status(200)?
            .json()?;
        projection(&value, &[])?;
    }
    // A valid first ID never makes a malformed later element acceptable.
    let body = json!({"ids":[s.original["id"],42]});
    s.http
        .raw(
            Method::POST,
            &p,
            Some(&token),
            Some(body.to_string().as_bytes()),
            Some("application/json"),
        )?
        .rejected(422)?;
    s.readonly()
}
fn ordered(s: &mut Suite) -> Result<(), Error> {
    let missing = Uuid::new_v4().to_string();
    let foreign = confirmation::member_row(
        &mut s.http.owner,
        &s.orgs[2].id,
        &s.accounts[1].token,
        text(&s.accounts[1].fixture["email"])?,
    )?;
    let sibling = confirmation::member_row(
        &mut s.http.owner,
        &s.orgs[1].id,
        &s.accounts[0].token,
        text(&s.accounts[1].fixture["email"])?,
    )?;
    let target = row(&s.original, &s.accounts[1].fixture["keys"]["publicKey"]);
    let own = s.target_rows()[0].clone();
    let ids = vec![
        json!(missing),
        s.original["id"].clone(),
        foreign["id"].clone(),
        s.original["id"].clone(),
        s.accounts[1].user_id.clone().into(),
        json!(""),
        json!("opaque 雪\0\nnot-a-UUID"),
        sibling["id"].clone(),
        s.members[0]["id"].clone(),
    ];
    s.query(0, 0, &ids, &[target.clone(), target.clone(), own])?;
    let upper = text(&s.original["id"])?.to_uppercase();
    s.query(0, 0, &[json!(upper)], &[])?;
    let value = s.http.batch(
        &s.orgs[0].id,
        &s.accounts[0].token,
        &json!({"ids":[s.original["id"]],"ignored":[null,{"key":"ignored"}]}),
    )?;
    projection(&value, std::slice::from_ref(&target))?;
    let ids = vec![s.original["id"].clone(); 1025];
    s.query(0, 0, &ids, &vec![target.clone(); 1025])?;
    s.http
        .raw(
            Method::POST,
            &path(&s.orgs[0].id.to_uppercase()),
            Some(&s.accounts[0].token),
            Some(json!({"ids":[s.original["id"]]}).to_string().as_bytes()),
            Some("application/json"),
        )?
        .rejected(401)?;
    let value = s.http.owner.json(
        Method::POST,
        &format!("{}?organizationId={}", path(&s.orgs[0].id), s.orgs[2].id),
        &s.accounts[0].token,
        Some(&json!({"ids":[s.original["id"]]})),
    )?;
    projection(&value, &[target])?;
    s.readonly()
}
fn states(s: &mut Suite) -> Result<(), Error> {
    let ids = s
        .members
        .iter()
        .map(|r| r["id"].clone())
        .collect::<Vec<_>>();
    let expected = s.target_rows();
    s.query(0, 0, &ids, &expected)?;
    for (index, document) in s.documents.iter().enumerate() {
        let p = format!(
            "/api/users/{}/public-key",
            text(&s.members[index + 2]["userId"])?
        );
        if document["keys"].is_null() {
            s.http
                .raw(Method::GET, &p, Some(&s.accounts[0].token), None, None)?
                .rejected(404)?;
        } else {
            let value = s.http.get(&p, &s.accounts[0].token)?;
            require(
                value["publicKey"] == document["keys"]["publicKey"],
                "Bulk key differed from individual public-key lookup",
            )?;
        }
    }
    // Member state is deliberately broader than the web Accepted-only selection.
    let id = text(&s.original["id"])?.to_owned();
    removal::confirm_fixture_member(
        &mut s.http.owner,
        &s.orgs[0],
        &id,
        &s.accounts[0].token,
        &s.accounts[1].fixture,
    )?;
    for (action, desired) in [(None, 2), (Some("revoke"), -1), (Some("restore"), 2)] {
        if let Some(action) = action {
            status::put_fixture_status(
                &mut s.http.owner,
                &s.orgs[0].id,
                &id,
                action,
                &s.accounts[0].token,
            )?;
        }
        let revision = s.http.owner.revision(&s.accounts[1].token)?;
        s.query(0, 0, &ids, &expected)?;
        require(
            s.http.owner.revision(&s.accounts[1].token)? == revision,
            "Public-key state read changed target revision",
        )?;
        let detail = s.http.get(
            &format!(
                "{}?includeCollections=true&includeGroups=true",
                crate::organization_members::detail_path(&s.orgs[0].id, &id)
            ),
            &s.accounts[0].token,
        )?;
        let mut original = s.original.clone();
        original["status"] = json!(desired);
        require(
            detail == original,
            "Public-key state read changed membership identity, role or grants",
        )?;
    }
    s.baseline = s.snapshot()?;
    s.readonly()
}
fn actors(s: &mut Suite) -> Result<(), Error> {
    // The main membership is now a confirmed Manager, which still cannot read keys.
    s.http
        .raw(
            Method::POST,
            &path(&s.orgs[0].id),
            Some(&s.accounts[1].token),
            Some(b"{"),
            None,
        )?
        .rejected(401)?;
    s.readonly()?;
    let id = text(&s.side["id"])?.to_owned();
    removal::confirm_fixture_member(
        &mut s.http.owner,
        &s.orgs[1],
        &id,
        &s.accounts[0].token,
        &s.accounts[1].fixture,
    )?;
    s.baseline = s.snapshot()?;
    let expected = row(&s.side, &s.accounts[1].fixture["keys"]["publicKey"]);
    s.query(
        1,
        1,
        &[s.side["id"].clone(), s.side["id"].clone()],
        &[expected.clone(), expected.clone()],
    )?;
    s.readonly()?;
    status::put_fixture_status(
        &mut s.http.owner,
        &s.orgs[1].id,
        &id,
        "revoke",
        &s.accounts[0].token,
    )?;
    s.baseline = s.snapshot()?;
    s.http
        .raw(
            Method::POST,
            &path(&s.orgs[1].id),
            Some(&s.accounts[1].token),
            Some(b"{"),
            None,
        )?
        .rejected(401)?;
    s.query(
        1,
        0,
        &[s.side["id"].clone()],
        std::slice::from_ref(&expected),
    )?;
    s.readonly()?;
    status::put_fixture_status(
        &mut s.http.owner,
        &s.orgs[1].id,
        &id,
        "restore",
        &s.accounts[0].token,
    )?;
    s.baseline = s.snapshot()?;
    s.query(1, 1, &[s.side["id"].clone()], &[expected])?;
    s.readonly()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..2 {
        let value = s.http.refresh(&s.accounts[i].refresh)?;
        let token = text(&value["access_token"])?;
        let profile = s.http.get("/api/accounts/profile", token)?;
        require(
            profile["id"] == s.accounts[i].user_id,
            "Public-key read changed refreshed identity",
        )?;
        let cipher = s
            .http
            .get(&format!("/api/ciphers/{}", s.accounts[i].cipher_id), token)?;
        let key = fixture::fixture_user_key(&s.accounts[i].fixture, &s.accounts[i].password)
            .map_err(|_| Error("Public-key personal key unwrap failed"))?;
        require(
            fixture::decrypt(text(&cipher["notes"])?, &key)
                .map_err(|_| Error("Public-key personal note authentication failed"))?
                == organization_owner::NOTE.as_bytes(),
            "Public-key read changed personal plaintext",
        )?;
    }
    s.readonly()
}
pub fn run() -> Result<(), Error> {
    let mut http = Http {
        owner: OwnerHttp::new()?,
        client: http_client()?,
        refreshes: 0,
    };
    let a = organization_owner::seed(&mut http.owner)?;
    let b = organization_owner::seed(&mut http.owner)?;
    let org = create_organization(&mut http.owner, &a)?;
    let sibling = create_organization(&mut http.owner, &a)?;
    let foreign = create_organization(&mut http.owner, &b)?;
    let ordinary = create_organization(&mut http.owner, &a)?;
    for (group, role) in [(&org, 3), (&sibling, 1), (&ordinary, 2)] {
        invites::invite_owner(
            &mut http.owner,
            &group.id,
            &a.token,
            &confirmation::invitation(text(&b.fixture["email"])?, role, Some(&group.collection_id)),
        )?;
    }
    let mut documents = Vec::new();
    for (role, key) in [(0, Value::Null), (1, json!("")), (2, json!(OPAQUE_KEY))] {
        let email = format!("member-public-keys-{}@example.test", Uuid::new_v4());
        let mut document = fixture::registration(&email, &Uuid::new_v4().to_string(), 600000)
            .map_err(|_| Error("Public-key special registration generation failed"))?;
        if key.is_null() {
            document["keys"] = Value::Null;
        } else {
            document["keys"]["publicKey"] = key;
        }
        fixture::register_modern_fixture(&http.owner.server, &document)
            .map_err(|_| Error("Public-key special registration rejected"))?;
        invites::invite_owner(
            &mut http.owner,
            &org.id,
            &a.token,
            &confirmation::invitation(&email, role, None),
        )?;
        documents.push(document);
    }
    let invited = format!("member-public-keys-invited-{}@example.test", Uuid::new_v4());
    invites::invite_owner(
        &mut http.owner,
        &org.id,
        &a.token,
        &confirmation::invitation(&invited, 2, None),
    )?;
    let list = http.get(&invites::member_path(&org.id), &a.token)?;
    let original = invites::member(&list, text(&b.fixture["email"])?)?.clone();
    let mut members = vec![
        invites::member(&list, text(&a.fixture["email"])?)?.clone(),
        original.clone(),
    ];
    for document in &documents {
        members.push(invites::member(&list, text(&document["email"])?)?.clone());
    }
    members.push(invites::member(&list, &invited)?.clone());
    let side = confirmation::member_row(
        &mut http.owner,
        &sibling.id,
        &a.token,
        text(&b.fixture["email"])?,
    )?;
    let normal = confirmation::member_row(
        &mut http.owner,
        &ordinary.id,
        &a.token,
        text(&b.fixture["email"])?,
    )?;
    removal::confirm_fixture_member(
        &mut http.owner,
        &ordinary,
        text(&normal["id"])?,
        &a.token,
        &b.fixture,
    )?;
    let mut s = Suite {
        http,
        accounts: vec![a, b],
        orgs: vec![org, sibling, foreign, ordinary],
        members,
        documents,
        original,
        side,
        baseline: Value::Null,
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_MEMBER_PUBLIC_KEYS_RECEIPT")?,
        finished: false,
    };
    require(
        s.original["status"] == 1
            && s.original["type"] == 4
            && s.side["status"] == 1
            && s.side["type"] == 1
            && s.members[5]["status"] == 0,
        "Public-key fixture roles or states differed",
    )?;
    s.baseline = s.snapshot()?;
    s.receipt("running")?;
    for (name, case) in CASES {
        eprintln!("Public-key case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.owner.requests == HTTP_REQUEST_COUNT
            && s.http.owner.logins == 2
            && s.http.refreshes == 2
            && s.passed.len() == CASE_COUNT,
        "Public-key exact request budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-member-public-keys: {CASE_COUNT} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        s.http.owner.requests
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projection_requires_exact_fields_nulls_case_and_order() {
        let member = json!({"id":"member","userId":"account","privateKey":"must-never-project"});
        let null = row(&member, &Value::Null);
        let empty = row(&member, &json!(""));
        let expected = [null.clone(), empty];
        let good = json!({"object":"list","continuationToken":null,"data":expected});
        assert!(projection(&good, &expected).is_ok());
        for field in ["id", "userId", "key", "object"] {
            let mut bad = good.clone();
            bad["data"][0].as_object_mut().unwrap().remove(field);
            assert!(projection(&bad, &expected).is_err());
        }
        let mut bad = good.clone();
        bad["data"].as_array_mut().unwrap().swap(0, 1);
        assert!(projection(&bad, &expected).is_err());
        let mut bad = good.clone();
        bad["data"][0]["object"] = json!("OrganizationUserPublicKeyResponseModel");
        assert!(projection(&bad, &expected).is_err());
        let mut bad = good;
        bad["data"][0]["privateKey"] = json!("unwanted");
        assert!(projection(&bad, &expected).is_err());
    }
}
