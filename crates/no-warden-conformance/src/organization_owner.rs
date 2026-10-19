//! Independently authored MIT/Apache-2.0 owner-only organization contracts.
//! No invitations, sharing, organization cipher writes, policies or admin APIs
//! are implied. Wire facts are pinned to organizations.rs/model projections.
use crate::{
    fixture,
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, server, text, write_receipt,
    },
};
use rand::{RngCore, rngs::OsRng};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{fs, io::Read};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
pub(crate) const COLLECTION_NAME: &str = "Initial owner collection 雪\0authenticated";
pub(crate) const NOTE: &str = "Personal vault survives organization creation Ω\0";
pub(crate) const ORG_NAME: &str = "Owner organization 雪\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    ("organization_owner_authentication_and_json_guards", guards),
    ("organization_owner_create_and_default_projection", create),
    (
        "organization_owner_get_authorization_and_identity",
        get_guards,
    ),
    (
        "organization_owner_initial_collection_and_sync_decryption",
        collection,
    ),
    ("organization_owner_opaque_positional_creation", opaque),
    (
        "organization_owner_preserved_vault_keys_and_sessions",
        preservation,
    ),
];
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, status: u16) -> Result<Self, Error> {
        if self.status != status {
            eprintln!(
                "Organization-owner HTTP status mismatch: expected {status}, actual {}",
                self.status
            );
        }
        require(
            self.status == status,
            "Organization-owner HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| Error("Organization-owner response was not JSON"))
    }
    fn rejected(self, status: u16) -> Result<(), Error> {
        let value = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&value.bytes) {
            require(
                [
                    "access_token",
                    "refresh_token",
                    "key",
                    "privateKey",
                    "publicKey",
                ]
                .iter()
                .all(|k| value.get(k).is_none()),
                "Rejected organization request exposed authority",
            )?;
        }
        Ok(())
    }
}
pub(crate) struct Http {
    pub(crate) server: String,
    client: Client,
    pub(crate) requests: usize,
    pub(crate) logins: usize,
    refreshes: usize,
}
impl Http {
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            server: server(),
            client: http_client()?,
            requests: 0,
            logins: 0,
            refreshes: 0,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, Error> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Organization private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Organization response exceeded private bound",
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
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(body) = body {
            request = request.body(body.to_vec());
            if let Some(media) = media {
                request = request.header("Content-Type", media);
            }
        }
        Self::read(
            request
                .send()
                .map_err(|_| Error("Organization HTTP request failed"))?,
        )
    }
    pub(crate) fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.raw(
            method,
            path,
            Some(bearer),
            body.map(Value::to_string).as_deref().map(str::as_bytes),
            Some("application/json"),
        )?
        .status(200)?
        .json()
    }
    fn token(&mut self, form: &[(&str, &str)]) -> Result<Value, Error> {
        self.requests += 1;
        Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| Error("Organization fixture identity failed"))?,
        )?
        .status(200)?
        .json()
    }
    fn login(&mut self, account: &Value) -> Result<(String, String), Error> {
        self.logins += 1;
        require(
            self.logins <= 2,
            "Organization HTTP password budget exceeded",
        )?;
        let value = self.token(&[
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&account["email"])?),
            ("password", text(&account["masterPasswordHash"])?),
            ("deviceIdentifier", "Organization-Owner-Fixture"),
            ("deviceName", "Organization owner fixture"),
            ("deviceType", "8"),
        ])?;
        Ok((
            text(&value["access_token"])?.into(),
            text(&value["refresh_token"])?.into(),
        ))
    }
    pub(crate) fn revision(&mut self, bearer: &str) -> Result<Value, Error> {
        self.json(Method::GET, "/api/accounts/revision-date", bearer, None)
    }
    pub(crate) fn personal(&mut self, bearer: &str) -> Result<Value, Error> {
        let mut sync = self.json(Method::GET, "/api/sync", bearer, None)?;
        for field in ["organizations", "organizationsNew"] {
            require(
                sync["profile"][field].is_array(),
                "Organization profile membership list missing",
            )?;
            sync["profile"][field] = json!([]);
        }
        require(
            sync["collections"].is_array(),
            "Synced collection list missing",
        )?;
        sync["collections"] = json!([]);
        let keys = self.json(Method::GET, "/api/accounts/keys", bearer, None)?;
        let devices = self.json(Method::GET, "/api/devices", bearer, None)?;
        let domains = self.json(Method::GET, "/api/settings/domains", bearer, None)?;
        Ok(json!({"sync":sync,"keys":keys,"devices":devices,"domains":domains}))
    }
}
pub(crate) struct Account {
    pub(crate) fixture: Value,
    pub(crate) password: String,
    pub(crate) token: String,
    pub(crate) refresh: String,
    pub(crate) user_id: String,
    pub(crate) cipher_id: String,
    user_key: [u8; 64],
}
pub(crate) fn seed(http: &mut Http) -> Result<Account, Error> {
    let email = format!("organization-owner-{}@example.test", Uuid::new_v4());
    let password = Uuid::new_v4().to_string();
    let account = fixture::registration(&email, &password, 600000)
        .map_err(|_| Error("Organization fixture creation failed"))?;
    fixture::register_modern_fixture(&http.server, &account)
        .map_err(|_| Error("Organization modern registration failed"))?;
    let (token, refresh) = http.login(&account)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &token, None)?;
    let user_id = text(&profile["id"])?.into();
    require(
        profile["organizations"] == json!([]) && profile["organizationsNew"] == json!([]),
        "Disposable owner already had membership",
    )?;
    let encrypted = fixture::encrypted_fixture_value(&account, &password, NOTE.as_bytes())
        .map_err(|_| Error("Organization personal note encryption failed"))?;
    let cipher=http.json(Method::POST,"/api/ciphers",&token,Some(&json!({"type":2,"encryptedFor":profile["id"],"name":encrypted,"notes":encrypted,"secureNote":{"type":0}})))?;
    let cipher_id = text(&cipher["id"])?.into();
    let user_key = fixture::fixture_user_key(&account, &password)
        .map_err(|_| Error("Organization fixture key unwrap failed"))?;
    Ok(Account {
        fixture: account,
        password,
        token,
        refresh,
        user_id,
        cipher_id,
        user_key,
    })
}
pub(crate) struct Organization {
    pub(crate) body: Value,
    pub(crate) key: [u8; 64],
    pub(crate) id: String,
    pub(crate) collection_id: String,
}
impl Organization {
    pub(crate) fn encrypted(account: &Account) -> Result<Self, Error> {
        let mut key = [0; 64];
        OsRng
            .try_fill_bytes(&mut key)
            .map_err(|_| Error("Organization key randomness failed"))?;
        let wrapped = fixture::organization_key_for_account(&account.fixture, &key)
            .map_err(|_| Error("Organization RSA key wrapping failed"))?;
        let name = fixture::encrypt(COLLECTION_NAME.as_bytes(), &key)
            .map_err(|_| Error("Organization collection encryption failed"))?;
        Ok(Self {
            body: json!({"billingEmail":text(&account.fixture["email"])?.to_uppercase(),"collectionName":name,"key":wrapped,"name":ORG_NAME,"planType":"future-plan-unparsed"}),
            key,
            id: String::new(),
            collection_id: String::new(),
        })
    }
}
fn list(value: &Value) -> Result<&[Value], Error> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error("Organization list missing"))
}
fn uuid(value: &Value) -> Result<(), Error> {
    require(
        value.as_str().is_some_and(|s| Uuid::parse_str(s).is_ok()),
        "Organization generated identifier was invalid",
    )
}
pub(crate) fn organization_shape(value: &Value, body: &Value, has_keys: bool) -> Result<(), Error> {
    require(
        value.as_object().is_some_and(|o| o.len() == 47),
        "Organization response field count differed",
    )?;
    uuid(&value["id"])?;
    require(
        value["name"] == body["name"]
            && value["businessName"] == body["name"]
            && value["billingEmail"] == text(&body["billingEmail"])?.to_lowercase()
            && value["object"] == "organization"
            && value["maxStorageGb"] == 32767
            && value["planType"] == 6,
        "Organization scalar projection differed",
    )?;
    for field in [
        "seats",
        "maxCollections",
        "businessAddress1",
        "businessAddress2",
        "businessAddress3",
        "businessCountry",
        "businessTaxNumber",
        "maxAutoscaleSeats",
        "maxAutoscaleSmSeats",
        "maxAutoscaleSmServiceAccounts",
        "secretsManagerPlan",
        "smSeats",
        "smServiceAccounts",
    ] {
        require(
            value.get(field).is_some_and(Value::is_null),
            "Organization nullable default differed",
        )?;
    }
    for (field, expected) in [
        ("use2fa", true),
        ("useCustomPermissions", true),
        ("useDirectory", false),
        ("useEvents", false),
        ("useGroups", false),
        ("useTotp", true),
        ("usePolicies", true),
        ("useScim", false),
        ("useSso", false),
        ("useKeyConnector", false),
        ("usePasswordManager", true),
        ("useSecretsManager", false),
        ("selfHost", true),
        ("useApi", true),
        ("useDisableSMAdsForUsers", true),
        ("useInviteLinks", false),
        ("useMyItems", false),
        ("useOrganizationDomains", false),
        ("usePam", false),
        ("usePhishingBlocker", false),
        ("hasPublicAndPrivateKeys", has_keys),
        ("useResetPassword", false),
        ("allowAdminAccessToAllCollectionItems", true),
        ("limitCollectionCreation", true),
        ("limitCollectionDeletion", true),
        ("limitItemDeletion", false),
        ("usersGetPremium", true),
    ] {
        require(
            value[field] == expected,
            "Organization default feature projection differed",
        )?;
    }
    Ok(())
}
fn basic_collection(value: &Value, organization: &Organization) -> Result<(), Error> {
    require(
        value.as_object().is_some_and(|o| o.len() == 7)
            && value["organizationId"] == organization.id
            && value["name"] == organization.body["collectionName"]
            && value["type"] == 0
            && value.get("externalId").is_some_and(Value::is_null)
            && value
                .get("defaultUserCollectionEmail")
                .is_some_and(Value::is_null)
            && value["object"] == "collection",
        "Basic organization collection projection differed",
    )?;
    uuid(&value["id"])
}
pub(crate) fn inspect_collection(
    http: &mut Http,
    account: &Account,
    organization: &mut Organization,
) -> Result<(), Error> {
    let response = http.json(
        Method::GET,
        "/api/collections?writeOnly=false&organizationId=ignored",
        &account.token,
        None,
    )?;
    require(
        response.as_object().is_some_and(|o| o.len() == 3)
            && response["object"] == "list"
            && response["continuationToken"].is_null(),
        "User collection list envelope differed",
    )?;
    let entries = list(&response["data"])?;
    let entry = entries
        .iter()
        .find(|v| v["organizationId"] == organization.id)
        .ok_or(Error("Initial organization collection missing"))?;
    basic_collection(entry, organization)?;
    organization.collection_id = text(&entry["id"])?.into();
    require(
        fixture::decrypt(text(&entry["name"])?, &organization.key)
            .is_ok_and(|p| p == COLLECTION_NAME.as_bytes()),
        "Initial organization collection failed authenticated decryption",
    )?;
    Ok(())
}
fn membership(
    value: &Value,
    account: &Account,
    organization: &Organization,
    has_keys: bool,
) -> Result<(), Error> {
    require(
        value.as_object().is_some_and(|o| o.len() == 59)
            && value["id"] == organization.id
            && value["name"] == organization.body["name"]
            && value["userId"] == account.user_id
            && value["key"] == organization.body["key"]
            && value["status"] == 2
            && value["type"] == 0
            && value["enabled"] == true
            && value["object"] == "profileOrganization"
            && value["seats"] == 20
            && value["limitCollectionCreation"] == false
            && value["hasPublicAndPrivateKeys"] == has_keys,
        "Confirmed owner membership projection differed",
    )?;
    uuid(&value["organizationUserId"])?;
    require(
        value["organizationUserId"] != account.user_id,
        "Server trusted a body owner identifier as membership ID",
    )?;
    require(
        value["permissions"]
            .as_object()
            .is_some_and(|o| o.len() == 12 && o.values().all(|v| v == false)),
        "Default owner custom-role permission flags differed",
    )
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    organizations: Vec<Organization>,
    personal: Vec<Value>,
    revisions: Vec<Value>,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.requests,"passwordCredentialAttempts":self.http.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":self.accounts.len(),"organizationCreates":self.organizations.iter().filter(|o|!o.id.is_empty()).count()}),
        )
    }
    fn unchanged_personal(&mut self) -> Result<(), Error> {
        for i in 0..self.accounts.len() {
            require(
                self.http.personal(&self.accounts[i].token)? == self.personal[i],
                "Organization lifecycle changed personal vault, keys, settings or devices",
            )?;
        }
        Ok(())
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[0].token.clone();
    for bearer in [None, Some("invalid-organization-bearer")] {
        s.http
            .raw(Method::POST, "/api/organizations", bearer, Some(b"{"), None)?
            .rejected(401)?;
        s.http
            .raw(Method::GET, "/api/collections", bearer, None, None)?
            .rejected(401)?;
    }
    let body = s.organizations[0].body.clone();
    let mut invalids = vec![
        (b"{".to_vec(), 400),
        (b"{}".to_vec(), 422),
        (b"[]".to_vec(), 422),
        (
            b"{\"billingEmail\":\"x\",\"ignored\":\"\xff\"}".to_vec(),
            400,
        ),
    ];
    for field in ["billingEmail", "collectionName", "key", "name", "planType"] {
        let mut value = body.clone();
        value
            .as_object_mut()
            .ok_or(Error("Organization fixture malformed"))?
            .remove(field);
        invalids.push((value.to_string().into_bytes(), 422));
    }
    for (field, value) in [
        ("billingEmail", json!(false)),
        ("key", Value::Null),
        ("keys", json!({"encryptedPrivateKey":null,"publicKey":""})),
        ("keys", json!([])),
        ("planType", json!(1.5)),
        ("planType", json!(true)),
    ] {
        let mut invalid = body.clone();
        invalid[field] = value;
        invalids.push((invalid.to_string().into_bytes(), 422));
    }
    let duplicate = format!("{{\"billingEmail\":\"first\",{}", &body.to_string()[1..]);
    invalids.push((duplicate.into_bytes(), 422));
    let mut billing = body.clone();
    billing["billingEmail"] = json!("not-an-email");
    invalids.push((billing.to_string().into_bytes(), 400));
    for (body, status) in invalids {
        s.http
            .raw(
                Method::POST,
                "/api/organizations",
                Some(&token),
                Some(&body),
                Some("application/json"),
            )?
            .rejected(status)?;
    }
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
        s.http
            .raw(method, "/api/organizations", Some(&token), None, None)?
            .rejected(404)?;
    }
    for i in 0..2 {
        require(
            s.http.revision(&s.accounts[i].token)? == s.revisions[i],
            "Rejected organization creation advanced account revision",
        )?;
        require(
            s.http
                .json(Method::GET, "/api/collections", &s.accounts[i].token, None)?["data"]
                == json!([]),
            "Rejected creation left a collection",
        )?;
        require(
            s.http.json(
                Method::GET,
                "/api/accounts/profile",
                &s.accounts[i].token,
                None,
            )?["organizations"]
                == json!([]),
            "Rejected creation left a membership",
        )?;
    }
    s.unchanged_personal()
}
fn create(s: &mut Suite) -> Result<(), Error> {
    let mut body = s.organizations[0].body.clone();
    body["owner"] = json!(s.accounts[1].user_id);
    body["userId"] = json!(s.accounts[1].user_id);
    body["id"] = json!(s.accounts[1].user_id);
    body["status"] = json!(0);
    body["type"] = json!(2);
    body["accessAll"] = json!(false);
    let created = s
        .http
        .raw(
            Method::POST,
            "/api/organizations",
            Some(&s.accounts[0].token),
            Some(body.to_string().as_bytes()),
            None,
        )?
        .status(200)?
        .json()?;
    organization_shape(&created, &body, false)?;
    s.organizations[0].id = text(&created["id"])?.into();
    require(
        s.organizations[0].id != s.accounts[1].user_id,
        "Organization trusted a body ID",
    )?;
    let fetched = s.http.json(
        Method::GET,
        &format!("/api/organizations/{}", s.organizations[0].id),
        &s.accounts[0].token,
        None,
    )?;
    require(
        fetched == created,
        "Created and owner-fetched organization differed",
    )?;
    require(
        s.http.revision(&s.accounts[0].token)? != s.revisions[0]
            && s.http.revision(&s.accounts[1].token)? == s.revisions[1],
        "Organization creation revision or foreign isolation differed",
    )?;
    s.revisions[0] = s.http.revision(&s.accounts[0].token)?;
    s.unchanged_personal()
}
fn get_guards(s: &mut Suite) -> Result<(), Error> {
    let own = s.accounts[0].token.clone();
    let foreign = s.accounts[1].token.clone();
    let id = s.organizations[0].id.clone();
    for (path, bearer, status) in [
        (format!("/api/organizations/{id}"), None, 401),
        (
            format!("/api/organizations/{id}"),
            Some(foreign.as_str()),
            401,
        ),
        (
            format!("/api/organizations/{}", Uuid::new_v4()),
            Some(own.as_str()),
            401,
        ),
        (
            "/api/organizations/malformed".into(),
            Some(own.as_str()),
            401,
        ),
        (
            format!("/api/organizations/malformed?organizationId={id}"),
            Some(own.as_str()),
            422,
        ),
        (
            format!("/api/organizations/{}?organizationId={id}", Uuid::new_v4()),
            Some(own.as_str()),
            401,
        ),
        ("/api/organizations/bad.id".into(), None, 401),
        ("/api/organizations/bad.id".into(), Some(own.as_str()), 401),
        (
            format!("/api/organizations/bad.id?organizationId={id}"),
            Some(own.as_str()),
            422,
        ),
    ] {
        s.http
            .raw(Method::GET, &path, bearer, None, None)?
            .rejected(status)?;
    }
    let fetched = s.http.json(
        Method::GET,
        &format!("/api/organizations/{id}?organizationId=foreign&ignored=true"),
        &own,
        None,
    )?;
    organization_shape(&fetched, &s.organizations[0].body, false)?;
    let (first, tail) = id
        .split_at_checked(1)
        .ok_or(Error("Organization fixture ID was not ASCII"))?;
    let encoded_id = format!("%{:02X}{tail}", first.as_bytes()[0]);
    let encoded = s.http.json(
        Method::GET,
        &format!("/api/organizations/{encoded_id}"),
        &own,
        None,
    )?;
    require(
        encoded == fetched,
        "Percent-decoded organization lookup differed from ordinary lookup",
    )?;
    s.http
        .raw(
            Method::PATCH,
            &format!("/api/organizations/{id}"),
            Some(&own),
            None,
            None,
        )?
        .rejected(404)?;
    require(
        s.http
            .json(Method::GET, "/api/collections", &foreign, None)?["data"]
            == json!([]),
        "Foreign owner saw another owner's collection",
    )?;
    require(
        s.http.revision(&own)? == s.revisions[0] && s.http.revision(&foreign)? == s.revisions[1],
        "Organization reads or guard failures advanced revisions",
    )?;
    s.unchanged_personal()
}
fn collection(s: &mut Suite) -> Result<(), Error> {
    inspect_collection(&mut s.http, &s.accounts[0], &mut s.organizations[0])?;
    let account = &s.accounts[0];
    let organization = &s.organizations[0];
    let profile = s
        .http
        .json(Method::GET, "/api/accounts/profile", &account.token, None)?;
    let sync = s
        .http
        .json(Method::GET, "/api/sync", &account.token, None)?;
    let owner = list(&profile["organizations"])?
        .iter()
        .find(|v| v["id"] == organization.id)
        .ok_or(Error("Created owner membership missing from profile"))?;
    membership(owner, account, organization, false)?;
    require(
        list(&profile["organizationsNew"])?.contains(owner)
            && list(&sync["profile"]["organizations"])?.contains(owner),
        "Confirmed owner membership did not persist across profile and sync",
    )?;
    let detail = list(&sync["collections"])?
        .iter()
        .find(|v| v["id"] == organization.collection_id)
        .ok_or(Error("Initial collection missing from sync"))?;
    let expected = json!({"id":organization.collection_id,"organizationId":organization.id,"name":organization.body["collectionName"],"externalId":null,"type":0,"defaultUserCollectionEmail":null,"object":"collectionDetails","readOnly":false,"hidePasswords":false,"manage":true});
    require(
        detail == &expected,
        "Owner sync collection detail projection differed",
    )?;
    require(
        s.http.revision(&account.token)? == s.revisions[0],
        "Collection or profile reads changed owner revision",
    )?;
    s.unchanged_personal()
}
fn opaque(s: &mut Suite) -> Result<(), Error> {
    let account = &s.accounts[1];
    // Some(empty,empty) must still report both asymmetric slots as present.
    let keys = json!(["", ""]);
    let body = json!([
        text(&account.fixture["email"])?.to_uppercase(),
        "",
        "",
        "",
        keys,
        i64::MIN
    ]);
    let response = s
        .http
        .raw(
            Method::POST,
            "/api/organizations",
            Some(&account.token),
            Some(body.to_string().as_bytes()),
            Some("application/problem+json"),
        )?
        .status(200)?
        .json()?;
    let normal = json!({"billingEmail":account.fixture["email"],"collectionName":"","key":"","name":"","keys":{"encryptedPrivateKey":"","publicKey":""},"planType":i64::MIN});
    organization_shape(&response, &normal, true)?;
    s.organizations[1].body = normal;
    s.organizations[1].id = text(&response["id"])?.into();
    let collections = s
        .http
        .json(Method::GET, "/api/collections", &account.token, None)?;
    let entry = list(&collections["data"])?
        .iter()
        .find(|v| v["organizationId"] == s.organizations[1].id)
        .ok_or(Error("Opaque initial collection missing"))?;
    basic_collection(entry, &s.organizations[1])?;
    let profile = s
        .http
        .json(Method::GET, "/api/accounts/profile", &account.token, None)?;
    let owner = list(&profile["organizations"])?
        .iter()
        .find(|v| v["id"] == s.organizations[1].id)
        .ok_or(Error("Opaque owner membership missing"))?;
    membership(owner, account, &s.organizations[1], true)?;
    require(
        s.http.revision(&account.token)? != s.revisions[1]
            && s.http.revision(&s.accounts[0].token)? == s.revisions[0],
        "Opaque organization creation changed wrong revision",
    )?;
    s.revisions[1] = s.http.revision(&account.token)?;
    s.unchanged_personal()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    let account = &s.accounts[0];
    let before = s
        .http
        .json(Method::GET, "/api/sync", &account.token, None)?;
    let revision = s.http.revision(&account.token)?;
    for (method, path) in [
        (Method::DELETE, "/api/accounts"),
        (Method::POST, "/api/accounts/delete"),
    ] {
        let proof = json!({"masterPasswordHash":account.fixture["masterPasswordHash"]});
        let error = s
            .http
            .raw(
                method,
                path,
                Some(&account.token),
                Some(proof.to_string().as_bytes()),
                Some("application/json"),
            )?
            .status(400)?
            .json()?;
        require(
            error["message"] == "Can't delete last owner",
            "Last-owner account deletion rejection differed",
        )?;
    }
    require(
        s.http
            .json(Method::GET, "/api/sync", &account.token, None)?
            == before
            && s.http.revision(&account.token)? == revision,
        "Rejected last-owner deletion changed vault or membership",
    )?;
    for account in &s.accounts {
        s.http.refreshes += 1;
        let value = s.http.token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &account.refresh),
            ("client_id", "cli"),
        ])?;
        let refreshed = text(&value["access_token"])?;
        require(
            s.http
                .json(Method::GET, "/api/accounts/profile", refreshed, None)?["id"]
                == account.user_id,
            "Organization creation invalidated or rebound refresh authority",
        )?;
        let cipher = s.http.json(
            Method::GET,
            &format!("/api/ciphers/{}", account.cipher_id),
            &account.token,
            None,
        )?;
        require(
            fixture::decrypt(text(&cipher["notes"])?, &account.user_key)
                .is_ok_and(|p| p == NOTE.as_bytes()),
            "Organization creation changed authenticated personal note",
        )?;
    }
    s.unchanged_personal()
}
pub fn run() -> Result<(), Error> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        organizations: Vec::new(),
        personal: Vec::new(),
        revisions: Vec::new(),
        passed: Vec::new(),
        receipt: receipt_file("BW_ORGANIZATION_OWNER_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for _ in 0..2 {
        let account = seed(&mut s.http)?;
        s.organizations.push(Organization::encrypted(&account)?);
        s.personal.push(s.http.personal(&account.token)?);
        s.revisions.push(s.http.revision(&account.token)?);
        s.accounts.push(account);
    }
    for (name, case) in CASES {
        eprintln!("Organization owner case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.logins == 2 && s.http.refreshes == 2 && s.passed.len() == CASE_COUNT,
        "Organization-owner case or identity budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS organization-owner: {} cases, {} HTTP requests, 2 password logins, 2 refreshes",
        CASE_COUNT, s.http.requests
    );
    Ok(())
}
