//! Actual official CLI item-collections mutations and fresh-cache decryption.
//! Independent MIT OR Apache-2.0; the safe TLS adapter captures no route trace.
use crate::{
    capture, fixture,
    organization_collections::create_organization,
    organization_confirmations, organization_invites,
    organization_owner::{self, Account, Http, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
    transport::TlsProxy,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

pub const COMMAND_COUNT: usize = 28;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 25;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    direct: Option<usize>,
    personal_totp_before: [bool; 2],
    personal_totp_after: [bool; 2],
    receipt: Option<fs::File>,
    finished: bool,
    owner_edit_completed: bool,
    recipient_edit_completed: bool,
    owner_fresh_completed: bool,
    recipient_fresh_completed: bool,
}
impl Drop for Cli {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Cli {
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"actualOwnerItemCollectionsCommandExecuted":self.owner_edit_completed,"actualRecipientItemCollectionsCommandExecuted":self.recipient_edit_completed,"ownerFreshCacheDecryptionCompleted":self.owner_fresh_completed,"recipientFreshCacheDecryptionCompleted":self.recipient_fresh_completed,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"browserTraceClaimed":false,"attachmentBearingTested":false,"legacyCollectionsAliasClaimed":false,"adminRouteClaimed":false,"bulkShareTested":false,"fullParityClaimed":false,"researchOnlyCapturedRouteTraceSeparate":true,"configuredPolicies":false,"groupsConfigured":false,"smtpEnabled":false,"separateFromBaseline120":true,"personalOrganizationUseTotpBeforeOrganizations":self.personal_totp_before,"personalOrganizationUseTotpAfterOrganizations":self.personal_totp_after}),
        )
    }
    fn command(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
    ) -> Result<String, Error> {
        self.commands += 1;
        require(
            self.commands <= COMMAND_COUNT,
            "Collection reassignment CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
        self.receipt("running")?;
        let mut env = self.environment.clone();
        env.insert(
            "BITWARDENCLI_APPDATA_DIR".into(),
            cache.as_os_str().to_owned(),
        );
        if let Some(session) = session {
            env.insert("BW_SESSION".into(), session.into());
        } else {
            env.remove(&OsString::from("BW_SESSION"));
        }
        let args = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(120))
            .map_err(|_| Error("Collection reassignment CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Collection reassignment CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(
            result.status.success(),
            "Collection reassignment CLI command failed",
        )?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Collection reassignment CLI output was not UTF8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Collection reassignment CLI JSON output malformed"))
    }
    fn login(
        &mut self,
        account: &Account,
        cache: &Path,
        server: &str,
        password_env: &str,
    ) -> Result<String, Error> {
        self.command(&["config", "server", server], cache, None)?;
        let session = self.command(
            &[
                "login",
                text(&account.fixture["email"])?,
                "--passwordenv",
                password_env,
                "--raw",
            ],
            cache,
            None,
        )?;
        require(
            session.len() > 20,
            "Collection reassignment CLI login did not return session",
        )?;
        self.command(&["sync"], cache, Some(&session))?;
        Ok(session)
    }
}
fn check_note(value: &Value, id: &str, org: Option<&Organization>) -> Result<(), Error> {
    require(
        value["id"] == id
            && value["name"] == organization_owner::NOTE
            && value["notes"] == organization_owner::NOTE
            && value["type"] == 2
            && value["secureNote"]["type"] == 0,
        "Collection reassignment CLI did not decrypt expected secure note",
    )?;
    match org {
        Some(org) => require(
            value["organizationId"] == org.id
                && value["collectionIds"] == json!([org.collection_id]),
            "Collection reassignment CLI lost target org/collection identity",
        ),
        None => require(
            value["organizationId"].is_null(),
            "Collection reassignment CLI personal control acquired org ownership",
        ),
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Collection reassignment CLI private directory unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).map_err(|_| {
            Error("Collection reassignment CLI private directory permissions failed")
        })?;
    }
    Ok(dir)
}
fn confirm(
    http: &mut Http,
    owner: &Account,
    recipient: &Account,
    org: &Organization,
    second: &str,
) -> Result<(), Error> {
    organization_invites::invite_owner(
        http,
        &org.id,
        &owner.token,
        &json!({"emails":[recipient.fixture["email"]],"type":2,"groups":[],"collections":[{"id":org.collection_id,"readOnly":false,"hidePasswords":false,"manage":false},{"id":second,"readOnly":false,"hidePasswords":false,"manage":false}]}),
    )?;
    let row = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    require(
        row["status"] == 1 && row["type"] == 2,
        "Collection reassignment CLI invitee fixture was not accepted User",
    )?;
    let wrapped = fixture::organization_key_for_account(&recipient.fixture, &org.key)
        .map_err(|_| Error("Collection reassignment CLI RSA fixture failed"))?;
    http.requests += 1;
    let response = http_client()?
        .post(format!(
            "{}/api/organizations/{}/users/{}/confirm",
            http.server,
            org.id,
            text(&row["id"])?
        ))
        .bearer_auth(&owner.token)
        .json(&json!({"key":wrapped}))
        .send()
        .map_err(|_| Error("Collection reassignment CLI confirmation request failed"))?;
    require(
        response.status().as_u16() == 200,
        "Collection reassignment CLI confirmation rejected",
    )?;
    let after = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    organization_confirmations::member_after(&row, &after, 2)
}
fn personal(http: &mut Http, account: &Account) -> Result<Value, Error> {
    http.json(
        Method::GET,
        &format!("/api/ciphers/{}", account.cipher_id),
        &account.token,
        None,
    )
}
fn totp(value: &Value) -> Result<bool, Error> {
    value["organizationUseTotp"]
        .as_bool()
        .ok_or(Error("Sharing personal TOTP projection missing"))
}
fn collection_note(
    value: &Value,
    id: &str,
    org: &Organization,
    selected: &str,
) -> Result<(), Error> {
    let mut normalized = value.clone();
    normalized["collectionIds"] = json!([org.collection_id]);
    check_note(&normalized, id, Some(org))?;
    require(
        value["collectionIds"] == json!([selected]),
        "Collection reassignment CLI selected identity differed",
    )
}
pub fn run() -> Result<(), Error> {
    let owner_cache = private_dir("no-warden-collection-owner-cli-")?;
    let recipient_cache = private_dir("no-warden-collection-recipient-cli-")?;
    let owner_fresh = private_dir("no-warden-collection-owner-fresh-cli-")?;
    let recipient_fresh = private_dir("no-warden-collection-recipient-fresh-cli-")?;
    let tls = private_dir("no-warden-collection-cli-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let before = [
        totp(&personal(&mut http, &owner)?)?,
        totp(&personal(&mut http, &recipient)?)?,
    ];
    let org = create_organization(&mut http, &owner)?;
    let name = fixture::encrypt(b"Second actual CLI collection", &org.key)
        .map_err(|_| Error("Collection CLI fixture encryption failed"))?;
    let second = http.json(
        Method::POST,
        &format!("/api/organizations/{}/collections", org.id),
        &owner.token,
        Some(&json!({"name":name,"users":[],"groups":[]})),
    )?;
    let second = text(&second["id"])?.to_owned();
    confirm(&mut http, &owner, &recipient, &org, &second)?;
    let owner_control = personal(&mut http, &owner)?;
    let recipient_control = personal(&mut http, &recipient)?;
    let after = [totp(&owner_control)?, totp(&recipient_control)?];
    require(
        before == [true; 2] && after == [true; 2],
        "Collection CLI personal TOTP projection differed",
    )?;
    let keys = [
        http.json(Method::GET, "/api/accounts/keys", &owner.token, None)?,
        http.json(Method::GET, "/api/accounts/keys", &recipient.token, None)?,
    ];
    // Direct fixture setup is explicitly separate from both actual CLI mutations.
    let encrypted = fixture::encrypt(organization_owner::NOTE.as_bytes(), &org.key)
        .map_err(|_| Error("Collection CLI organization encryption failed"))?;
    http.json(Method::PUT,&format!("/api/ciphers/{}/share",owner.cipher_id),&owner.token,Some(&json!({"collectionIds":[org.collection_id],"cipher":{"type":2,"encryptedFor":owner.user_id,"organizationId":org.id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"key":null,"favorite":false,"folderId":null,"lastKnownRevisionDate":owner_control["revisionDate"]}})))?;
    let shared_before = personal(&mut http, &owner)?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Collection CLI TLS setup failed"))?,
        )
    } else {
        None
    };
    let server = proxy
        .as_ref()
        .map_or(http.server.as_str(), TlsProxy::url)
        .to_owned();
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| if local.exists() { local } else { "bw".into() });
    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for key in [
        "BW_SESSION",
        "BW_CLIENTID",
        "BW_CLIENTSECRET",
        "BW_RESPONSE",
        "BW_QUIET",
        "BW_CLEANEXIT",
        "BW_RAW",
        "DEBUG",
        "DEBUG_FILE",
        "PWDEBUG",
        "NODE_DEBUG",
        "NODE_DEBUG_NATIVE",
    ] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert(
        "BW_SHARING_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_SHARING_RECIPIENT_PASSWORD".into(),
        recipient.password.clone().into(),
    );
    if let Some(proxy) = &proxy {
        environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            proxy.certificate().as_os_str().to_owned(),
        );
    }
    let mut c = Cli {
        binary,
        environment,
        commands: 0,
        logins: 0,
        direct: None,
        personal_totp_before: before,
        personal_totp_after: after,
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_COLLECTIONS_CLI_RECEIPT")?,
        finished: false,
        owner_edit_completed: false,
        recipient_edit_completed: false,
        owner_fresh_completed: false,
        recipient_fresh_completed: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Collection CLI version differed",
    )?;
    let os = c.login(
        &owner,
        owner_cache.path(),
        &server,
        "BW_SHARING_OWNER_PASSWORD",
    )?;
    let rs = c.login(
        &recipient,
        recipient_cache.path(),
        &server,
        "BW_SHARING_RECIPIENT_PASSWORD",
    )?;
    let read = |c: &mut Cli, cache: &Path, session: &str, selected: &str| -> Result<(), Error> {
        let value = c.json(&["get", "item", &owner.cipher_id], cache, session)?;
        collection_note(&value, &owner.cipher_id, &org, selected)
    };
    read(&mut c, owner_cache.path(), &os, &org.collection_id)?;
    let encoded = STANDARD.encode(json!([second]).to_string());
    let value = c.json(
        &["edit", "item-collections", &owner.cipher_id, &encoded],
        owner_cache.path(),
        &os,
    )?;
    collection_note(&value, &owner.cipher_id, &org, &second)?;
    c.owner_edit_completed = true;
    c.command(&["sync"], owner_cache.path(), Some(&os))?;
    read(&mut c, owner_cache.path(), &os, &second)?;
    c.command(&["sync"], recipient_cache.path(), Some(&rs))?;
    read(&mut c, recipient_cache.path(), &rs, &second)?;
    let encoded = STANDARD.encode(json!([org.collection_id]).to_string());
    let value = c.json(
        &["edit", "item-collections", &owner.cipher_id, &encoded],
        recipient_cache.path(),
        &rs,
    )?;
    collection_note(&value, &owner.cipher_id, &org, &org.collection_id)?;
    c.recipient_edit_completed = true;
    c.command(&["sync"], recipient_cache.path(), Some(&rs))?;
    read(&mut c, recipient_cache.path(), &rs, &org.collection_id)?;
    let ofs = c.login(
        &owner,
        owner_fresh.path(),
        &server,
        "BW_SHARING_OWNER_PASSWORD",
    )?;
    read(&mut c, owner_fresh.path(), &ofs, &org.collection_id)?;
    c.owner_fresh_completed = true;
    let rfs = c.login(
        &recipient,
        recipient_fresh.path(),
        &server,
        "BW_SHARING_RECIPIENT_PASSWORD",
    )?;
    read(&mut c, recipient_fresh.path(), &rfs, &org.collection_id)?;
    c.recipient_fresh_completed = true;
    let shared_after = personal(&mut http, &owner)?;
    require(
        shared_before == shared_after,
        "Collection CLI roundtrip rewrote opaque bytes, cipher revision or private annotations",
    )?;
    require(
        personal(&mut http, &recipient)? == recipient_control,
        "Collection CLI changed recipient personal control",
    )?;
    let after_keys = [
        http.json(Method::GET, "/api/accounts/keys", &owner.token, None)?,
        http.json(Method::GET, "/api/accounts/keys", &recipient.token, None)?,
    ];
    require(keys == after_keys, "Collection CLI changed account keys")?;
    for (cache, session) in [
        (owner_cache.path(), &os),
        (recipient_cache.path(), &rs),
        (owner_fresh.path(), &ofs),
        (recipient_fresh.path(), &rfs),
    ] {
        c.command(&["logout"], cache, Some(session))?;
    }
    c.direct = Some(http.requests);
    if http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Collection CLI direct request budget expected {DIRECT_HTTP_REQUEST_COUNT}, actual {}",
            http.requests
        );
    }
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 4
            && http.logins == 2
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Collection CLI fixture budget differed",
    )?;
    c.finished = true;
    c.receipt("passed")?;
    println!("PASS organization-cipher-collections CLI: {COMMAND_COUNT} commands");
    Ok(())
}
