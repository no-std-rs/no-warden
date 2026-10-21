//! Actual official CLI move with owner/recipient fresh-cache decryption.
//! Independent MIT OR Apache-2.0; the safe TLS adapter captures no route trace.
use crate::{
    capture, fixture,
    organization_cipher_sharing::{CipherExpectation, check_cipher},
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

pub const COMMAND_COUNT: usize = 21;
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
    move_completed: bool,
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"actualMoveCommandExecuted":self.move_completed,"ownerFreshCacheDecryptionCompleted":self.owner_fresh_completed,"recipientFreshCacheDecryptionCompleted":self.recipient_fresh_completed,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"browserTraceClaimed":false,"attachmentBearingMoveTested":false,"deprecatedShareAliasTested":false,"bulkShareTested":false,"configuredPolicies":false,"groupsConfigured":false,"smtpEnabled":false,"separateFromBaseline120":true,"personalOrganizationUseTotpBeforeOrganizations":self.personal_totp_before,"personalOrganizationUseTotpAfterOrganizations":self.personal_totp_after}),
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
            "Sharing CLI command budget exceeded",
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
            .map_err(|_| Error("Sharing CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Sharing CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Sharing CLI command failed")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Sharing CLI output was not UTF8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Sharing CLI JSON output malformed"))
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
            "Sharing CLI login did not return session",
        )?;
        self.command(&["sync"], cache, Some(&session))?;
        Ok(session)
    }
    fn note(
        &mut self,
        account: &Account,
        org: Option<&Organization>,
        cache: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(&["get", "item", &account.cipher_id], cache, session)?;
        check_note(&value, &account.cipher_id, org)
    }
}
fn check_note(value: &Value, id: &str, org: Option<&Organization>) -> Result<(), Error> {
    require(
        value["id"] == id
            && value["name"] == organization_owner::NOTE
            && value["notes"] == organization_owner::NOTE
            && value["type"] == 2
            && value["secureNote"]["type"] == 0,
        "Sharing CLI did not decrypt expected secure note",
    )?;
    match org {
        Some(org) => require(
            value["organizationId"] == org.id
                && value["collectionIds"] == json!([org.collection_id]),
            "Sharing CLI lost target org/collection identity",
        ),
        None => require(
            value["organizationId"].is_null(),
            "Sharing CLI personal control acquired org ownership",
        ),
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Sharing CLI private directory unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Sharing CLI private directory permissions failed"))?;
    }
    Ok(dir)
}
fn confirm(
    http: &mut Http,
    owner: &Account,
    recipient: &Account,
    org: &Organization,
) -> Result<(), Error> {
    organization_invites::invite_owner(
        http,
        &org.id,
        &owner.token,
        &json!({"emails":[recipient.fixture["email"]],"type":2,"groups":[],"collections":[{"id":org.collection_id,"readOnly":false,"hidePasswords":false,"manage":false}]}),
    )?;
    let row = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    require(
        row["status"] == 1 && row["type"] == 2,
        "Sharing CLI invitee fixture was not accepted User",
    )?;
    let wrapped = fixture::organization_key_for_account(&recipient.fixture, &org.key)
        .map_err(|_| Error("Sharing CLI RSA fixture failed"))?;
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
        .map_err(|_| Error("Sharing CLI confirmation request failed"))?;
    require(
        response.status().as_u16() == 200,
        "Sharing CLI confirmation rejected",
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
fn live_shared(
    http: &mut Http,
    account: &Account,
    owner: &Account,
    org: &Organization,
) -> Result<(), Error> {
    let value = http.json(
        Method::GET,
        &format!("/api/ciphers/{}", owner.cipher_id),
        &account.token,
        None,
    )?;
    let ids = vec![org.collection_id.clone()];
    check_cipher(
        &value,
        CipherExpectation {
            id: &owner.cipher_id,
            organization: Some(&org.id),
            collections: &ids,
            edit: true,
            view_password: true,
            favorite: false,
            folder: None,
        },
    )?;
    let sync = http.json(Method::GET, "/api/sync", &account.token, None)?;
    let matches = sync["ciphers"]
        .as_array()
        .ok_or(Error("Sharing CLI live sync ciphers absent"))?
        .iter()
        .filter(|v| v["id"] == owner.cipher_id)
        .collect::<Vec<_>>();
    require(
        matches.len() == 1
            && matches[0]["organizationId"] == org.id
            && matches[0]["collectionIds"] == json!(ids),
        "Sharing CLI live sync lost shared item",
    )
}
pub fn run() -> Result<(), Error> {
    let owner_cache = private_dir("no-warden-sharing-owner-cli-")?;
    let fresh = private_dir("no-warden-sharing-fresh-cli-")?;
    let recipient_cache = private_dir("no-warden-sharing-recipient-cli-")?;
    let tls = private_dir("no-warden-sharing-cli-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let before = [
        totp(&personal(&mut http, &owner)?)?,
        totp(&personal(&mut http, &recipient)?)?,
    ];
    let org = create_organization(&mut http, &owner)?;
    confirm(&mut http, &owner, &recipient, &org)?;
    let owner_control = personal(&mut http, &owner)?;
    let recipient_control = personal(&mut http, &recipient)?;
    let after = [totp(&owner_control)?, totp(&recipient_control)?];
    require(
        before == [true; 2] && after == [true; 2],
        "Sharing personal TOTP flags differed before or after organization setup",
    )?;
    let keys = [
        http.json(Method::GET, "/api/accounts/keys", &owner.token, None)?,
        http.json(Method::GET, "/api/accounts/keys", &recipient.token, None)?,
    ];
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Sharing CLI TLS setup failed"))?,
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
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_SHARING_CLI_RECEIPT")?,
        finished: false,
        move_completed: false,
        owner_fresh_completed: false,
        recipient_fresh_completed: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Sharing CLI version differed",
    )?;
    let owner_session = c.login(
        &owner,
        owner_cache.path(),
        &server,
        "BW_SHARING_OWNER_PASSWORD",
    )?;
    c.note(&owner, None, owner_cache.path(), &owner_session)?;
    let encoded = STANDARD.encode(json!([org.collection_id]).to_string());
    let moved = c.json(
        &["move", &owner.cipher_id, &org.id, &encoded],
        owner_cache.path(),
        &owner_session,
    )?;
    check_note(&moved, &owner.cipher_id, Some(&org))?;
    c.move_completed = true;
    live_shared(&mut http, &owner, &owner, &org)?;
    live_shared(&mut http, &recipient, &owner, &org)?;
    c.command(&["sync"], owner_cache.path(), Some(&owner_session))?;
    c.note(&owner, Some(&org), owner_cache.path(), &owner_session)?;
    let fresh_session = c.login(&owner, fresh.path(), &server, "BW_SHARING_OWNER_PASSWORD")?;
    c.note(&owner, Some(&org), fresh.path(), &fresh_session)?;
    c.owner_fresh_completed = true;
    let recipient_session = c.login(
        &recipient,
        recipient_cache.path(),
        &server,
        "BW_SHARING_RECIPIENT_PASSWORD",
    )?;
    let shared = c.json(
        &["get", "item", &owner.cipher_id],
        recipient_cache.path(),
        &recipient_session,
    )?;
    check_note(&shared, &owner.cipher_id, Some(&org))?;
    c.note(&recipient, None, recipient_cache.path(), &recipient_session)?;
    let collections = c.json(
        &["list", "collections", "--organizationid", &org.id],
        recipient_cache.path(),
        &recipient_session,
    )?;
    require(
        collections.as_array().is_some_and(|a| {
            a.iter().any(|v| {
                v["id"] == org.collection_id && v["name"] == organization_owner::COLLECTION_NAME
            })
        }),
        "Sharing CLI recipient did not decrypt assigned collection",
    )?;
    c.recipient_fresh_completed = true;
    require(
        personal(&mut http, &recipient)? == recipient_control,
        "Sharing CLI changed recipient personal control",
    )?;
    let after_keys = [
        http.json(Method::GET, "/api/accounts/keys", &owner.token, None)?,
        http.json(Method::GET, "/api/accounts/keys", &recipient.token, None)?,
    ];
    require(
        after_keys == keys,
        "Sharing CLI changed account key material",
    )?;
    for (cache, session) in [
        (owner_cache.path(), &owner_session),
        (fresh.path(), &fresh_session),
        (recipient_cache.path(), &recipient_session),
    ] {
        c.command(&["logout"], cache, Some(session))?;
    }
    c.direct = Some(http.requests);
    require(
        c.commands == COMMAND_COUNT && c.logins == 3 && http.logins == 2,
        "Sharing CLI command/login budget differed",
    )?;
    if http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Sharing CLI direct request budget: expected {DIRECT_HTTP_REQUEST_COUNT}, actual {}",
            http.requests
        );
    }
    require(
        http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Sharing CLI direct request budget differed",
    )?;
    c.finished = true;
    c.receipt("passed")?;
    println!("PASS organization-cipher-sharing CLI: {COMMAND_COUNT} commands");
    Ok(())
}
