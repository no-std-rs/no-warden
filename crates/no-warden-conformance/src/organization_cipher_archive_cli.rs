//! Actual official CLI archive/unarchive commands on a shared secure note.
//! Source-attributed bulk route caller; no captured HTTP trace or browser claim.
//! Independently authored MIT OR Apache-2.0.
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

pub const COMMAND_COUNT: usize = 39;
// Development count; fixed after actual native execution; excludes4 registrations.
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 0;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    direct: Option<usize>,
    receipt: Option<fs::File>,
    finished: bool,
    owner_observation_completed: bool,
    recipient_observation_completed: bool,
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"observerOnly":false,"actualArchiveCliCommandExecuted":self.owner_observation_completed&&self.recipient_observation_completed,"actualUnarchiveCliCommandExecuted":self.owner_observation_completed&&self.recipient_observation_completed,"sourceAttributedBulkCaller":true,"ownerArchiveUnarchiveDecryptionCompleted":self.owner_observation_completed,"readonlyRecipientArchiveUnarchiveDecryptionCompleted":self.recipient_observation_completed,"ownerFreshCacheDecryptionCompleted":self.owner_fresh_completed,"recipientFreshCacheArchivedDecryptionCompleted":self.recipient_fresh_completed,"privateFoldersAndFavoriteObserved":self.finished,"selectedActorOnlyRevisionAndCommonCipherRevisionPreserved":self.finished,"readonlyRecipientFixture":true,"premiumRequiredClientGuardExercised":false,"alreadyArchivedClientGuardExercised":false,"deletedClientGuardExercised":false,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"browserTraceClaimed":false,"attachmentBearingTested":false,"fullParityClaimed":false,"configuredPolicies":false,"groupsConfigured":false,"smtpEnabled":false,"separateFromBaseline120":true}),
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
            "Archive CLI command budget exceeded",
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
            .map_err(|_| Error("Archive CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Archive CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Archive CLI command failed")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Archive CLI output was not UTF8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Archive CLI JSON output malformed"))
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
            "Archive CLI login did not return session",
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
        "Archive CLI did not decrypt expected secure note",
    )?;
    match org {
        Some(org) => require(
            value["organizationId"] == org.id
                && value["collectionIds"] == json!([org.collection_id]),
            "Archive CLI lost target org/collection identity",
        ),
        None => require(
            value["organizationId"].is_null(),
            "Archive CLI personal control acquired org ownership",
        ),
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Archive CLI private directory unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Archive CLI private directory permissions failed"))?;
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
        &json!({"emails":[recipient.fixture["email"]],"type":2,"groups":[],"collections":[{"id":org.collection_id,"readOnly":true,"hidePasswords":false,"manage":false}]}),
    )?;
    let row = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    require(
        row["status"] == 1 && row["type"] == 2,
        "Archive CLI invitee fixture was not accepted User",
    )?;
    let wrapped = fixture::organization_key_for_account(&recipient.fixture, &org.key)
        .map_err(|_| Error("Archive CLI RSA fixture failed"))?;
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
        .map_err(|_| Error("Archive CLI confirmation request failed"))?;
    require(
        response.status().as_u16() == 200,
        "Archive CLI confirmation rejected",
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
fn check_private(
    value: &Value,
    id: &str,
    org: &Organization,
    favorite: bool,
    folder: Option<&str>,
) -> Result<(), Error> {
    check_note(value, id, Some(org))?;
    require(
        value["favorite"] == favorite && value["folderId"].as_str() == folder,
        "Archive decrypted private annotations differed",
    )
}
fn revision(http: &mut Http, accounts: [&Account; 2]) -> Result<[Value; 2], Error> {
    Ok([
        http.json(
            Method::GET,
            "/api/accounts/revision-date",
            &accounts[0].token,
            None,
        )?,
        http.json(
            Method::GET,
            "/api/accounts/revision-date",
            &accounts[1].token,
            None,
        )?,
    ])
}
fn archive_only(before: &Value, after: &Value) -> bool {
    let mut wanted = before.clone();
    wanted["archivedDate"] = after["archivedDate"].clone();
    wanted == *after
}
const FOLDER_NAME: &str = "Private archive folder";
pub fn run() -> Result<(), Error> {
    let owner_cache = private_dir("no-warden-archive-owner-cli-")?;
    let recipient_cache = private_dir("no-warden-archive-recipient-cli-")?;
    let owner_fresh = private_dir("no-warden-archive-owner-fresh-")?;
    let recipient_fresh = private_dir("no-warden-archive-recipient-fresh-")?;
    let tls = private_dir("no-warden-archive-cli-tls-")?;
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
        "Archive personal TOTP changed",
    )?;
    let keys = [
        http.json(Method::GET, "/api/accounts/keys", &owner.token, None)?,
        http.json(Method::GET, "/api/accounts/keys", &recipient.token, None)?,
    ];
    let mut folders = Vec::new();
    for a in [&owner, &recipient] {
        let name =
            fixture::encrypted_fixture_value(&a.fixture, &a.password, FOLDER_NAME.as_bytes())
                .map_err(|_| Error("Archive folder encryption failed"))?;
        let v = http.json(
            Method::POST,
            "/api/folders",
            &a.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&v["id"])?.to_owned());
    }
    let encrypted = fixture::encrypt(organization_owner::NOTE.as_bytes(), &org.key)
        .map_err(|_| Error("Archive org encryption failed"))?;
    http.json(Method::PUT,&format!("/api/ciphers/{}/share",owner.cipher_id),&owner.token,Some(&json!({"collectionIds":[org.collection_id],"cipher":{"type":2,"encryptedFor":owner.user_id,"organizationId":org.id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"key":null,"favorite":true,"folderId":folders[0]}})))?;
    let owner_before = personal(&mut http, &owner)?;
    http.json(
        Method::PUT,
        &format!("/api/ciphers/{}/partial", owner.cipher_id),
        &recipient.token,
        Some(&json!({"favorite":false,"folderId":folders[1]})),
    )?;
    let recipient_before = http.json(
        Method::GET,
        &format!("/api/ciphers/{}", owner.cipher_id),
        &recipient.token,
        None,
    )?;
    require(
        owner_before["edit"] == true && recipient_before["edit"] == false,
        "Archive recipient was not readonly",
    )?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Archive TLS setup failed"))?,
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
        "BW_ARCHIVE_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_ARCHIVE_RECIPIENT_PASSWORD".into(),
        recipient.password.clone().into(),
    );
    if let Some(p) = &proxy {
        environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            p.certificate().as_os_str().to_owned(),
        );
    }
    let mut c = Cli {
        binary,
        environment,
        commands: 0,
        logins: 0,
        direct: None,
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_ARCHIVE_CLI_RECEIPT")?,
        finished: false,
        owner_observation_completed: false,
        recipient_observation_completed: false,
        owner_fresh_completed: false,
        recipient_fresh_completed: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Archive CLI version differed",
    )?;
    let os = c.login(
        &owner,
        owner_cache.path(),
        &server,
        "BW_ARCHIVE_OWNER_PASSWORD",
    )?;
    let rs = c.login(
        &recipient,
        recipient_cache.path(),
        &server,
        "BW_ARCHIVE_RECIPIENT_PASSWORD",
    )?;
    let check = |v: &Value, actor: usize, archived: bool| -> Result<(), Error> {
        check_private(v, &owner.cipher_id, &org, actor == 0, Some(&folders[actor]))?;
        require(
            if archived {
                v["archivedDate"].is_string()
            } else {
                v["archivedDate"].is_null()
            },
            "Archive CLI date differed",
        )
    };
    for (actor, cache, session) in [
        (0, owner_cache.path(), &os),
        (1, recipient_cache.path(), &rs),
    ] {
        let v = c.json(&["get", "item", &owner.cipher_id], cache, session)?;
        check(&v, actor, false)?;
    }
    let mut baseline = [owner_before, recipient_before];
    for (actor, cache, session) in [
        (0, owner_cache.path(), &os),
        (1, recipient_cache.path(), &rs),
    ] {
        for archived in [true, false] {
            let before = revision(&mut http, [&owner, &recipient])?;
            c.command(
                &[
                    if archived { "archive" } else { "restore" },
                    "item",
                    &owner.cipher_id,
                ],
                cache,
                Some(session),
            )?;
            let after = revision(&mut http, [&owner, &recipient])?;
            require(
                before[actor] != after[actor] && before[1 - actor] == after[1 - actor],
                "Archive CLI selected mutation changed wrong account revision",
            )?;
            let accounts = [&owner, &recipient];
            for viewer in 0..2 {
                let doc = http.json(
                    Method::GET,
                    &format!("/api/ciphers/{}", owner.cipher_id),
                    &accounts[viewer].token,
                    None,
                )?;
                require(
                    archive_only(&baseline[viewer], &doc),
                    "Archive CLI changed opaque/private/cipher revision state",
                )?;
                if viewer != actor {
                    require(doc == baseline[viewer], "Archive CLI changed peer date")?;
                }
                baseline[viewer] = doc;
            }
            c.command(&["sync"], cache, Some(session))?;
            let v = c.json(&["get", "item", &owner.cipher_id], cache, session)?;
            check(&v, actor, archived)?;
            if archived {
                let list = c.json(&["list", "items", "--archived"], cache, session)?;
                let v = list
                    .as_array()
                    .and_then(|a| a.iter().find(|v| v["id"] == owner.cipher_id))
                    .ok_or(Error("Archive CLI item absent from archived list"))?;
                check(v, actor, true)?;
            }
        }
        if actor == 0 {
            c.owner_observation_completed = true;
        } else {
            c.recipient_observation_completed = true;
        }
    }
    // Leave the readonly recipient archived for independently logged-in fresh decryption.
    let before = revision(&mut http, [&owner, &recipient])?;
    c.command(
        &["archive", "item", &owner.cipher_id],
        recipient_cache.path(),
        Some(&rs),
    )?;
    c.command(&["sync"], recipient_cache.path(), Some(&rs))?;
    let after = revision(&mut http, [&owner, &recipient])?;
    require(
        before[0] == after[0] && before[1] != after[1],
        "Final archive CLI notified peer",
    )?;
    let ofs = c.login(
        &owner,
        owner_fresh.path(),
        &server,
        "BW_ARCHIVE_OWNER_PASSWORD",
    )?;
    let v = c.json(&["get", "item", &owner.cipher_id], owner_fresh.path(), &ofs)?;
    check(&v, 0, false)?;
    c.owner_fresh_completed = true;
    let rfs = c.login(
        &recipient,
        recipient_fresh.path(),
        &server,
        "BW_ARCHIVE_RECIPIENT_PASSWORD",
    )?;
    let v = c.json(
        &["get", "item", &owner.cipher_id],
        recipient_fresh.path(),
        &rfs,
    )?;
    check(&v, 1, true)?;
    c.recipient_fresh_completed = true;
    for (actor, cache, session) in [
        (0, owner_fresh.path(), &ofs),
        (1, recipient_fresh.path(), &rfs),
    ] {
        let v = c.json(&["list", "folders"], cache, session)?;
        let rows = v.as_array().ok_or(Error("Archive CLI folders not array"))?;
        require(
            rows.iter()
                .any(|v| v["id"] == folders[actor] && v["name"] == FOLDER_NAME)
                && rows.iter().all(|v| v["id"] != folders[1 - actor]),
            "Archive CLI private folder decryption differed",
        )?;
    }
    let accounts = [&owner, &recipient];
    for actor in 0..2 {
        let doc = http.json(
            Method::GET,
            &format!("/api/ciphers/{}", owner.cipher_id),
            &accounts[actor].token,
            None,
        )?;
        require(
            archive_only(&baseline[actor], &doc)
                && if actor == 1 {
                    doc["archivedDate"].is_string()
                } else {
                    doc == baseline[actor]
                },
            "Archive fresh cache changed common/private state",
        )?;
        require(
            http.json(
                Method::GET,
                "/api/accounts/keys",
                &accounts[actor].token,
                None,
            )? == keys[actor],
            "Archive CLI changed account keys",
        )?;
    }
    require(
        personal(&mut http, &recipient)? == recipient_control,
        "Archive CLI changed personal control",
    )?;
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
            "Archive direct budget expected {DIRECT_HTTP_REQUEST_COUNT}, actual {}",
            http.requests
        );
    }
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 4
            && http.logins == 2
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Archive fixture budget differed",
    )?;
    c.finished = true;
    c.receipt("passed")?;
    println!("PASS organization-cipher-archive CLI: {COMMAND_COUNT} commands");
    Ok(())
}
