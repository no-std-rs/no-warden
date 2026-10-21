//! Actual official CLI observes manual selected lifecycle mutations.
//! No selected-lifecycle CLI caller or captured request trace is claimed.
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
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

pub const COMMAND_COUNT: usize = 0;
// Set after successful native development; registration HTTP is separate.
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"observerOnly":true,"selectedLifecycleMutationsAreDirectHttp":true,"actualSelectedLifecycleCliCallerClaimed":false,"ownerBulkStateDecryptionObserved":self.owner_observation_completed,"readonlyRecipientBulkStateDecryptionObserved":self.recipient_observation_completed,"ownerFreshCacheDecryptionCompleted":self.owner_fresh_completed,"recipientFreshCacheDecryptionCompleted":self.recipient_fresh_completed,"privateFoldersFavoriteAndArchiveDatesPreserved":self.finished,"currentReaderRevisionsAndOpaqueCipherPayloadAsserted":self.finished,"bothNotesAbsentAfterManualPermanentDeleteAsserted":self.finished,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"browserTraceClaimed":false,"attachmentBearingTested":false,"fullParityClaimed":false,"configuredPolicies":false,"groupsConfigured":false,"smtpEnabled":false,"separateFromBaseline120":true}),
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
            COMMAND_COUNT == 0 || self.commands <= COMMAND_COUNT,
            "Lifecycle CLI command budget exceeded",
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
            .map_err(|_| Error("Lifecycle CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Lifecycle CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Lifecycle CLI command failed")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Lifecycle CLI output was not UTF8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Lifecycle CLI JSON output malformed"))
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
            "Lifecycle CLI login did not return session",
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
        "Lifecycle CLI did not decrypt expected secure note",
    )?;
    match org {
        Some(org) => require(
            value["organizationId"] == org.id
                && value["collectionIds"] == json!([org.collection_id]),
            "Lifecycle CLI lost target org/collection identity",
        ),
        None => require(
            value["organizationId"].is_null(),
            "Lifecycle CLI personal control acquired org ownership",
        ),
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Lifecycle CLI private directory unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Lifecycle CLI private directory permissions failed"))?;
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
        "Lifecycle CLI invitee fixture was not accepted User",
    )?;
    let wrapped = fixture::organization_key_for_account(&recipient.fixture, &org.key)
        .map_err(|_| Error("Lifecycle CLI RSA fixture failed"))?;
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
        .map_err(|_| Error("Lifecycle CLI confirmation request failed"))?;
    require(
        response.status().as_u16() == 200,
        "Lifecycle CLI confirmation rejected",
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
        "Lifecycle decrypted private annotations differed",
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

const FOLDER_NAME: &str = "Selected lifecycle private folder";
fn documents(
    http: &mut Http,
    accounts: [&Account; 2],
    ids: &[String],
) -> Result<Vec<Value>, Error> {
    let mut result = Vec::new();
    for id in ids {
        for a in accounts {
            result.push(http.json(Method::GET, &format!("/api/ciphers/{id}"), &a.token, None)?);
        }
    }
    Ok(result)
}
fn mutate(
    http: &mut Http,
    owner: &Account,
    ids: &[String],
    kind: &str,
    before: &[Value],
    accounts: [&Account; 2],
) -> Result<Vec<Value>, Error> {
    let prior = revision(http, accounts)?;
    http.requests += 1;
    let response = http_client()?
        .request(
            if kind == "permanent" {
                Method::DELETE
            } else {
                Method::PUT
            },
            format!(
                "{}/api/ciphers{}",
                http.server,
                if kind == "trash" {
                    "/delete"
                } else if kind == "restore" {
                    "/restore"
                } else {
                    ""
                }
            ),
        )
        .bearer_auth(&owner.token)
        .header("Accept", "application/json")
        .json(&json!({"ids":ids}))
        .send()
        .map_err(|_| Error("Bulk lifecycle setup mutation failed"))?;
    require(
        response.status().as_u16() == 200,
        "Bulk lifecycle direct mutation status differed",
    )?;
    let media = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let mut bytes = Vec::new();
    response
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("Bulk lifecycle private response capture failed"))?;
    require(
        bytes.len() <= 16 * 1024 * 1024,
        "Bulk lifecycle response bound exceeded",
    )?;
    let after_revision = revision(http, accounts)?;
    require(
        prior.iter().zip(&after_revision).all(|(a, b)| a != b),
        "Bulk lifecycle did not notify both current readers",
    )?;
    if kind == "permanent" {
        require(
            bytes.is_empty() && media.is_none(),
            "Bulk permanent reply not empty/noCT",
        )?;
        for id in ids {
            for a in accounts {
                http.requests += 1;
                let reply = http_client()?
                    .get(format!("{}/api/ciphers/{id}", http.server))
                    .bearer_auth(&a.token)
                    .send()
                    .map_err(|_| Error("Bulk permanent absence request failed"))?;
                require(
                    reply.status().as_u16() == 400,
                    "Bulk permanent source remained readable",
                )?;
            }
        }
        return Ok(Vec::new());
    }
    let after = documents(http, accounts, ids)?;
    for (a, b) in before.iter().zip(&after) {
        let mut expected = a.clone();
        expected["deletedDate"] = b["deletedDate"].clone();
        expected["revisionDate"] = b["revisionDate"].clone();
        require(
            expected == *b
                && a["revisionDate"] != b["revisionDate"]
                && if kind == "trash" {
                    b["deletedDate"].is_string()
                } else {
                    b["deletedDate"].is_null()
                },
            "Bulk lifecycle changed opaque/private/archive/key state",
        )?;
    }
    if kind == "trash" {
        require(
            bytes.is_empty() && media.is_none(),
            "Bulk Trash reply not empty/noCT",
        )?;
    } else {
        require(
            media
                .as_deref()
                .is_some_and(|v| v.starts_with("application/json")),
            "Bulk Restore reply not JSON",
        )?;
        let v: Value =
            serde_json::from_slice(&bytes).map_err(|_| Error("Bulk Restore JSON malformed"))?;
        let rows = v["data"]
            .as_array()
            .ok_or(Error("Bulk Restore rows missing"))?;
        require(
            v.as_object().is_some_and(|o| o.len() == 3)
                && v["object"] == "list"
                && v["continuationToken"].is_null()
                && rows.len() == ids.len(),
            "Bulk Restore list envelope differed",
        )?;
        for (index, id) in ids.iter().enumerate() {
            let found = rows.iter().filter(|v| v["id"] == *id).collect::<Vec<_>>();
            require(
                found.len() == 1
                    && found[0] == &after[index * 2]
                    && found[0].as_object().is_some_and(|o| o.len() == 30),
                "Bulk Restore unordered rows differed from owner GET",
            )?;
        }
    }
    Ok(after)
}
pub fn run() -> Result<(), Error> {
    let owner_cache = private_dir("no-warden-bulk-lifecycle-owner-")?;
    let recipient_cache = private_dir("no-warden-bulk-lifecycle-recipient-")?;
    let owner_fresh = private_dir("no-warden-bulk-lifecycle-owner-fresh-")?;
    let recipient_fresh = private_dir("no-warden-bulk-lifecycle-recipient-fresh-")?;
    let tls = private_dir("no-warden-bulk-lifecycle-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let initial = [
        totp(&personal(&mut http, &owner)?)?,
        totp(&personal(&mut http, &recipient)?)?,
    ];
    let org = create_organization(&mut http, &owner)?;
    confirm(&mut http, &owner, &recipient, &org)?;
    let recipient_control = personal(&mut http, &recipient)?;
    require(
        initial == [true; 2],
        "Bulk personal fixture projection differed",
    )?;
    let accounts = [&owner, &recipient];
    let keys = [
        http.json(Method::GET, "/api/accounts/keys", &owner.token, None)?,
        http.json(Method::GET, "/api/accounts/keys", &recipient.token, None)?,
    ];
    let mut folders = Vec::new();
    for a in accounts {
        let name =
            fixture::encrypted_fixture_value(&a.fixture, &a.password, FOLDER_NAME.as_bytes())
                .map_err(|_| Error("Bulk private folder encryption failed"))?;
        let v = http.json(
            Method::POST,
            "/api/folders",
            &a.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&v["id"])?.to_owned());
    }
    let personal_sealed = fixture::encrypted_fixture_value(
        &owner.fixture,
        &owner.password,
        organization_owner::NOTE.as_bytes(),
    )
    .map_err(|_| Error("Bulk second personal note encryption failed"))?;
    let second=http.json(Method::POST,"/api/ciphers",&owner.token,Some(&json!({"type":2,"encryptedFor":owner.user_id,"name":personal_sealed,"notes":personal_sealed,"secureNote":{"type":0},"favorite":true,"folderId":folders[0]})))?;
    let ids = vec![owner.cipher_id.clone(), text(&second["id"])?.to_owned()];
    require(
        ids[0] != ids[1],
        "Bulk observer two-note fixture reused an ID",
    )?;
    for id in &ids {
        let key = [53u8; 64];
        let encrypted = fixture::encrypt(organization_owner::NOTE.as_bytes(), &key)
            .map_err(|_| Error("Bulk note encryption failed"))?;
        let wrapped = fixture::encrypt(&key, &org.key)
            .map_err(|_| Error("Bulk wrapped cipher key failed"))?;
        http.json(Method::PUT,&format!("/api/ciphers/{id}/share"),&owner.token,Some(&json!({"collectionIds":[org.collection_id],"cipher":{"type":2,"encryptedFor":owner.user_id,"organizationId":org.id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"key":wrapped,"favorite":true,"folderId":folders[0]}})))?;
        http.json(
            Method::PUT,
            &format!("/api/ciphers/{id}/partial"),
            &recipient.token,
            Some(&json!({"favorite":false,"folderId":folders[1]})),
        )?;
        for a in accounts {
            http.json(
                Method::PUT,
                &format!("/api/ciphers/{id}/archive"),
                &a.token,
                None,
            )?;
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let mut baseline = documents(&mut http, accounts, &ids)?;
    require(
        baseline
            .iter()
            .all(|v| v["key"].is_string() && v["archivedDate"].is_string())
            && baseline[0]["edit"] == true
            && baseline[1]["edit"] == false,
        "Bulk readonly observer/wrapped-key/archive fixture differed",
    )?;
    // TLS and actual officialCLI capture follow the same independently authored
    // fixture boundary as the single lifecycle runner, with manual bulk calls.
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Lifecycle TLS setup failed"))?,
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
        "BW_BULK_LIFECYCLE_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_BULK_LIFECYCLE_RECIPIENT_PASSWORD".into(),
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
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_BULK_LIFECYCLE_CLI_RECEIPT")?,
        finished: false,
        owner_observation_completed: false,
        recipient_observation_completed: false,
        owner_fresh_completed: false,
        recipient_fresh_completed: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Lifecycle CLI version differed",
    )?;
    let os = c.login(
        &owner,
        owner_cache.path(),
        &server,
        "BW_BULK_LIFECYCLE_OWNER_PASSWORD",
    )?;
    let rs = c.login(
        &recipient,
        recipient_cache.path(),
        &server,
        "BW_BULK_LIFECYCLE_RECIPIENT_PASSWORD",
    )?;

    let check = |value: &Value, id: &str, actor: usize, trashed: bool| -> Result<(), Error> {
        check_private(value, id, &org, actor == 0, Some(&folders[actor]))?;
        require(
            value["archivedDate"].is_string()
                && if trashed {
                    value["deletedDate"].is_string()
                } else {
                    value["deletedDate"].is_null()
                },
            "Bulk CLI observed wrong lifecycle/archive state",
        )
    };
    for (actor, cache, session) in [
        (0, owner_cache.path(), &os),
        (1, recipient_cache.path(), &rs),
    ] {
        for id in &ids {
            check(
                &c.json(&["get", "item", id], cache, session)?,
                id,
                actor,
                false,
            )?;
        }
    }
    for kind in ["trash", "restore"] {
        baseline = mutate(&mut http, &owner, &ids, kind, &baseline, accounts)?;
        for (actor, cache, session) in [
            (0, owner_cache.path(), &os),
            (1, recipient_cache.path(), &rs),
        ] {
            c.command(&["sync"], cache, Some(session))?;
            for id in &ids {
                check(
                    &c.json(&["get", "item", id], cache, session)?,
                    id,
                    actor,
                    kind == "trash",
                )?;
            }
            if kind == "trash" {
                let rows = c.json(&["list", "items", "--trash", "--archived"], cache, session)?;
                for id in &ids {
                    let row = rows
                        .as_array()
                        .and_then(|a| a.iter().find(|v| v["id"] == *id))
                        .ok_or(Error("Bulk CLI note missing from archived Trash"))?;
                    check(row, id, actor, true)?;
                }
            }
        }
    }
    c.owner_observation_completed = true;
    c.recipient_observation_completed = true;
    let ofs = c.login(
        &owner,
        owner_fresh.path(),
        &server,
        "BW_BULK_LIFECYCLE_OWNER_PASSWORD",
    )?;
    for id in &ids {
        check(
            &c.json(&["get", "item", id], owner_fresh.path(), &ofs)?,
            id,
            0,
            false,
        )?;
    }
    c.owner_fresh_completed = true;
    let rfs = c.login(
        &recipient,
        recipient_fresh.path(),
        &server,
        "BW_BULK_LIFECYCLE_RECIPIENT_PASSWORD",
    )?;
    for id in &ids {
        check(
            &c.json(&["get", "item", id], recipient_fresh.path(), &rfs)?,
            id,
            1,
            false,
        )?;
    }
    c.recipient_fresh_completed = true;
    for (actor, cache, session) in [
        (0, owner_fresh.path(), &ofs),
        (1, recipient_fresh.path(), &rfs),
    ] {
        let rows = c.json(&["list", "folders"], cache, session)?;
        require(
            rows.as_array().is_some_and(|a| {
                a.iter()
                    .any(|v| v["id"] == folders[actor] && v["name"] == FOLDER_NAME)
                    && a.iter().all(|v| v["id"] != folders[1 - actor])
            }),
            "Bulk CLI private folder decryption/isolation differed",
        )?;
    }
    mutate(&mut http, &owner, &ids, "permanent", &baseline, accounts)?;
    for (cache, session) in [(owner_fresh.path(), &ofs), (recipient_fresh.path(), &rfs)] {
        c.command(&["sync"], cache, Some(session))?;
        for args in [
            vec!["list", "items", "--archived"],
            vec!["list", "items", "--trash", "--archived"],
        ] {
            let rows = c.json(&args, cache, session)?;
            require(
                rows.as_array()
                    .is_some_and(|a| a.iter().all(|v| !ids.iter().any(|id| v["id"] == *id))),
                "Bulk permanent source remained in actualCLI cache",
            )?;
        }
    }
    for (actor, a) in accounts.iter().enumerate() {
        require(
            http.json(Method::GET, "/api/accounts/keys", &a.token, None)? == keys[actor],
            "Bulk CLI observer changed keys",
        )?;
    }
    require(
        personal(&mut http, &recipient)? == recipient_control,
        "Bulk CLI observer changed unrelated personal control",
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
    if c.commands != COMMAND_COUNT || http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Bulk lifecycle measured commands {}, direct requests {}",
            c.commands, http.requests
        );
    }
    require(
        c.commands == COMMAND_COUNT
            && http.requests == DIRECT_HTTP_REQUEST_COUNT
            && c.logins == 4
            && http.logins == 2,
        "Bulk CLI fixture budget differed",
    )?;
    c.finished = true;
    c.receipt("passed")?;
    println!("PASS organization-cipher-bulk-lifecycle CLI observer: {COMMAND_COUNT} commands");
    Ok(())
}
