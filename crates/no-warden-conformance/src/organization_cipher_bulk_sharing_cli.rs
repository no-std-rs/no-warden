//! Actual official CLI observer around explicitly direct native bulk PUTs.
//! Independently authored MIT OR Apache-2.0; no CLI bulk caller or trace claimed.
use crate::{
    capture, fixture, organization_cipher_bulk_sharing as bulk,
    organization_collections::create_organization,
    organization_owner::{self, Account, Http},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
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
pub const COMMAND_COUNT: usize = 37;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 31;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    direct: Option<usize>,
    receipt: Option<fs::File>,
    finished: bool,
    bulk_puts: usize,
    owner_fresh: bool,
    recipient_fresh: bool,
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"directBulkPutMutations":self.bulk_puts,"expectedDirectBulkPutMutations":2,"cliBulkCallerClaimed":false,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"browserTraceClaimed":false,"configuredGroups":false,"configuredPolicies":false,"attachments":false,"otherItemTypes":false,"smtpEnabled":false,"fullParityClaimed":false,"separateFromBaseline120":true,"ownerFreshCacheDecryptionCompleted":self.owner_fresh,"recipientFreshCacheDecryptionCompleted":self.recipient_fresh,"perViewerFolderFavoritePreservationAsserted":self.recipient_fresh}),
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
            "Bulk sharing CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
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
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(90))
            .map_err(|_| Error("Bulk sharing CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Bulk sharing CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Bulk sharing CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|v| v.trim().to_owned())
            .map_err(|_| Error("Bulk sharing CLI returned non-UTF8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Bulk sharing CLI JSON malformed"))
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Bulk CLI private directory failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Bulk CLI directory privacy failed"))?;
    }
    Ok(dir)
}
fn login(
    c: &mut Cli,
    a: &Account,
    cache: &Path,
    server: &str,
    passwordenv: &str,
) -> Result<String, Error> {
    c.command(&["config", "server", server], cache, None)?;
    let session = c.command(
        &[
            "login",
            text(&a.fixture["email"])?,
            "--passwordenv",
            passwordenv,
            "--raw",
        ],
        cache,
        None,
    )?;
    require(session.len() > 20, "Bulk CLI login failed to unlock")?;
    c.command(&["sync"], cache, Some(&session))?;
    Ok(session)
}
struct Expected<'a> {
    id: &'a str,
    org: Option<&'a str>,
    collection: Option<&'a str>,
    variant: &'a str,
    folder: Option<&'a str>,
    favorite: bool,
}
fn check_note(v: &Value, e: Expected<'_>) -> Result<(), Error> {
    let plaintext = if e.org.is_some() {
        format!("{}{}", bulk::NOTE, e.variant)
    } else {
        organization_owner::NOTE.into()
    };
    require(
        v["id"] == e.id
            && v["name"] == plaintext
            && v["notes"] == plaintext
            && v["type"] == 2
            && v["secureNote"]["type"] == 0
            && v["organizationId"].as_str() == e.org
            && v["folderId"].as_str() == e.folder
            && v["favorite"] == e.favorite
            && v["collectionIds"] == e.collection.map_or_else(|| json!([]), |id| json!([id])),
        "Bulk CLI decrypted note/context/private annotations differed",
    )
}
fn note(c: &mut Cli, e: Expected<'_>, cache: &Path, session: &str) -> Result<(), Error> {
    let v = c.json(&["get", "item", e.id], cache, session)?;
    check_note(&v, e)
}
fn folder(http: &mut Http, a: &Account) -> Result<String, Error> {
    let name = fixture::encrypted_fixture_value(
        &a.fixture,
        &a.password,
        b"Independent bulk private folder",
    )
    .map_err(|_| Error("Bulk CLI folder encryption failed"))?;
    let v = http.json(
        Method::POST,
        "/api/folders",
        &a.token,
        Some(&json!({"name":name})),
    )?;
    Ok(text(&v["id"])?.to_owned())
}
fn check_folder(c: &mut Cli, id: &str, cache: &Path, session: &str) -> Result<(), Error> {
    let v = c.json(&["get", "folder", id], cache, session)?;
    require(
        v["id"] == id && v["name"] == "Independent bulk private folder",
        "Bulk CLI private folder did not decrypt",
    )
}
fn create(http: &mut Http, a: &Account) -> Result<String, Error> {
    let name = fixture::encrypted_fixture_value(&a.fixture, &a.password, bulk::NOTE.as_bytes())
        .map_err(|_| Error("Bulk CLI source encryption failed"))?;
    let v=http.json(Method::POST,"/api/ciphers",&a.token,Some(&json!({"type":2,"encryptedFor":a.user_id,"name":name,"notes":name,"secureNote":{"type":0}})))?;
    Ok(text(&v["id"])?.to_owned())
}
fn account_state(http: &mut Http, a: &Account) -> Result<Value, Error> {
    let keys = http.json(Method::GET, "/api/accounts/keys", &a.token, None)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &a.token, None)?;
    require(profile.is_object(), "Bulk CLI profile malformed")?;
    Ok(json!({"keys":keys,"profile":profile}))
}
fn observed(
    http: &mut Http,
    a: &Account,
    id: &str,
    folder: Option<&str>,
    favorite: bool,
    payload: &Value,
) -> Result<(), Error> {
    let v = http.json(Method::GET, &format!("/api/ciphers/{id}"), &a.token, None)?;
    require(
        v["name"] == payload["name"]
            && v["notes"] == payload["notes"]
            && v["folderId"].as_str() == folder
            && v["favorite"] == favorite,
        "Bulk direct private annotation observation differed",
    )
}
pub fn run() -> Result<(), Error> {
    let oc = private_dir("no-warden-bulk-owner-")?;
    let rc = private_dir("no-warden-bulk-recipient-")?;
    let of = private_dir("no-warden-bulk-owner-fresh-")?;
    let rf = private_dir("no-warden-bulk-recipient-fresh-")?;
    let tls = private_dir("no-warden-bulk-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let org = create_organization(&mut http, &owner)?;
    bulk::invite(
        &mut http,
        &owner,
        &recipient,
        &org,
        2,
        json!([{"id":org.collection_id,"readOnly":false,"hidePasswords":false,"manage":false}]),
        true,
    )?;
    let ownfolder = folder(&mut http, &owner)?;
    let recipfolder = folder(&mut http, &recipient)?;
    let first = create(&mut http, &owner)?;
    let second = create(&mut http, &owner)?;
    let before = [
        account_state(&mut http, &owner)?,
        account_state(&mut http, &recipient)?,
    ];
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Bulk CLI TLS setup failed"))?,
        )
    } else {
        None
    };
    let configured = proxy
        .as_ref()
        .map_or(http.server.as_str(), TlsProxy::url)
        .to_owned();
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| if local.exists() { local } else { "bw".into() });
    let mut env = std::env::vars_os().collect::<BTreeMap<_, _>>();
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
        "NODE_DEBUG",
        "NODE_DEBUG_NATIVE",
        "LOG_FILE",
    ] {
        env.remove(&OsString::from(key));
    }
    env.insert("BW_NOINTERACTION".into(), "true".into());
    env.insert(
        "BW_BULK_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    env.insert(
        "BW_BULK_RECIPIENT_PASSWORD".into(),
        recipient.password.clone().into(),
    );
    if let Some(p) = &proxy {
        env.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            p.certificate().as_os_str().to_owned(),
        );
    }
    let mut c = Cli {
        binary,
        environment: env,
        commands: 0,
        logins: 0,
        direct: None,
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_BULK_SHARING_CLI_RECEIPT")?,
        finished: false,
        bulk_puts: 0,
        owner_fresh: false,
        recipient_fresh: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], oc.path(), None)? == "2026.10.0",
        "Bulk CLI version differed",
    )?;
    let os = login(
        &mut c,
        &owner,
        oc.path(),
        &configured,
        "BW_BULK_OWNER_PASSWORD",
    )?;
    note(
        &mut c,
        Expected {
            id: &owner.cipher_id,
            org: None,
            collection: None,
            variant: "",
            folder: None,
            favorite: false,
        },
        oc.path(),
        &os,
    )?;
    let rs = login(
        &mut c,
        &recipient,
        rc.path(),
        &configured,
        "BW_BULK_RECIPIENT_PASSWORD",
    )?;
    note(
        &mut c,
        Expected {
            id: &recipient.cipher_id,
            org: None,
            collection: None,
            variant: "",
            folder: None,
            favorite: false,
        },
        rc.path(),
        &rs,
    )?;
    let mut p = vec![
        bulk::item(&first, &owner, Some(&org), "first")?,
        bulk::item(&second, &owner, Some(&org), "second")?,
    ];
    for v in &mut p {
        v["folderId"] = json!(ownfolder);
    }
    bulk::put(
        &mut http,
        &owner.token,
        &bulk::wrapper(json!(p), json!([org.collection_id])),
        true,
    )?;
    c.bulk_puts += 1;
    observed(&mut http, &owner, &first, Some(&ownfolder), false, &p[0])?;
    observed(&mut http, &recipient, &first, None, false, &p[0])?;
    c.command(&["sync"], oc.path(), Some(&os))?;
    for (id, variant) in [(&first, "first"), (&second, "second")] {
        note(
            &mut c,
            Expected {
                id,
                org: Some(&org.id),
                collection: Some(&org.collection_id),
                variant,
                folder: Some(&ownfolder),
                favorite: false,
            },
            oc.path(),
            &os,
        )?;
    }
    c.command(&["sync"], rc.path(), Some(&rs))?;
    for (id, variant) in [(&first, "first"), (&second, "second")] {
        note(
            &mut c,
            Expected {
                id,
                org: Some(&org.id),
                collection: Some(&org.collection_id),
                variant,
                folder: None,
                favorite: false,
            },
            rc.path(),
            &rs,
        )?;
    }
    let mut update = bulk::item(&first, &recipient, Some(&org), "recipient update")?;
    update["folderId"] = json!(recipfolder);
    update["favorite"] = json!(true);
    bulk::put(
        &mut http,
        &recipient.token,
        &bulk::wrapper(json!([update]), json!([org.collection_id])),
        true,
    )?;
    c.bulk_puts += 1;
    observed(&mut http, &owner, &first, Some(&ownfolder), false, &update)?;
    observed(
        &mut http,
        &recipient,
        &first,
        Some(&recipfolder),
        true,
        &update,
    )?;
    c.command(&["sync"], oc.path(), Some(&os))?;
    note(
        &mut c,
        Expected {
            id: &first,
            org: Some(&org.id),
            collection: Some(&org.collection_id),
            variant: "recipient update",
            folder: Some(&ownfolder),
            favorite: false,
        },
        oc.path(),
        &os,
    )?;
    c.command(&["sync"], rc.path(), Some(&rs))?;
    note(
        &mut c,
        Expected {
            id: &first,
            org: Some(&org.id),
            collection: Some(&org.collection_id),
            variant: "recipient update",
            folder: Some(&recipfolder),
            favorite: true,
        },
        rc.path(),
        &rs,
    )?;
    c.command(&["logout"], oc.path(), Some(&os))?;
    let ofs = login(
        &mut c,
        &owner,
        of.path(),
        &configured,
        "BW_BULK_OWNER_PASSWORD",
    )?;
    for (id, variant) in [(&first, "recipient update"), (&second, "second")] {
        note(
            &mut c,
            Expected {
                id,
                org: Some(&org.id),
                collection: Some(&org.collection_id),
                variant,
                folder: Some(&ownfolder),
                favorite: false,
            },
            of.path(),
            &ofs,
        )?;
    }
    note(
        &mut c,
        Expected {
            id: &owner.cipher_id,
            org: None,
            collection: None,
            variant: "",
            folder: None,
            favorite: false,
        },
        of.path(),
        &ofs,
    )?;
    check_folder(&mut c, &ownfolder, of.path(), &ofs)?;
    c.owner_fresh = true;
    c.command(&["logout"], rc.path(), Some(&rs))?;
    let rfs = login(
        &mut c,
        &recipient,
        rf.path(),
        &configured,
        "BW_BULK_RECIPIENT_PASSWORD",
    )?;
    for (id, variant, folder, favorite) in [
        (&first, "recipient update", Some(recipfolder.as_str()), true),
        (&second, "second", None, false),
    ] {
        note(
            &mut c,
            Expected {
                id,
                org: Some(&org.id),
                collection: Some(&org.collection_id),
                variant,
                folder,
                favorite,
            },
            rf.path(),
            &rfs,
        )?;
    }
    note(
        &mut c,
        Expected {
            id: &recipient.cipher_id,
            org: None,
            collection: None,
            variant: "",
            folder: None,
            favorite: false,
        },
        rf.path(),
        &rfs,
    )?;
    check_folder(&mut c, &recipfolder, rf.path(), &rfs)?;
    c.recipient_fresh = true;
    c.command(&["logout"], of.path(), Some(&ofs))?;
    c.command(&["logout"], rf.path(), Some(&rfs))?;
    require(
        account_state(&mut http, &owner)? == before[0]
            && account_state(&mut http, &recipient)? == before[1],
        "Bulk CLI changed retained keys/account/org context",
    )?;
    for a in [&owner, &recipient] {
        let control = http.json(
            Method::GET,
            &format!("/api/ciphers/{}", a.cipher_id),
            &a.token,
            None,
        )?;
        let key = fixture::fixture_user_key(&a.fixture, &a.password)
            .map_err(|_| Error("Bulk CLI control key failed"))?;
        require(
            fixture::decrypt(text(&control["notes"])?, &key)
                .map_err(|_| Error("Bulk CLI retained control decryption failed"))?
                == organization_owner::NOTE.as_bytes(),
            "Bulk CLI altered personal control",
        )?;
    }
    c.direct = Some(http.requests);
    if http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Bulk CLI direct HTTP actual {}, expected {DIRECT_HTTP_REQUEST_COUNT}",
            http.requests
        );
    }
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 4
            && c.bulk_puts == 2
            && http.logins == 2
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Bulk CLI command/direct HTTP budget differed",
    )?;
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-cipher-bulk-sharing CLI:{COMMAND_COUNT} commands/{DIRECT_HTTP_REQUEST_COUNT} direct HTTP"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bulk_observer_rejects_wrong_context_annotations_and_plaintext() {
        let mut v = json!({"id":"id","name":format!("{}first",bulk::NOTE),"notes":format!("{}first",bulk::NOTE),"type":2,"secureNote":{"type":0},"organizationId":"org","folderId":"folder","favorite":true,"collectionIds":["collection"]});
        let check = |v: &Value| {
            check_note(
                v,
                Expected {
                    id: "id",
                    org: Some("org"),
                    collection: Some("collection"),
                    variant: "first",
                    folder: Some("folder"),
                    favorite: true,
                },
            )
        };
        assert!(check(&v).is_ok());
        for f in ["name", "notes", "organizationId", "folderId", "favorite"] {
            let old = v[f].clone();
            v[f] = json!("wrong");
            assert!(check(&v).is_err());
            v[f] = old;
        }
    }
}
