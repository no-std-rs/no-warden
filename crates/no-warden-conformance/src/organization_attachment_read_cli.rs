//! Actual pinned CLI attachment-bearing move setup and fresh-cache attachment READ.
//! Independent MIT OR Apache-2.0. No route trace, browser or shared-write claim.
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
use rand::{RngCore, rngs::OsRng};
use reqwest::{Method, Url};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::{NamedTempFile, TempDir};

// Measured with the pinned native server and unmodified CLI: 32 commands,
// 101 direct requests, excluding four fixture-registration requests.
pub const COMMAND_COUNT: usize = 32;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 101;
const DEVELOPMENT_COMMAND_LIMIT: usize = 64;
const CLI_SHA256: &str = "7cad23262b9ca168f22c12d7cdf64ef168e57d49784377c2b8cd02707759e4d7";
const MAX_FILE: u64 = 4 * 1024 * 1024;
const NOTE_NAME: &str = "Attachment-bearing shared note 雪";
const NOTE_TEXT: &str = "Shared attachment READ private fixture Ω\0retained";
const OWNER_FOLDER: &str = "Owner attachment private folder Ω";
const RECIPIENT_FOLDER: &str = "Recipient attachment private folder 雪";

struct FileFixture {
    label: &'static str,
    name: &'static str,
    path: PathBuf,
    bytes: Vec<u8>,
    attachment: Option<String>,
}
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    private: PathBuf,
    commands: usize,
    successful_commands: usize,
    logins: usize,
    downloads: usize,
    direct: Option<usize>,
    receipt: Option<fs::File>,
    finished: bool,
    premium: bool,
    personal_completed: bool,
    move_completed: bool,
    ciphertext_preserved: bool,
    owner_fresh_completed: bool,
    recipient_fresh_completed: bool,
    read_state_preserved: bool,
    login_setup_observations: Vec<Value>,
    login_setup_protected_state_passed: bool,
    sdk_key_id_migrations_observed: usize,
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
        let mut receipt = json!({
                "schemaVersion":1,"status":status,"commands":self.commands,
                "expectedCommands":COMMAND_COUNT,"successfulCommands":self.successful_commands,
                "cliVersion":"2026.10.0","cliBundleSha256":CLI_SHA256,
                "cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,
                "directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,
                "fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,
                "fixturePlaintextByteCounts":[0,257,2*1024*1024+37],
                "profilePremiumGuardPassed":self.premium,
                "personalAttachmentUploadAndPrivateDownloadSetupCompleted":self.personal_completed,
                "actualAttachmentBearingMoveCommandExecuted":self.move_completed,
                "encryptedAttachmentBytesPreservedAcrossMove":self.ciphertext_preserved,
                "ownerFreshCacheAttachmentDecryptionCompleted":self.owner_fresh_completed,
                "readonlyRecipientFreshCacheAttachmentDecryptionCompleted":self.recipient_fresh_completed,
                "successfulAttachmentDownloadCommands":self.downloads,
                "readPhaseCommonPrivateCipherAndAccountRevisionsKeysFoldersAndControlsUnchanged":self.read_state_preserved,
                "actualCliExecuted":self.successful_commands>0,
                "productionGetAttachmentCallerExecuted":self.downloads>0,
                "setupMutationAndReadInvariantsSeparatelyAttributed":true,
                "fixedPrivateStdinWrapper":true,"cliUnmodifiedAndBundlePinned":true,
                "capturedRouteTrace":false,"clientInternalRequestsCounted":false,
                "actualBrowserExecuted":false,"sharedAttachmentUploadDeleteUpdateTested":false,
                "legacyMissingKeyAttachmentTested":false,"archiveOrTrashBearingSourceTested":false,
                "groupsConfigured":false,"configuredPolicies":false,"smtpEnabled":false,
                "fullParityClaimed":false,"separateFromBaseline120":true
        });
        receipt["loginSetupProtectedStatePassed"] = json!(self.login_setup_protected_state_passed);
        receipt["actualSdkKeyIdMigrationObserved"] = json!(self.sdk_key_id_migrations_observed > 0);
        receipt["sdkKeyIdMigrationObservations"] = json!(self.sdk_key_id_migrations_observed);
        receipt["loginSetupObservations"] = json!(self.login_setup_observations);
        receipt["freshCacheLoginsPrecedeStrictReadBaseline"] =
            json!(self.login_setup_protected_state_passed);
        receipt["sdkKeyIdMigrationAttribution"] =
            json!("pinned-source-and-login-key-id-transition");
        receipt["sdkKeyIdBackfillRouteCaptured"] = json!(false);
        receipt["readPhaseUserKeyIdsUnchanged"] = json!(self.read_state_preserved);
        write_receipt(&mut self.receipt, &receipt)
    }
    fn command(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
        input: Option<&Value>,
    ) -> Result<Vec<u8>, Error> {
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
        let mut argv: Vec<OsString> = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect();
        // capture's ordinary stdin is null. A fixed shell exec supplies an owned
        // private input file, without putting JSON/plaintext into process argv.
        // NamedTempFile is create_new/0600 and unlinks on every return path.
        let mut stdin_file = None;
        let program = if let Some(input) = input {
            let mut file = NamedTempFile::new_in(&self.private)
                .map_err(|_| Error("Attachment CLI private stdin unavailable"))?;
            file.write_all(STANDARD.encode(input.to_string()).as_bytes())
                .map_err(|_| Error("Attachment CLI private stdin write failed"))?;
            env.insert(
                "BW_ATTACHMENT_CLI".into(),
                self.binary.as_os_str().to_owned(),
            );
            env.insert(
                "BW_ATTACHMENT_INPUT".into(),
                file.path().as_os_str().to_owned(),
            );
            let mut shell = vec![
                OsString::from("-c"),
                OsString::from(r#"exec "$BW_ATTACHMENT_CLI" "$@" < "$BW_ATTACHMENT_INPUT""#),
                OsString::from("private-attachment-stdin"),
            ];
            shell.append(&mut argv);
            argv = shell;
            stdin_file = Some(file);
            PathBuf::from("/bin/sh")
        } else {
            self.binary.clone()
        };
        self.commands += 1;
        let limit = if COMMAND_COUNT == 0 {
            DEVELOPMENT_COMMAND_LIMIT
        } else {
            COMMAND_COUNT
        };
        require(
            self.commands <= limit,
            "Attachment CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
        self.receipt("running")?;
        let limits = capture::CaptureLimits {
            temp_directory: Some(self.private.clone()),
            ..capture::CaptureLimits::default()
        };
        let result =
            capture::run_with_limits(&program, &argv, &env, Duration::from_secs(120), &limits)
                .map_err(|_| Error("Attachment CLI private capture failed"))?;
        drop(stdin_file);
        if !result.status.success() {
            eprintln!(
                "Attachment CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Attachment CLI command failed")?;
        self.successful_commands += 1;
        Ok(result.stdout)
    }
    fn string(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
        input: Option<&Value>,
    ) -> Result<String, Error> {
        String::from_utf8(self.command(args, cache, session, input)?)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Attachment CLI text output invalid"))
    }
    fn json(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: &str,
        input: Option<&Value>,
    ) -> Result<Value, Error> {
        serde_json::from_slice(&self.command(args, cache, Some(session), input)?)
            .map_err(|_| Error("Attachment CLI JSON output invalid"))
    }
    fn login(
        &mut self,
        account: &Account,
        cache: &Path,
        server: &str,
        password_env: &str,
    ) -> Result<String, Error> {
        self.command(&["config", "server", server], cache, None, None)?;
        let session = self.string(
            &[
                "login",
                text(&account.fixture["email"])?,
                "--passwordenv",
                password_env,
                "--raw",
            ],
            cache,
            None,
            None,
        )?;
        require(
            session.len() > 20,
            "Attachment CLI login did not return session",
        )?;
        Ok(session)
    }
    fn download(
        &mut self,
        cache: &Path,
        session: &str,
        cipher: &str,
        file: &FileFixture,
        output: &Path,
    ) -> Result<(), Error> {
        require(
            !output.exists(),
            "Attachment CLI output must be a fresh private path",
        )?;
        self.command(
            &[
                "get",
                "attachment",
                file.id()?,
                "--itemid",
                cipher,
                "--output",
                path_text(output)?,
            ],
            cache,
            Some(session),
            None,
        )?;
        let metadata = fs::symlink_metadata(output)
            .map_err(|_| Error("Attachment CLI output file missing"))?;
        require(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == file.bytes.len() as u64,
            "Attachment CLI output file shape differed",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            require(
                metadata.permissions().mode() & 0o777 == 0o600,
                "Attachment CLI plaintext file permissions differed",
            )?;
        }
        let bytes =
            fs::read(output).map_err(|_| Error("Attachment CLI private output read failed"))?;
        fs::remove_file(output)
            .map_err(|_| Error("Attachment CLI private output cleanup failed"))?;
        require(
            bytes == file.bytes,
            "Attachment CLI plaintext byte equality failed",
        )?;
        self.downloads += 1;
        Ok(())
    }
}
impl FileFixture {
    fn id(&self) -> Result<&str, Error> {
        self.attachment
            .as_deref()
            .ok_or(Error("Attachment CLI fixture ID missing"))
    }
}
fn path_text(path: &Path) -> Result<&str, Error> {
    path.to_str()
        .ok_or(Error("Attachment CLI private path encoding invalid"))
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Attachment CLI private directory unavailable"))?;
    permissions(dir.path(), 0o700)?;
    Ok(dir)
}
fn permissions(path: &Path, mode: u32) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|_| Error("Attachment CLI private permissions failed"))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}
fn subdir(root: &Path, name: &str) -> Result<PathBuf, Error> {
    let path = root.join(name);
    fs::create_dir(&path).map_err(|_| Error("Attachment CLI private subdirectory failed"))?;
    permissions(&path, 0o700)?;
    Ok(path)
}
fn pin(binary: &Path) -> Result<(), Error> {
    let mut file =
        fs::File::open(binary).map_err(|_| Error("Attachment CLI bundle unavailable"))?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| Error("Attachment CLI bundle read failed"))?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    require(
        format!("{:x}", hash.finalize()) == CLI_SHA256,
        "Attachment CLI bundle pin differed",
    )
}
fn files(root: &Path) -> Result<Vec<FileFixture>, Error> {
    let mut large = vec![0; 2 * 1024 * 1024 + 37];
    OsRng
        .try_fill_bytes(&mut large)
        .map_err(|_| Error("Attachment CLI byte randomness failed"))?;
    let rows = [
        ("empty", "empty.bin", Vec::new()),
        (
            "arbitrary257",
            "arbitrary257.bin",
            (0..257).map(|i| (i & 255) as u8).collect(),
        ),
        ("large2MiBPlus37", "large2MiBPlus37.bin", large),
    ];
    rows.into_iter()
        .map(|(label, name, bytes)| {
            let path = root.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options
                .open(&path)
                .map_err(|_| Error("Attachment CLI private fixture file unavailable"))?;
            output
                .write_all(&bytes)
                .map_err(|_| Error("Attachment CLI private fixture write failed"))?;
            Ok(FileFixture {
                label,
                name,
                path,
                bytes,
                attachment: None,
            })
        })
        .collect()
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
    let before = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    require(
        before["status"] == 1 && before["type"] == 2,
        "Attachment CLI recipient was not accepted ordinary User",
    )?;
    let key = fixture::organization_key_for_account(&recipient.fixture, &org.key)
        .map_err(|_| Error("Attachment CLI RSA confirmation fixture failed"))?;
    http.requests += 1;
    let response = http_client()?
        .post(format!(
            "{}/api/organizations/{}/users/{}/confirm",
            http.server,
            org.id,
            text(&before["id"])?
        ))
        .bearer_auth(&owner.token)
        .json(&json!({"key":key}))
        .send()
        .map_err(|_| Error("Attachment CLI confirmation request failed"))?;
    require(
        response.status().as_u16() == 200,
        "Attachment CLI confirmation rejected",
    )?;
    let after = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    organization_confirmations::member_after(&before, &after, 2)?;
    require(
        after["collections"].as_array().is_some_and(|rows| {
            rows.iter().any(|v| {
                v["id"] == org.collection_id && v["readOnly"] == true && v["manage"] == false
            })
        }),
        "Attachment CLI readonly collection fixture differed",
    )
}
fn rows(value: &Value) -> Result<&[Value], Error> {
    value["attachments"]
        .as_array()
        .map(Vec::as_slice)
        .ok_or(Error("Attachment CLI metadata array missing"))
}
fn check_note(
    value: &Value,
    id: &str,
    org: Option<&Organization>,
    folder: &str,
    favorite: bool,
    files: &[FileFixture],
) -> Result<(), Error> {
    require(
        value["id"] == id
            && value["type"] == 2
            && value["secureNote"]["type"] == 0
            && value["name"] == NOTE_NAME
            && value["notes"] == NOTE_TEXT
            && value["folderId"] == folder
            && value["favorite"] == favorite,
        "Attachment CLI decrypted note or private annotation differed",
    )?;
    if let Some(org) = org {
        require(
            value["organizationId"] == org.id
                && value["collectionIds"] == json!([org.collection_id]),
            "Attachment CLI shared ownership or collection differed",
        )?;
    } else {
        require(
            value["organizationId"].is_null(),
            "Attachment CLI personal source acquired organization",
        )?;
    }
    if files.is_empty() {
        require(
            value["attachments"].is_null() || value["attachments"] == json!([]),
            "Attachment CLI new note already had attachment",
        )?;
        return Ok(());
    }
    let actual = rows(value)?;
    require(
        actual.len() == files.len(),
        "Attachment CLI attachment count differed",
    )?;
    for file in files {
        let matches: Vec<_> = actual
            .iter()
            .filter(|v| v["id"] == file.attachment.as_deref().unwrap_or(""))
            .collect();
        require(
            matches.len() == 1 && matches[0]["fileName"] == file.name,
            "Attachment CLI attachment ID or plaintext filename differed",
        )?;
    }
    Ok(())
}
fn plain_folder(value: &Value, own: &str, other: &str, name: &str) -> Result<(), Error> {
    let rows = value
        .as_array()
        .ok_or(Error("Attachment CLI folders output was not an array"))?;
    require(
        rows.iter().any(|v| v["id"] == own && v["name"] == name)
            && !rows.iter().any(|v| v["id"] == other),
        "Attachment CLI folder decryption or isolation differed",
    )
}
fn read_cipher(http: &mut Http, actor: &Account, id: &str) -> Result<Value, Error> {
    http.json(
        Method::GET,
        &format!("/api/ciphers/{id}"),
        &actor.token,
        None,
    )
}
// Capability bytes rotate. Retain the origin/path/query-key structure and every
// other attachment field; only query values are normalized in private memory.
fn normalize_capabilities(mut value: Value) -> Result<Value, Error> {
    for row in value["attachments"]
        .as_array_mut()
        .ok_or(Error("Attachment CLI snapshot attachment array missing"))?
    {
        let mut url = Url::parse(text(&row["url"])?)
            .map_err(|_| Error("Attachment CLI snapshot capability invalid"))?;
        let keys: Vec<String> = url.query_pairs().map(|(key, _)| key.into_owned()).collect();
        require(!keys.is_empty(), "Attachment CLI capability query missing")?;
        url.set_query(None);
        {
            let mut query = url.query_pairs_mut();
            for key in keys {
                query.append_pair(&key, "private-capability");
            }
        }
        row["url"] = Value::String(url.to_string());
    }
    Ok(value)
}
fn encrypted_bytes(
    http: &mut Http,
    owner: &Account,
    id: &str,
    files: &[FileFixture],
) -> Result<Vec<Vec<u8>>, Error> {
    let base =
        Url::parse(&http.server).map_err(|_| Error("Attachment CLI fixture origin invalid"))?;
    let mut result = Vec::new();
    for file in files {
        let value = http.json(
            Method::GET,
            &format!("/api/ciphers/{id}/attachment/{}", file.id()?),
            &owner.token,
            None,
        )?;
        require(
            value["id"] == file.id()?
                && value["object"] == "attachment"
                && value.as_object().is_some_and(|object| {
                    object.len() == 7
                        && ["fileName", "id", "key", "object", "size", "sizeName", "url"]
                            .iter()
                            .all(|key| object.get(*key).is_some_and(Value::is_string))
                }),
            "Attachment CLI metadata identity differed",
        )?;
        let url = Url::parse(text(&value["url"])?)
            .map_err(|_| Error("Attachment CLI private capability URL invalid"))?;
        require(
            url.origin() == base.origin()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.path() == format!("/attachments/{id}/{}", file.id()?)
                && url
                    .query_pairs()
                    .any(|(key, value)| key == "token" && !value.is_empty()),
            "Attachment CLI capability escaped fixture origin",
        )?;
        http.requests += 1;
        let response = http_client()?
            .get(url)
            .send()
            .map_err(|_| Error("Attachment CLI encrypted download failed"))?;
        require(
            response.status().as_u16() == 200,
            "Attachment CLI encrypted download rejected",
        )?;
        let mut bytes = Vec::new();
        response
            .take(MAX_FILE + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Attachment CLI private encrypted read failed"))?;
        require(
            !bytes.is_empty() && bytes.len() as u64 <= MAX_FILE && bytes != file.bytes,
            "Attachment CLI encrypted byte shape differed",
        )?;
        result.push(bytes);
    }
    Ok(result)
}
fn snapshot(
    http: &mut Http,
    owner: &Account,
    recipient: &Account,
    id: &str,
    folders: [&str; 2],
) -> Result<Value, Error> {
    let mut views = Vec::new();
    for (actor, folder) in [owner, recipient].into_iter().zip(folders) {
        views.push(json!({"cipher":normalize_capabilities(read_cipher(http,actor,id)?)?,"revision":http.json(Method::GET,"/api/accounts/revision-date",&actor.token,None)?,"keys":http.json(Method::GET,"/api/accounts/keys",&actor.token,None)?,"folder":http.json(Method::GET,&format!("/api/folders/{folder}"),&actor.token,None)?,"control":read_cipher(http,actor,&actor.cipher_id)?}));
    }
    Ok(json!(views))
}

fn user_key_id(http: &mut Http, actor: &Account) -> Result<Value, Error> {
    let sync = http.json(Method::GET, "/api/sync", &actor.token, None)?;
    sync.get("userDecryption")
        .and_then(|value| value.get("userKeyId"))
        .cloned()
        .ok_or(Error("Attachment CLI sync user key ID field missing"))
}

fn sdk_key_id(value: &Value) -> bool {
    value.as_str().is_some_and(|value| {
        value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

// The pinned client migration delegates to SDK user_key_id_backfill, which posts only the
// 32-lowercase-hex identifier of its existing UserKey. This exception is confined to actual
// fresh-cache authentication setup; the following attachment READ phase permits no changes.
fn login_setup_observation(
    before: &Value,
    after: &Value,
    actor_index: usize,
    key_id_before: &Value,
    key_id_after: &Value,
) -> Value {
    let fields = ["cipher", "revision", "keys", "folder", "control"];
    let shape_valid = actor_index < 2
        && [before, after].into_iter().all(|snapshot| {
            snapshot.as_array().is_some_and(|views| {
                views.len() == 2
                    && views.iter().all(|view| {
                        view.as_object().is_some_and(|object| {
                            object.len() == fields.len()
                                && fields.iter().all(|field| object.contains_key(*field))
                        })
                    })
            })
        });
    let preserved = |field: &str| {
        shape_valid && (0..2).all(|index| before[index][field] == after[index][field])
    };
    let cipher_preserved = preserved("cipher");
    let keys_preserved = preserved("keys");
    let folders_preserved = preserved("folder");
    let controls_preserved = preserved("control");
    let protected_state_preserved =
        cipher_preserved && keys_preserved && folders_preserved && controls_preserved;
    let peer_revision_preserved =
        shape_valid && before[1 - actor_index]["revision"] == after[1 - actor_index]["revision"];
    let actor_revision_changed =
        shape_valid && before[actor_index]["revision"] != after[actor_index]["revision"];
    let migration = key_id_before.is_null() && sdk_key_id(key_id_after);
    let unchanged =
        key_id_before == key_id_after && (key_id_before.is_null() || sdk_key_id(key_id_before));
    let transition = if migration {
        "null-to-sdk-id"
    } else if unchanged && key_id_before.is_null() {
        "unchanged-null"
    } else if unchanged {
        "unchanged-existing"
    } else {
        "rejected-transition"
    };
    json!({
        "snapshotShapeValid":shape_valid,
        "commonAndPrivateCipherPreserved":cipher_preserved,
        "keysPreserved":keys_preserved,
        "foldersPreserved":folders_preserved,
        "personalControlsPreserved":controls_preserved,
        "otherAccountRevisionPreserved":peer_revision_preserved,
        "actorAccountRevisionChanged":actor_revision_changed,
        "keyIdTransition":transition,
        "sdkKeyIdMigrationObserved":migration,
        "passed":shape_valid && protected_state_preserved && peer_revision_preserved
            && (migration || unchanged) && (!actor_revision_changed || migration)
    })
}

pub fn run() -> Result<(), Error> {
    let work = private_dir("no-warden-attachment-read-cli-")?;
    let creator = subdir(work.path(), "creator")?;
    let owner_fresh = subdir(work.path(), "owner-fresh")?;
    let recipient_fresh = subdir(work.path(), "readonly-recipient-fresh")?;
    let inputs = subdir(work.path(), "inputs")?;
    let output = subdir(work.path(), "outputs")?;
    let tls = subdir(work.path(), "tls")?;
    let capture_dir = subdir(work.path(), "capture")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let owner_control = read_cipher(&mut http, &owner, &owner.cipher_id)?;
    let recipient_control = read_cipher(&mut http, &recipient, &recipient.cipher_id)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &owner.token, None)?;
    require(
        profile["premium"] == true,
        "Attachment CLI personal upload requires actual profile premium",
    )?;
    let org = create_organization(&mut http, &owner)?;
    confirm(&mut http, &owner, &recipient, &org)?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, &tls)
                .map_err(|_| Error("Attachment CLI TLS setup failed"))?,
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
    let binary =
        fs::canonicalize(binary).map_err(|_| Error("Attachment CLI executable unavailable"))?;
    pin(&binary)?;
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
        "BW_ATTACHMENT_CLI",
        "BW_ATTACHMENT_INPUT",
    ] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert(
        "BW_ATTACHMENT_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_ATTACHMENT_RECIPIENT_PASSWORD".into(),
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
        private: capture_dir,
        commands: 0,
        successful_commands: 0,
        logins: 0,
        downloads: 0,
        direct: None,
        receipt: receipt_file("BW_ORGANIZATION_ATTACHMENT_READ_CLI_RECEIPT")?,
        finished: false,
        premium: true,
        personal_completed: false,
        move_completed: false,
        ciphertext_preserved: false,
        owner_fresh_completed: false,
        recipient_fresh_completed: false,
        read_state_preserved: false,
        login_setup_observations: Vec::new(),
        login_setup_protected_state_passed: false,
        sdk_key_id_migrations_observed: 0,
    };
    c.receipt("running")?;
    require(
        c.string(&["--version"], &creator, None, None)? == "2026.10.0",
        "Attachment CLI version differed",
    )?;
    let creator_session = c.login(&owner, &creator, &server, "BW_ATTACHMENT_OWNER_PASSWORD")?;
    let folder = c.json(
        &["create", "folder"],
        &creator,
        &creator_session,
        Some(&json!({"name":OWNER_FOLDER})),
    )?;
    let owner_folder = text(&folder["id"])?.to_owned();
    require(
        folder["name"] == OWNER_FOLDER,
        "Attachment CLI owner folder did not decrypt",
    )?;
    let created=c.json(&["create","item"],&creator,&creator_session,Some(&json!({"type":2,"name":NOTE_NAME,"notes":NOTE_TEXT,"secureNote":{"type":0},"favorite":true,"folderId":owner_folder})))?;
    let id = text(&created["id"])?.to_owned();
    check_note(&created, &id, None, &owner_folder, true, &[])?;
    let mut files = files(&inputs)?;
    for index in 0..files.len() {
        let value = c.json(
            &[
                "create",
                "attachment",
                "--file",
                path_text(&files[index].path)?,
                "--itemid",
                &id,
            ],
            &creator,
            &creator_session,
            None,
        )?;
        let matches: Vec<_> = rows(&value)?
            .iter()
            .filter(|v| v["fileName"] == files[index].name)
            .collect();
        require(
            matches.len() == 1,
            "Attachment CLI upload did not return one expected filename",
        )?;
        let attachment = text(&matches[0]["id"])?.to_owned();
        require(
            !attachment.is_empty()
                && !files
                    .iter()
                    .any(|f| f.attachment.as_deref() == Some(attachment.as_str())),
            "Attachment CLI upload ID duplicated",
        )?;
        files[index].attachment = Some(attachment);
        check_note(&value, &id, None, &owner_folder, true, &files[..=index])?;
    }
    let personal = read_cipher(&mut http, &owner, &id)?;
    for file in &files {
        let matching: Vec<_> = rows(&personal)?
            .iter()
            .filter(|v| v["id"] == file.id().unwrap_or(""))
            .collect();
        require(
            matching.len() == 1 && matching[0]["key"].as_str().is_some_and(|v| !v.is_empty()),
            "Attachment CLI upload did not retain a wrapped file key",
        )?;
        c.download(
            &creator,
            &creator_session,
            &id,
            file,
            &output.join(format!("personal-{}", file.label)),
        )?;
    }
    c.personal_completed = true;
    let before_move = encrypted_bytes(&mut http, &owner, &id, &files)?;
    let moved = c.json(
        &["move", &id, &org.id],
        &creator,
        &creator_session,
        Some(&json!([org.collection_id])),
    )?;
    check_note(&moved, &id, Some(&org), &owner_folder, true, &files)?;
    c.move_completed = true;
    let after_move = encrypted_bytes(&mut http, &owner, &id, &files)?;
    require(
        before_move == after_move,
        "Attachment CLI move changed encrypted file bytes",
    )?;
    c.ciphertext_preserved = true;
    let value = c.json(&["get", "item", &id], &creator, &creator_session, None)?;
    check_note(&value, &id, Some(&org), &owner_folder, true, &files)?;
    c.command(&["sync"], &creator, Some(&creator_session), None)?;
    let value = c.json(&["get", "item", &id], &creator, &creator_session, None)?;
    check_note(&value, &id, Some(&org), &owner_folder, true, &files)?;
    let encrypted = fixture::encrypted_fixture_value(
        &recipient.fixture,
        &recipient.password,
        RECIPIENT_FOLDER.as_bytes(),
    )
    .map_err(|_| Error("Attachment CLI recipient folder encryption failed"))?;
    let folder = http.json(
        Method::POST,
        "/api/folders",
        &recipient.token,
        Some(&json!({"name":encrypted})),
    )?;
    let recipient_folder = text(&folder["id"])?.to_owned();
    require(
        owner_folder != recipient_folder,
        "Attachment CLI private folders must differ",
    )?;
    http.requests += 1;
    let response = http_client()?
        .put(format!("{}/api/ciphers/{id}/partial", http.server))
        .bearer_auth(&recipient.token)
        .json(&json!({"favorite":false,"folderId":recipient_folder}))
        .send()
        .map_err(|_| Error("Attachment CLI private annotation setup failed"))?;
    require(
        response.status().as_u16() == 200,
        "Attachment CLI private annotation setup rejected",
    )?;
    let recipient_live = read_cipher(&mut http, &recipient, &id)?;
    require(
        recipient_live["edit"] == false
            && recipient_live["permissions"]["delete"] == false
            && recipient_live["permissions"]["restore"] == false,
        "Attachment CLI ordinary readonly source flags differed",
    )?;
    let readers = [
        (
            &owner,
            &owner_fresh,
            &owner_folder,
            &recipient_folder,
            OWNER_FOLDER,
            true,
            "BW_ATTACHMENT_OWNER_PASSWORD",
            "owner-fresh",
        ),
        (
            &recipient,
            &recipient_fresh,
            &recipient_folder,
            &owner_folder,
            RECIPIENT_FOLDER,
            false,
            "BW_ATTACHMENT_RECIPIENT_PASSWORD",
            "recipient-fresh",
        ),
    ];
    let mut fresh_sessions = Vec::new();
    for (actor_index, (actor, cache, _, _, _, _, password_env, label)) in readers.iter().enumerate()
    {
        let before_login = snapshot(
            &mut http,
            &owner,
            &recipient,
            &id,
            [&owner_folder, &recipient_folder],
        )?;
        let key_before = user_key_id(&mut http, actor)?;
        let session = c.login(actor, cache, &server, password_env)?;
        let key_after = user_key_id(&mut http, actor)?;
        let after_login = snapshot(
            &mut http,
            &owner,
            &recipient,
            &id,
            [&owner_folder, &recipient_folder],
        )?;
        let mut observation = login_setup_observation(
            &before_login,
            &after_login,
            actor_index,
            &key_before,
            &key_after,
        );
        observation["actor"] = json!(label);
        // This object contains only static labels, booleans and transition categories.
        // Neither snapshot values nor the key identifier enter diagnostics or receipts.
        eprintln!("Attachment CLI login setup observation: {observation}");
        let passed = observation["passed"] == true;
        if passed && observation["sdkKeyIdMigrationObserved"] == true {
            c.sdk_key_id_migrations_observed += 1;
        }
        c.login_setup_observations.push(observation);
        c.receipt("running")?;
        require(
            passed,
            "Attachment CLI login setup changed protected state or an unqualified revision",
        )?;
        fresh_sessions.push((*cache, session));
    }
    c.login_setup_protected_state_passed = true;
    let before = snapshot(
        &mut http,
        &owner,
        &recipient,
        &id,
        [&owner_folder, &recipient_folder],
    )?;
    let read_key_ids_before = [
        user_key_id(&mut http, &owner)?,
        user_key_id(&mut http, &recipient)?,
    ];
    require(
        before[0]["cipher"]["archivedDate"].is_null()
            && before[1]["cipher"]["archivedDate"].is_null(),
        "Attachment CLI fixture unexpectedly archived",
    )?;
    for ((_, cache, folder, other_folder, name, favorite, _, label), (_, session)) in
        readers.into_iter().zip(&fresh_sessions)
    {
        let value = c.json(&["get", "item", &id], cache, session, None)?;
        check_note(&value, &id, Some(&org), folder, favorite, &files)?;
        for file in &files {
            c.download(
                cache,
                session,
                &id,
                file,
                &output.join(format!("{label}-{}", file.label)),
            )?;
        }
        let folders = c.json(&["list", "folders"], cache, session, None)?;
        plain_folder(&folders, folder, other_folder, name)?;
        if favorite {
            c.owner_fresh_completed = true;
        } else {
            c.recipient_fresh_completed = true;
        }
    }
    require(
        snapshot(
            &mut http,
            &owner,
            &recipient,
            &id,
            [&owner_folder, &recipient_folder],
        )? == before,
        "Attachment CLI READ changed common private source revision account revision keys folders or controls",
    )?;
    require(
        [
            user_key_id(&mut http, &owner)?,
            user_key_id(&mut http, &recipient)?,
        ] == read_key_ids_before,
        "Attachment CLI READ changed a user key identifier",
    )?;
    require(
        read_cipher(&mut http, &owner, &owner.cipher_id)? == owner_control
            && read_cipher(&mut http, &recipient, &recipient.cipher_id)? == recipient_control,
        "Attachment CLI setup changed unrelated personal controls",
    )?;
    c.read_state_preserved = true;
    c.command(&["logout"], &creator, Some(&creator_session), None)?;
    for (cache, session) in fresh_sessions {
        c.command(&["logout"], cache, Some(&session), None)?;
    }
    c.direct = Some(http.requests);
    c.receipt("running")?;
    require(
        c.logins == 3 && http.logins == 2 && c.downloads == 9,
        "Attachment CLI actual login or byte comparison count differed",
    )?;
    if c.commands != COMMAND_COUNT || http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Attachment CLI budgets expected commands {COMMAND_COUNT} direct {DIRECT_HTTP_REQUEST_COUNT}; actual commands {} direct {}",
            c.commands, http.requests
        );
    }
    pin(&c.binary)?;
    require(
        c.commands == COMMAND_COUNT && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Attachment CLI literal measured budgets differed",
    )?;
    c.finished = true;
    c.receipt("passed")?;
    println!("PASS organization-attachment-read CLI: {COMMAND_COUNT} commands");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_snapshot() -> Value {
        json!([
            {"cipher":{"private":"owner"},"revision":1,"keys":{"retained":true},"folder":{"own":true},"control":{"personal":true}},
            {"cipher":{"private":"recipient"},"revision":2,"keys":{"retained":true},"folder":{"own":true},"control":{"personal":true}}
        ])
    }

    #[test]
    fn login_setup_allows_only_actor_revision_with_observed_sdk_id_initialization() {
        let before = setup_snapshot();
        let sdk_id = json!("0123456789abcdef0123456789abcdef");
        for actor in 0..2 {
            let mut after = before.clone();
            after[actor]["revision"] = json!(3);
            let observation =
                login_setup_observation(&before, &after, actor, &Value::Null, &sdk_id);
            assert!(observation["passed"] == true);
            assert!(observation["sdkKeyIdMigrationObserved"] == true);
            assert!(observation["actorAccountRevisionChanged"] == true);
            assert!(observation["otherAccountRevisionPreserved"] == true);
            assert!(
                login_setup_observation(&before, &after, actor, &sdk_id, &sdk_id)["passed"]
                    == false
            );
            assert!(
                login_setup_observation(&before, &after, actor, &Value::Null, &Value::Null)["passed"]
                    == false
            );
            after[1 - actor]["revision"] = json!(4);
            assert!(
                login_setup_observation(&before, &after, actor, &Value::Null, &sdk_id)["passed"]
                    == false
            );
        }
    }

    #[test]
    fn login_setup_never_masks_protected_vault_private_keys_folders_or_personal_changes() {
        let before = setup_snapshot();
        let sdk_id = json!("0123456789abcdef0123456789abcdef");
        for viewer in 0..2 {
            for field in ["cipher", "keys", "folder", "control"] {
                let mut after = before.clone();
                after[viewer][field] = json!({"changed":true});
                after[0]["revision"] = json!(3);
                assert!(
                    login_setup_observation(&before, &after, 0, &Value::Null, &sdk_id)["passed"]
                        == false
                );
                assert!(before != after);
            }
        }
        let mut extra_field = before.clone();
        extra_field[0]["unexpected"] = json!(true);
        assert!(
            login_setup_observation(&before, &extra_field, 0, &Value::Null, &sdk_id)["passed"]
                == false
        );
    }

    #[test]
    fn login_setup_rejects_replacing_existing_or_malformed_sdk_ids() {
        let before = setup_snapshot();
        let sdk_id = json!("0123456789abcdef0123456789abcdef");
        for key in [&Value::Null, &sdk_id] {
            assert!(login_setup_observation(&before, &before, 0, key, key)["passed"] == true);
        }
        for invalid in [
            json!(""),
            json!("0123456789ABCDEF0123456789ABCDEF"),
            json!("0123456789abcdef0123456789abcde"),
            json!(17),
            json!({}),
        ] {
            assert!(
                login_setup_observation(&before, &before, 0, &Value::Null, &invalid)["passed"]
                    == false
            );
        }
        for changed in [Value::Null, json!("fedcba9876543210fedcba9876543210")] {
            assert!(
                login_setup_observation(&before, &before, 0, &sdk_id, &changed)["passed"] == false
            );
        }
        assert!(
            login_setup_observation(&before, &before, 2, &Value::Null, &Value::Null)["passed"]
                == false
        );
    }

    #[test]
    fn capability_rotation_masks_only_values_preserving_all_other_metadata() {
        let sample = |url: &str| json!({"attachments":[{"id":"attachment","fileName":"opaque","key":"wrapped","url":url}]});
        let baseline = normalize_capabilities(sample(
            "https://localhost:1234/attachments/cipher/attachment?token=one&other=two",
        ))
        .unwrap_or_else(|_| panic!("Static capability fixture invalid"));
        let rotation = normalize_capabilities(sample(
            "https://localhost:1234/attachments/cipher/attachment?token=three&other=four",
        ))
        .unwrap_or_else(|_| panic!("Static capability fixture invalid"));
        assert!(baseline == rotation);
        for changed in [
            "https://localhost:1235/attachments/cipher/attachment?token=one&other=two",
            "https://localhost:1234/attachments/foreign/attachment?token=one&other=two",
            "https://localhost:1234/attachments/cipher/attachment?different=one&other=two",
        ] {
            let changed = normalize_capabilities(sample(changed))
                .unwrap_or_else(|_| panic!("Static capability fixture invalid"));
            assert!(baseline != changed);
        }
        let mut changed = rotation;
        changed["attachments"][0]["key"] = json!("different-wrapped-key");
        assert!(baseline != changed);
    }

    #[test]
    fn malformed_capabilities_and_missing_attachment_arrays_are_rejected() {
        for value in [
            json!({}),
            json!({"attachments":[{"url":"not a URL"}]}),
            json!({"attachments":[{"url":"https://localhost/attachments/cipher/attachment"}]}),
        ] {
            assert!(normalize_capabilities(value).is_err());
        }
    }
}
