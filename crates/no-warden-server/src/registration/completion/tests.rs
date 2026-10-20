use crate::organization_collections::tests::{create_org, fixture, org};
use crate::{Store, registration};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use no_warden::{
    VaultService, registration::RegistrationEmail, wire::RegistrationVerificationRequest,
};
use rusqlite::{params, types::Value as SqlValue};
use serde_json::{Value, json};

fn placeholder(store: &mut Store) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let document = json!({"id":id,"email":"pending@example.test","name":"Retained name","key":"","keys":{"publicKey":"retained-public","encryptedPrivateKey":"retained-private"},"avatarColor":"#123456","userKeyId":"retained-key-id","creationDate":"2000-01-01T00:00:00.000Z","revisionDate":"2000-01-01T00:00:00.000Z"});
    store.db.execute("INSERT INTO accounts VALUES(?1,'pending@example.test',?2,'','2000-01-01T00:00:00.000Z')",params![id,document.to_string()]).unwrap();
    store
        .db
        .execute(
            "INSERT INTO organization_invitations VALUES('pending@example.test')",
            [],
        )
        .unwrap();
    let first = org(store);
    for (index, status) in [0, 0, 1, -128].into_iter().enumerate() {
        let organization = if index == 0 {
            first.clone()
        } else {
            create_org(store, "alice")
        };
        store
            .db
            .execute(
                "INSERT INTO organization_memberships VALUES(?1,?2,?3,'',2,?4,0)",
                params![format!("pending-{index}"), organization, id, status],
            )
            .unwrap();
    }
    store.db.execute("INSERT INTO device_registry VALUES(?1,'pending-device','retained-device',23,'2000','2000')",[&id]).unwrap();
    id
}
fn input(store: &mut Store, name: Option<&str>, keys: bool) -> Value {
    store.registration_issuer = registration::issuer("https://registration.example.test")
        .unwrap_or_else(|_| panic!("Registration origin fixture failed"));
    let token = VaultService::new(store)
        .request_registration_verification(&RegistrationVerificationRequest {
            email: "pending@example.test",
            name,
        })
        .unwrap();
    let mut document = json!({"email":"pending@example.test","emailVerificationToken":token.expose_token(),"masterPasswordHash":"registration-proof\0雪","key":"opaque-wrapped-key","kdf":0,"kdfIterations":600000,"name":"FORGED","id":"forged-id","future":"forged-extension"});
    if keys {
        document["keys"] = json!({"publicKey":"new-public","encryptedPrivateKey":"new-private"});
    }
    document
}
fn finish(store: &mut Store, document: &Value) -> bool {
    let input = registration::parse_finish(&serde_json::to_vec(document).unwrap())
        .unwrap_or_else(|_| panic!("Registration fixture schema failed"));
    VaultService::new(store)
        .finish_registration(
            &input.request(),
            &RegistrationEmail {
                storage_email: "pending@example.test",
                salt_email: "pending@example.test",
            },
        )
        .is_ok()
}
fn snapshot(store: &Store) -> Vec<Vec<SqlValue>> {
    let mut output = Vec::new();
    for table in [
        "accounts",
        "organization_memberships",
        "organization_invitations",
        "registration_metadata",
        "account_security",
        "sessions",
        "session_devices",
        "device_registry",
        "account_password_access",
        "account_password_exceptions",
    ] {
        let mut query = store
            .db
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
            .unwrap();
        let count = query.column_count();
        output.extend(
            query
                .query_map([], |row| {
                    (0..count)
                        .map(|i| row.get(i))
                        .collect::<rusqlite::Result<Vec<SqlValue>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
        );
    }
    output
}

#[test]
fn placeholder_completion_retains_identity_and_accepts_only_all_invited_memberships() {
    let mut store = fixture(":memory:");
    let id = placeholder(&mut store);
    store.db.execute("INSERT INTO sessions VALUES('pending-access','pending-refresh',?1,9999999999,9999999999)",[&id]).unwrap();
    store
        .db
        .execute(
            "INSERT INTO session_devices VALUES('pending-access',?1,'pending-device')",
            [&id],
        )
        .unwrap();
    store.db.execute("INSERT INTO account_password_access VALUES('old-private-access',?1,'pending-device','old-stamp',9999999999)",[&id]).unwrap();
    store.db.execute("INSERT INTO account_password_exceptions VALUES(?1,'old-stamp','old-generation',9999999999)",[&id]).unwrap();
    let foreign_before = store.account("id", "alice").unwrap();
    let document = input(&mut store, None, false);
    let before = store.account("id", &id).unwrap().unwrap();
    assert!(finish(&mut store, &document));
    let account = store.account("id", &id).unwrap().unwrap();
    assert!(
        account["id"] == id
            && account["name"] == before["name"]
            && account["creationDate"] == before["creationDate"]
            && account["keys"] == before["keys"]
            && account["avatarColor"] == before["avatarColor"]
            && account["userKeyId"] == before["userKeyId"]
    );
    assert!(
        account["revisionDate"] != before["revisionDate"]
            && account["key"] == "opaque-wrapped-key"
            && account.get("future").is_none()
    );
    let statuses: Vec<i32> = store
        .db
        .prepare("SELECT status FROM organization_memberships WHERE user_id=?1 ORDER BY id")
        .unwrap()
        .query_map([&id], |r| r.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(statuses == [1, 1, 1, -128]);
    let unchanged:bool=store.db.query_row("SELECT NOT EXISTS(SELECT 1 FROM organization_memberships WHERE user_id=?1 AND (key<>'' OR role<>2 OR access_all<>0))",[&id],|r|r.get(0)).unwrap();
    assert!(
        unchanged
            && !registration::invitation_exists(&store.db, "PENDING@EXAMPLE.TEST").unwrap()
            && store.account("id", "alice").unwrap() == foreign_before
    );
    let verifier: String = store
        .db
        .query_row("SELECT password FROM accounts WHERE id=?1", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(
        Argon2::default()
            .verify_password(
                "registration-proof\0雪".as_bytes(),
                &PasswordHash::new(&verifier).unwrap()
            )
            .is_ok()
    );
    let devices: i64 = store
        .db
        .query_row(
            "SELECT COUNT(*) FROM device_registry WHERE owner=?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(devices == 1 && crate::account_security::stamp(&store.db, &id).unwrap() != id);
    for table in [
        "sessions",
        "session_devices",
        "account_password_access",
        "account_password_exceptions",
    ] {
        let count: i64 = store
            .db
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE owner=?1"),
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            count == 0,
            "Pre-initialization bearer authority remained valid"
        );
    }
    let foreign_sessions: i64 = store
        .db
        .query_row(
            "SELECT COUNT(*) FROM sessions WHERE owner='alice'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(foreign_sessions == 1);
    let stable = snapshot(&store);
    assert!(!finish(&mut store, &document) && snapshot(&store) == stable);
}

#[test]
fn placeholder_completion_applies_only_verified_claim_name_and_explicit_key_pair() {
    let mut store = fixture(":memory:");
    let id = placeholder(&mut store);
    let document = input(&mut store, Some("Verified claim 雪"), true);
    assert!(finish(&mut store, &document));
    let account = store.account("id", &id).unwrap().unwrap();
    assert!(
        account["name"] == "Verified claim 雪"
            && account["keys"]
                == json!({"publicKey":"new-public","encryptedPrivateKey":"new-private"})
            && account["creationDate"] == "2000-01-01T00:00:00.000Z"
    );
}

#[test]
fn pending_invitation_allows_signup_disabled_but_never_overwrites_an_initialized_account() {
    let mut store = fixture(":memory:");
    let id = placeholder(&mut store);
    store.registration_policy.signups_allowed = false;
    let document = input(&mut store, None, false);
    assert!(finish(&mut store, &document));
    // A stale invitation must not permit reinitialization, even after signed issuance.
    store
        .db
        .execute(
            "INSERT INTO organization_invitations VALUES('pending@example.test')",
            [],
        )
        .unwrap();
    let stale = input(&mut store, Some("forged replacement"), true);
    let before = snapshot(&store);
    assert!(!finish(&mut store, &stale) && snapshot(&store) == before);
    assert!(store.account("id", &id).unwrap().unwrap()["name"] == "Retained name");
}

#[test]
fn placeholder_registration_failures_preserve_pending_authority_and_are_retryable() {
    for phase in 0..6 {
        let mut store = fixture(":memory:");
        placeholder(&mut store);
        let document = input(&mut store, None, false);
        let before = snapshot(&store);
        store.db.execute_batch(match phase {
            0=>"CREATE TRIGGER reject_completion BEFORE UPDATE OF password ON accounts BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            1=>"CREATE TRIGGER reject_completion AFTER UPDATE OF password ON accounts BEGIN SELECT RAISE(FAIL,'fixture'); END;",
            2=>"CREATE TRIGGER reject_completion BEFORE INSERT ON registration_metadata BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            3=>"CREATE TRIGGER reject_completion BEFORE DELETE ON organization_invitations BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            4=>"CREATE TRIGGER reject_completion BEFORE UPDATE OF status ON organization_memberships BEGIN SELECT RAISE(ABORT,'fixture'); END;",
            _=>"CREATE TABLE failed_completion(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_completion AFTER UPDATE OF status ON organization_memberships BEGIN INSERT INTO failed_completion VALUES('missing-owner'); END;",
        }).unwrap();
        assert!(
            !finish(&mut store, &document) && snapshot(&store) == before,
            "Failed completion escaped its savepoint"
        );
        store
            .db
            .execute_batch("DROP TRIGGER reject_completion")
            .unwrap();
        assert!(finish(&mut store, &document));
    }
}

#[test]
fn placeholder_without_pending_invitation_does_not_autoaccept_memberships() {
    let mut store = fixture(":memory:");
    let id = placeholder(&mut store);
    store
        .db
        .execute("DELETE FROM organization_invitations", [])
        .unwrap();
    let document = input(&mut store, None, false);
    assert!(finish(&mut store, &document));
    let pending: i64 = store
        .db
        .query_row(
            "SELECT COUNT(*) FROM organization_memberships WHERE user_id=?1 AND status=0",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(pending == 2);
}

#[test]
fn placeholder_has_one_concurrent_initializer_and_durable_consumed_invitation() {
    use std::sync::{Arc, Barrier};
    let directory =
        std::env::temp_dir().join(format!("no-warden-placeholder-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.join("vault.db");
    let filename = path.to_str().unwrap();
    let mut store = fixture(filename);
    let id = placeholder(&mut store);
    let document = input(&mut store, None, false);
    drop(store);
    let stores: Vec<_> = (0..2)
        .map(|_| {
            let mut store = Store::open(filename).unwrap();
            store
                .db
                .busy_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            store.registration_issuer = registration::issuer("https://registration.example.test")
                .unwrap_or_else(|_| panic!("Registration origin fixture failed"));
            store
        })
        .collect();
    let barrier = Arc::new(Barrier::new(2));
    let workers: Vec<_> = stores
        .into_iter()
        .map(|mut store| {
            let document = document.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                finish(&mut store, &document)
            })
        })
        .collect();
    let winners = workers
        .into_iter()
        .map(|w| usize::from(w.join().unwrap()))
        .sum::<usize>();
    assert!(winners == 1);
    let mut reopened = Store::open(filename).unwrap();
    reopened.registration_issuer = registration::issuer("https://registration.example.test")
        .unwrap_or_else(|_| panic!("Registration origin fixture failed"));
    assert!(
        reopened
            .account("email", "pending@example.test")
            .unwrap()
            .unwrap()["id"]
            == id
            && !registration::invitation_exists(&reopened.db, "pending@example.test").unwrap()
    );
    let pending: i64 = reopened
        .db
        .query_row(
            "SELECT COUNT(*) FROM organization_memberships WHERE user_id=?1 AND status=0",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(pending == 0 && !finish(&mut reopened, &document));
    drop(reopened);
    std::fs::remove_dir_all(directory).unwrap();
}
