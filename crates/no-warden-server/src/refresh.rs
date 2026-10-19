//! Password-method refresh authority. Proofs remain opaque to clients and core;
//! the adapter owns verification, original deadlines, device binding and issuance.
use crate::{App, Failure, auth_requests, devices, issue_token_grant_bound, store::Store};
use axum::{http::StatusCode, response::Response};
use no_warden::{
    VaultService,
    identity::Secret,
    refresh::{RefreshIdentity, RefreshMethod, RefreshStorage},
    wire::RefreshTokenRequest,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

pub struct Input(Vec<(String, String)>);
impl Input {
    pub fn selected(body: &[u8]) -> Result<Option<Self>, Failure> {
        let fields = Self(serde_urlencoded::from_bytes(body).map_err(|_| crate::invalid())?);
        Ok((fields.first(&["grant_type", "granttype"]) == Some("refresh_token")).then_some(fields))
    }
    fn first(&self, aliases: &[&str]) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| {
                aliases
                    .iter()
                    .any(|alias| auth_requests::query_root(name).eq_ignore_ascii_case(alias))
            })
            .map(|(_, value)| value.as_str())
    }
    fn optional(&self, aliases: &[&str]) -> Option<&str> {
        // Rocket Option<T> forces strict inner scalar parsing and suppresses
        // its duplicate error into None; required String remains first-wins.
        let mut values = self.0.iter().filter(|(name, _)| {
            aliases
                .iter()
                .any(|alias| auth_requests::query_root(name).eq_ignore_ascii_case(alias))
        });
        let value = values.next().map(|(_, value)| value.as_str());
        if values.next().is_some() { None } else { value }
    }
    fn request(&self) -> RefreshTokenRequest<'_> {
        RefreshTokenRequest {
            grant_type: self.first(&["grant_type", "granttype"]),
            refresh_token: self
                .optional(&["refresh_token", "refreshtoken"])
                .map(Secret::new),
            client_id: self.optional(&["client_id", "clientid"]),
        }
    }
}

// The local adapter uses random unguessable bearer handles rather than upstream
// refresh JWTs. Their digest, original validity window and verified current
// device binding authenticate the proof. JWT encoding remains an explicit gap.
fn authority_at(
    db: &Connection,
    proof: &Secret<'_>,
    now: i64,
) -> rusqlite::Result<Option<RefreshIdentity<String, String>>> {
    // Upstream decode_jwt strips all Unicode whitespace, not just its ends.
    let normalized: String = proof
        .expose_secret()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let digest = crate::digest(&normalized);
    let owner: Option<String> = db.query_row(
        "SELECT owner FROM sessions WHERE refresh=?1 AND refresh_expires>0 AND refresh_expires>=?2",
        params![digest,now.saturating_sub(30)],
        |row| row.get(0),
    ).optional()?;
    let Some(owner) = owner else { return Ok(None) };
    let binding = devices::refresh_binding(db, &digest, &owner)?;
    Ok(binding.map(|device_identifier| RefreshIdentity {
        owner,
        device_identifier,
        method: RefreshMethod::Password,
    }))
}

impl RefreshStorage for Store {
    type OwnerId = String;
    type DeviceId = String;
    fn verify_refresh_token(
        &mut self,
        proof: &Secret<'_>,
    ) -> rusqlite::Result<Option<RefreshIdentity<String, String>>> {
        authority_at(&self.db, proof, chrono::Utc::now().timestamp())
    }
    fn prepare_password_refresh(&mut self, owner: &str, identifier: &str) -> rusqlite::Result<()> {
        // This host has no SSO-only policy; the verified Password method is
        // admitted without a password, enabled flag or old-stamp comparison.
        devices::touch(&self.db, owner, identifier)
    }
}

pub fn login(app: &App, store: &mut Store, input: &Input) -> Result<Response, Failure> {
    // Preserve every old proof/deadline. The operation lock/savepoint covers
    // preparation, activity, new sessions/bindings and deferred commit failures.
    store.db.execute_batch("SAVEPOINT password_refresh")?;
    let result = (|| {
        let grant = VaultService::new(&mut *store).authenticate_refresh(&input.request())?;
        let account = store
            .account("id", grant.user_id())?
            .ok_or(Failure(StatusCode::BAD_REQUEST, "Invalid refresh token"))?;
        let tokens = issue_token_grant_bound(
            app,
            &store.db,
            &account,
            None,
            Some(grant.device_identifier()),
            Some(grant.client_id()),
        )?;
        let result = token_response(&tokens);
        store.db.execute_batch("RELEASE password_refresh")?;
        Ok(crate::json_response(result))
    })();
    if result.is_err() {
        store
            .db
            .execute_batch("ROLLBACK TO password_refresh; RELEASE password_refresh")?;
    }
    result
}

fn token_response(tokens: &Value) -> Value {
    json!({"refresh_token":tokens["refresh_token"],"access_token":tokens["access_token"],
        "expires_in":tokens["expires_in"],"token_type":tokens["token_type"],"scope":tokens["scope"]})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_scalar_names_follow_required_first_and_optional_strict_rules() {
        let input = Input::selected(
            b"[GRANTTYPE].x=refresh_token&grant_type=password&.REFRESHTOKEN[x]=opaque&[CLIENTID]=",
        )
        .unwrap_or_else(|_| panic!("Form invalid"))
        .unwrap_or_else(|| panic!("Refresh not selected"));
        let request = input.request();
        assert!(
            request.grant_type == Some("refresh_token")
                && request.refresh_token.as_ref().unwrap().expose_secret() == "opaque"
                && request.client_id == Some("")
        );
        let input = Input::selected(b"grant_type=refresh_token&refresh_token=first&refreshtoken.x=second&CLIENTID=first&client_id=second").unwrap_or_else(|_| panic!("Form invalid")).unwrap_or_else(|| panic!("Refresh not selected"));
        let request = input.request();
        assert!(request.refresh_token.is_none() && request.client_id.is_none());
        assert!(
            Input::selected(b"grant_type=password&grant_type=refresh_token")
                .unwrap_or_else(|_| panic!("Form invalid"))
                .is_none()
        );
    }

    #[test]
    fn opaque_refresh_deadline_replay_whitespace_and_current_device_are_authoritative() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE sessions(access TEXT,refresh TEXT,owner TEXT,access_expires INTEGER,refresh_expires INTEGER); CREATE TABLE session_devices(access TEXT,owner TEXT,identifier TEXT); CREATE TABLE device_registry(owner TEXT,identifier TEXT);
            INSERT INTO device_registry VALUES('owner',''); INSERT INTO session_devices VALUES('old-access','owner','');").unwrap();
        db.execute(
            "INSERT INTO sessions VALUES('old-access',?1,'owner',0,1000)",
            [crate::digest("original-proof")],
        )
        .unwrap();
        let proof = Secret::new("\u{2003}ori\n gin\tal-proof\u{a0}");
        for time in [999, 1000, 1030, 1030] {
            let grant = authority_at(&db, &proof, time).unwrap().unwrap();
            assert!(
                grant.owner == "owner"
                    && grant.device_identifier.is_empty()
                    && grant.method == RefreshMethod::Password
            );
        }
        assert!(authority_at(&db, &proof, 1031).unwrap().is_none());
        db.execute(
            "INSERT INTO sessions VALUES('new-access',?1,'owner',0,2000)",
            [crate::digest("new-proof")],
        )
        .unwrap();
        db.execute(
            "INSERT INTO session_devices VALUES('new-access','owner','')",
            [],
        )
        .unwrap();
        assert!(authority_at(&db, &proof, 1031).unwrap().is_none());
        assert!(
            authority_at(&db, &Secret::new("new-proof"), 1031)
                .unwrap()
                .is_some()
        );
        let old_deadline: i64 = db
            .query_row(
                "SELECT refresh_expires FROM sessions WHERE access='old-access'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(old_deadline == 1000);
        assert!(
            authority_at(&db, &Secret::new("old-access"), 999)
                .unwrap()
                .is_none()
        );
        db.execute("DELETE FROM device_registry", []).unwrap();
        assert!(
            authority_at(&db, &Secret::new("new-proof"), 1031)
                .unwrap()
                .is_none()
        );
    }
}
