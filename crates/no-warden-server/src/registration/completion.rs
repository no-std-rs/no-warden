//! Same-ID registration for passwordless invitations, independently authored.
//! Persistence and credential preparation stay outside the allocation-free core.
use super::Policy;
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use no_warden::registration::ValidatedRegistration;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

pub(crate) fn invitation_exists(db: &Connection, email: &str) -> rusqlite::Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM organization_invitations WHERE email=?1)",
        [email.to_lowercase()],
        |row| row.get(0),
    )
}

pub(crate) fn finish_account(
    db: &mut Connection,
    policy: &Policy,
    plan: &ValidatedRegistration<'_>,
) -> rusqlite::Result<()> {
    if (!policy.password_hints_allowed && plan.master_password_hint().is_some())
        || !super::valid_storage_email(plan.email())
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let verifier = Argon2::default()
        .hash_password(
            plan.master_password_hash().expose_secret().as_bytes(),
            &SaltString::generate(&mut OsRng),
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .to_string();
    let tx = db.savepoint()?;
    let prior: Option<(String, String, String)> = tx
        .query_row(
            "SELECT id,password,document FROM accounts WHERE email=?1",
            [plan.email()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let invited = invitation_exists(&tx, plan.email())?;
    if (!policy.signups_allowed && !invited)
        || prior
            .as_ref()
            .is_some_and(|(_, password, _)| !password.is_empty())
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let existing = prior.is_some();
    let (id, mut document, revision) = match prior {
        Some((id, _, raw)) => {
            let revision = crate::store::next_revision(&tx, &id)?;
            let document: Value =
                serde_json::from_str(&raw).map_err(|_| rusqlite::Error::InvalidQuery)?;
            if !document.is_object() {
                return Err(rusqlite::Error::InvalidQuery);
            }
            (id, document, revision)
        }
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            let revision = crate::store::now();
            let document = json!({"id":id,"email":plan.email(),"name":plan.email(),"keys":null,"avatarColor":null,"userKeyId":null,"creationDate":revision});
            (id, document, revision)
        }
    };
    let kdf = plan.kdf();
    document["id"] = json!(id);
    document["email"] = json!(plan.email());
    if let Some(name) = plan.name() {
        document["name"] = json!(name);
    } else if document.get("name").is_none() {
        document["name"] = json!(plan.email());
    }
    if let Some(keys) = plan.keys() {
        document["keys"] =
            json!({"publicKey":keys.public_key,"encryptedPrivateKey":keys.encrypted_private_key});
    }
    document["key"] = json!(plan.key().expose_secret());
    document["masterPasswordHint"] = json!(plan.master_password_hint());
    document["kdf"] = json!(kdf.kdf);
    document["kdfIterations"] = json!(kdf.kdf_iterations);
    document["kdfMemory"] = json!(kdf.kdf_memory);
    document["kdfParallelism"] = json!(kdf.kdf_parallelism);
    document["revisionDate"] = json!(revision);
    if existing {
        if tx.execute(
            "UPDATE accounts SET document=?1,password=?2,revision=?3 WHERE id=?4 AND password=''",
            params![document.to_string(), verifier, revision, id],
        )? != 1
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        // Source registration resets the stamp and rotates refresh credentials,
        // while retaining device rows. Never retain pre-initialization bearers.
        tx.execute("INSERT INTO account_security(owner,stamp) VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET stamp=excluded.stamp",params![id,uuid::Uuid::new_v4().to_string()])?;
        tx.execute("DELETE FROM sessions WHERE owner=?1", [&id])?;
        tx.execute("DELETE FROM account_password_access WHERE owner=?1", [&id])?;
        tx.execute(
            "DELETE FROM account_password_exceptions WHERE owner=?1",
            [&id],
        )?;
    } else {
        tx.execute(
            "INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,?4,?5)",
            params![id, plan.email(), document.to_string(), verifier, revision],
        )?;
    }
    tx.execute("INSERT INTO registration_metadata(owner,email_verified) VALUES(?1,?2) ON CONFLICT(owner) DO UPDATE SET email_verified=MAX(registration_metadata.email_verified,excluded.email_verified)",params![id,plan.email_verified()])?;
    if invited {
        tx.execute(
            "DELETE FROM organization_invitations WHERE email=?1",
            [plan.email()],
        )?;
        tx.execute(
            "UPDATE organization_memberships SET status=1 WHERE user_id=?1 AND status=0",
            [&id],
        )?;
    }
    tx.commit()
}

#[cfg(test)]
mod tests;
