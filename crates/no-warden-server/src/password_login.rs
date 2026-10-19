//! Ordinary password grant adapter. The core owns authorization; this adapter
//! owns ordered Rocket-compatible form names, password verification and issuance.
use crate::{App, Failure, auth_requests, authenticated_login, store::Store};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService,
    devices::DeviceRegistration,
    identity::Secret,
    password_login::{PasswordLoginAccount, PasswordLoginDevice, PasswordLoginStorage},
    wire::PasswordLoginRequest,
};
use rusqlite::OptionalExtension;
use serde_json::json;

// The required grant_type String is lenient and takes the first matching value.
// Optional String fields force strict parsing: duplicate alias/root matches
// invalidate that option, and Rocket then supplies None to the handler.
pub struct Input(Vec<(String, String)>);
impl Input {
    pub fn ordinary(body: &[u8]) -> Result<Option<Self>, Failure> {
        let fields = Self(serde_urlencoded::from_bytes(body).map_err(|_| crate::invalid())?);
        if fields.first_field(&["grant_type", "granttype"]) != Some("password")
            || fields.first_field(&["authrequest"]).is_some()
        {
            return Ok(None);
        }
        Ok(Some(fields))
    }
    fn first_field(&self, aliases: &[&str]) -> Option<&str> {
        self.0
            .iter()
            .find(|(name, _)| {
                let root = auth_requests::query_root(name);
                aliases.iter().any(|alias| root.eq_ignore_ascii_case(alias))
            })
            .map(|(_, value)| value.as_str())
    }
    fn optional_field(&self, aliases: &[&str]) -> Option<&str> {
        let mut matches = self.0.iter().filter(|(name, _)| {
            let root = auth_requests::query_root(name);
            aliases.iter().any(|alias| root.eq_ignore_ascii_case(alias))
        });
        let first = matches.next().map(|(_, value)| value.as_str());
        if matches.next().is_some() {
            None
        } else {
            first
        }
    }
    fn request(&self) -> PasswordLoginRequest<'_> {
        PasswordLoginRequest {
            grant_type: self.first_field(&["grant_type", "granttype"]),
            client_id: self.optional_field(&["client_id", "clientid"]),
            password: self.optional_field(&["password"]).map(Secret::new),
            scope: self.optional_field(&["scope"]),
            username: self.optional_field(&["username"]),
            device_identifier: self.optional_field(&["device_identifier", "deviceidentifier"]),
            device_name: self.optional_field(&["device_name", "devicename"]),
            device_type: self.optional_field(&["device_type", "devicetype"]),
            auth_request: self.optional_field(&["authrequest"]),
        }
    }
}

impl PasswordLoginStorage for Store {
    type OwnerId = String;
    fn verify_password_login(
        &mut self,
        username: &str,
        password: &Secret<'_>,
    ) -> rusqlite::Result<Option<PasswordLoginAccount<String>>> {
        let record = self.db.query_row(
            "SELECT id,password,COALESCE((SELECT enabled FROM account_auth_policy WHERE owner=accounts.id),1) FROM accounts WHERE email=?1",
            [username.to_lowercase()],
            |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,bool>(2)?)),
        ).optional()?;
        let Some((owner, encoded, enabled)) = record else {
            return Ok(None);
        };
        let parsed = PasswordHash::new(&encoded).map_err(|_| rusqlite::Error::InvalidQuery)?;
        if Argon2::default()
            .verify_password(password.expose_secret().as_bytes(), &parsed)
            .is_err()
        {
            return Ok(None);
        }
        Ok(Some(PasswordLoginAccount { owner, enabled }))
    }
    fn prepare_password_login(
        &mut self,
        _owner: &str,
        _password: &Secret<'_>,
        _device: PasswordLoginDevice<'_>,
    ) -> rusqlite::Result<()> {
        // This conformance host has fixed verifier parameters and no SMTP,
        // two-factor or SSO configuration. Richer providers complete those
        // policies here before the core grants issuance authority.
        Ok(())
    }
}

pub fn login(app: &App, store: &mut Store, input: &Input) -> Result<Response, Failure> {
    let request = input.request();
    let grant = match VaultService::new(&mut *store).authenticate_password(&request) {
        Ok(grant) => grant,
        Err(error) => {
            if error.message == "Scope not supported" {
                let message = format!(
                    "Scope ({}) not supported",
                    request.scope.unwrap_or_default().escape_debug()
                );
                return Ok(error_response(StatusCode::BAD_REQUEST, &message));
            }
            return Err(error.into());
        }
    };
    let account = store
        .account("id", grant.user_id())?
        .ok_or_else(crate::invalid_grant)?;
    let device = grant.device();
    let registration = DeviceRegistration {
        identifier: device.identifier,
        name: device.name,
        device_type: device.device_type.parse().unwrap_or(14),
    };
    Ok(crate::json_response(authenticated_login(
        app,
        store,
        &account,
        &registration,
        None,
        Some(grant.client_id()),
    )?))
}

pub fn is_password_error(message: &str) -> bool {
    matches!(
        message,
        "client_id cannot be blank"
            | "password cannot be blank"
            | "scope cannot be blank"
            | "username cannot be blank"
            | "device_identifier cannot be blank"
            | "device_name cannot be blank"
            | "device_type cannot be blank"
            | "This user has been disabled"
            | "Username or password is incorrect. Try again"
    )
}

pub fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({
            "message":message,"validationErrors":{"":[message]},
            "errorModel":{"message":message,"object":"error"},
            "error":"","error_description":"","exceptionMessage":null,
            "exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_forms_preserve_required_first_value_and_nested_optional_values() {
        let input = Input::ordinary(b".GrAnTtYpE[nested]=password&grant_type=other&[CLIENTID].ignored=first&[UsErNaMe]=%E2%80%83Alice%40EXAMPLE.test%20&password=%20Proof%00%E9%9B%AA%20&scope=api+offline_access&deviceIdentifier=x&deviceName=&deviceType=garbage")
            .unwrap_or_else(|_| panic!("Form decoding failed"))
            .unwrap_or_else(|| panic!("Ordinary form not selected"));
        let request = input.request();
        assert!(request.client_id == Some("first"));
        assert!(request.username == Some("\u{2003}Alice@EXAMPLE.test "));
        assert!(request.password.as_ref().unwrap().expose_secret() == " Proof\0雪 ");
        assert!(request.device_name == Some(""));
        assert!(request.device_type == Some("garbage"));
    }

    #[test]
    fn repeated_optional_alias_or_nested_fields_become_absent() {
        for (index, aliases) in [
            ["client_id", "[CLIENTID].nested"],
            ["password", "PASSWORD.x"],
            ["scope", "[SCOPE]"],
            ["username", ".USERNAME"],
            ["deviceIdentifier", "DEVICE_IDENTIFIER"],
            ["device_name", "DEVICENAME.x"],
            ["deviceType", "[DEVICE_TYPE]"],
        ]
        .into_iter()
        .enumerate()
        {
            let body = serde_urlencoded::to_string([
                ("grant_type", "password"),
                (aliases[0], "first"),
                (aliases[1], "second"),
            ])
            .unwrap();
            let input = Input::ordinary(body.as_bytes())
                .unwrap_or_else(|_| panic!("Form decoding failed"))
                .unwrap_or_else(|| panic!("Ordinary form not selected"));
            let request = input.request();
            assert!(match index {
                0 => request.client_id.is_none(),
                1 => request.password.is_none(),
                2 => request.scope.is_none(),
                3 => request.username.is_none(),
                4 => request.device_identifier.is_none(),
                5 => request.device_name.is_none(),
                6 => request.device_type.is_none(),
                _ => unreachable!(),
            });
        }
    }

    #[test]
    fn auth_request_presence_cannot_select_ordinary_password_fallback() {
        for name in [
            "authrequest",
            "AUTHREQUEST.nested",
            "[AuthRequest]",
            ".authrequest[code]",
        ] {
            let body = format!("grant_type=password&{name}=");
            assert!(
                Input::ordinary(body.as_bytes())
                    .unwrap_or_else(|_| panic!("Form decoding failed"))
                    .is_none()
            );
        }
        for body in [
            b"grant_type=refresh_token".as_slice(),
            b"grant_type=client_credentials",
            b"grant_type=&grant_type=password",
            b"username=x",
        ] {
            assert!(
                Input::ordinary(body)
                    .unwrap_or_else(|_| panic!("Form decoding failed"))
                    .is_none()
            );
        }
        assert!(
            Input::ordinary(b"grant_type=password&auth_request=ignored")
                .unwrap_or_else(|_| panic!("Form decoding failed"))
                .is_some()
        );
    }
}
