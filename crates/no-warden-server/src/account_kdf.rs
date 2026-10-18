//! Nested KDF-change JSON guard. Protocol facts follow Vaultwarden
//! 58a980f850464f7d9cdc99a765df36f0a3308b91 accounts.rs:85-94,725-797.
//! Proofs and wrapped keys are opaque and never enter diagnostics.

use crate::Failure;
use no_warden::{
    identity::Secret,
    wire::{AccountKdfAuthentication, AccountKdfRequest, AccountKdfUnlock, RegistrationKdf},
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Input {
    authentication_data: Authentication,
    unlock_data: Unlock,
    master_password_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Authentication {
    #[serde(alias = "Salt")]
    salt: String,
    #[serde(alias = "Kdf")]
    kdf: RegistrationKdf,
    #[serde(alias = "MasterPasswordAuthenticationHash")]
    master_password_authentication_hash: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Unlock {
    salt: String,
    kdf: RegistrationKdf,
    master_key_wrapped_user_key: String,
}
impl Input {
    pub fn request(&self) -> AccountKdfRequest<'_> {
        AccountKdfRequest {
            authentication_data: AccountKdfAuthentication {
                salt: &self.authentication_data.salt,
                kdf: self.authentication_data.kdf,
                master_password_authentication_hash: Secret::new(
                    &self.authentication_data.master_password_authentication_hash,
                ),
            },
            unlock_data: AccountKdfUnlock {
                salt: &self.unlock_data.salt,
                kdf: self.unlock_data.kdf,
                master_key_wrapped_user_key: Secret::new(
                    &self.unlock_data.master_key_wrapped_user_key,
                ),
            },
            master_password_hash: Secret::new(&self.master_password_hash),
        }
    }
}
pub fn parse(body: &[u8]) -> Result<Input, Failure> {
    serde_json::from_slice(body).map_err(crate::json_guard_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde_json::json;

    fn document() -> serde_json::Value {
        json!({"authenticationData":{"salt":"alice@example.test","kdf":{"kdf":0,"kdfIterations":100000},"masterPasswordAuthenticationHash":"new-private-proof\0雪"},"unlockData":{"salt":"alice@example.test","kdf":{"kdf":0,"kdfIterations":100000},"masterKeyWrappedUserKey":"new-private-key\0雪"},"masterPasswordHash":"old-private-proof","unknown":{"preservedByParser":true}})
    }
    #[test]
    fn account_kdf_owned_guard_preserves_exact_aliases_positional_schema_and_secret_redaction() {
        let input = parse(&serde_json::to_vec(&document()).unwrap())
            .unwrap_or_else(|_| panic!("Valid nested KDF input rejected."));
        let request = input.request();
        assert!(
            request
                .authentication_data
                .master_password_authentication_hash
                .expose_secret()
                == "new-private-proof\0雪"
        );
        assert!(
            request
                .unlock_data
                .master_key_wrapped_user_key
                .expose_secret()
                == "new-private-key\0雪"
        );
        let debug = format!("{request:?}");
        for secret in ["old-private-proof", "new-private-proof", "new-private-key"] {
            assert!(
                !debug.contains(secret),
                "KDF request Debug exposed a secret."
            );
        }
        let aliases = br#"{"authenticationData":{"Salt":"a","Kdf":{"kdfType":-7,"iterations":-8,"memory":-9,"parallelism":-10},"MasterPasswordAuthenticationHash":""},"unlockData":{"salt":"a","kdf":{"kdfType":-7,"iterations":-8,"memory":-9,"parallelism":-10},"masterKeyWrappedUserKey":""},"masterPasswordHash":""}"#;
        assert!(parse(aliases).is_ok());
        assert!(
            parse(br#"[["a",[0,100000,null,null],"new"],["a",[0,100000,null,null],"key"],"old"]"#)
                .is_ok()
        );
        for (location, field, replacement) in [
            ("", "authenticationData", "AuthenticationData"),
            ("", "unlockData", "UnlockData"),
            ("", "masterPasswordHash", "MasterPasswordHash"),
            (
                "authenticationData",
                "masterPasswordAuthenticationHash",
                "hash",
            ),
            ("unlockData", "salt", "Salt"),
            ("unlockData", "kdf", "Kdf"),
            ("unlockData", "masterKeyWrappedUserKey", "key"),
        ] {
            let mut value = document();
            let object = if location.is_empty() {
                &mut value
            } else {
                &mut value[location]
            };
            let fields = object.as_object_mut().unwrap();
            let old = fields.remove(field).unwrap();
            fields.insert(replacement.into(), old);
            let Err(error) = parse(&serde_json::to_vec(&value).unwrap()) else {
                panic!("Unsupported KDF alias accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
        for body in [
            b"{}".as_slice(), b"[]", br#"{"kdf":0,"kdfIterations":100000,"masterPasswordHash":"old","newMasterPasswordHash":"new","key":"key"}"#,
            br#"{"authenticationData":null,"unlockData":{},"masterPasswordHash":"old"}"#,
            br#"[["a",[0,100000],"new"],["a",[0,100000,null,null],"key"],"old"]"#,
            br#"[["a",[2147483648,100000,null,null],"new"],["a",[0,100000,null,null],"key"],"old"]"#,
            br#"{"authenticationData":{"salt":"a","Salt":"a","kdf":{"kdf":0,"kdfIterations":100000},"masterPasswordAuthenticationHash":"new"},"unlockData":{"salt":"a","kdf":{"kdf":0,"kdfIterations":100000},"masterKeyWrappedUserKey":"key"},"masterPasswordHash":"old"}"#,
            br#"{"authenticationData":{"salt":"a","kdf":{"kdf":0,"kdfType":0,"kdfIterations":100000},"masterPasswordAuthenticationHash":"new"},"unlockData":{"salt":"a","kdf":{"kdf":0,"kdfIterations":100000},"masterKeyWrappedUserKey":"key"},"masterPasswordHash":"old"}"#,
        ] {
            let Err(error) = parse(body) else { panic!("Invalid KDF schema accepted.") };
            assert_eq!(error.0,StatusCode::UNPROCESSABLE_ENTITY);
        }
        for body in [
            b"{".as_slice(),
            br#"[["a",[0,100000,null,null],"new"],["a",[0,100000,null,null],"key"],"old",null]"#,
        ] {
            let Err(error) = parse(body) else {
                panic!("Invalid KDF syntax accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
    }
}
