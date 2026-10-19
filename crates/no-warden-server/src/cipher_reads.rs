//! The three cipher read routes share Rocket's UUID path guard.

use crate::Failure;
use axum::http::StatusCode;

pub(crate) fn path_id(raw: &str) -> Result<String, Failure> {
    // Reuse the existing, tested one-pass Rocket UUID decoder. Only the public
    // route-specific error text differs; neither decoder normalizes UUIDs.
    crate::auth_requests::path_id(raw)
        .map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid cipher ID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_read_uuid_guard_decodes_once_and_retains_accepted_spelling() {
        for (raw, expected) in [
            (
                "%31%32%33e4567-e89b-42d3-a456-426614174000",
                "123e4567-e89b-42d3-a456-426614174000",
            ),
            (
                "123E4567-E89B-42D3-A456-426614174000",
                "123E4567-E89B-42D3-A456-426614174000",
            ),
            (
                "123e4567e89b42d3a456426614174000",
                "123e4567e89b42d3a456426614174000",
            ),
            (
                "%7B123e4567-e89b-42d3-a456-426614174000%7D",
                "{123e4567-e89b-42d3-a456-426614174000}",
            ),
            (
                "urn%3Auuid%3A123e4567-e89b-42d3-a456-426614174000",
                "urn:uuid:123e4567-e89b-42d3-a456-426614174000",
            ),
        ] {
            assert!(
                path_id(raw).unwrap_or_else(|_| panic!("Valid cipher UUID rejected.")) == expected
            );
        }
        for raw in [
            "",
            "purge",
            "%2531%2532%2533e4567-e89b-42d3-a456-426614174000",
            "%ff",
            "bad%",
            "123e4567-e89b-42d3-a456-426614174000%2Fother",
        ] {
            let Err(error) = path_id(raw) else {
                panic!("Invalid cipher UUID accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
            assert!(error.1 == "Invalid cipher ID");
        }
    }
}
