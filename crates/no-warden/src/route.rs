//! HTTP routing without a server framework or allocation.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Options,
}

impl Method {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            "PUT" => Some(Self::Put),
            "DELETE" => Some(Self::Delete),
            "OPTIONS" => Some(Self::Options),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route<'a> {
    Config,
    Prelogin,
    Register,
    Profile,
    UserKeyId,
    RevisionDate,
    Token,
    Sync,
    Folders,
    FolderCreate,
    FolderGet(&'a str),
    FolderUpdate(&'a str),
    FolderDelete(&'a str),
    Ciphers,
    CipherCreate,
    CipherGet(&'a str),
    CipherUpdate(&'a str),
    CipherSoftDelete(&'a str),
    CipherRestore(&'a str),
    CipherDelete(&'a str),
}

impl Route<'_> {
    pub const fn requires_authentication(self) -> bool {
        !matches!(
            self,
            Self::Config | Self::Prelogin | Self::Register | Self::Token
        )
    }
}

/// Classify an origin-form URI. Query parameters and a trailing slash are accepted.
/// IDs are returned as slices of the original URI; URL decoding belongs to the adapter.
pub fn classify(method: Method, uri: &str) -> Option<Route<'_>> {
    use Method::*;
    use Route::*;
    let path = uri.split_once('?').map_or(uri, |(path, _)| path);
    let path = path.strip_suffix('/').unwrap_or(path);
    match (method, path) {
        (Get, "/api/config") => Some(Config),
        (
            Post,
            "/api/accounts/prelogin"
            | "/identity/accounts/prelogin"
            | "/identity/accounts/prelogin/password",
        ) => Some(Prelogin),
        (Post, "/api/accounts/register") => Some(Register),
        (Get, "/api/accounts/profile") => Some(Profile),
        (Post, "/api/accounts/key-management/user-key-id") => Some(UserKeyId),
        (Get, "/api/accounts/revision-date") => Some(RevisionDate),
        (Post, "/identity/connect/token") => Some(Token),
        (Get, "/api/sync") => Some(Sync),
        (Get, "/api/folders") => Some(Folders),
        (Post, "/api/folders") => Some(FolderCreate),
        (Get, "/api/ciphers") => Some(Ciphers),
        (Post, "/api/ciphers") => Some(CipherCreate),
        _ => {
            if let Some(tail) = path.strip_prefix("/api/folders/") {
                if valid_segment(tail) {
                    return match method {
                        Get => Some(FolderGet(tail)),
                        Put => Some(FolderUpdate(tail)),
                        Delete => Some(FolderDelete(tail)),
                        _ => None,
                    };
                }
            }
            let tail = path.strip_prefix("/api/ciphers/")?;
            if let Some((id, action)) = tail.split_once('/') {
                if !valid_segment(id) {
                    return None;
                }
                return match (method, action) {
                    (Put, "delete") => Some(CipherSoftDelete(id)),
                    (Post, "delete") => Some(CipherDelete(id)),
                    (Put | Post, "restore") => Some(CipherRestore(id)),
                    _ => None,
                };
            }
            if !valid_segment(tail) {
                return None;
            }
            match method {
                Get => Some(CipherGet(tail)),
                Put | Post => Some(CipherUpdate(tail)),
                Delete => Some(CipherDelete(tail)),
                _ => None,
            }
        }
    }
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_authentication_and_actions() {
        assert_eq!(
            classify(Method::Post, "/api/ciphers/item-id"),
            Some(Route::CipherUpdate("item-id"))
        );
        assert_eq!(
            classify(Method::Get, "/api/sync?excludeDomains=true"),
            Some(Route::Sync)
        );
        assert_eq!(
            classify(Method::Put, "/api/ciphers/abc-123/delete"),
            Some(Route::CipherSoftDelete("abc-123"))
        );
        assert_eq!(
            classify(Method::Post, "/api/ciphers/abc-123/delete"),
            Some(Route::CipherDelete("abc-123"))
        );
        assert_eq!(
            classify(Method::Get, "/api/folders/abc/"),
            Some(Route::FolderGet("abc"))
        );
        assert!(!Route::Prelogin.requires_authentication());
        assert!(Route::Sync.requires_authentication());
        assert_eq!(
            classify(Method::Post, "/api/accounts/key-management/user-key-id"),
            Some(Route::UserKeyId)
        );
        assert!(Route::UserKeyId.requires_authentication());
        for path in [
            "/api/ciphers/../delete",
            "/api/ciphers//restore",
            "/api/folders/a/b",
            "/api/ciphers/a%2fb",
        ] {
            assert_eq!(classify(Method::Get, path), None);
        }
        assert_eq!(classify(Method::Get, "/identity/connect/token"), None);
    }
}
