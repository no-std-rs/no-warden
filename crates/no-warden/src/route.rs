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
    AccountApiKey,
    AccountRotateApiKey,
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
    CipherCreateWrapped,
    CipherImport,
    CipherBulkTrash,
    CipherBulkRestore,
    CipherBulkDelete,
    CipherBulkArchive,
    CipherBulkUnarchive,
    CipherGet(&'a str),
    CipherUpdate(&'a str),
    CipherSoftDelete(&'a str),
    CipherRestore(&'a str),
    CipherDelete(&'a str),
    CipherArchive(&'a str),
    CipherUnarchive(&'a str),
    AttachmentReserve(&'a str),
    AttachmentUpload(&'a str, &'a str),
    AttachmentLegacy(&'a str),
    AttachmentLegacyReplace(&'a str, &'a str),
    AttachmentGet(&'a str, &'a str),
    AttachmentDelete(&'a str, &'a str),
    AttachmentDownload(&'a str, &'a str),
}

impl Route<'_> {
    /// Whether the adapter must verify a bearer. Attachment downloads instead require
    /// the scoped capability checked by `VaultService::authorize_attachment_download`.
    pub const fn requires_authentication(self) -> bool {
        !matches!(
            self,
            Self::Config
                | Self::Prelogin
                | Self::Register
                | Self::Token
                | Self::AttachmentDownload(_, _)
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
    if let Some(tail) = path.strip_prefix("/attachments/") {
        let (cipher, attachment) = tail.split_once('/')?;
        return (method == Get && valid_segment(cipher) && valid_segment(attachment))
            .then_some(AttachmentDownload(cipher, attachment));
    }
    match (method, path) {
        (Get, "/api/config") => Some(Config),
        (
            Post,
            "/api/accounts/prelogin"
            | "/identity/accounts/prelogin"
            | "/identity/accounts/prelogin/password",
        ) => Some(Prelogin),
        (Post, "/api/accounts/register") => Some(Register),
        (Post, "/api/accounts/api-key") => Some(AccountApiKey),
        (Post, "/api/accounts/rotate-api-key") => Some(AccountRotateApiKey),
        (Get, "/api/accounts/profile") => Some(Profile),
        (Post, "/api/accounts/key-management/user-key-id") => Some(UserKeyId),
        (Get, "/api/accounts/revision-date") => Some(RevisionDate),
        (Post, "/identity/connect/token") => Some(Token),
        (Get, "/api/sync") => Some(Sync),
        (Get, "/api/folders") => Some(Folders),
        (Post, "/api/folders") => Some(FolderCreate),
        (Get, "/api/ciphers") => Some(Ciphers),
        (Post, "/api/ciphers") => Some(CipherCreate),
        (Post, "/api/ciphers/create") => Some(CipherCreateWrapped),
        (_, "/api/ciphers/create") => None,
        (Post, "/api/ciphers/import") => Some(CipherImport),
        (_, "/api/ciphers/import") => None,
        (Delete, "/api/ciphers" | "/api/ciphers/admin") => Some(CipherBulkDelete),
        (Post, "/api/ciphers/delete" | "/api/ciphers/delete-admin") => Some(CipherBulkDelete),
        (Put, "/api/ciphers/delete" | "/api/ciphers/delete-admin") => Some(CipherBulkTrash),
        (Put, "/api/ciphers/restore" | "/api/ciphers/restore-admin") => Some(CipherBulkRestore),
        (Put, "/api/ciphers/archive") => Some(CipherBulkArchive),
        (Put, "/api/ciphers/unarchive") => Some(CipherBulkUnarchive),
        (
            _,
            "/api/ciphers/admin"
            | "/api/ciphers/delete"
            | "/api/ciphers/delete-admin"
            | "/api/ciphers/restore"
            | "/api/ciphers/restore-admin"
            | "/api/ciphers/archive"
            | "/api/ciphers/unarchive",
        ) => None,
        _ => {
            if let Some(tail) = path.strip_prefix("/api/folders/") {
                if let Some((id, "delete")) = tail.split_once('/') {
                    return if method == Post && valid_segment(id) {
                        Some(FolderDelete(id))
                    } else {
                        None
                    };
                }
                if valid_segment(tail) {
                    return match method {
                        Get => Some(FolderGet(tail)),
                        Put | Post => Some(FolderUpdate(tail)),
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
                if action == "attachment" || action == "attachment-admin" {
                    return (method == Post).then_some(AttachmentLegacy(id));
                }
                if let Some(attachment) = action.strip_prefix("attachment/") {
                    if attachment == "v2" {
                        return (method == Post).then_some(AttachmentReserve(id));
                    }
                    if let Some((attachment, suffix)) = attachment.split_once('/') {
                        if !valid_segment(attachment) {
                            return None;
                        }
                        return match (method, suffix) {
                            (Post, "share") => Some(AttachmentLegacyReplace(id, attachment)),
                            (Post, "delete" | "delete-admin") | (Delete, "admin") => {
                                Some(AttachmentDelete(id, attachment))
                            }
                            _ => None,
                        };
                    }
                    if !valid_segment(attachment) {
                        return None;
                    }
                    return match method {
                        Get => Some(AttachmentGet(id, attachment)),
                        Post => Some(AttachmentUpload(id, attachment)),
                        Delete => Some(AttachmentDelete(id, attachment)),
                        _ => None,
                    };
                }
                return match (method, action) {
                    (Put, "delete") => Some(CipherSoftDelete(id)),
                    (Post, "delete") => Some(CipherDelete(id)),
                    (Put | Post, "restore") => Some(CipherRestore(id)),
                    (Put, "archive") => Some(CipherArchive(id)),
                    (Put, "unarchive") => Some(CipherUnarchive(id)),
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
    fn attachment_routes_keep_admin_aliases_and_scoped_download_authentication_distinct() {
        use Method::*;
        use Route::*;
        let cases = [
            (
                Post,
                "/api/ciphers/cipher/attachment/v2",
                AttachmentReserve("cipher"),
            ),
            (
                Post,
                "/api/ciphers/cipher/attachment/file",
                AttachmentUpload("cipher", "file"),
            ),
            (
                Get,
                "/api/ciphers/cipher/attachment/file",
                AttachmentGet("cipher", "file"),
            ),
            (
                Post,
                "/api/ciphers/cipher/attachment",
                AttachmentLegacy("cipher"),
            ),
            (
                Post,
                "/api/ciphers/cipher/attachment-admin",
                AttachmentLegacy("cipher"),
            ),
            (
                Post,
                "/api/ciphers/cipher/attachment/file/share",
                AttachmentLegacyReplace("cipher", "file"),
            ),
            (
                Post,
                "/api/ciphers/cipher/attachment/file/delete",
                AttachmentDelete("cipher", "file"),
            ),
            (
                Post,
                "/api/ciphers/cipher/attachment/file/delete-admin",
                AttachmentDelete("cipher", "file"),
            ),
            (
                Delete,
                "/api/ciphers/cipher/attachment/file",
                AttachmentDelete("cipher", "file"),
            ),
            (
                Delete,
                "/api/ciphers/cipher/attachment/file/admin",
                AttachmentDelete("cipher", "file"),
            ),
            (
                Get,
                "/attachments/cipher/file?token=not-logged",
                AttachmentDownload("cipher", "file"),
            ),
        ];
        for (method, path, expected) in cases {
            assert_eq!(classify(method, path), Some(expected));
            assert_eq!(
                expected.requires_authentication(),
                !matches!(expected, AttachmentDownload(_, _))
            );
        }
        for path in [
            "/api/ciphers/cipher/attachment",
            "/api/ciphers/cipher/attachment-admin",
            "/api/ciphers/cipher/attachment/v2",
            "/api/ciphers/cipher/attachment/file",
            "/api/ciphers/cipher/attachment/file/share",
            "/api/ciphers/cipher/attachment/file/delete",
            "/api/ciphers/cipher/attachment/file/delete-admin",
            "/api/ciphers/cipher/attachment/file/admin",
            "/attachments/cipher/file?token=not-logged",
        ] {
            for method in [Get, Post, Put, Delete, Options] {
                if !cases
                    .iter()
                    .any(|(allowed, known, _)| method == *allowed && path == *known)
                {
                    assert_eq!(classify(method, path), None);
                }
            }
        }
        for path in [
            "/attachments/../file",
            "/attachments/cipher/../file",
            "/attachments/cipher/a%2fb",
            "/api/ciphers/cipher/attachment/../delete",
            "/api/ciphers/cipher/attachment/file/delete/extra",
        ] {
            assert_eq!(classify(Get, path), None);
            assert_eq!(classify(Post, path), None);
        }
    }
    #[test]
    fn api_key_management_is_authenticated_and_post_only() {
        for (path, expected) in [
            ("/api/accounts/api-key", Route::AccountApiKey),
            ("/api/accounts/rotate-api-key", Route::AccountRotateApiKey),
        ] {
            assert_eq!(classify(Method::Post, path), Some(expected));
            assert!(expected.requires_authentication());
            for method in [Method::Get, Method::Put, Method::Delete, Method::Options] {
                assert_eq!(classify(method, path), None);
            }
        }
    }
    #[test]
    fn selected_lifecycle_and_archive_routes_require_authentication_without_admin_bypass() {
        use Method::*;
        use Route::*;
        let cases = [
            (Delete, "/api/ciphers", CipherBulkDelete),
            (Post, "/api/ciphers/delete", CipherBulkDelete),
            (Put, "/api/ciphers/delete", CipherBulkTrash),
            (Delete, "/api/ciphers/admin", CipherBulkDelete),
            (Post, "/api/ciphers/delete-admin", CipherBulkDelete),
            (Put, "/api/ciphers/delete-admin", CipherBulkTrash),
            (Put, "/api/ciphers/restore", CipherBulkRestore),
            (Put, "/api/ciphers/restore-admin", CipherBulkRestore),
            (Put, "/api/ciphers/archive", CipherBulkArchive),
            (Put, "/api/ciphers/unarchive", CipherBulkUnarchive),
            (Put, "/api/ciphers/item/archive", CipherArchive("item")),
            (Put, "/api/ciphers/item/unarchive", CipherUnarchive("item")),
        ];
        for (method, path, expected) in cases {
            assert_eq!(classify(method, path), Some(expected));
            assert!(expected.requires_authentication());
        }
        for path in [
            "/api/ciphers/admin",
            "/api/ciphers/delete",
            "/api/ciphers/delete-admin",
            "/api/ciphers/restore",
            "/api/ciphers/restore-admin",
            "/api/ciphers/archive",
            "/api/ciphers/unarchive",
            "/api/ciphers/item/archive",
            "/api/ciphers/item/unarchive",
        ] {
            for method in [Get, Post, Put, Delete, Options] {
                if !cases
                    .iter()
                    .any(|(allowed, known, _)| *allowed == method && *known == path)
                {
                    assert_eq!(classify(method, path), None);
                }
            }
        }
    }
    #[test]
    fn routes_authentication_and_actions() {
        assert_eq!(
            classify(Method::Post, "/api/folders/folder-id"),
            Some(Route::FolderUpdate("folder-id"))
        );
        assert_eq!(
            classify(Method::Post, "/api/folders/folder-id/delete"),
            Some(Route::FolderDelete("folder-id"))
        );
        assert_eq!(classify(Method::Post, "/api/folders/../delete"), None);
        assert_eq!(
            classify(Method::Post, "/api/ciphers/create"),
            Some(Route::CipherCreateWrapped)
        );
        for method in [Method::Get, Method::Put, Method::Delete] {
            assert_eq!(classify(method, "/api/ciphers/create"), None);
            assert_eq!(classify(method, "/api/ciphers/import"), None);
        }
        assert_eq!(
            classify(Method::Post, "/api/ciphers/import"),
            Some(Route::CipherImport)
        );
        assert!(Route::CipherImport.requires_authentication());
        assert_eq!(classify(Method::Post, "/api/import-ciphers"), None);
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
