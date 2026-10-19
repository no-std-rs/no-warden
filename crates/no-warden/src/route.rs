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
    RegistrationVerification,
    RegistrationFinish,
    AccountApiKey,
    AccountRotateApiKey,
    AccountVerifyPassword,
    AccountSecurityStamp,
    AccountKdfChange,
    AccountPasswordChange,
    AccountDelete,
    AccountKeysGet,
    AccountKeysInitialize,
    UserPublicKey(&'a str),
    WebAuthnCredentials,
    Profile,
    ProfileUpdate,
    AvatarUpdate,
    UserKeyId,
    RevisionDate,
    Token,
    AuthRequestCreate,
    AuthRequests,
    AuthRequestGet(&'a str),
    AuthRequestUpdate(&'a str),
    AuthRequestResponse(&'a str),
    Sync,
    SendList,
    SendGet(&'a str),
    SendCreate,
    SendUpdate(&'a str),
    SendDelete(&'a str),
    SendRemovePassword(&'a str),
    SendAccess,
    SendFileCreate,
    SendFileUpload(&'a str, &'a str),
    SendFileAccess(&'a str),
    SendFileDownload(&'a str, &'a str),
    KnownDevice,
    Devices,
    DeviceGet(&'a str),
    DevicePushToken(&'a str),
    DevicePushClear(&'a str),
    DomainsGet,
    DomainsUpdate,
    Folders,
    FolderCreate,
    FolderGet(&'a str),
    FolderUpdate(&'a str),
    FolderDelete(&'a str),
    Ciphers,
    CipherCreate,
    CipherCreateWrapped,
    CipherImport,
    CipherPurge,
    CipherBulkTrash,
    CipherBulkRestore,
    CipherBulkDelete,
    CipherBulkArchive,
    CipherBulkUnarchive,
    CipherGet(&'a str),
    CipherDetails(&'a str),
    CipherAdmin(&'a str),
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
                | Self::RegistrationVerification
                | Self::RegistrationFinish
                | Self::Token
                | Self::SendAccess
                | Self::SendFileAccess(_)
                | Self::SendFileDownload(_, _)
                | Self::AuthRequestCreate
                | Self::AuthRequestResponse(_)
                | Self::KnownDevice
                | Self::DevicePushClear(_)
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
        (
            Get,
            "/api/ciphers/create"
            | "/api/ciphers/import"
            | "/api/ciphers/purge"
            | "/api/ciphers/admin"
            | "/api/ciphers/delete"
            | "/api/ciphers/delete-admin"
            | "/api/ciphers/restore"
            | "/api/ciphers/restore-admin"
            | "/api/ciphers/archive"
            | "/api/ciphers/unarchive",
        ) => path.strip_prefix("/api/ciphers/").map(CipherGet),
        (Get, "/api/config") => Some(Config),
        (
            Post,
            "/api/accounts/prelogin"
            | "/identity/accounts/prelogin"
            | "/identity/accounts/prelogin/password",
        ) => Some(Prelogin),
        (Post, "/api/accounts/register") => Some(Register),
        (Post, "/identity/accounts/register/send-verification-email") => {
            Some(RegistrationVerification)
        }
        (Post, "/identity/accounts/register/finish") => Some(RegistrationFinish),
        (Post, "/api/accounts/api-key") => Some(AccountApiKey),
        (Post, "/api/accounts/rotate-api-key") => Some(AccountRotateApiKey),
        (Post, "/api/accounts/verify-password") => Some(AccountVerifyPassword),
        (Post, "/api/accounts/security-stamp") => Some(AccountSecurityStamp),
        (Post, "/api/accounts/kdf") => Some(AccountKdfChange),
        (Post, "/api/accounts/password") => Some(AccountPasswordChange),
        (Delete, "/api/accounts") | (Post, "/api/accounts/delete") => Some(AccountDelete),
        (Get, "/api/accounts/keys") => Some(AccountKeysGet),
        (Post, "/api/accounts/keys") => Some(AccountKeysInitialize),
        (Get, "/api/webauthn") => Some(WebAuthnCredentials),
        (Get, "/api/accounts/profile") => Some(Profile),
        (Put | Post, "/api/accounts/profile") => Some(ProfileUpdate),
        (Put, "/api/accounts/avatar") => Some(AvatarUpdate),
        (Post, "/api/accounts/key-management/user-key-id") => Some(UserKeyId),
        (Get, "/api/accounts/revision-date") => Some(RevisionDate),
        (Post, "/identity/connect/token") => Some(Token),
        (Post, "/api/auth-requests") => Some(AuthRequestCreate),
        (Get, "/api/auth-requests" | "/api/auth-requests/pending") => Some(AuthRequests),
        (Get, "/api/sync") => Some(Sync),
        (Get, "/api/sends") => Some(SendList),
        (Post, "/api/sends") => Some(SendCreate),
        (Post, "/api/sends/access") => Some(SendAccess),
        (Post, "/api/sends/file/v2") => Some(SendFileCreate),
        (Get, "/api/devices/knowndevice") => Some(KnownDevice),
        (Get, "/api/devices") => Some(Devices),
        (Get, "/api/settings/domains") => Some(DomainsGet),
        (Post | Put, "/api/settings/domains") => Some(DomainsUpdate),
        (Get, "/api/folders") => Some(Folders),
        (Post, "/api/folders") => Some(FolderCreate),
        (Get, "/api/ciphers") => Some(Ciphers),
        (Post, "/api/ciphers") => Some(CipherCreate),
        (Post, "/api/ciphers/create") => Some(CipherCreateWrapped),
        (_, "/api/ciphers/create") => None,
        (Post, "/api/ciphers/import") => Some(CipherImport),
        (_, "/api/ciphers/import") => None,
        (Post, "/api/ciphers/purge") => Some(CipherPurge),
        (_, "/api/ciphers/purge") => None,
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
            if let Some(tail) = path.strip_prefix("/api/sends/") {
                if let Some(file_id) = tail.strip_prefix("access/file/") {
                    return (method == Post && !file_id.is_empty() && !file_id.contains('/'))
                        .then_some(SendFileAccess(file_id));
                }
                if let Some((id, action)) = tail.split_once('/') {
                    if id.is_empty() {
                        return None;
                    }
                    if method == Put && action == "remove-password" {
                        return Some(SendRemovePassword(id));
                    }
                    if let Some(file_id) = action.strip_prefix("file/") {
                        return (method == Post && !file_id.is_empty() && !file_id.contains('/'))
                            .then_some(SendFileUpload(id, file_id));
                    }
                    return (method == Get && !action.is_empty() && !action.contains('/'))
                        .then_some(SendFileDownload(id, action));
                }
                if tail.is_empty() {
                    return None;
                }
                // The adapter applies the source UUID guard after authentication.
                return match method {
                    Get => Some(SendGet(tail)),
                    Put => Some(SendUpdate(tail)),
                    Delete => Some(SendDelete(tail)),
                    _ => None,
                };
            }
            if let Some(id) = path.strip_prefix("/api/auth-requests/") {
                // UUID/query guards belong to the adapter, with route-specific authentication.
                if let Some((id, action)) = id.split_once('/') {
                    return (method == Get && !id.is_empty() && action == "response")
                        .then_some(AuthRequestResponse(id));
                }
                if id.is_empty() {
                    return None;
                }
                return match method {
                    Get => Some(AuthRequestGet(id)),
                    Put => Some(AuthRequestUpdate(id)),
                    _ => None,
                };
            }
            if let Some(identifier) = path.strip_prefix("/api/devices/identifier/") {
                // The adapter percent-decodes and applies upstream IdFromParam.
                // Capture invalid values too so that guard can return 422 rather than 404.
                if let Some((identifier, action)) = identifier.split_once('/') {
                    if identifier.is_empty() {
                        return None;
                    }
                    return match (method, action) {
                        (Post | Put, "token") => Some(DevicePushToken(identifier)),
                        (Post | Put, "clear-token") => Some(DevicePushClear(identifier)),
                        _ => None,
                    };
                }
                return (method == Get && !identifier.is_empty()).then_some(DeviceGet(identifier));
            }
            if let Some(tail) = path.strip_prefix("/api/users/") {
                let (id, "public-key") = tail.split_once('/')? else {
                    return None;
                };
                return (method == Get && valid_segment(id)).then_some(UserPublicKey(id));
            }
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
                if method == Get && !id.is_empty() {
                    match action {
                        "details" => return Some(CipherDetails(id)),
                        "admin" => return Some(CipherAdmin(id)),
                        _ => {}
                    }
                }
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
            // HTTP adapters decode and apply the UUID guard after authentication.
            if method == Get && !tail.is_empty() {
                return Some(CipherGet(tail));
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
    fn file_send_routes_keep_owner_uploads_and_scoped_recipient_downloads_distinct() {
        for (method, path, expected, owner_authenticated) in [
            (
                Method::Post,
                "/api/sends/file/v2",
                Route::SendFileCreate,
                true,
            ),
            (
                Method::Post,
                "/api/sends/raw/file/opaque-file",
                Route::SendFileUpload("raw", "opaque-file"),
                true,
            ),
            (
                Method::Post,
                "/api/sends/access/file/opaque-file",
                Route::SendFileAccess("opaque-file"),
                false,
            ),
            (
                Method::Get,
                "/api/sends/raw/opaque-file",
                Route::SendFileDownload("raw", "opaque-file"),
                false,
            ),
        ] {
            assert_eq!(classify(method, path), Some(expected));
            assert_eq!(
                classify(method, &std::format!("{path}/?t=opaque")),
                Some(expected)
            );
            assert_eq!(expected.requires_authentication(), owner_authenticated);
        }
        for (method, path) in [
            (Method::Put, "/api/sends/file/v2"),
            (Method::Get, "/api/sends/raw/file/opaque-file"),
            (Method::Post, "/api/sends/raw/opaque-file"),
            (Method::Post, "/api/sends/access/file/"),
            (Method::Post, "/api/sends/raw/file/id/extra"),
            (Method::Get, "/api/sends//file"),
        ] {
            assert_eq!(classify(method, path), None);
        }
        assert_eq!(
            classify(Method::Get, "/api/sends/raw/remove-password"),
            Some(Route::SendFileDownload("raw", "remove-password"))
        );
    }

    #[test]
    fn text_send_routes_preserve_source_methods_and_separate_recipient_authority() {
        for (method, path, route) in [
            (Method::Get, "/api/sends", Route::SendList),
            (Method::Post, "/api/sends", Route::SendCreate),
            (Method::Get, "/api/sends/%41raw", Route::SendGet("%41raw")),
            (Method::Put, "/api/sends/raw", Route::SendUpdate("raw")),
            (Method::Delete, "/api/sends/raw", Route::SendDelete("raw")),
            (
                Method::Put,
                "/api/sends/raw/remove-password",
                Route::SendRemovePassword("raw"),
            ),
            (Method::Post, "/api/sends/access", Route::SendAccess),
        ] {
            assert_eq!(classify(method, path), Some(route));
            assert_eq!(
                classify(method, &std::format!("{path}/?ignored=true")),
                Some(route)
            );
            assert_eq!(route.requires_authentication(), route != Route::SendAccess);
        }
        // These match source dynamic UUID routes; the adapter returns the guard status.
        assert_eq!(
            classify(Method::Get, "/api/sends/access"),
            Some(Route::SendGet("access"))
        );
        for (method, path) in [
            (Method::Post, "/api/sends/raw"),
            (Method::Post, "/api/sends/raw/remove-password"),
            (Method::Delete, "/api/sends"),
            (Method::Put, "/api/sends/raw/Remove-Password"),
            (Method::Get, "/api/sends//remove-password"),
        ] {
            assert!(classify(method, path).is_none());
        }
    }

    #[test]
    fn cipher_read_aliases_require_authentication_and_preserve_raw_uuid_guard_inputs() {
        for id in ["ABCdef-123", "%41BCdef-123", "not:a:uuid", "%2F", "."] {
            for (suffix, expected) in [
                ("", Route::CipherGet(id)),
                ("/details", Route::CipherDetails(id)),
                ("/admin", Route::CipherAdmin(id)),
            ] {
                let path = std::format!("/api/ciphers/{id}{suffix}");
                assert_eq!(classify(Method::Get, &path), Some(expected));
                assert_eq!(
                    classify(Method::Get, &std::format!("{path}/?ignored=true")),
                    Some(expected)
                );
                assert!(expected.requires_authentication());
                if !suffix.is_empty() {
                    for method in [Method::Post, Method::Put, Method::Delete, Method::Options] {
                        assert!(classify(method, &path).is_none());
                    }
                }
            }
        }
        for literal in [
            "create",
            "import",
            "purge",
            "admin",
            "delete",
            "delete-admin",
            "restore",
            "restore-admin",
            "archive",
            "unarchive",
        ] {
            let path = std::format!("/api/ciphers/{literal}");
            assert_eq!(
                classify(Method::Get, &path),
                Some(Route::CipherGet(literal))
            );
        }
        for path in [
            "/api/ciphers//details",
            "/api/ciphers//admin",
            "/api/ciphers/id/details/extra",
            "/api/ciphers/id/Admin",
            "/api/ciphers/id/Details",
        ] {
            assert!(classify(Method::Get, path).is_none());
        }
    }

    #[test]
    fn account_deletion_aliases_require_authentication_and_preserve_exact_methods() {
        for (method, path) in [
            (Method::Delete, "/api/accounts"),
            (Method::Post, "/api/accounts/delete"),
        ] {
            assert_eq!(classify(method, path), Some(Route::AccountDelete));
            assert_eq!(
                classify(method, &std::format!("{path}/?ignored=true")),
                Some(Route::AccountDelete)
            );
            assert!(Route::AccountDelete.requires_authentication());
            for wrong in [
                Method::Get,
                Method::Post,
                Method::Put,
                Method::Delete,
                Method::Options,
            ] {
                if wrong != method {
                    assert!(classify(wrong, path).is_none());
                }
            }
            assert!(classify(method, &std::format!("{path}/extra")).is_none());
        }
        assert!(classify(Method::Post, "/api/accounts/Delete").is_none());
    }

    #[test]
    fn personal_vault_purge_is_authenticated_post_with_get_uuid_guard_and_reserved_mutations() {
        for path in [
            "/api/ciphers/purge",
            "/api/ciphers/purge/",
            "/api/ciphers/purge?organizationId=adapter-owned-selection",
        ] {
            assert_eq!(classify(Method::Post, path), Some(Route::CipherPurge));
            assert!(Route::CipherPurge.requires_authentication());
            assert_eq!(classify(Method::Get, path), Some(Route::CipherGet("purge")));
            for method in [Method::Put, Method::Delete, Method::Options] {
                assert!(classify(method, path).is_none());
            }
        }
        assert!(classify(Method::Post, "/api/ciphers/purge/extra").is_none());
        // The reserved lowercase action does not normalize opaque item identifiers.
        assert_eq!(
            classify(Method::Post, "/api/ciphers/Purge"),
            Some(Route::CipherUpdate("Purge"))
        );
    }

    #[test]
    fn webauthn_credential_metadata_is_authenticated_get_without_two_factor_aliases() {
        for path in [
            "/api/webauthn",
            "/api/webauthn/",
            "/api/webauthn?ignored=true",
            "/api/webauthn/?ignored=true",
        ] {
            assert_eq!(
                classify(Method::Get, path),
                Some(Route::WebAuthnCredentials)
            );
            assert!(Route::WebAuthnCredentials.requires_authentication());
            for method in [Method::Post, Method::Put, Method::Delete, Method::Options] {
                assert!(classify(method, path).is_none());
            }
        }
        for path in [
            "/api/WebAuthn",
            "/api/webauthn//",
            "/api/webauthn/extra",
            "/api/two-factor/get-webauthn",
            "/api/two-factor/webauthn",
        ] {
            assert!(classify(Method::Get, path).is_none());
        }
    }

    #[test]
    fn password_change_is_authenticated_post_with_query_and_trailing_slash() {
        for path in [
            "/api/accounts/password",
            "/api/accounts/password/?ignored=true",
        ] {
            let route = classify(Method::Post, path).unwrap();
            assert_eq!(route, Route::AccountPasswordChange);
            assert!(route.requires_authentication());
            for method in [Method::Get, Method::Put, Method::Delete, Method::Options] {
                assert!(classify(method, path).is_none());
            }
        }
        assert!(classify(Method::Post, "/api/accounts/password/extra").is_none());
    }

    #[test]
    fn registration_verification_and_finish_are_public_post_routes() {
        for (path, route) in [
            (
                "/identity/accounts/register/send-verification-email",
                Route::RegistrationVerification,
            ),
            (
                "/identity/accounts/register/finish",
                Route::RegistrationFinish,
            ),
        ] {
            assert_eq!(classify(Method::Post, path), Some(route));
            assert_eq!(
                classify(Method::Post, &std::format!("{path}/?ignored=true")),
                Some(route)
            );
            assert!(!route.requires_authentication());
            for method in [Method::Get, Method::Put, Method::Delete, Method::Options] {
                assert!(classify(method, path).is_none());
            }
            assert!(classify(Method::Post, &std::format!("{path}/extra")).is_none());
        }
    }

    #[test]
    fn auth_request_decisions_and_public_code_responses_preserve_route_specific_guards() {
        for (method, path, expected, authenticated) in [
            (
                Method::Put,
                "/api/auth-requests/Mixed-Case",
                Route::AuthRequestUpdate("Mixed-Case"),
                true,
            ),
            (
                Method::Put,
                "/api/auth-requests/invalid%2Fid",
                Route::AuthRequestUpdate("invalid%2Fid"),
                true,
            ),
            (
                Method::Put,
                "/api/auth-requests/pending",
                Route::AuthRequestUpdate("pending"),
                true,
            ),
            (
                Method::Get,
                "/api/auth-requests/Mixed-Case/response/?code=opaque%2Bcode",
                Route::AuthRequestResponse("Mixed-Case"),
                false,
            ),
            (
                Method::Get,
                "/api/auth-requests/id/response",
                Route::AuthRequestResponse("id"),
                false,
            ),
        ] {
            assert_eq!(classify(method, path), Some(expected));
            assert_eq!(expected.requires_authentication(), authenticated);
        }
        for method in [Method::Post, Method::Put, Method::Delete, Method::Options] {
            assert!(classify(method, "/api/auth-requests/id/response?code=x").is_none());
        }
        for method in [Method::Post, Method::Delete, Method::Options] {
            assert!(classify(method, "/api/auth-requests/id").is_none());
        }
        for path in [
            "/api/auth-requests//response",
            "/api/auth-requests/id/response/extra",
            "/api/auth-requests/id/unknown",
        ] {
            assert!(classify(Method::Get, path).is_none());
        }
    }

    #[test]
    fn auth_request_creation_and_discovery_routes_keep_public_and_authenticated_guards_distinct() {
        for (method, path, expected, authenticated) in [
            (
                Method::Post,
                "/api/auth-requests",
                Route::AuthRequestCreate,
                false,
            ),
            (Method::Get, "/api/auth-requests", Route::AuthRequests, true),
            (
                Method::Get,
                "/api/auth-requests/pending/?ignored=true",
                Route::AuthRequests,
                true,
            ),
            (
                Method::Get,
                "/api/auth-requests/ABCdef-123",
                Route::AuthRequestGet("ABCdef-123"),
                true,
            ),
            (
                Method::Get,
                "/api/auth-requests/invalid%2Fid",
                Route::AuthRequestGet("invalid%2Fid"),
                true,
            ),
        ] {
            assert_eq!(classify(method, path), Some(expected));
            assert_eq!(expected.requires_authentication(), authenticated);
        }
        for path in ["/api/auth-requests/pending", "/api/auth-requests/id"] {
            for method in [Method::Post, Method::Delete, Method::Options] {
                assert!(classify(method, path).is_none());
            }
        }
        for method in [Method::Put, Method::Delete, Method::Options] {
            assert!(classify(method, "/api/auth-requests").is_none());
        }
        for path in ["/api/auth-requests//", "/api/auth-requests/id/extra"] {
            assert!(classify(Method::Get, path).is_none());
        }
    }

    #[test]
    fn device_push_aliases_keep_session_updates_authenticated_and_public_clears_separate() {
        for method in [Method::Post, Method::Put] {
            for (action, expected, authenticated) in [
                ("token", Route::DevicePushToken("Different-Path"), true),
                (
                    "clear-token",
                    Route::DevicePushClear("Different-Path"),
                    false,
                ),
            ] {
                let path =
                    std::format!("/api/devices/identifier/Different-Path/{action}/?ignored=true");
                assert_eq!(classify(method, &path), Some(expected));
                assert_eq!(expected.requires_authentication(), authenticated);
                for wrong in [Method::Get, Method::Delete, Method::Options] {
                    assert!(classify(wrong, &path).is_none());
                }
            }
            assert_eq!(
                classify(method, "/api/devices/identifier/invalid%2Fid/token"),
                Some(Route::DevicePushToken("invalid%2Fid"))
            );
            assert_eq!(
                classify(method, "/api/devices/identifier/invalid_+/clear-token"),
                Some(Route::DevicePushClear("invalid_+"))
            );
            for path in [
                "/api/devices/identifier//token",
                "/api/devices/identifier/id/token/extra",
                "/api/devices/identifier/id/clear-token/extra",
                "/api/devices/identifier/id/unknown",
            ] {
                assert!(classify(method, path).is_none());
            }
        }
    }

    #[test]
    fn device_discovery_routes_keep_public_headers_and_authenticated_opaque_paths_distinct() {
        for (path, expected) in [
            ("/api/devices/knowndevice", Route::KnownDevice),
            ("/api/devices/?future=yes", Route::Devices),
            (
                "/api/devices/identifier/MixedCase-123",
                Route::DeviceGet("MixedCase-123"),
            ),
            ("/api/devices/identifier/%41%2b", Route::DeviceGet("%41%2b")),
            (
                "/api/devices/identifier/invalid_+",
                Route::DeviceGet("invalid_+"),
            ),
        ] {
            assert_eq!(classify(Method::Get, path), Some(expected));
            assert_eq!(
                expected.requires_authentication(),
                !matches!(expected, Route::KnownDevice)
            );
            for method in [Method::Post, Method::Put, Method::Delete, Method::Options] {
                assert_eq!(classify(method, path), None);
            }
        }
        for path in [
            "/api/devices/identifier/",
            "/api/devices/identifier/id/extra",
            "/api/devices/identifier/id/token",
            "/api/devices/unknown",
            "/api/devices/knowndevice/extra",
        ] {
            assert_eq!(classify(Method::Get, path), None);
        }
    }

    #[test]
    fn domain_settings_routes_require_authentication_and_preserve_method_aliases() {
        for (method, expected) in [
            (Method::Get, Route::DomainsGet),
            (Method::Post, Route::DomainsUpdate),
            (Method::Put, Route::DomainsUpdate),
        ] {
            assert_eq!(
                classify(method, "/api/settings/domains/?future=true"),
                Some(expected)
            );
            assert!(expected.requires_authentication());
        }
        for method in [Method::Delete, Method::Options] {
            assert!(classify(method, "/api/settings/domains").is_none());
        }
        for path in ["/api/settings/domains/extra", "/api/settings/unknown"] {
            assert!(classify(Method::Get, path).is_none());
        }
    }

    #[test]
    fn profile_and_avatar_mutation_routes_require_authentication_and_exact_methods() {
        for (method, path, expected) in [
            (Method::Put, "/api/accounts/profile", Route::ProfileUpdate),
            (
                Method::Post,
                "/api/accounts/profile/?future=true",
                Route::ProfileUpdate,
            ),
            (Method::Put, "/api/accounts/avatar", Route::AvatarUpdate),
            (
                Method::Post,
                "/api/accounts/verify-password/?future=true",
                Route::AccountVerifyPassword,
            ),
            (
                Method::Post,
                "/api/accounts/security-stamp",
                Route::AccountSecurityStamp,
            ),
            (Method::Post, "/api/accounts/kdf", Route::AccountKdfChange),
        ] {
            assert_eq!(classify(method, path), Some(expected));
            assert!(expected.requires_authentication());
        }
        assert_eq!(
            classify(Method::Get, "/api/accounts/profile"),
            Some(Route::Profile)
        );
        for method in [Method::Delete, Method::Options] {
            assert!(classify(method, "/api/accounts/profile").is_none());
        }
        for method in [Method::Get, Method::Post, Method::Delete, Method::Options] {
            assert!(classify(method, "/api/accounts/avatar").is_none());
        }
        for path in [
            "/api/accounts/verify-password",
            "/api/accounts/security-stamp",
            "/api/accounts/kdf",
        ] {
            for method in [Method::Get, Method::Put, Method::Delete, Method::Options] {
                assert!(classify(method, path).is_none());
            }
        }
        for path in [
            "/api/accounts/profile/unknown",
            "/api/accounts/avatar/unknown",
            "/api/accounts/avatar-update",
        ] {
            assert!(classify(Method::Put, path).is_none());
        }
    }

    #[test]
    fn account_key_routes_require_authentication_and_preserve_identifier_spelling() {
        for (method, path, expected) in [
            (Method::Get, "/api/accounts/keys", Route::AccountKeysGet),
            (
                Method::Post,
                "/api/accounts/keys",
                Route::AccountKeysInitialize,
            ),
            (
                Method::Get,
                "/api/users/ABCdef-123/public-key?ignored=true",
                Route::UserPublicKey("ABCdef-123"),
            ),
        ] {
            let route = classify(method, path).unwrap();
            assert_eq!(route, expected);
            assert!(route.requires_authentication());
        }
        for method in [Method::Put, Method::Delete, Method::Options] {
            assert!(classify(method, "/api/accounts/keys").is_none());
        }
        for method in [Method::Post, Method::Put, Method::Delete, Method::Options] {
            assert!(classify(method, "/api/users/ABCdef-123/public-key").is_none());
        }
        for path in [
            "/api/accounts/keys/unknown",
            "/api/users/public-key",
            "/api/users//public-key",
            "/api/users/../public-key",
            "/api/users/user/public-key/extra",
            "/api/users/user/private-key",
            "/api/users/user%2Fother/public-key",
        ] {
            assert!(classify(Method::Get, path).is_none());
        }
    }

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
                if method == Get && !path.strip_prefix("/api/ciphers/").unwrap().contains('/') {
                    assert!(matches!(classify(method, path), Some(CipherGet(_))));
                    continue;
                }
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
        assert_eq!(
            classify(Method::Get, "/api/ciphers/create"),
            Some(Route::CipherGet("create"))
        );
        assert_eq!(
            classify(Method::Get, "/api/ciphers/import"),
            Some(Route::CipherGet("import"))
        );
        for method in [Method::Put, Method::Delete] {
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
        ] {
            assert_eq!(classify(Method::Get, path), None);
        }
        assert_eq!(
            classify(Method::Get, "/api/ciphers/a%2fb"),
            Some(Route::CipherGet("a%2fb"))
        );
        assert_eq!(classify(Method::Get, "/identity/connect/token"), None);
    }
}
