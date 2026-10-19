//! Link a real bare-metal executable without a global allocator.
#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::{hint::black_box, panic::PanicInfo};
use no_warden::{
    auth_login::{AuthRequestLoginContext, AuthRequestLoginDevice, AuthRequestLoginRecord},
    auth_requests::{AuthRequestContext, AuthRequestRecord},
    devices::{DeviceRecord, PendingDeviceAuthRequest},
    domains::{DomainProjection, DomainSettingsView, GlobalDomain},
    identity::Secret,
    registration::RegistrationEmail,
    route::{Method, classify},
    service::ImportData,
    wire::{
        AccountKdfRequest, AccountKeys, AccountKeysResponse, AccountPasswordRequest,
        ApiKeyResponse, AttachmentRequest, AttachmentResponse, AttachmentUploadResponse,
        AuthRequestCreateRequest, AuthRequestListResponse, AuthRequestLoginRequest,
        AuthRequestResponse, AuthRequestUpdateRequest, AvatarUpdateRequest, CipherIdsRequest,
        CipherRequest, ClientCredentialsRequest, DeviceListResponse, DevicePushTokenRequest,
        DeviceResponse, DomainSettingsRequest, DomainSettingsResponse,
        DomainSettingsUpdateResponse, ImportRequest, InitializedAccountKeysResponse,
        KnownDeviceRequest, KnownDeviceResponse, MasterPasswordPolicy,
        MasterPasswordPolicyResponse, PasswordOrOtpRequest, PreloginRequest, PreloginResponse,
        ProfileUpdateRequest, RegistrationAuthentication, RegistrationCredentials,
        RegistrationFinishRequest, RegistrationFinishResponse, RegistrationUnlock,
        RegistrationVerificationRequest, RegistrationVerificationToken, SecretVerificationRequest,
        UserPublicKeyResponse,
    },
};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let input = black_box(br#"{"email":"bare-metal@example.com"}"#);
    let request = serde_json_core::from_slice::<PreloginRequest<'_>>(input);
    let _ = black_box(request);
    let registration = serde_json_core::from_slice::<RegistrationVerificationRequest<'_>>(input);
    let _ = black_box(registration);
    let authentication = serde_json_core::from_slice::<RegistrationAuthentication<'_>>(black_box(
        br#"{"kdf":{"kdf":0,"kdfIterations":100000},"salt":"bare-metal@example.com","hash":"opaque-proof"}"#,
    ));
    let unlock = serde_json_core::from_slice::<RegistrationUnlock<'_>>(black_box(
        br#"{"kdf":{"kdf":0,"kdfIterations":100000},"salt":"bare-metal@example.com","key":"opaque-wrapped-key"}"#,
    ));
    if let (Ok((authentication, _)), Ok((unlock, _))) = (authentication, unlock) {
        black_box(RegistrationFinishRequest {
            email: "bare-metal@example.com",
            credentials: RegistrationCredentials::Nested {
                authentication,
                unlock,
            },
            email_verification_token: Some(Secret::new("opaque-verification-token")),
            keys: None,
            master_password_hint: None,
        });
    }
    black_box(RegistrationEmail {
        storage_email: "bare-metal@example.com",
        salt_email: "bare-metal@example.com",
    });
    let mut registration_output = [0u8; 128];
    let _ = black_box(serde_json_core::to_slice(
        &RegistrationVerificationToken::new(black_box("opaque-verification-token")),
        &mut registration_output,
    ));
    let _ = black_box(serde_json_core::to_slice(
        &RegistrationFinishResponse,
        &mut registration_output,
    ));
    black_box(registration_output);
    black_box(classify(
        Method::Post,
        black_box("/identity/accounts/register/finish"),
    ));
    black_box(classify(
        Method::Get,
        black_box("/api/sync?excludeDomains=true"),
    ));
    let mut output = [0u8; 256];
    let _ = black_box(serde_json_core::to_slice(
        &PreloginResponse::default(),
        &mut output,
    ));
    black_box(output);
    let cipher = serde_json_core::from_slice::<CipherRequest<'_>>(black_box(
        br#"{"type":1,"data":"opaque sealed blob"}"#,
    ));
    if let Ok((cipher, _)) = cipher {
        let _ = black_box(no_warden::validation::validate_cipher(&cipher));
        let mut encoded = [0u8; 2048];
        let _ = black_box(serde_json_core::to_slice(&cipher, &mut encoded));
        black_box(encoded);
    }
    let import = serde_json_core::from_slice::<ImportRequest<'_, 1, 1, 1>>(black_box(
        br#"{"folders":[{"name":"encrypted folder"}],"ciphers":[{"type":1,"data":"opaque sealed blob","encryptedByKeyId":"opaque:key/id"}],"folderRelationships":[{"key":0,"value":0}]}"#,
    ));
    if let Ok((import, _)) = import {
        black_box(import.folder_count());
        black_box(import.cipher(0));
        let mut encoded = [0u8; 2048];
        let _ = black_box(serde_json_core::to_slice(&import, &mut encoded));
        black_box(encoded);
    }
    let ids = serde_json_core::from_slice::<CipherIdsRequest<'_, 3>>(black_box(
        br#"{"ids":["opaque:One/id","opaque:One/id","opaque:one/id"]}"#,
    ));
    if let Ok((ids, _)) = ids {
        black_box(ids.ids.len());
        let mut encoded = [0u8; 256];
        let _ = black_box(serde_json_core::to_slice(&ids, &mut encoded));
        black_box(encoded);
    }
    let proof = serde_json_core::from_slice::<PasswordOrOtpRequest<'_>>(black_box(
        br#"{"masterPasswordHash":"test-only-authorization-hash"}"#,
    ));
    if let Ok((proof, _)) = proof {
        let _ = black_box(proof.proof());
    }
    let verification = serde_json_core::from_slice::<SecretVerificationRequest<'_>>(black_box(
        br#"{"masterPasswordHash":"test-only-authorization-hash"}"#,
    ));
    black_box(verification);
    let mut policy_output = [0_u8; 512];
    for policy in [
        None,
        Some(MasterPasswordPolicy {
            min_complexity: Some(3),
            min_length: Some(12),
            require_lower: true,
            require_upper: true,
            require_numbers: true,
            require_special: false,
            enforce_on_login: true,
        }),
    ] {
        let _ = black_box(serde_json_core::to_slice(
            &MasterPasswordPolicyResponse { policy },
            &mut policy_output,
        ));
    }
    black_box(policy_output);
    black_box(classify(
        Method::Post,
        black_box("/api/accounts/security-stamp"),
    ));
    let kdf = serde_json_core::from_slice::<AccountKdfRequest<'_>>(black_box(
        br#"{"authenticationData":{"salt":"bare-metal@example.com","kdf":{"kdf":0,"kdfIterations":700000},"masterPasswordAuthenticationHash":"new-opaque-proof"},"unlockData":{"salt":"bare-metal@example.com","kdf":{"kdf":0,"kdfIterations":700000},"masterKeyWrappedUserKey":"opaque-rewrapped-key"},"masterPasswordHash":"old-opaque-proof"}"#,
    ));
    let _ = black_box(kdf);
    black_box(classify(Method::Post, black_box("/api/accounts/kdf")));
    let password = serde_json_core::from_slice::<AccountPasswordRequest<'_>>(black_box(
        br#"{"masterPasswordHash":"old-opaque-proof","newMasterPasswordHash":"new-opaque-proof","key":"opaque-rewrapped-key"}"#,
    ));
    black_box(password);
    black_box(classify(Method::Post, black_box("/api/accounts/password")));
    let policy = no_warden::account_password::PasswordChangeStampPolicy;
    black_box(policy.expires_at(black_box(1_800_000_000)));
    black_box(policy.authorize_previous_stamp(
        black_box(1_800_000_120),
        black_box(1_800_000_120),
        black_box("get_public_keys"),
        black_box(true),
    ));
    let credentials = serde_json_core::from_slice::<ClientCredentialsRequest<'_>>(black_box(
        br#"{"grant_type":"client_credentials","client_id":"user.opaque:ID","client_secret":"test-only-key","scope":"api","deviceIdentifier":"device","deviceName":"bare metal","deviceType":"iOS"}"#,
    ));
    let _ = black_box(credentials);
    let mut encoded = [0u8; 256];
    let _ = black_box(serde_json_core::to_slice(
        &ApiKeyResponse {
            api_key: Secret::new(black_box("test-only-key")),
            revision_date: "2026-01-01T00:00:00Z",
        },
        &mut encoded,
    ));
    black_box(encoded);
    // This decoder lacks deserialize_any for the numeric-or-string size union.
    // Hosts can construct the borrowed request; encoding and core rules remain no_alloc.
    let attachment = AttachmentRequest {
        key: "opaque-wrapped-key",
        file_name: "opaque-filename",
        file_size: 17,
        admin_request: None,
    };
    let mut attachment_output = [0u8; 1024];
    let _ = black_box(serde_json_core::to_slice(
        &attachment,
        &mut attachment_output,
    ));
    let response = AttachmentResponse {
        id: "attachment",
        url: Secret::new("scoped-download-url"),
        file_name: "opaque-filename",
        size: "17",
        size_name: "17 B",
        key: Some("opaque-wrapped-key"),
    };
    let _ = black_box(serde_json_core::to_slice(&response, &mut attachment_output));
    let upload = AttachmentUploadResponse::direct(
        "attachment",
        Secret::new("relative-upload-url"),
        0_u8,
        false,
    );
    let _ = black_box(serde_json_core::to_slice(&upload, &mut attachment_output));
    black_box(attachment_output);
    let pair = serde_json_core::from_slice::<AccountKeys<'_>>(black_box(
        br#"{"encryptedPrivateKey":"opaque-private-key","publicKey":"opaque-public-key"}"#,
    ));
    if let Ok((pair, _)) = pair {
        let mut key_output = [0u8; 1024];
        let own_keys = AccountKeysResponse {
            key: Some(Secret::new("opaque-symmetric-key")),
            public_key: pair.public_key,
            private_key: Secret::new(pair.encrypted_private_key),
        };
        let _ = black_box(serde_json_core::to_slice(&own_keys, &mut key_output));
        let initialized = InitializedAccountKeysResponse {
            public_key: pair.public_key,
            private_key: Secret::new(pair.encrypted_private_key),
        };
        let _ = black_box(serde_json_core::to_slice(&initialized, &mut key_output));
        let public_key = UserPublicKeyResponse {
            user_id: "requested-user",
            public_key: pair.public_key,
        };
        let _ = black_box(serde_json_core::to_slice(&public_key, &mut key_output));
        black_box(key_output);
    }
    let profile = serde_json_core::from_slice::<ProfileUpdateRequest<'_>>(black_box(
        br#"{"name":"bare-metal profile"}"#,
    ));
    if let Ok((profile, _)) = profile {
        let mut output = [0u8; 128];
        let _ = black_box(serde_json_core::to_slice(&profile, &mut output));
        black_box(output);
    }
    let avatar = serde_json_core::from_slice::<AvatarUpdateRequest<'_>>(black_box(
        br##"{"avatarColor":"#abc123"}"##,
    ));
    if let Ok((avatar, _)) = avatar {
        let mut output = [0u8; 128];
        let _ = black_box(serde_json_core::to_slice(&avatar, &mut output));
        black_box(output);
    }
    let domains = serde_json_core::from_slice::<DomainSettingsRequest<'_, 2, 2, 2>>(black_box(
        br#"{"excludedGlobalEquivalentDomains":[1],"equivalentDomains":[["example.test","example.org"]]}"#,
    ));
    if let Ok((domains, _)) = domains {
        let mut output = [0u8; 256];
        let _ = black_box(serde_json_core::to_slice(&domains, &mut output));
        black_box(output);
    }
    let groups: &[&[&str]] = &[&["embedded.test", "embedded.example"]];
    let catalog = [
        GlobalDomain {
            kind: 1,
            domains: &["example.org"],
        },
        GlobalDomain {
            kind: 2,
            domains: &["example.net"],
        },
    ];
    for projection in [DomainProjection::All, DomainProjection::Sync] {
        let settings = DomainSettingsView {
            excluded_globals: black_box(&[1]),
            equivalent_domains: black_box(groups),
        };
        let response = DomainSettingsResponse::new(settings, black_box(&catalog[..]), projection);
        let mut output = [0u8; 512];
        let _ = black_box(serde_json_core::to_slice(&response, &mut output));
        black_box(output);
    }
    let mut output = [0u8; 8];
    let _ = black_box(serde_json_core::to_slice(
        &DomainSettingsUpdateResponse {},
        &mut output,
    ));
    black_box(output);
    let auth = serde_json_core::from_slice::<AuthRequestCreateRequest<'_>>(black_box(
        br#"{"accessCode":"caller-supplied-test-code","deviceIdentifier":"embedded-device","email":"bare-metal@example.com","publicKey":"caller-supplied-public-key"}"#,
    ));
    let mut auth_output = [0_u8; 2048];
    if let Ok((auth, _)) = auth {
        let _ = black_box(serde_json_core::to_slice(&auth, &mut auth_output));
    }
    let approval = serde_json_core::from_slice::<AuthRequestUpdateRequest<'_>>(black_box(
        br#"{"deviceIdentifier":"embedded-response-device","key":"opaque-wrapped-key","masterPasswordHash":null,"requestApproved":true}"#,
    ));
    if let Ok((approval, _)) = approval {
        let _ = black_box(serde_json_core::to_slice(&approval, &mut auth_output));
    }
    let poll_code = Secret::new(black_box("caller-supplied-test-code"));
    black_box(poll_code.expose_secret());
    black_box(classify(
        Method::Put,
        black_box("/api/auth-requests/request-id"),
    ));
    black_box(classify(
        Method::Get,
        black_box("/api/auth-requests/request-id/response?code=caller-supplied-test-code"),
    ));
    let request_login = serde_json_core::from_slice::<AuthRequestLoginRequest<'_>>(black_box(
        br#"{"grant_type":"password","username":"bare-metal@example.com","password":"caller-supplied-test-code","authRequest":"authentication-request","scope":"api offline_access","client_id":"embedded","deviceIdentifier":"new-device","deviceName":"caller-name","deviceType":"25"}"#,
    ));
    black_box(request_login);
    black_box(AuthRequestLoginContext {
        request_ip: "127.0.0.1",
        now_unix_nanos: 1_800_000_000_000_000_000,
    });
    black_box(AuthRequestLoginRecord {
        id: "authentication-request",
        owner_id: "private-owner",
        request_ip: "127.0.0.1",
        approved: Some(true),
        used: false,
        created_at_unix_nanos: 1_800_000_000_000_000_000,
        account_enabled: true,
    });
    black_box(AuthRequestLoginDevice {
        identifier: "new-device",
        name: "caller-name",
        device_type: "25",
    });
    let auth_context = AuthRequestContext {
        device_type: 25,
        request_ip: "127.0.0.1",
        origin: "https://example.test",
    };
    black_box(auth_context);
    let auth_record = AuthRequestRecord {
        id: "authentication-request",
        owner_id: "private-owner",
        request_device_identifier: "embedded-device",
        device_type: 25,
        request_ip: "127.0.0.1",
        access_code: "caller-supplied-test-code",
        public_key: "caller-supplied-public-key",
        key: None,
        master_password_hash: None,
        approved: None,
        creation_date: "2026-01-01T00:00:00Z",
        response_date: None,
    };
    for state in [
        AuthRequestRecord {
            key: Some("opaque-wrapped-key"),
            master_password_hash: Some("opaque-master-password-hash"),
            approved: Some(true),
            response_date: Some("2026-01-01T00:01:00Z"),
            ..auth_record
        },
        AuthRequestRecord {
            response_date: Some("2026-01-01T00:01:00Z"),
            ..auth_record
        },
    ] {
        let _ = black_box(serde_json_core::to_slice(
            &AuthRequestResponse::stored(black_box(state), auth_context.origin),
            &mut auth_output,
        ));
    }
    let _ = black_box(serde_json_core::to_slice(
        &AuthRequestResponse::created(black_box(auth_record), auth_context.origin),
        &mut auth_output,
    ));
    let _ = black_box(serde_json_core::to_slice(
        &AuthRequestResponse::stored(black_box(auth_record), auth_context.origin),
        &mut auth_output,
    ));
    let auth_records = [
        auth_record,
        AuthRequestRecord {
            approved: Some(true),
            ..auth_record
        },
    ];
    let _ = black_box(serde_json_core::to_slice(
        &AuthRequestListResponse::new(black_box(&auth_records[..]), auth_context.origin),
        &mut auth_output,
    ));
    black_box(auth_output);
    black_box(classify(
        Method::Get,
        black_box("/api/auth-requests/pending"),
    ));
    let push = serde_json_core::from_slice::<DevicePushTokenRequest<'_>>(black_box(
        br#"{"pushToken":"caller-supplied-test-value"}"#,
    ));
    if let Ok((push, _)) = push {
        let mut encoded = [0_u8; 256];
        let _ = black_box(serde_json_core::to_slice(&push, &mut encoded));
        black_box(encoded);
    }
    black_box(classify(
        Method::Put,
        black_box("/api/devices/identifier/device/token"),
    ));
    black_box(KnownDeviceRequest {
        email: "embedded@example.test",
        identifier: "embedded-device",
    });
    let mut known_output = [0u8; 8];
    let _ = black_box(serde_json_core::to_slice(
        &KnownDeviceResponse(true),
        &mut known_output,
    ));
    black_box(known_output);
    let device = DeviceRecord {
        owner_id: "embedded-owner",
        identifier: "embedded-device",
        name: "embedded client",
        device_type: 8,
        creation_date: "2026-10-18T00:00:00.000000Z",
        pending_auth_request: Some(PendingDeviceAuthRequest {
            id: "pending-request",
            creation_date: "2026-10-18T00:00:00.000000Z",
        }),
    };
    let mut device_output = [0u8; 1024];
    let _ = black_box(serde_json_core::to_slice(
        &DeviceResponse::new(black_box(device)),
        &mut device_output,
    ));
    black_box(device_output);
    let records = [device];
    let response = DeviceListResponse::new(black_box(&records[..]));
    let mut list_output = [0u8; 1024];
    let _ = black_box(serde_json_core::to_slice(&response, &mut list_output));
    black_box(list_output);
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
