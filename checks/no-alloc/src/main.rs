//! Link a real bare-metal executable without a global allocator.
#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::{hint::black_box, panic::PanicInfo};
use no_warden::{
    devices::{DeviceRecord, PendingDeviceAuthRequest},
    domains::{DomainProjection, DomainSettingsView, GlobalDomain},
    identity::Secret,
    route::{Method, classify},
    service::ImportData,
    wire::{
        AccountKeys, AccountKeysResponse, ApiKeyResponse, AttachmentRequest, AttachmentResponse,
        AttachmentUploadResponse, AvatarUpdateRequest, CipherIdsRequest, CipherRequest,
        ClientCredentialsRequest, DeviceListResponse, DeviceResponse, DomainSettingsRequest,
        DomainSettingsResponse, DomainSettingsUpdateResponse, ImportRequest,
        InitializedAccountKeysResponse, KnownDeviceRequest, KnownDeviceResponse,
        PasswordOrOtpRequest, PreloginRequest, PreloginResponse, ProfileUpdateRequest,
        UserPublicKeyResponse,
    },
};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let input = black_box(br#"{"email":"bare-metal@example.com"}"#);
    let request = serde_json_core::from_slice::<PreloginRequest<'_>>(input);
    let _ = black_box(request);
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
