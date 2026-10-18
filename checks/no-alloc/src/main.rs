//! Link a real bare-metal executable without a global allocator.
#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::{hint::black_box, panic::PanicInfo};
use no_warden::{
    identity::Secret,
    route::{Method, classify},
    service::ImportData,
    wire::{
        AccountKeys, AccountKeysResponse, ApiKeyResponse, AttachmentRequest, AttachmentResponse,
        AttachmentUploadResponse, CipherIdsRequest, CipherRequest, ClientCredentialsRequest,
        ImportRequest, InitializedAccountKeysResponse, PasswordOrOtpRequest, PreloginRequest,
        PreloginResponse, UserPublicKeyResponse,
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
