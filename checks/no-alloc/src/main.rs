//! Link a real bare-metal executable without a global allocator.
#![no_std]
#![no_main]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::{hint::black_box, panic::PanicInfo};
use no_warden::{
    route::{Method, classify},
    service::ImportData,
    wire::{CipherIdsRequest, CipherRequest, ImportRequest, PreloginRequest, PreloginResponse},
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
