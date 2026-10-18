//! Link and exercise the real fixed-capacity consumer without a global allocator.
#![no_std]
#![no_main]

use core::{hint::black_box, panic::PanicInfo};
use no_warden_embedded_vault::{FixedVault, exercise};

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut vault = FixedVault::default();
    exercise(black_box(&mut vault));
    black_box(vault);
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
