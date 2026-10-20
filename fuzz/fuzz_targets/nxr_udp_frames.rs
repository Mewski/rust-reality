#![no_main]

use libfuzzer_sys::fuzz_target;
use rust_reality::protocol::nxr_udp::fuzz_decode_frame;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_frame(data);
});
