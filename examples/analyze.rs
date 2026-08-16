//! Performance probe for static bytecode analysis (CPU-only, no network).
//! Usage: cargo run --release --example analyze -- [size_bytes] [iterations]
//! Defaults to a 24,000-byte synthetic contract (≈ real PoolManager size), 100k iters.

use std::time::Instant;

use blockscan::analysis::analyze;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let size: usize = a.first().and_then(|s| s.parse().ok()).unwrap_or(24_000);
    let iters: usize = a.get(1).and_then(|s| s.parse().ok()).unwrap_or(100_000);

    // Synthetic bytecode: a mix of PUSH4 selectors, PUSH-immediates and opcodes
    // so the PUSH-skip walk does representative work.
    let mut code = Vec::with_capacity(size);
    let pattern: [u8; 8] = [0x63, 0xa9, 0x05, 0x9c, 0xbb, 0xf4, 0x60, 0xff];
    while code.len() < size {
        code.extend_from_slice(&pattern);
    }
    code.truncate(size);

    // Warm up, then time.
    let _ = analyze(&code);
    let t = Instant::now();
    let mut sink = 0usize;
    for _ in 0..iters {
        sink = sink.wrapping_add(analyze(&code).opcodes.len());
    }
    let el = t.elapsed();
    let per = el.as_secs_f64() / iters as f64;
    let mbps = (size as f64 * iters as f64) / el.as_secs_f64() / 1e6;
    println!(
        "analyze {size} bytes x {iters} iters in {:.3}s -> {:.2} µs/call, {:.0} MB/s (sink={sink})",
        el.as_secs_f64(),
        per * 1e6,
        mbps
    );
}
