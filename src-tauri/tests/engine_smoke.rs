//! Manual smoke test for the check engine. Run with:
//!   cargo test --test engine_smoke -- --nocapture
//! Verifies each check runs on the host and reports a sane outcome.

use byte_check_lib::checks;

#[test]
fn engine_smoke() {
    let process = checks::process::run();
    println!("[process] {:?} — {}", process.status_str(), process.detail);

    let overlay = checks::overlay::run();
    println!("[overlay] {:?} — {}", overlay.status_str(), overlay.detail);

    let clock = checks::clock::run();
    println!("[clock] {:?} — {}", clock.status_str(), clock.detail);

    let screen = checks::screen::run();
    println!("[screen] {:?} — {}", screen.status_str(), screen.detail);

    let av = checks::av::run();
    println!("[av] {:?} — {}", av.status_str(), av.detail);

    let ocean = checks::ocean::run();
    println!("[ocean] {:?} — {}", ocean.status_str(), ocean.detail);

    let trace = checks::trace::run();
    println!("[trace] {:?} — {}", trace.status_str(), trace.detail);
}