use std::net::ToSocketAddrs;

use super::CheckReport;

const SKEW_THRESHOLD_MS: i64 = 60_000;

/// System clock sync — FIXABLE.
///
/// A skewed clock breaks timestamp correlation across every artifact Ocean
/// reads (prefetch, logs, journal, file timestamps).
pub fn run() -> CheckReport {
    let name = "System clock sync";

    match clock_offset_ms() {
        Ok(offset) => {
            if offset.abs() <= SKEW_THRESHOLD_MS {
                let secs = SKEW_THRESHOLD_MS / 1000;
                CheckReport::pass(
                    "clock",
                    name,
                    format!("System time within {secs}s of the network time."),
                )
            } else {
                CheckReport::fail(
                    "clock",
                    name,
                    true,
                    format!(
                        "Clock is {}s off from network time; timestamps would be unreliable.",
                        offset / 1000
                    ),
                )
            }
        }
        Err(e) => CheckReport::warning(
            "clock",
            name,
            format!("Could not reach an NTP server ({e}); clock not verified."),
        ),
    }
}

pub fn fix() -> bool {
    #[cfg(target_os = "windows")]
    {
        let resync = std::process::Command::new("w32tm")
            .args(["/resync", "/force"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let _ = std::process::Command::new("w32tm")
            .args(["/config", "/syncfromflags:manual", "/manualpeerlist:pool.ntp.org"])
            .status();
        resync
    }

    #[cfg(target_os = "linux")]
    {
        // Enable + restart the sync service, then step the clock. These need
        // root, so they run through per-operation elevation on Linux.
        let _ = super::run_privileged("timedatectl", &["set-ntp", "true"]);
        let restart = super::run_privileged("systemctl", &["restart", "systemd-timesyncd"]);
        let _ = super::run_privileged("chronyc", &["makestep"]);
        restart
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

/// Query a public NTP server over UDP and return the offset of the local clock
/// from network time, in milliseconds.
fn clock_offset_ms() -> Result<i64, String> {
    let mut req = [0u8; 48];
    req[0] = 0x1b; // NTP v3, client mode

    let sock = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(4)))
        .map_err(|e| e.to_string())?;

    for host in ["time.google.com", "pool.ntp.org", "time.cloudflare.com"] {
        let Ok(addr) = (host, 123).to_socket_addrs() else { continue };
        let Some(addr) = addr.clone().next() else { continue };
        if sock.send_to(&req, addr).is_err() {
            continue;
        }
        let mut buf = [0u8; 48];
        if sock.recv_from(&mut buf).is_err() {
            continue;
        }
        // Transmit timestamp: bytes 40..44 (seconds), 44..48 (fraction).
        let secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
        let frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]);
        // NTP epoch is 1900; Unix epoch offset is 2_208_988_800 seconds.
        let ntp_unix = secs as i64 - 2_208_988_800;
        let server_ms = ntp_unix * 1000 + (frac as i64 * 1000 >> 32);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

        return Ok(server_ms - now_ms);
    }

    Err("all NTP servers unreachable".to_string())
}