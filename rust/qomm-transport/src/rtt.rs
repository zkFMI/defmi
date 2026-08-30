//! TCP-handshake round-trip measurement used by the site harness.

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Median successful TCP connection time in milliseconds.
///
/// A fresh socket is used for every sample.
/// Failed attempts are omitted; `None` means that no attempt connected.
pub fn tcp_handshake_median_ms(
    host: &str,
    port: u16,
    attempts: usize,
    timeout: Duration,
) -> io::Result<Option<f64>> {
    let addresses = (host, port).to_socket_addrs()?.collect::<Vec<_>>();
    let mut samples = Vec::with_capacity(attempts);
    for _ in 0..attempts {
        let started = Instant::now();
        let connected = addresses
            .iter()
            .any(|address| TcpStream::connect_timeout(address, timeout).is_ok());
        if connected {
            samples.push(started.elapsed().as_secs_f64() * 1_000.0);
        }
    }
    samples.sort_by(f64::total_cmp);
    Ok(match samples.len() {
        0 => None,
        length if length % 2 == 1 => Some(samples[length / 2]),
        length => Some(0.5 * (samples[length / 2 - 1] + samples[length / 2])),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn measures_real_loopback_handshakes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            for _ in 0..3 {
                let _ = listener.accept().unwrap();
            }
        });
        let median = tcp_handshake_median_ms("127.0.0.1", port, 3, Duration::from_secs(1)).unwrap();
        assert!(median.is_some_and(|value| value >= 0.0));
        server.join().unwrap();
    }
}
