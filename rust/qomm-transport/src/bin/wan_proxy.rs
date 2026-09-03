//! Bidirectional loopback TCP proxies, one delay per link.

use serde::Deserialize;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
struct Config {
    one_way_delay_ms: f64,
    proxies: Vec<ProxyConfig>,
}

#[derive(Deserialize)]
struct ProxyConfig {
    listen_port: u16,
    target_port: u16,
    one_way_delay_ms: Option<f64>,
}

fn pipe(mut reader: TcpStream, mut writer: TcpStream, delay: Duration) {
    let mut buffer = [0_u8; 65_536];
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) | Err(_) => return,
            Ok(count) => count,
        };
        thread::sleep(delay);
        if writer.write_all(&buffer[..count]).is_err() || writer.flush().is_err() {
            return;
        }
    }
}

fn connect_target(port: u16) -> io::Result<Option<TcpStream>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => return Ok(Some(stream)),
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn handle(client: TcpStream, target_port: u16, delay: Duration) -> io::Result<()> {
    let Some(server) = connect_target(target_port)? else {
        let _ = client.shutdown(Shutdown::Both);
        return Ok(());
    };

    let client_reader = client.try_clone()?;
    let server_reader = server.try_clone()?;
    let client_writer = client.try_clone()?;
    let server_writer = server.try_clone()?;
    let to_server = thread::spawn(move || pipe(client_reader, server_writer, delay));
    let to_client = thread::spawn(move || pipe(server_reader, client_writer, delay));
    let _ = to_server.join();
    let _ = to_client.join();
    let _ = server.shutdown(Shutdown::Both);
    let _ = client.shutdown(Shutdown::Both);
    Ok(())
}

fn parse_args() -> Result<(PathBuf, PathBuf)> {
    let mut args = std::env::args_os().skip(1);
    let mut config = None;
    let mut ready = None;
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--config") => {
                config = Some(PathBuf::from(
                    args.next().ok_or("argument --config expects one value")?,
                ));
            }
            Some("--ready") => {
                ready = Some(PathBuf::from(
                    args.next().ok_or("argument --ready expects one value")?,
                ));
            }
            Some(value) => return Err(format!("unrecognized argument: {value}").into()),
            None => return Err("argument is not valid UTF-8".into()),
        }
    }
    Ok((
        config.ok_or("the following arguments are required: --config")?,
        ready.ok_or("the following arguments are required: --ready")?,
    ))
}

fn milliseconds(value: f64) -> Result<Duration> {
    if !value.is_finite() || value < 0.0 {
        return Err("one_way_delay_ms must be a finite non-negative number".into());
    }
    Ok(Duration::from_secs_f64(value / 1_000.0))
}

fn run(config_path: &Path, ready_path: &Path) -> Result<()> {
    let config: Config = serde_json::from_slice(&fs::read(config_path)?)?;
    let mut listeners = Vec::with_capacity(config.proxies.len());
    for proxy in config.proxies {
        let listener = TcpListener::bind(("127.0.0.1", proxy.listen_port))?;
        let delay = milliseconds(proxy.one_way_delay_ms.unwrap_or(config.one_way_delay_ms))?;
        listeners.push((listener, proxy.target_port, delay));
    }

    if let Some(parent) = ready_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        ready_path,
        format!(
            "{{\"status\": \"ready\", \"proxy_count\": {}}}",
            listeners.len()
        ),
    )?;

    let handles = listeners
        .into_iter()
        .map(|(listener, target_port, delay)| {
            thread::spawn(move || -> io::Result<()> {
                for client in listener.incoming() {
                    let client = client?;
                    thread::spawn(move || {
                        if let Err(error) = handle(client, target_port, delay) {
                            eprintln!("proxy connection failed: {error}");
                        }
                    });
                }
                Ok(())
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        match handle.join() {
            Ok(result) => result?,
            Err(_) => return Err("proxy listener thread panicked".into()),
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let (config, ready) = parse_args()?;
    run(&config, &ready)
}
