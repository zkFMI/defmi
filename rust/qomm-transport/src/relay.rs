//! Slot-batching relays, one per computing node.

use crate::wire::{frame_is_authentic, Frame, FRAME_BYTES};
use rand::seq::SliceRandom;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Arrival {
    pub slot: u32,
    pub order: usize,
    pub received_at: Instant,
    pub size: usize,
}

#[derive(Debug)]
pub struct NodeInbox {
    pub node: u16,
    pub arrivals: Vec<Arrival>,
    pub frames: BTreeMap<u32, Vec<Frame>>,
}

impl NodeInbox {
    pub fn new(node: u16) -> Self {
        Self {
            node,
            arrivals: Vec::new(),
            frames: BTreeMap::new(),
        }
    }

    pub fn accept(&mut self, slot: u32, batch: Vec<Frame>) {
        let at = Instant::now();
        for (order, _) in batch.iter().enumerate() {
            self.arrivals.push(Arrival {
                slot,
                order,
                received_at: at,
                size: FRAME_BYTES,
            });
        }
        self.frames.entry(slot).or_default().extend(batch);
    }
}

pub struct Relay {
    pub node: u16,
    pub hop: usize,
    pub inbox: Option<Arc<Mutex<NodeInbox>>>,
    pub downstream_port: Option<u16>,
    pub key: Option<Vec<u8>>,
    pending: Arc<Mutex<BTreeMap<u32, Vec<Frame>>>>,
    refused: Arc<AtomicU64>,
    bytes_in: Arc<AtomicU64>,
    bytes_out: AtomicU64,
    stop: Arc<AtomicBool>,
    port: u16,
    handle: Option<JoinHandle<()>>,
}

impl Relay {
    pub fn new(
        node: u16,
        inbox: Option<Arc<Mutex<NodeInbox>>>,
        downstream_port: Option<u16>,
        hop: usize,
        key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            node,
            hop,
            inbox,
            downstream_port,
            key,
            pending: Arc::new(Mutex::new(BTreeMap::new())),
            refused: Arc::new(AtomicU64::new(0)),
            bytes_in: Arc::new(AtomicU64::new(0)),
            bytes_out: AtomicU64::new(0),
            stop: Arc::new(AtomicBool::new(false)),
            port: 0,
            handle: None,
        }
    }

    pub fn start(&mut self) -> io::Result<u16> {
        if self.handle.is_some() {
            return Ok(self.port);
        }
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        self.port = listener.local_addr()?.port();
        let pending = Arc::clone(&self.pending);
        let refused = Arc::clone(&self.refused);
        let bytes_in = Arc::clone(&self.bytes_in);
        let stop = Arc::clone(&self.stop);
        let key = self.key.clone();
        self.handle = Some(thread::spawn(move || {
            let mut workers = Vec::new();
            while !stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        // The listener is nonblocking so the accept loop can
                        // observe `stop`, but a client connection is long-lived
                        // across slots.  Some platforms propagate O_NONBLOCK to
                        // accepted sockets; `read_exact` would then interpret a
                        // quiet point between slots as the end of the worker and
                        // the client would see EPIPE on its next send.
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let pending = Arc::clone(&pending);
                        let refused = Arc::clone(&refused);
                        let bytes_in = Arc::clone(&bytes_in);
                        let key = key.clone();
                        workers.push(thread::spawn(move || {
                            let mut raw = [0_u8; FRAME_BYTES];
                            while stream.read_exact(&mut raw).is_ok() {
                                bytes_in.fetch_add(FRAME_BYTES as u64, Ordering::Relaxed);
                                let Ok(frame) = Frame::decode(&raw) else {
                                    refused.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                };
                                if key
                                    .as_deref()
                                    .is_some_and(|secret| !frame_is_authentic(secret, &frame))
                                {
                                    refused.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                }
                                pending
                                    .lock()
                                    .expect("relay pending lock")
                                    .entry(frame.slot)
                                    .or_default()
                                    .push(frame);
                            }
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
        }));
        Ok(self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    pub fn bytes_in(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed)
    }

    pub fn bytes_out(&self) -> u64 {
        self.bytes_out.load(Ordering::Relaxed)
    }

    pub fn close_slot(&self, slot: u32) -> io::Result<usize> {
        let mut batch = self
            .pending
            .lock()
            .expect("relay pending lock")
            .remove(&slot)
            .unwrap_or_default();
        batch.shuffle(&mut rand::thread_rng());
        let count = batch.len();
        if let Some(port) = self.downstream_port {
            let mut stream = TcpStream::connect(("127.0.0.1", port))?;
            for frame in &batch {
                stream.write_all(&frame.encode())?;
            }
            stream.flush()?;
            let _ = stream.shutdown(Shutdown::Write);
            self.bytes_out
                .fetch_add((FRAME_BYTES * count) as u64, Ordering::Relaxed);
        } else if let Some(inbox) = &self.inbox {
            inbox.lock().expect("relay inbox lock").accept(slot, batch);
        }
        Ok(count)
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if self.port != 0 {
            let _ = TcpStream::connect(("127.0.0.1", self.port));
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stop();
    }
}
