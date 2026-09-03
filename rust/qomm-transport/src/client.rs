//! A client that sends one fixed frame per node on every slot.

use crate::wire::{share_request, Frame, FRAME_BYTES};
use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Instant;

pub const N_REQUEST_VALUES: usize = 4;

#[derive(Clone, Debug)]
pub struct SendRecord {
    pub slot: u32,
    pub node: usize,
    pub sent_at: Instant,
    pub size: usize,
    /// Local test ground truth only; it never enters a frame.
    pub was_real: bool,
}

pub struct Client {
    pub client_id: usize,
    pub key: Vec<u8>,
    pub ports: Vec<u16>,
    pub sends: Vec<SendRecord>,
    writers: Vec<TcpStream>,
}

impl Client {
    pub fn new(client_id: usize, key: Vec<u8>, ports: Vec<u16>) -> Self {
        Self {
            client_id,
            key,
            ports,
            sends: Vec::new(),
            writers: Vec::new(),
        }
    }

    pub fn connect(&mut self) -> io::Result<()> {
        if !self.writers.is_empty() {
            return Ok(());
        }
        self.writers = self
            .ports
            .iter()
            .map(|port| TcpStream::connect(("127.0.0.1", *port)))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(())
    }

    pub fn send_slot(
        &mut self,
        slot: u32,
        request: Option<[u128; N_REQUEST_VALUES]>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.writers.len() != self.ports.len() {
            self.connect()?;
        }
        let real = request.is_some();
        let values = request.unwrap_or([0; N_REQUEST_VALUES]);
        let payloads = share_request(&values, self.writers.len())?;
        for (node, (writer, payload)) in self.writers.iter_mut().zip(payloads).enumerate() {
            let frame = Frame::new(slot, node, payload, &self.key)?;
            writer.write_all(&frame.encode())?;
            self.sends.push(SendRecord {
                slot,
                node,
                sent_at: Instant::now(),
                size: FRAME_BYTES,
                was_real: real,
            });
        }
        for writer in &mut self.writers {
            writer.flush()?;
        }
        Ok(())
    }

    pub fn close(&mut self) {
        for writer in self.writers.drain(..) {
            let _ = writer.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}
