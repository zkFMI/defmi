//! Mutually authenticated client for a resident proof/FROST participant.
//!
//! Stateful proof operations are deliberately not retried automatically.  A
//! lost reply after a successful state transition must be reconciled through
//! the operation-specific status call, not repeated with a fresh request.

use crate::node_service::ClientTlsConfig;
use crate::proof_party::{ProofRequest, ProofResponse};
use openssl::ssl::SslStream;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 8 << 20;
const MAX_REQUEST_BYTES: usize = 8 << 20;

pub struct ProofPartyTlsClient {
    host: String,
    port: u16,
    tls: ClientTlsConfig,
    server_name: String,
    timeout: Duration,
    stream: Option<BufReader<SslStream<TcpStream>>>,
    next_id: u64,
}

pub trait ProofPartyRpc {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String>;
}

impl ProofPartyTlsClient {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        tls: ClientTlsConfig,
        server_name: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            tls,
            server_name: server_name.into(),
            timeout,
            stream: None,
            next_id: 1,
        }
    }

    pub fn connect(&mut self) -> Result<(), String> {
        self.stream = Some(BufReader::new(self.tls.connect_tcp(
            &self.host,
            self.port,
            &self.server_name,
            self.timeout,
        )?));
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(mut reader) = self.stream.take() {
            let _ = reader.get_mut().shutdown();
            let _ = reader.get_ref().get_ref().shutdown(Shutdown::Both);
        }
    }

    pub(crate) fn read_bounded_line(reader: &mut impl BufRead) -> Result<Vec<u8>, String> {
        let mut line = Vec::new();
        loop {
            let available = reader.fill_buf().map_err(|error| error.to_string())?;
            if available.is_empty() {
                return Err("proof-party closed without a response".into());
            }
            let take = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |position| position + 1);
            if line.len().saturating_add(take) > MAX_RESPONSE_BYTES {
                return Err("proof-party response exceeds its fixed bound".into());
            }
            let terminated = available[take - 1] == b'\n';
            line.extend_from_slice(&available[..take]);
            reader.consume(take);
            if terminated {
                return Ok(line);
            }
        }
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        if method.is_empty() || method.len() > 128 {
            return Err("proof-party method is outside its fixed bound".into());
        }
        if self.stream.is_none() {
            self.connect()?;
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| "proof-party request identifier is exhausted".to_string())?;
        let request = ProofRequest {
            id,
            method: method.to_string(),
            params,
        };
        let result = (|| {
            let stream = self.stream.as_mut().expect("proof-party client connected");
            let encoded = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
            if encoded.len().saturating_add(1) > MAX_REQUEST_BYTES {
                return Err("proof-party request exceeds its fixed bound".into());
            }
            stream
                .get_mut()
                .write_all(&encoded)
                .and_then(|_| stream.get_mut().write_all(b"\n"))
                .and_then(|_| stream.get_mut().flush())
                .map_err(|error| error.to_string())?;
            let line = Self::read_bounded_line(stream)?;
            let response: ProofResponse = serde_json::from_slice(&line)
                .map_err(|_| "proof-party returned invalid JSON".to_string())?;
            if response.id != id {
                return Err("proof-party response identifier does not match".into());
            }
            if !response.ok {
                return Err(response
                    .error
                    .unwrap_or_else(|| "proof-party rejected the request".into()));
            }
            response
                .result
                .ok_or_else(|| "proof-party success response has no result".into())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}

impl ProofPartyRpc for ProofPartyTlsClient {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        ProofPartyTlsClient::call(self, method, params)
    }
}

impl Drop for ProofPartyTlsClient {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_line_reader_requires_a_complete_bounded_record() {
        let mut valid = Cursor::new(b"{\"ok\":true}\ntrailing".to_vec());
        assert_eq!(
            ProofPartyTlsClient::read_bounded_line(&mut valid).unwrap(),
            b"{\"ok\":true}\n"
        );
        let mut closed = Cursor::new(b"unterminated".to_vec());
        assert!(ProofPartyTlsClient::read_bounded_line(&mut closed)
            .unwrap_err()
            .contains("closed"));
        let mut oversized = Cursor::new(vec![b'x'; MAX_RESPONSE_BYTES + 1]);
        assert!(ProofPartyTlsClient::read_bounded_line(&mut oversized)
            .unwrap_err()
            .contains("fixed bound"));
    }
}
