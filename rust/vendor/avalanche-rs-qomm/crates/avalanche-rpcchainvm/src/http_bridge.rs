//! Bounded client for AvalancheGo's legacy `HTTP.Handle` callback services.
//!
//! AvalancheGo routes ordinary HTTP/1 requests through `HandleSimple`, but
//! HTTP/2 and protocol-upgrade requests use `Handle`. In that form the request
//! body and response writer are temporary gRPC services owned by AvalancheGo.
//! QOMM does not support WebSockets, but it must still serve ordinary JSON-RPC
//! requests received over HTTP/2 rather than returning gRPC UNIMPLEMENTED.

use std::{error::Error as StdError, fmt, time::Duration};

use tonic::transport::{Channel, Endpoint};

use crate::{
    pb::{
        http::{
            responsewriter::{
                writer_client::WriterClient, Header, WriteHeaderRequest, WriteRequest,
            },
            Element,
        },
        io::reader::{reader_client::ReaderClient, ErrorCode, ReadRequest},
    },
    DEFAULT_MAX_MESSAGE_BYTES,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const READ_CHUNK_BYTES: i32 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HttpBridgeError {
    BodyTooLarge { actual: usize, maximum: usize },
    InvalidRead(String),
    ShortWrite { written: usize, expected: usize },
    Transport(String),
    Remote(String),
}

impl fmt::Display for HttpBridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BodyTooLarge { actual, maximum } => write!(
                formatter,
                "Avalanche HTTP request body is too large ({actual} bytes > {maximum} bytes)"
            ),
            Self::InvalidRead(message) => write!(formatter, "Avalanche HTTP reader: {message}"),
            Self::ShortWrite { written, expected } => write!(
                formatter,
                "Avalanche HTTP writer accepted {written} of {expected} bytes"
            ),
            Self::Transport(message) => write!(formatter, "Avalanche HTTP transport: {message}"),
            Self::Remote(message) => write!(formatter, "Avalanche HTTP callback RPC: {message}"),
        }
    }
}

impl StdError for HttpBridgeError {}

fn endpoint_uri(address: &str) -> String {
    if address.starts_with("http://") || address.starts_with("https://") {
        address.to_owned()
    } else {
        format!("http://{address}")
    }
}

async fn connect(address: &str) -> Result<Channel, HttpBridgeError> {
    Endpoint::from_shared(endpoint_uri(address))
        .map_err(|error| HttpBridgeError::Transport(error.to_string()))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect()
        .await
        .map_err(|error| HttpBridgeError::Transport(error.to_string()))
}

pub struct HttpBridge {
    reader: ReaderClient<Channel>,
    writer: WriterClient<Channel>,
    max_body_bytes: usize,
}

impl HttpBridge {
    pub async fn connect(address: &str, max_body_bytes: usize) -> Result<Self, HttpBridgeError> {
        let channel = connect(address).await?;
        Ok(Self {
            reader: ReaderClient::new(channel.clone())
                .max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(DEFAULT_MAX_MESSAGE_BYTES),
            writer: WriterClient::new(channel)
                .max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(DEFAULT_MAX_MESSAGE_BYTES),
            max_body_bytes,
        })
    }

    pub async fn read_body(&mut self) -> Result<Vec<u8>, HttpBridgeError> {
        let mut body = Vec::new();
        loop {
            let response = self
                .reader
                .read(ReadRequest {
                    length: READ_CHUNK_BYTES,
                })
                .await
                .map_err(|status| {
                    HttpBridgeError::Remote(format!("{}: {}", status.code(), status.message()))
                })?
                .into_inner();
            if response.read.len() > READ_CHUNK_BYTES as usize {
                return Err(HttpBridgeError::InvalidRead(format!(
                    "server returned {} bytes for a {}-byte read",
                    response.read.len(),
                    READ_CHUNK_BYTES
                )));
            }
            let next = body.len().saturating_add(response.read.len());
            if next > self.max_body_bytes {
                return Err(HttpBridgeError::BodyTooLarge {
                    actual: next,
                    maximum: self.max_body_bytes,
                });
            }
            body.extend_from_slice(&response.read);
            match response.error {
                Some(error) if ErrorCode::try_from(error.error_code) == Ok(ErrorCode::Eof) => {
                    return Ok(body);
                }
                Some(error) => {
                    return Err(HttpBridgeError::InvalidRead(if error.message.is_empty() {
                        format!("unknown reader error code {}", error.error_code)
                    } else {
                        error.message
                    }));
                }
                None if response.read.is_empty() => {
                    return Err(HttpBridgeError::InvalidRead(
                        "zero-byte read without EOF would not make progress".into(),
                    ));
                }
                None => {}
            }
        }
    }

    pub async fn write_response(
        &mut self,
        status_code: i32,
        headers: &[Element],
        body: &[u8],
    ) -> Result<(), HttpBridgeError> {
        if !(100..=599).contains(&status_code) {
            return Err(HttpBridgeError::InvalidRead(format!(
                "invalid HTTP response status {status_code}"
            )));
        }
        if body.len() > DEFAULT_MAX_MESSAGE_BYTES {
            return Err(HttpBridgeError::BodyTooLarge {
                actual: body.len(),
                maximum: DEFAULT_MAX_MESSAGE_BYTES,
            });
        }
        let headers = headers
            .iter()
            .map(|element| Header {
                key: element.key.clone(),
                values: element.values.clone(),
            })
            .collect::<Vec<_>>();
        self.writer
            .write_header(WriteHeaderRequest {
                headers: headers.clone(),
                status_code,
            })
            .await
            .map_err(|status| {
                HttpBridgeError::Remote(format!("{}: {}", status.code(), status.message()))
            })?;
        let written = self
            .writer
            .write(WriteRequest {
                headers,
                payload: body.to_vec(),
            })
            .await
            .map_err(|status| {
                HttpBridgeError::Remote(format!("{}: {}", status.code(), status.message()))
            })?
            .into_inner()
            .written;
        let written = usize::try_from(written).unwrap_or_default();
        if written != body.len() {
            return Err(HttpBridgeError::ShortWrite {
                written,
                expected: body.len(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{transport::Server, Request, Response, Status};

    use super::*;
    use crate::pb::{
        http::responsewriter::{
            writer_server::{Writer, WriterServer},
            HijackResponse, WriteResponse,
        },
        io::reader::{
            reader_server::{Reader, ReaderServer},
            Error as ReadError, ReadResponse,
        },
    };

    #[derive(Clone)]
    struct Callbacks {
        request: Arc<Mutex<Option<Vec<u8>>>>,
        status: Arc<Mutex<Option<i32>>>,
        response: Arc<Mutex<Vec<u8>>>,
    }

    impl Callbacks {
        fn new(request: &[u8]) -> Self {
            Self {
                request: Arc::new(Mutex::new(Some(request.to_vec()))),
                status: Arc::new(Mutex::new(None)),
                response: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[tonic::async_trait]
    impl Reader for Callbacks {
        async fn read(
            &self,
            request: Request<ReadRequest>,
        ) -> Result<Response<ReadResponse>, Status> {
            let maximum = usize::try_from(request.into_inner().length)
                .map_err(|_| Status::invalid_argument("negative read length"))?;
            let mut state = self.request.lock().expect("request lock");
            let mut available = state.take().unwrap_or_default();
            let tail = available.split_off(available.len().min(maximum));
            let eof = tail.is_empty();
            *state = (!eof).then_some(tail);
            Ok(Response::new(ReadResponse {
                read: available,
                error: eof.then_some(ReadError {
                    error_code: ErrorCode::Eof as i32,
                    message: String::new(),
                }),
            }))
        }
    }

    #[tonic::async_trait]
    impl Writer for Callbacks {
        async fn write(
            &self,
            request: Request<WriteRequest>,
        ) -> Result<Response<WriteResponse>, Status> {
            let payload = request.into_inner().payload;
            self.response
                .lock()
                .expect("response lock")
                .extend_from_slice(&payload);
            Ok(Response::new(WriteResponse {
                written: i32::try_from(payload.len()).expect("test response length"),
            }))
        }

        async fn write_header(
            &self,
            request: Request<WriteHeaderRequest>,
        ) -> Result<Response<()>, Status> {
            *self.status.lock().expect("status lock") = Some(request.into_inner().status_code);
            Ok(Response::new(()))
        }

        async fn flush(&self, _request: Request<()>) -> Result<Response<()>, Status> {
            Ok(Response::new(()))
        }

        async fn hijack(&self, _request: Request<()>) -> Result<Response<HijackResponse>, Status> {
            Err(Status::failed_precondition(
                "QOMM has no WebSocket endpoint",
            ))
        }
    }

    async fn serve(callbacks: Callbacks) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("local address");
        tokio::spawn(
            Server::builder()
                .add_service(ReaderServer::new(callbacks.clone()))
                .add_service(WriterServer::new(callbacks))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        address.to_string()
    }

    #[tokio::test]
    async fn callback_bridge_reads_and_writes_bounded_http_bodies() {
        let callbacks = Callbacks::new(br#"{"jsonrpc":"2.0"}"#);
        let address = serve(callbacks.clone()).await;
        let mut bridge = HttpBridge::connect(&address, 1_024).await.expect("connect");
        assert_eq!(
            bridge.read_body().await.expect("read"),
            br#"{"jsonrpc":"2.0"}"#
        );
        bridge
            .write_response(
                200,
                &[Element {
                    key: "Content-Type".into(),
                    values: vec!["application/json".into()],
                }],
                br#"{"ok":true}"#,
            )
            .await
            .expect("write");
        assert_eq!(*callbacks.status.lock().expect("status"), Some(200));
        assert_eq!(
            callbacks.response.lock().expect("response").as_slice(),
            br#"{"ok":true}"#
        );
    }

    #[tokio::test]
    async fn callback_bridge_refuses_a_body_over_the_product_limit() {
        let callbacks = Callbacks::new(b"too large");
        let address = serve(callbacks).await;
        let mut bridge = HttpBridge::connect(&address, 3).await.expect("connect");
        assert_eq!(
            bridge.read_body().await,
            Err(HttpBridgeError::BodyTooLarge {
                actual: 9,
                maximum: 3,
            })
        );
    }
}
