//! RPCChainVM plugin process server.

use std::{env, future::Future, io, net::SocketAddr};

use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic_health::ServingStatus;

use crate::{
    pb::{
        http::http_server::{Http, HttpServer},
        vm::runtime::{runtime_client::RuntimeClient, InitializeRequest},
        vm::vm_server::{Vm, VmServer},
    },
    DEFAULT_MAX_MESSAGE_BYTES, PROTOCOL_VERSION,
};

/// AvalancheGo passes the address of its runtime-registration service through
/// this environment variable before starting every external VM process.
pub const RUNTIME_ENGINE_ADDRESS_ENV: &str = "AVALANCHE_VM_RUNTIME_ENGINE_ADDR";

/// Serves a VM on an ephemeral localhost port until Ctrl-C.
pub async fn serve<V>(vm: V) -> io::Result<()>
where
    V: Vm,
{
    let engine_address = env::var(RUNTIME_ENGINE_ADDRESS_ENV).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{RUNTIME_ENGINE_ADDRESS_ENV} is not set"),
        )
    })?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    serve_with_runtime_engine(vm, listener, &engine_address, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}

/// Serves a VM using an already-bound listener and registers it with the
/// AvalancheGo runtime service before accepting chain calls.
///
/// Binding first is important: AvalancheGo starts dialing immediately after
/// runtime registration, so publishing an address before the socket exists
/// creates a startup race.
pub async fn serve_with_runtime_engine<V, F>(
    vm: V,
    listener: TcpListener,
    engine_address: &str,
    shutdown: F,
) -> io::Result<()>
where
    V: Vm,
    F: Future<Output = ()> + Send + 'static,
{
    let address = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    // HashiCorp go-plugin probes the standard aggregate service name (the
    // empty string) before AvalancheGo asks for the VM client. Advertising
    // only a named service makes an otherwise healthy Rust plugin look dead.
    health_reporter
        .set_service_status("", ServingStatus::Serving)
        .await;

    notify_runtime_engine(engine_address, address).await?;

    Server::builder()
        .add_service(health_service)
        .add_service(
            VmServer::new(vm)
                .max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(DEFAULT_MAX_MESSAGE_BYTES),
        )
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(|error| io::Error::other(format!("RPCChainVM gRPC server failed: {error}")))
}

async fn notify_runtime_engine(engine_address: &str, vm_address: SocketAddr) -> io::Result<()> {
    let engine_socket = engine_address.parse::<SocketAddr>().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid Avalanche runtime engine address: {error}"),
        )
    })?;
    if !engine_socket.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Avalanche runtime engine address must be loopback",
        ));
    }
    let endpoint = tonic::transport::Endpoint::from_shared(format!("http://{engine_socket}"))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let channel = endpoint
        .connect()
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::ConnectionRefused, error.to_string()))?;
    let mut client = RuntimeClient::new(channel);
    client
        .initialize(InitializeRequest {
            protocol_version: PROTOCOL_VERSION,
            addr: vm_address.to_string(),
        })
        .await
        .map_err(|error| io::Error::other(format!("runtime registration failed: {error}")))?;
    Ok(())
}

/// Handle for the sidecar gRPC server used by AvalancheGo's HTTP proxy.
pub struct HttpServerHandle {
    pub address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl HttpServerHandle {
    pub async fn shutdown(mut self) -> io::Result<()> {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
        self.task
            .await
            .map_err(|error| io::Error::other(format!("HTTP gRPC task failed: {error}")))?
    }
}

/// Starts the protocol-45 simple HTTP bridge on an ephemeral localhost port.
pub async fn spawn_http_server<H>(handler: H) -> io::Result<HttpServerHandle>
where
    H: Http,
{
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let incoming = TcpListenerStream::new(listener);
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(
                HttpServer::new(handler)
                    .max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES)
                    .max_encoding_message_size(DEFAULT_MAX_MESSAGE_BYTES),
            )
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_receiver.await;
            })
            .await
            .map_err(|error| io::Error::other(format!("HTTP proxy gRPC server failed: {error}")))
    });
    Ok(HttpServerHandle {
        address,
        shutdown: Some(shutdown_sender),
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::pb::vm::runtime::{
        runtime_server::{Runtime, RuntimeServer},
        InitializeRequest,
    };
    use tokio::sync::oneshot;
    use tonic::{Request, Response, Status};

    #[derive(Clone)]
    struct RuntimeRecorder {
        request: Arc<Mutex<Option<oneshot::Sender<InitializeRequest>>>>,
    }

    #[tonic::async_trait]
    impl Runtime for RuntimeRecorder {
        async fn initialize(
            &self,
            request: Request<InitializeRequest>,
        ) -> Result<Response<()>, Status> {
            let sender = self
                .request
                .lock()
                .map_err(|_| Status::internal("recorder lock poisoned"))?
                .take()
                .ok_or_else(|| Status::already_exists("runtime already initialized"))?;
            sender
                .send(request.into_inner())
                .map_err(|_| Status::cancelled("test receiver dropped"))?;
            Ok(Response::new(()))
        }
    }

    #[tokio::test]
    async fn runtime_registration_uses_protocol_45_and_bound_vm_address() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("runtime listener");
        let engine_address = listener.local_addr().expect("engine address");
        let incoming = TcpListenerStream::new(listener);
        let (sender, receiver) = oneshot::channel();
        let recorder = RuntimeRecorder {
            request: Arc::new(Mutex::new(Some(sender))),
        };
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(RuntimeServer::new(recorder))
                .serve_with_incoming(incoming)
                .await
        });

        let vm_address = "127.0.0.1:9650".parse().expect("VM address");
        notify_runtime_engine(&engine_address.to_string(), vm_address)
            .await
            .expect("runtime registration");
        let request = receiver.await.expect("registration request");
        assert_eq!(request.protocol_version, PROTOCOL_VERSION);
        assert_eq!(request.addr, vm_address.to_string());
        server.abort();
    }

    #[tokio::test]
    async fn runtime_registration_rejects_non_loopback_engine() {
        let error = notify_runtime_engine(
            "192.0.2.1:9650",
            "127.0.0.1:9651".parse().expect("VM address"),
        )
        .await
        .expect_err("non-loopback engine must fail");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
