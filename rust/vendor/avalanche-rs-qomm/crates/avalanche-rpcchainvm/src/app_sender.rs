//! Client for AvalancheGo's application-message service.

use std::{error::Error as StdError, fmt, time::Duration};

use tonic::transport::{Channel, Endpoint};

use crate::{
    pb::appsender::{
        app_sender_client::AppSenderClient, SendAppErrorMsg, SendAppGossipMsg, SendAppRequestMsg,
        SendAppResponseMsg,
    },
    DEFAULT_MAX_MESSAGE_BYTES,
};

const NODE_ID_BYTES: usize = 20;
const MAX_RECIPIENTS: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppSenderError {
    InvalidNodeIdLength(usize),
    TooManyRecipients(usize),
    MessageTooLarge(usize),
    Transport(String),
    Remote(String),
}

impl fmt::Display for AppSenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNodeIdLength(actual) => write!(
                formatter,
                "Avalanche node ID has {actual} bytes; expected {NODE_ID_BYTES}"
            ),
            Self::TooManyRecipients(actual) => write!(
                formatter,
                "Avalanche application message has {actual} recipients; maximum is {MAX_RECIPIENTS}"
            ),
            Self::MessageTooLarge(actual) => write!(
                formatter,
                "Avalanche application message has {actual} bytes; maximum is {DEFAULT_MAX_MESSAGE_BYTES}"
            ),
            Self::Transport(message) => write!(formatter, "Avalanche AppSender transport: {message}"),
            Self::Remote(message) => write!(formatter, "Avalanche AppSender RPC: {message}"),
        }
    }
}

impl StdError for AppSenderError {}

fn endpoint_uri(address: &str) -> String {
    if address.starts_with("http://") || address.starts_with("https://") {
        address.to_owned()
    } else {
        format!("http://{address}")
    }
}

fn validate_node_id(node_id: &[u8]) -> Result<(), AppSenderError> {
    if node_id.len() == NODE_ID_BYTES {
        Ok(())
    } else {
        Err(AppSenderError::InvalidNodeIdLength(node_id.len()))
    }
}

fn validate_message(message: &[u8]) -> Result<(), AppSenderError> {
    if message.len() <= DEFAULT_MAX_MESSAGE_BYTES {
        Ok(())
    } else {
        Err(AppSenderError::MessageTooLarge(message.len()))
    }
}

fn validate_recipients(node_ids: &[Vec<u8>]) -> Result<(), AppSenderError> {
    if node_ids.len() > MAX_RECIPIENTS {
        return Err(AppSenderError::TooManyRecipients(node_ids.len()));
    }
    node_ids
        .iter()
        .try_for_each(|node_id| validate_node_id(node_id))
}

fn status_error(status: tonic::Status) -> AppSenderError {
    AppSenderError::Remote(format!("{}: {}", status.code(), status.message()))
}

#[derive(Clone)]
pub struct AppSender {
    inner: AppSenderClient<Channel>,
}

impl AppSender {
    pub async fn connect(address: &str) -> Result<Self, AppSenderError> {
        let endpoint = Endpoint::from_shared(endpoint_uri(address))
            .map_err(|error| AppSenderError::Transport(error.to_string()))?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        let channel = endpoint
            .connect()
            .await
            .map_err(|error| AppSenderError::Transport(error.to_string()))?;
        Ok(Self::from_channel(channel))
    }

    pub fn from_channel(channel: Channel) -> Self {
        Self {
            inner: AppSenderClient::new(channel)
                .max_decoding_message_size(DEFAULT_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(DEFAULT_MAX_MESSAGE_BYTES),
        }
    }

    pub async fn send_request(
        &self,
        node_ids: Vec<Vec<u8>>,
        request_id: u32,
        request: Vec<u8>,
    ) -> Result<(), AppSenderError> {
        validate_recipients(&node_ids)?;
        validate_message(&request)?;
        self.inner
            .clone()
            .send_app_request(SendAppRequestMsg {
                node_ids,
                request_id,
                request,
            })
            .await
            .map_err(status_error)?;
        Ok(())
    }

    pub async fn send_response(
        &self,
        node_id: Vec<u8>,
        request_id: u32,
        response: Vec<u8>,
    ) -> Result<(), AppSenderError> {
        validate_node_id(&node_id)?;
        validate_message(&response)?;
        self.inner
            .clone()
            .send_app_response(SendAppResponseMsg {
                node_id,
                request_id,
                response,
            })
            .await
            .map_err(status_error)?;
        Ok(())
    }

    pub async fn send_error(
        &self,
        node_id: Vec<u8>,
        request_id: u32,
        error_code: i32,
        error_message: String,
    ) -> Result<(), AppSenderError> {
        validate_node_id(&node_id)?;
        validate_message(error_message.as_bytes())?;
        self.inner
            .clone()
            .send_app_error(SendAppErrorMsg {
                node_id,
                request_id,
                error_code,
                error_message,
            })
            .await
            .map_err(status_error)?;
        Ok(())
    }

    pub async fn send_gossip(
        &self,
        node_ids: Vec<Vec<u8>>,
        validators: u64,
        non_validators: u64,
        peers: u64,
        message: Vec<u8>,
    ) -> Result<(), AppSenderError> {
        validate_recipients(&node_ids)?;
        validate_message(&message)?;
        self.inner
            .clone()
            .send_app_gossip(SendAppGossipMsg {
                node_ids,
                validators,
                non_validators,
                peers,
                msg: message,
            })
            .await
            .map_err(status_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_avalanche_node_ids() {
        assert_eq!(
            validate_node_id(&[0; 19]),
            Err(AppSenderError::InvalidNodeIdLength(19))
        );
        assert_eq!(validate_node_id(&[0; NODE_ID_BYTES]), Ok(()));
    }

    #[test]
    fn rejects_unbounded_recipient_sets() {
        let ids = vec![vec![0; NODE_ID_BYTES]; MAX_RECIPIENTS + 1];
        assert_eq!(
            validate_recipients(&ids),
            Err(AppSenderError::TooManyRecipients(MAX_RECIPIENTS + 1))
        );
    }
}
