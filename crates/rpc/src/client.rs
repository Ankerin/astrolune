// Copyright (c) 2026 Astrolune contributors
// SPDX-License-Identifier: MIT

//! Typed client for the daemon's length-prefixed JSON-RPC protocol.
//! One connection per call, one absolute deadline, and no automatic retries.
//! This transport has no authentication: use a trusted local endpoint or tunnel.

use std::{
    fmt::{self, Write as _},
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use codec::CanonicalDecode;
use types::{AccountState, Address, Hash256};

use crate::json::{JsonValue, parse_json, to_json};

/// Maximum canonical transaction accepted by the network exchange.
pub const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4096;

/// Finalized head reported by the contacted node; not a cryptographic proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainStatus {
    /// Chain replay-protection identifier.
    pub chain_id: u32,
    /// Finalized block height.
    pub finalized_height: u64,
    /// Finalized block commitment.
    pub finalized_block: Hash256,
}

/// Client failure. A transport/protocol failure after submission can be ambiguous.
#[derive(Debug)]
pub enum ClientError {
    /// Connection, deadline, or incomplete frame.
    Io(io::Error),
    /// Response violates the expected JSON-RPC or typed result schema.
    Protocol(&'static str),
    /// Request would exceed the supported bound.
    LimitExceeded,
    /// A matching JSON-RPC error response was received.
    Remote {
        /// Remote error code.
        code: i64,
        /// Remote error description.
        message: String,
    },
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "RPC transport: {error}"),
            Self::Protocol(message) => write!(f, "RPC protocol: {message}"),
            Self::LimitExceeded => write!(f, "RPC request exceeds the transaction limit"),
            Self::Remote { code, message } => {
                // Escape terminal controls supplied by an untrusted server.
                write!(f, "RPC rejected request ({code}): {message:?}")
            }
        }
    }
}
impl std::error::Error for ClientError {}
impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Bounded, synchronous RPC client. Numeric socket addresses avoid unbounded DNS.
pub struct TcpRpcClient {
    address: SocketAddr,
    timeout: Duration,
}

impl TcpRpcClient {
    /// Creates a client with a positive per-call deadline of at most 60 seconds.
    pub fn new(address: SocketAddr, timeout: Duration) -> Result<Self, ClientError> {
        if timeout.is_zero() || timeout > Duration::from_secs(60) {
            return Err(ClientError::Protocol("timeout must be in (0, 60s]"));
        }
        Ok(Self { address, timeout })
    }

    /// Reads the contacted node's finalized head.
    pub fn chain_status(&self) -> Result<ChainStatus, ClientError> {
        let value = self.call("chain_status", JsonValue::Object(vec![]))?;
        let chain_id = number_field(&value, "chain_id")?;
        let finalized_height = number_field(&value, "finalized_height")?;
        let finalized_block = hash_value(value.get("finalized_block"))?;
        Ok(ChainStatus {
            chain_id: u32::try_from(chain_id)
                .map_err(|_| ClientError::Protocol("invalid chain id"))?,
            finalized_height,
            finalized_block,
        })
    }

    /// Reads a finalized account; absence is distinct from a zero-balance account.
    pub fn account(&self, address: Address) -> Result<Option<AccountState>, ClientError> {
        let value = self.call(
            "account",
            JsonValue::Object(vec![(
                "address".into(),
                JsonValue::String(address.to_string()),
            )]),
        )?;
        if value == JsonValue::Null {
            return Ok(None);
        }
        let hex = value
            .as_str()
            .ok_or(ClientError::Protocol("invalid account"))?;
        let bytes = decode_hex::<16>(hex)?;
        AccountState::decode(&bytes)
            .map(Some)
            .map_err(|_| ClientError::Protocol("invalid canonical account"))
    }

    /// Submits exactly these bytes once. Acceptance does not mean finalization.
    /// Callers should retain the signed bytes and verify the returned identifier.
    pub fn submit_transaction(&self, bytes: &[u8]) -> Result<Hash256, ClientError> {
        if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(ClientError::LimitExceeded);
        }
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(hex, "{byte:02x}");
        }
        let value = self.call(
            "submit_transaction",
            JsonValue::Object(vec![("data".into(), JsonValue::String(hex))]),
        )?;
        hash_value(Some(&value))
    }

    fn call(&self, method: &str, params: JsonValue) -> Result<JsonValue, ClientError> {
        let request = to_json(&JsonValue::Object(vec![
            ("jsonrpc".into(), JsonValue::String("2.0".into())),
            ("id".into(), JsonValue::Number(1)),
            ("method".into(), JsonValue::String(method.into())),
            ("params".into(), params),
        ]));
        let length = u32::try_from(request.len()).map_err(|_| ClientError::LimitExceeded)?;
        let mut frame = length.to_le_bytes().to_vec();
        frame.extend_from_slice(request.as_bytes());
        let deadline = Instant::now() + self.timeout;
        let mut stream = TcpStream::connect_timeout(&self.address, remaining(deadline)?)?;
        let mut bytes = frame.as_slice();
        while !bytes.is_empty() {
            stream.set_write_timeout(Some(remaining(deadline)?))?;
            match stream.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        let mut prefix = [0; 4];
        read_exact(&mut stream, &mut prefix, deadline)?;
        let length = u32::from_le_bytes(prefix) as usize;
        if length == 0 || length > MAX_RESPONSE_BYTES {
            return Err(ClientError::Protocol("invalid response frame size"));
        }
        let mut payload = vec![0; length];
        read_exact(&mut stream, &mut payload, deadline)?;
        let text =
            std::str::from_utf8(&payload).map_err(|_| ClientError::Protocol("invalid UTF-8"))?;
        let value = parse_json(text).map_err(|_| ClientError::Protocol("invalid JSON"))?;
        response_result(&value)
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

fn read_exact(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    // Also reject a final chunk delivered after the overall deadline.
    remaining(deadline)?;
    Ok(())
}

fn response_result(value: &JsonValue) -> Result<JsonValue, ClientError> {
    if value.get("jsonrpc").and_then(JsonValue::as_str) != Some("2.0")
        || value.get("id").and_then(JsonValue::as_i64) != Some(1)
    {
        return Err(ClientError::Protocol("response version or id mismatch"));
    }
    match (value.get("result"), value.get("error")) {
        (Some(result), None) => Ok(result.clone()),
        (None, Some(error)) => {
            let code = error
                .get("code")
                .and_then(JsonValue::as_i64)
                .ok_or(ClientError::Protocol("invalid error code"))?;
            let message = error
                .get("message")
                .and_then(JsonValue::as_str)
                .ok_or(ClientError::Protocol("invalid error message"))?;
            Err(ClientError::Remote {
                code,
                message: message.into(),
            })
        }
        _ => Err(ClientError::Protocol(
            "expected exactly one result or error",
        )),
    }
}

fn number_field(value: &JsonValue, field: &str) -> Result<u64, ClientError> {
    value
        .get(field)
        .and_then(JsonValue::as_i64)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(ClientError::Protocol("missing or invalid unsigned integer"))
}

fn hash_value(value: Option<&JsonValue>) -> Result<Hash256, ClientError> {
    let text = value
        .and_then(JsonValue::as_str)
        .ok_or(ClientError::Protocol("invalid hash"))?;
    decode_hex(text).map(Hash256)
}

/// Decodes an exact-size hexadecimal value, optionally prefixed with `0x`.
pub fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N], ClientError> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if text.len() != N * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ClientError::Protocol("invalid hexadecimal value"));
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| ClientError::Protocol("invalid hexadecimal value"))?;
    }
    Ok(result)
}

impl From<io::ErrorKind> for ClientError {
    fn from(kind: io::ErrorKind) -> Self {
        Self::Io(kind.into())
    }
}
