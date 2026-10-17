#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PacketInspectionError {
    #[error("Malformed {protocol} payload: {reason}")]
    MalformedPayload {
        protocol: &'static str,
        reason: &'static str,
    },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReassemblyError {
    #[error("TCP stream exceeded configured size limit")]
    StreamTooLarge,
    #[error("Maximum concurrent TCP streams reached")]
    TooManyStreams,
}
