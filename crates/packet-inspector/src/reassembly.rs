use crate::ReassemblyError;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

const MAX_STREAM_BYTES: usize = 64 * 1024;
const MAX_ACTIVE_STREAMS: usize = 4096;
const STREAM_IDLE_TIMEOUT_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct StreamKey {
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
}

#[derive(Default)]
pub struct TcpStreamReassembler {
    streams: HashMap<StreamKey, StreamState>,
}

#[derive(Default)]
struct StreamState {
    expected_sequence: Option<u32>,
    bytes: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    last_seen_ms: i64,
}

impl TcpStreamReassembler {
    pub fn push(
        &mut self,
        key: StreamKey,
        sequence: u32,
        payload: &[u8],
        timestamp_ms: i64,
        fin_or_rst: bool,
    ) -> Result<Option<Vec<u8>>, ReassemblyError> {
        self.expire(timestamp_ms);
        if !self.streams.contains_key(&key) && self.streams.len() >= MAX_ACTIVE_STREAMS {
            return Err(ReassemblyError::TooManyStreams);
        }

        let state = self.streams.entry(key.clone()).or_default();
        state.last_seen_ms = timestamp_ms;
        if state.expected_sequence.is_none() {
            state.expected_sequence = Some(sequence.wrapping_add(payload.len() as u32));
            state.bytes.extend_from_slice(payload);
        } else if Some(sequence) == state.expected_sequence {
            state.bytes.extend_from_slice(payload);
            state.expected_sequence = Some(sequence.wrapping_add(payload.len() as u32));
            loop {
                let Some(expected) = state.expected_sequence else {
                    break;
                };
                let Some(next) = state.pending.remove(&expected) else {
                    break;
                };
                state.bytes.extend_from_slice(&next);
                state.expected_sequence = Some(expected.wrapping_add(next.len() as u32));
            }
        } else if let Some(expected_sequence) = state.expected_sequence {
            if sequence.wrapping_sub(expected_sequence) < (1 << 31) {
                state
                    .pending
                    .entry(sequence)
                    .or_insert_with(|| payload.to_vec());
            }
        }

        if state.bytes.len() + state.pending.values().map(Vec::len).sum::<usize>()
            > MAX_STREAM_BYTES
        {
            self.streams.remove(&key);
            return Err(ReassemblyError::StreamTooLarge);
        }

        if fin_or_rst {
            let state = self.streams.remove(&key);
            return Ok(state.map(|state| state.bytes));
        }
        Ok(None)
    }

    pub fn expire(&mut self, now_ms: i64) {
        self.streams.retain(|_, stream| {
            now_ms.saturating_sub(stream.last_seen_ms) < STREAM_IDLE_TIMEOUT_MS
        });
    }

    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> StreamKey {
        StreamKey {
            source_ip: "192.0.2.1".parse().expect("source IP"),
            source_port: 12345,
            destination_ip: "198.51.100.1".parse().expect("destination IP"),
            destination_port: 80,
        }
    }

    #[test]
    fn reassembles_out_of_order_segments() {
        let mut reassembler = TcpStreamReassembler::default();
        assert!(reassembler
            .push(key(), 100, b"hello ", 0, false)
            .expect("first segment")
            .is_none());
        reassembler
            .push(key(), 112, b"world", 1, false)
            .expect("out-of-order segment");
        let complete = reassembler
            .push(key(), 106, b"there ", 2, true)
            .expect("missing segment")
            .expect("closed stream");
        assert_eq!(complete, b"hello there world");
        assert_eq!(reassembler.active_stream_count(), 0);
    }

    #[test]
    fn expires_idle_streams() {
        let mut reassembler = TcpStreamReassembler::default();
        reassembler
            .push(key(), 1, b"partial", 0, false)
            .expect("segment");
        reassembler.expire(5 * 60 * 1000);
        assert_eq!(reassembler.active_stream_count(), 0);
    }
}
