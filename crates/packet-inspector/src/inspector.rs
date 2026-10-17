use crate::PacketInspectionError;
use security_control_plane_common::{
    SecurityEvent, SensorMetadata, SensorType, Severity, SourceContext,
};
use serde_json::Value;
use std::net::IpAddr;

pub struct PacketInspector {
    app_id: String,
}

impl PacketInspector {
    pub fn new(app_id: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
        }
    }

    pub fn inspect_tcp_payload(
        &self,
        source_ip: IpAddr,
        source_port: u16,
        payload: &[u8],
    ) -> Result<Option<SecurityEvent>, PacketInspectionError> {
        if payload.first() == Some(&22) {
            return inspect_tls(&self.app_id, source_ip, source_port, payload);
        }
        if looks_like_http(payload) {
            return inspect_http(&self.app_id, source_ip, source_port, payload);
        }
        Ok(None)
    }

    pub fn inspect_dns_query(
        &self,
        source_ip: IpAddr,
        source_port: u16,
        payload: &[u8],
    ) -> Result<Option<SecurityEvent>, PacketInspectionError> {
        let Some(query) = parse_dns_question(payload)? else {
            return Ok(None);
        };

        let is_tunneling = query.longest_label_len > 50;
        let mut event = self.event(
            "net.dns.query",
            source_ip,
            source_port,
            if is_tunneling {
                Severity::High
            } else {
                Severity::Low
            },
            is_tunneling,
        );
        event.metadata.insert(
            "dns_label_count".into(),
            Value::from(query.label_count as u64),
        );
        event.metadata.insert(
            "dns_longest_label_length".into(),
            Value::from(query.longest_label_len as u64),
        );
        event
            .metadata
            .insert("dns_query_type".into(), Value::from(query.query_type));
        event
            .metadata
            .insert("dns_tunneling".into(), Value::from(is_tunneling));
        Ok(Some(event))
    }

    fn event(
        &self,
        event_type: &str,
        source_ip: IpAddr,
        source_port: u16,
        severity: Severity,
        significant: bool,
    ) -> SecurityEvent {
        let mut event = SecurityEvent::new(
            self.app_id.clone(),
            "production",
            event_type,
            SourceContext {
                ip: Some(source_ip.to_string()),
                port: Some(source_port),
                user_agent: None,
                sensor: SensorMetadata {
                    sensor_type: SensorType::PacketInspector,
                    raw_event_type: event_type.to_string(),
                    sensor_id: None,
                    raw_payload: None,
                },
                container_id: None,
                pid: None,
                process_name: None,
            },
        );
        event.severity = severity;
        event.is_security_significant = significant;
        event
    }
}

fn looks_like_http(payload: &[u8]) -> bool {
    [
        b"GET ".as_slice(),
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
    ]
    .iter()
    .any(|prefix| payload.starts_with(prefix))
}

fn inspect_http(
    app_id: &str,
    source_ip: IpAddr,
    source_port: u16,
    payload: &[u8],
) -> Result<Option<SecurityEvent>, PacketInspectionError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    match request.parse(payload) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => {
            return Err(PacketInspectionError::MalformedPayload {
                protocol: "HTTP",
                reason: "request headers are incomplete",
            })
        }
        Err(_) => {
            return Err(PacketInspectionError::MalformedPayload {
                protocol: "HTTP",
                reason: "request syntax is invalid",
            })
        }
    }

    let path = request.path.unwrap_or_default().to_ascii_lowercase();
    let traversal = path.contains("../")
        || path.contains("..%2f")
        || path.contains("%2e%2e%2f")
        || path.contains("%2e%2e/");
    let mut suspicious_agent = false;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("user-agent") {
            let value = std::str::from_utf8(header.value).map_err(|_| {
                PacketInspectionError::MalformedPayload {
                    protocol: "HTTP",
                    reason: "user-agent header is not valid UTF-8",
                }
            })?;
            let value = value.to_ascii_lowercase();
            suspicious_agent = ["sqlmap", "nikto", "masscan", "nmap"]
                .iter()
                .any(|needle| value.contains(needle));
        }
    }
    let long_headers = request
        .headers
        .iter()
        .any(|header| header.value.len() > 8 * 1024);
    let is_anomaly = traversal || suspicious_agent || long_headers;
    if !is_anomaly {
        return Ok(None);
    }

    let mut event = make_event(
        app_id,
        "net.http.anomaly",
        source_ip,
        source_port,
        Severity::High,
    );
    event.is_security_significant = true;
    event
        .metadata
        .insert("http_anomaly".into(), Value::Bool(true));
    event
        .metadata
        .insert("path_traversal".into(), Value::Bool(traversal));
    event.metadata.insert(
        "suspicious_user_agent".into(),
        Value::Bool(suspicious_agent),
    );
    event
        .metadata
        .insert("oversized_header".into(), Value::Bool(long_headers));
    Ok(Some(event))
}

struct DnsQuestion {
    label_count: usize,
    longest_label_len: usize,
    query_type: u16,
}

fn parse_dns_question(payload: &[u8]) -> Result<Option<DnsQuestion>, PacketInspectionError> {
    if payload.len() < 12 {
        return Err(PacketInspectionError::MalformedPayload {
            protocol: "DNS",
            reason: "header is shorter than 12 bytes",
        });
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let question_count = u16::from_be_bytes([payload[4], payload[5]]);
    if flags & 0x8000 != 0 || question_count == 0 {
        return Ok(None);
    }

    let mut offset = 12;
    let mut labels = 0;
    let mut longest_label_len = 0;
    loop {
        let length = *payload
            .get(offset)
            .ok_or(PacketInspectionError::MalformedPayload {
                protocol: "DNS",
                reason: "question name is truncated",
            })?;
        offset += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 != 0 {
            return Err(PacketInspectionError::MalformedPayload {
                protocol: "DNS",
                reason: "compressed question names are unsupported",
            });
        }
        let end =
            offset
                .checked_add(length as usize)
                .ok_or(PacketInspectionError::MalformedPayload {
                    protocol: "DNS",
                    reason: "question name length overflow",
                })?;
        if end > payload.len() {
            return Err(PacketInspectionError::MalformedPayload {
                protocol: "DNS",
                reason: "label exceeds packet boundary",
            });
        }
        labels += 1;
        longest_label_len = longest_label_len.max(length as usize);
        offset = end;
    }

    let query_type_bytes =
        payload
            .get(offset..offset + 2)
            .ok_or(PacketInspectionError::MalformedPayload {
                protocol: "DNS",
                reason: "query type is truncated",
            })?;
    let query_type = u16::from_be_bytes([query_type_bytes[0], query_type_bytes[1]]);
    Ok(Some(DnsQuestion {
        label_count: labels,
        longest_label_len,
        query_type,
    }))
}

fn inspect_tls(
    app_id: &str,
    source_ip: IpAddr,
    source_port: u16,
    payload: &[u8],
) -> Result<Option<SecurityEvent>, PacketInspectionError> {
    let hello = parse_client_hello(payload)?;
    let weak_tls = hello.version < 0x0303 || hello.weak_cipher;
    let mut event = make_event(
        app_id,
        "net.tls.client_hello",
        source_ip,
        source_port,
        if weak_tls {
            Severity::High
        } else {
            Severity::Low
        },
    );
    event.is_security_significant = weak_tls;
    event
        .metadata
        .insert("tls_version".into(), Value::from(hello.version));
    event
        .metadata
        .insert("tls_anomaly".into(), Value::Bool(weak_tls));
    if let Some(sni) = hello.sni {
        event.metadata.insert("tls_sni".into(), Value::String(sni));
    }
    Ok(Some(event))
}

struct ClientHello {
    version: u16,
    weak_cipher: bool,
    sni: Option<String>,
}

fn parse_client_hello(payload: &[u8]) -> Result<ClientHello, PacketInspectionError> {
    let malformed = || PacketInspectionError::MalformedPayload {
        protocol: "TLS",
        reason: "invalid ClientHello structure",
    };
    if payload.len() < 9 || payload[0] != 22 || payload[5] != 1 {
        return Err(malformed());
    }
    let record_end = 5 + u16::from_be_bytes([payload[3], payload[4]]) as usize;
    let hello_end = 9 + u32::from_be_bytes([0, payload[6], payload[7], payload[8]]) as usize;
    if record_end > payload.len() || hello_end > record_end || hello_end < 41 {
        return Err(malformed());
    }
    let version = u16::from_be_bytes([payload[9], payload[10]]);
    let mut offset = 9 + 2 + 32;
    let session_len = *payload.get(offset).ok_or_else(malformed)? as usize;
    offset = offset.checked_add(1 + session_len).ok_or_else(malformed)?;
    let cipher_len_bytes = payload.get(offset..offset + 2).ok_or_else(malformed)?;
    let cipher_len = u16::from_be_bytes([cipher_len_bytes[0], cipher_len_bytes[1]]) as usize;
    offset += 2;
    let ciphers = payload
        .get(offset..offset + cipher_len)
        .ok_or_else(malformed)?;
    let weak_cipher = ciphers.chunks_exact(2).any(|cipher| {
        matches!(
            u16::from_be_bytes([cipher[0], cipher[1]]),
            0x0004 | 0x0005 | 0x000a
        )
    });
    offset += cipher_len;
    let compression_len = *payload.get(offset).ok_or_else(malformed)? as usize;
    offset = offset
        .checked_add(1 + compression_len)
        .ok_or_else(malformed)?;
    let extensions_len_bytes = payload.get(offset..offset + 2).ok_or_else(malformed)?;
    let extensions_len =
        u16::from_be_bytes([extensions_len_bytes[0], extensions_len_bytes[1]]) as usize;
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len).ok_or_else(malformed)?;
    if extensions_end > hello_end {
        return Err(malformed());
    }

    let mut sni = None;
    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let extension_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
        offset += 4;
        let extension_end = offset.checked_add(extension_len).ok_or_else(malformed)?;
        if extension_end > extensions_end {
            return Err(malformed());
        }
        if extension_type == 0 && extension_len >= 5 {
            let name_type = payload[offset + 2];
            let name_len = u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;
            let name_end = offset.checked_add(5 + name_len).ok_or_else(malformed)?;
            if name_type == 0 && name_end <= extension_end {
                sni = Some(
                    std::str::from_utf8(&payload[offset + 5..name_end])
                        .map_err(|_| malformed())?
                        .to_string(),
                );
            }
        }
        offset = extension_end;
    }
    Ok(ClientHello {
        version,
        weak_cipher,
        sni,
    })
}

fn make_event(
    app_id: &str,
    event_type: &str,
    source_ip: IpAddr,
    source_port: u16,
    severity: Severity,
) -> SecurityEvent {
    let mut event = SecurityEvent::new(
        app_id,
        "production",
        event_type,
        SourceContext {
            ip: Some(source_ip.to_string()),
            port: Some(source_port),
            user_agent: None,
            sensor: SensorMetadata {
                sensor_type: SensorType::PacketInspector,
                raw_event_type: event_type.to_string(),
                sensor_id: None,
                raw_payload: None,
            },
            container_id: None,
            pid: None,
            process_name: None,
        },
    );
    event.severity = severity;
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_query(label: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        packet
    }

    fn tls_client_hello(version: u16, cipher: u16, sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut body = vec![(version >> 8) as u8, version as u8];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, (cipher >> 8) as u8, cipher as u8]);
        body.extend_from_slice(&[1, 0]);

        let list_len = 3 + name.len();
        let mut sni_extension = vec![
            ((list_len >> 8) & 0xff) as u8,
            (list_len & 0xff) as u8,
            0,
            ((name.len() >> 8) & 0xff) as u8,
            (name.len() & 0xff) as u8,
        ];
        sni_extension.extend_from_slice(name);
        let extension_len = sni_extension.len() as u16;
        let mut extensions = vec![0, 0, (extension_len >> 8) as u8, extension_len as u8];
        extensions.extend_from_slice(&sni_extension);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1, 0, 0, body.len() as u8];
        handshake.extend_from_slice(&body);
        let record_len = handshake.len() as u16;
        let mut record = vec![22, 3, 1, (record_len >> 8) as u8, record_len as u8];
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn detects_path_traversal_without_retaining_request_path() {
        let inspector = PacketInspector::new("test-host");
        let payload = b"GET /../../etc/passwd HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let event = inspector
            .inspect_tcp_payload("192.0.2.1".parse().expect("ip"), 12345, payload)
            .expect("valid HTTP")
            .expect("anomaly");

        assert_eq!(event.event_type, "net.http.anomaly");
        assert_eq!(event.source.sensor.sensor_type, SensorType::PacketInspector);
        assert_eq!(event.severity, Severity::High);
        assert_eq!(
            event.metadata.get("path_traversal"),
            Some(&Value::Bool(true))
        );
        assert!(!event.metadata.contains_key("request_path"));
    }

    #[test]
    fn records_dns_queries_and_flags_long_labels() {
        let inspector = PacketInspector::new("test-host");
        let payload = dns_query(&vec![b'a'; 51]);
        let event = inspector
            .inspect_dns_query("192.0.2.2".parse().expect("ip"), 53000, &payload)
            .expect("valid DNS")
            .expect("query");
        assert_eq!(event.event_type, "net.dns.query");
        assert_eq!(event.severity, Severity::High);
        assert_eq!(
            event.metadata.get("dns_tunneling"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn extracts_tls_sni_and_flags_weak_cipher() {
        let inspector = PacketInspector::new("test-host");
        let payload = tls_client_hello(0x0301, 0x0004, "service.example");
        let event = inspector
            .inspect_tcp_payload("192.0.2.3".parse().expect("ip"), 443, &payload)
            .expect("valid TLS")
            .expect("ClientHello");
        assert_eq!(event.event_type, "net.tls.client_hello");
        assert_eq!(
            event.metadata.get("tls_sni"),
            Some(&Value::String("service.example".into()))
        );
        assert_eq!(event.metadata.get("tls_anomaly"), Some(&Value::Bool(true)));
    }
}
