use anyhow::{anyhow, Result};
use bytecodec::{DecodeExt, EncodeExt};
use std::net::{SocketAddr, UdpSocket};
use stun_codec::{
    rfc5389::{
        attributes::{MappedAddress, XorMappedAddress},
        methods::BINDING,
        Attribute,
    },
    Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
};

const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun3.l.google.com:19302",
    "stun4.l.google.com:19302",
];

pub fn discover_public_address() -> Result<SocketAddr> {
    for server in STUN_SERVERS {
        if let Ok(addr) = try_stun_server(server) {
            return Ok(addr);
        }
    }
    Err(anyhow!("Failed to discover public address via STUN"))
}

fn try_stun_server(server: &str) -> Result<SocketAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(3)))?;

    let server_addr: SocketAddr = server
        .parse()
        .or_else(|_| {
            std::net::ToSocketAddrs::to_socket_addrs(server)?
                .next()
                .ok_or_else(|| anyhow!("Failed to resolve STUN server"))
        })?;

    let transaction_id = TransactionId::new(rand::random());
    let mut message = Message::<Attribute>::new(MessageClass::Request, BINDING, transaction_id);

    let mut encoder = MessageEncoder::new();
    let bytes = encoder.encode_into_bytes(message.clone())?;

    socket.send_to(&bytes, server_addr)?;

    let mut buf = [0u8; 1024];
    let (size, _) = socket.recv_from(&mut buf)?;

    let mut decoder = MessageDecoder::<Attribute>::new();
    let decoded = decoder
        .decode_from_bytes(&buf[..size])
        .map_err(|e| anyhow!("Failed to decode STUN response: {:?}", e))?;
    let response = decoded.map_err(|e| anyhow!("Broken STUN message: {:?}", e))?;

    if response.transaction_id() != message.transaction_id() {
        return Err(anyhow!("Transaction ID mismatch"));
    }

    for attr in response.attributes() {
        match attr {
            Attribute::XorMappedAddress(xor_mapped) => {
                return Ok(xor_mapped.address());
            }
            Attribute::MappedAddress(mapped) => {
                return Ok(mapped.address());
            }
            _ => continue,
        }
    }

    Err(anyhow!("No address attribute in STUN response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_stun_discovery() {
        let addr = discover_public_address();
        assert!(addr.is_ok());
        println!("Discovered address: {:?}", addr);
    }
}
