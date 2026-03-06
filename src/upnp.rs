use anyhow::Result;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

/// Obtém o IP local da máquina (primeira interface não-loopback)
fn get_local_ip() -> Result<IpAddr> {
    use std::net::UdpSocket;

    // Truque: conecta em IP externo qualquer (não envia dados) para descobrir qual interface local seria usada
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let local_addr = socket.local_addr()?;

    Ok(local_addr.ip())
}

/// Abre porta no roteador via UPnP automaticamente
pub async fn open_port(port: u16) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        // Busca gateway UPnP
        let gateway = igd_next::search_gateway(igd_next::SearchOptions {
            timeout: Some(std::time::Duration::from_secs(3)),
            ..Default::default()
        })?;

        // Pega IP local
        let local_ip = get_local_ip()?;

        // Cria SocketAddr com IP local e porta
        let local_addr = SocketAddr::new(local_ip, port);

        // Adiciona port mapping
        gateway.add_port(
            igd_next::PortMappingProtocol::TCP,
            port,
            local_addr,
            60 * 60, // 1 hora de lease
            "t-chat relay",
        )?;

        Ok::<(), anyhow::Error>(())
    })
    .await?
}

/// Remove port mapping quando terminar
pub async fn close_port(port: u16) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let gateway = igd_next::search_gateway(igd_next::SearchOptions {
            timeout: Some(std::time::Duration::from_secs(3)),
            ..Default::default()
        })?;

        gateway.remove_port(igd_next::PortMappingProtocol::TCP, port)?;

        Ok::<(), anyhow::Error>(())
    })
    .await?
}
