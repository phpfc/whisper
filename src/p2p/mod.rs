use crate::session::{SessionId, SessionMessage};
use anyhow::{anyhow, Result};
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

type PeerMap = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>;

#[derive(Clone)]
pub struct Session {
    pub id: SessionId,
    pub password_hash: [u8; 32],
    pub peers: PeerMap,
    pub public_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl Session {
    pub fn new(id: SessionId, password_hash: [u8; 32]) -> Self {
        Self {
            id,
            password_hash,
            peers: Arc::new(RwLock::new(HashMap::new())),
            public_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn add_peer(
        &self,
        username: String,
        public_key: Vec<u8>,
        tx: mpsc::UnboundedSender<String>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut peers = self.peers.write().await;
        let mut keys = self.public_keys.write().await;

        if peers.contains_key(&username) {
            return Err(anyhow!("Username already taken"));
        }

        let existing_peers: Vec<(String, Vec<u8>)> = keys
            .iter()
            .map(|(name, key)| (name.clone(), key.clone()))
            .collect();

        peers.insert(username.clone(), tx);
        keys.insert(username, public_key);

        Ok(existing_peers)
    }

    pub async fn remove_peer(&self, username: &str) {
        let mut peers = self.peers.write().await;
        let mut keys = self.public_keys.write().await;
        peers.remove(username);
        keys.remove(username);
    }

    pub async fn broadcast(&self, message: &str, exclude: Option<&str>) {
        let peers = self.peers.read().await;
        for (username, tx) in peers.iter() {
            if exclude.is_some() && exclude.unwrap() == username {
                continue;
            }
            let _ = tx.send(message.to_string());
        }
    }
}

pub struct Server {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_session(&self, id: SessionId, password_hash: [u8; 32]) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        if sessions.contains_key(id.as_str()) {
            return Err(anyhow!("Session already exists"));
        }
        sessions.insert(id.as_str().to_string(), Session::new(id, password_hash));
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_session(&self, id: &SessionId) -> Option<Session> {
        let sessions = self.sessions.read().await;
        sessions.get(id.as_str()).cloned()
    }

    pub async fn run(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        println!("Server listening on {}", addr);

        loop {
            let (stream, _) = listener.accept().await?;
            let sessions = self.sessions.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, sessions).await {
                    eprintln!("Connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    let mut current_session: Option<(Session, String)> = None;

    let write_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if writer.write_all(msg.as_bytes()).await.is_err() {
                break;
            }
            if writer.write_all(b"\n").await.is_err() {
                break;
            }
            if writer.flush().await.is_err() {
                break;
            }
        }
    });

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                let msg: SessionMessage = match serde_json::from_str(&line) {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                match msg {
                    SessionMessage::Join {
                        session_id,
                        password_hash,
                        public_key,
                        username,
                    } => {
                        let sessions_read = sessions.read().await;
                        let session_opt = sessions_read.get(session_id.as_str()).cloned();
                        drop(sessions_read);

                        let session = if let Some(existing_session) = session_opt {
                            if existing_session.password_hash != password_hash {
                                let ack = SessionMessage::JoinAck {
                                    success: false,
                                    peer_public_keys: vec![],
                                };
                                tx.send(serde_json::to_string(&ack).unwrap() + "\n")
                                    .ok();
                                continue;
                            }
                            existing_session
                        } else {
                            let new_session = Session::new(session_id.clone(), password_hash);
                            let mut sessions_write = sessions.write().await;
                            sessions_write.insert(session_id.as_str().to_string(), new_session.clone());
                            drop(sessions_write);
                            new_session
                        };

                        match session
                            .add_peer(username.clone(), public_key.clone(), tx.clone())
                            .await
                        {
                            Ok(peer_keys) => {
                                let ack = SessionMessage::JoinAck {
                                    success: true,
                                    peer_public_keys: peer_keys,
                                };
                                let ack_str = serde_json::to_string(&ack).unwrap() + "\n";
                                tx.send(ack_str).ok();

                                let join_notification = SessionMessage::PeerJoined {
                                    username: username.clone(),
                                    public_key,
                                };
                                session
                                    .broadcast(
                                        &(serde_json::to_string(&join_notification).unwrap()
                                            + "\n"),
                                        Some(&username),
                                    )
                                    .await;

                                current_session = Some((session, username));
                            }
                            Err(_) => {
                                let ack = SessionMessage::JoinAck {
                                    success: false,
                                    peer_public_keys: vec![],
                                };
                                tx.send(serde_json::to_string(&ack).unwrap() + "\n")
                                    .ok();
                            }
                        }
                    }
                    SessionMessage::ChatMessage { sender, encrypted_message } => {
                        if let Some((session, username)) = &current_session {
                            let msg = SessionMessage::ChatMessage {
                                sender,
                                encrypted_message
                            };
                            session
                                .broadcast(
                                    &(serde_json::to_string(&msg).unwrap() + "\n"),
                                    Some(username),
                                )
                                .await;
                        }
                    }
                    SessionMessage::KeyExchange { from, to, public_key } => {
                        if let Some((session, _)) = &current_session {
                            let msg = SessionMessage::KeyExchange {
                                from,
                                to: to.clone(),
                                public_key,
                            };
                            let msg_str = serde_json::to_string(&msg).unwrap() + "\n";
                            let peers = session.peers.read().await;
                            if let Some(peer_tx) = peers.get(&to) {
                                peer_tx.send(msg_str).ok();
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => break,
        }
    }

    if let Some((session, username)) = current_session {
        session.remove_peer(&username).await;
        let leave_msg = SessionMessage::PeerLeft {
            username: username.clone(),
        };
        session
            .broadcast(&(serde_json::to_string(&leave_msg).unwrap() + "\n"), None)
            .await;
    }

    write_handle.abort();
    Ok(())
}
