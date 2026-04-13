use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub country: String,
    pub state: Option<String>,
    pub endpoint: String,
    pub public_key: String,
}

pub struct ServerManager {
    servers: Vec<Server>,
}

impl ServerManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            servers: Vec::new(),
        })
    }

    pub fn get_servers(&self) -> &[Server] {
        &self.servers
    }

    pub fn select_best_server(&self) -> Option<&Server> {
        self.servers.first()
    }
}
