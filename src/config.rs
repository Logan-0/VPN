use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub auto_connect: bool,
    pub kill_switch_enabled: bool,
    pub dns_filtering_enabled: bool,
    pub selected_server: Option<String>,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            auto_connect: false,
            kill_switch_enabled: true,
            dns_filtering_enabled: true,
            selected_server: None,
        }
    }
}

impl VpnConfig {
    pub fn load() -> Result<Self> {
        Ok(Self::default())
    }

    pub fn save(&self) -> Result<()> {
        Ok(())
    }
}
