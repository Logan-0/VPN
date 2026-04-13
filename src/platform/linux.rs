use anyhow::Result;

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}
