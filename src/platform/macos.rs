use anyhow::Result;

pub struct MacOSPlatform;

impl MacOSPlatform {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}
