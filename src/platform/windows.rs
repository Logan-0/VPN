use anyhow::Result;

pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}
