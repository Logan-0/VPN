use anyhow::Result;

pub struct DnsResolver;

impl DnsResolver {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}
