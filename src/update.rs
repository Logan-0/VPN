use anyhow::Result;

pub struct UpdateChecker {
    current_version: String,
}

impl UpdateChecker {
    pub fn new(version: String) -> Self {
        Self {
            current_version: version,
        }
    }

    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    pub async fn check_for_updates(&self) -> Result<Option<String>> {
        Ok(None)
    }
}
