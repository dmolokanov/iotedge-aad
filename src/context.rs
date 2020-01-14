use crate::Result;
use config::{Config, File};
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct Context {
    client_id: String,
    cert: String,
    tenant_id: String,
}

impl Context {
    pub fn from(path: &Path) -> Result<Context> {
        let mut config = Config::new();
        config.merge(File::from(path))?;
        let context = config.try_into()?;
        Ok(context)
    }

    pub fn new(client_id: String, cert: String, tenant_id: String) -> Self {
        Self {
            client_id,
            cert,
            tenant_id,
        }
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn cert(&self) -> &str {
        &self.cert
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}
