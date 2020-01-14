use crate::{Result, TokenSource};
use chrono::NaiveDateTime;
use hex::ToHex;
use openssl::x509::X509;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub struct Identity<A> {
    client: Arc<Client>,
    auth: A,
}

impl<A> Identity<A>
where
    A: TokenSource,
{
    pub fn new(client: Arc<Client>, auth: A) -> Self {
        Self { client, auth }
    }

    pub async fn provision(
        &self,
        name: &str,
        cert_path: Option<PathBuf>,
    ) -> Result<CreatedIdentity> {
        // prepare auth credentials for an app registration
        let module_cert_path = PathBuf::from(format!("{}/cert.pem", name));
        match cert_path {
            Some(cert_path) => {
                let dir_path = Path::new(name);
                if !dir_path.exists() {
                    fs::create_dir(dir_path)?;
                }
                fs::copy(cert_path, &module_cert_path)?;
            }
            None => unimplemented!("cert generation unsupported yet"),
        };

        let credentials = self.build_application_credentials(name, &module_cert_path)?;
        // TODO add default role assignments for identity
        let body = json!(
        {
            "displayName": name,
            "keyCredentials": credentials
        });

        // create an app registration
        let app_id = self.create_application(body).await?;

        // create a service principal corresponding to an app registration
        self.create_service_principal(&app_id).await?;

        Ok(CreatedIdentity { app_id })
    }

    async fn create_application(&self, body: Value) -> Result<String> {
        let url = "https://graph.microsoft.com/beta/applications".to_string();

        let res = self
            .client
            .post(&url)
            .bearer_auth(self.auth.get())
            .json(&body)
            .send()
            .await?;

        match res.status() {
            StatusCode::CREATED => {
                let content: Value = res.json().await?;

                let app_id = content["appId"].as_str().unwrap().to_string();
                Ok(app_id)
            }
            _ => {
                let content: Value = res.json().await?;
                Err(content.to_string().into())
            }
        }
    }

    async fn create_service_principal(&self, app_id: &str) -> Result<()> {
        let url = "https://graph.microsoft.com/beta/servicePrincipals".to_string();

        let res = self
            .client
            .post(&url)
            .bearer_auth(self.auth.get())
            .json(&json!({ "appId": app_id }))
            .send()
            .await?;

        match res.status() {
            StatusCode::CREATED => {
                let _content: Value = res.json().await?;
                Ok(())
            }
            _ => {
                let content: Value = res.json().await?;
                Err(content.to_string().into())
            }
        }
    }

    fn build_application_credentials(&self, name: &str, cert_path: &Path) -> Result<Value> {
        let cert_data = fs::read_to_string(cert_path)?;
        let cert = X509::from_pem(cert_data.as_ref())?;

        let cert_value = String::from_utf8(cert.to_pem()?)?;
        let cert_value = cert_value.replace("-----BEGIN CERTIFICATE-----\n", "");
        let cert_value = cert_value.replace("-----END CERTIFICATE-----\n", "");

        let start_date = asn_time_to_iso_string(&cert.not_before().to_string())?;
        let end_date = asn_time_to_iso_string(&cert.not_after().to_string())?;

        let fingerprint = cert.digest(openssl::hash::MessageDigest::sha1())?;
        let fingerprint = fingerprint.encode_hex_upper::<String>();

        let credentials = json!(
            [
                {
                    "startDateTime": start_date,
                    "endDateTime": end_date,
                    "keyId": Uuid::new_v4(),
                    "key": cert_value,
                    "usage": "Verify",
                    "type": "AsymmetricX509Cert",
                    "customKeyIdentifier": fingerprint,
                    "displayName": format!("{}-cert", name)
                }
            ]
        );

        Ok(credentials)
    }

    pub async fn delete(&self, _name: &str) -> Result<()> {
        unimplemented!()
    }
}

fn asn_time_to_iso_string(date: &str) -> Result<String> {
    let parsed = NaiveDateTime::parse_from_str(date, "%b %e %T %Y GMT")?;
    Ok(parsed.format("%FT%TZ").to_string())
}

#[derive(Debug)]
pub struct CreatedIdentity {
    pub app_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Auth, Context};
    use matches::assert_matches;
    use reqwest::Client;
    use std::{path::Path, sync::Arc};

    #[tokio::test]
    async fn it_creates_application() {
        let client = Arc::new(Client::new());
        let auth = Auth::new(client.clone());
        let context = Context::from(Path::new("context.json")).unwrap();
        let auth = auth
            .authorize_with_secret(
                context.tenant_id(),
                context.client_id(),
                context.client_secret(),
            )
            .await;
        let cert_path = Some(PathBuf::from("module-a/combined.pem"));
        let identity = Identity::new(client, auth.unwrap());

        let created = identity.provision("module-a", cert_path).await;

        assert_matches!(created, Ok(created) if !created.app_id.is_empty());
    }

    #[test]
    fn it_parses_cert_time() {
        let date = "Jan 11 08:06:36 2020 GMT";

        let iso = asn_time_to_iso_string(date);

        assert_matches!(iso, Ok(date) if date == "2020-01-11T08:06:36Z");
    }
}
