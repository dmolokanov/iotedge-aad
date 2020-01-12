use crate::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::Deserialize;

#[derive(Debug)]
pub struct Auth {
    token: String,
}

impl Auth {
    pub async fn authorize(client: impl AsRef<Client>, context: Context) -> Result<Self> {
        // let resource = "https://management.azure.com/";
        let resource = "https://graph.microsoft.com/";
        let scope = "https://graph.microsoft.com/.default";

        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/token",
            context.tenant_id()
        );
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", context.client_id())
            .append_pair("client_secret", context.client_secret())
            .append_pair("resource", resource)
            .append_pair("scope", scope)
            .finish();

        let res = client
            .as_ref()
            .post(&url)
            .header("ContentType", "Application / WwwFormUrlEncoded")
            .body(body)
            .send()
            .await?;

        match res.status() {
            StatusCode::OK => {
                let token: TokenResponse = res.json().await?;
                Ok(Self {
                    token: token.access_token,
                })
            }
            _ => {
                let error: ErrorResponse = res.json().await?;
                Err(error.error_description.into())
            }
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

impl TokenProvider for Auth {
    fn token(&self) -> &str {
        &self.token
    }
}

pub trait TokenProvider {
    fn token(&self) -> &str;
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct TokenResponse {
    token_type: String,
    expires_in: String,
    ext_expires_in: String,
    expires_on: String,
    not_before: String,
    resource: String,
    access_token: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: String,
    error_codes: Vec<u32>,
    timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use matches::assert_matches;
    use std::sync::Arc;

    #[tokio::test]
    async fn it_obtains_auth_token() {
        let client = Arc::new(Client::new());
        // let context = Context::new(String::default(), String::default(), String::default());
        let context = Context::from(std::path::Path::new("context.json")).unwrap();
        let auth = Auth::authorize(client, context).await;
        assert_matches!(auth, Ok(auth) if !auth.token().is_empty());
    }
}
