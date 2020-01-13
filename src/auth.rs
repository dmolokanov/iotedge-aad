use crate::Result;
use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer, x509::X509};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;

pub struct Auth {
    client: Arc<Client>,
}

impl Auth {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    pub async fn authorize_with_secret(
        &self,
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<AuthToken> {
        let scope = "https://graph.microsoft.com/.default";

        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        );
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", client_id)
            .append_pair("client_secret", client_secret)
            .append_pair("scope", scope)
            .finish();

        let res = self
            .client
            .post(&url)
            .header("ContentType", "Application / WwwFormUrlEncoded")
            .body(body)
            .send()
            .await?;

        match res.status() {
            StatusCode::OK => {
                let token: TokenResponse = res.json().await?;
                let auth = AuthToken(token.access_token);
                Ok(auth)
            }
            _ => {
                let error: ErrorResponse = res.json().await?;
                Err(error.error_description.into())
            }
        }
    }

    pub async fn authorize_with_certificate(
        &self,
        tenant_id: &str,
        client_id: &str,
        cert_path: &Path,
    ) -> Result<AuthToken> {
        let token = create_jwt(tenant_id, client_id, cert_path)?;

        let scope = "https://graph.microsoft.com/.default";

        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        );
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", client_id)
            .append_pair("scope", scope)
            .append_pair(
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            )
            .append_pair("client_assertion", &token)
            .finish();

        let res = self
            .client
            .post(&url)
            .header("ContentType", "Application / WwwFormUrlEncoded")
            .body(body)
            .send()
            .await?;

        match res.status() {
            StatusCode::OK => {
                let token: TokenResponse = res.json().await?;
                let auth = AuthToken(token.access_token);
                Ok(auth)
            }
            _ => {
                let error: ErrorResponse = res.json().await?;
                Err(error.error_description.into())
            }
        }
    }
}

fn create_jwt(tenant_id: &str, client_id: &str, cert_path: &Path) -> Result<String> {
    let cert_data = std::fs::read_to_string(&cert_path)?;
    let cert = X509::from_pem(cert_data.as_ref())?;

    let fingerprint = cert.digest(MessageDigest::sha1())?;

    let header = json!(
        {
            "typ": "JWT",
            "alg": "RS256",
            "x5t": base64::encode_config(&fingerprint, base64::URL_SAFE_NO_PAD)
        }
    );
    let claims = json!(
        {
            "exp": 1583020800, // TODO generate for an hour
            "aud": format!("https://login.microsoftonline.com/{}/oauth2/token", tenant_id),
            "iss": client_id,
            "sub": client_id,
          }
    );

    let data = [
        base64::encode_config(&header.to_string(), base64::URL_SAFE_NO_PAD),
        base64::encode_config(&claims.to_string(), base64::URL_SAFE_NO_PAD),
    ]
    .join(".");

    let key = PKey::private_key_from_pem(cert_data.as_ref())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(data.as_ref())?;
    let signature = signer.sign_to_vec()?;
    let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

    Ok(format!("{}.{}", data, signature))
}

#[derive(Debug)]
pub struct AuthToken(String);

impl TokenSource for AuthToken {
    fn get(&self) -> &str {
        &self.0
    }
}

pub trait TokenSource {
    fn get(&self) -> &str;
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct TokenResponse {
    token_type: String,
    expires_in: u32,
    ext_expires_in: u32,
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
    use crate::Context;
    use matches::assert_matches;
    use std::{path::Path, sync::Arc};

    #[tokio::test]
    async fn it_obtains_auth_token_with_secret() {
        // let context = Context::new(String::default(), String::default(), String::default());
        let context = Context::from(std::path::Path::new("context.json")).unwrap();
        let auth = Auth::new(Arc::new(Client::new()));

        let auth = auth
            .authorize_with_secret(
                context.tenant_id(),
                context.client_id(),
                context.client_secret(),
            )
            .await;

        assert_matches!(auth, Ok(auth) if !auth.get().is_empty());
    }

    #[tokio::test]
    async fn it_obtains_auth_token_for_module() {
        let context = Context::from(Path::new("context-module-a.json")).unwrap();
        let auth = Auth::new(Arc::new(Client::new()));
        let cert_path = Path::new("module-a/combined.pem");

        let auth = auth
            .authorize_with_certificate(context.tenant_id(), context.client_id(), &cert_path)
            .await;

        assert_matches!(auth, Ok(auth) if !auth.get().is_empty());
    }

    #[test]
    fn it_generates_jwt() {
        let cert_path = Path::new("module-a/combined.pem");
        let context = Context::from(Path::new("context-module-a.json")).unwrap();

        let token = create_jwt(context.tenant_id(), context.client_id(), &cert_path);

        let expected = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1dCI6IkM1dEp5ODJoZjhVMUZ6SGQ3QXRhbEdJdVY5USJ9.eyJhdWQiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vZThiNjIzNGEtNDVmNi00ZjIxLWEzODctMDY4MzMzNzg3YzQ1L29hdXRoMi90b2tlbiIsImV4cCI6MTU4MzAyMDgwMCwiaXNzIjoiMzEzZjk3M2UtODA0Yy00ZjhkLWJmOTAtZDM4MWI1NmM3MmQwIiwic3ViIjoiMzEzZjk3M2UtODA0Yy00ZjhkLWJmOTAtZDM4MWI1NmM3MmQwIn0.W2nGdG1v3IM3MFckjCn7iNj6zMOFI2qn83nVlX8IbUkP33HPfPaPFofmjU1Tc2T3E3_aWGoKCphiKHCQwUBh8U-eUKRbDYUV_0tlZf0TotIZAL8_XaS2T7uflMYfLMMmIhOL5-7JbOFvpPrHANpTA_IUC6mha9W2MET0eStHf11GS1PAznJOD4GkczOVsOY8vqoMA055tZcJof6rYeNY2mToDL8jXbgP1xg7UG1fenw9qY0Jdg3X8lWYX_uZA8WzMiuY8fOsMnh9fLCe7NebbBP1l9LE7U_snzBdhfBxrHEJx7fUsLY0kl8FPP0OE9eVCY2WL79RUbNB2zyu2R9BhQ";
        assert_matches!(token, Ok(token) if token == expected)
    }
}
