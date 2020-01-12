use crate::{Result, TokenProvider};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;

pub struct Identity<A> {
    client: Arc<Client>,
    auth: A,
}

impl<A> Identity<A>
where
    A: TokenProvider,
{
    pub fn new(client: Arc<Client>, auth: A) -> Self {
        Self { client, auth }
    }

    pub async fn provision(&self, name: &str) -> Result<()> {
        // create an app registration
        let app_id = self.create_application(name).await?;

        // create a service principal corresponding to an app registration
        self.create_service_principal(&app_id).await?;

        // add credentials for an app registration
        self.reset_service_principal_credentials(&app_id).await?;

        Ok(())
    }

    async fn create_application(&self, name: &str) -> Result<String> {
        let url = "https://graph.microsoft.com/beta/applications".to_string();

        let res = self
            .client
            .post(&url)
            .bearer_auth(self.auth.token())
            .json(&json!({ "displayName": name }))
            .send()
            .await?;

        match res.status() {
            StatusCode::CREATED => {
                let content: Value = res.json().await?;

                let app_id = content["appId"].as_str().unwrap().to_string();

                // dbg!(content);

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
            .bearer_auth(self.auth.token())
            .json(&json!({ "appId": app_id }))
            .send()
            .await?;

        match res.status() {
            StatusCode::CREATED => {
                let content: Value = res.json().await?;

                dbg!(content);

                Ok(())
            }
            _ => {
                let content: Value = res.json().await?;
                Err(content.to_string().into())
            }
        }
    }

    async fn reset_service_principal_credentials(&self, app_id: &str) -> Result<()> {
        let url = format!("https://graph.microsoft.com/beta/applications/{}", app_id);

        let res = self
            .client
            .patch(&url)
            .bearer_auth(self.auth.token())
            .json(&json!(
            {
                "appId": app_id,


            }
            ))
            .send()
            .await?;

        match res.status() {
            StatusCode::NO_CONTENT => {
                let content: Value = res.json().await?;

                dbg!(content);

                Ok(())
            }
            _ => {
                let content: Value = res.json().await?;
                Err(content.to_string().into())
            }
        }
    }

    pub async fn delete(&self, _name: &str) -> Result<()> {
        unimplemented!()
    }
}
