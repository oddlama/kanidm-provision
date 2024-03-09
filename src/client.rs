use std::collections::HashMap;

use color_eyre::{
    eyre::{bail, eyre, Context, OptionExt, Result},
    Section,
};
use reqwest::{
    blocking::{Client, Response},
    header::{HeaderMap, HeaderValue},
};
use serde_json::{json, Value};

use crate::log_event;

pub const ENDPOINT_AUTH: &str = "/v1/auth";
pub const ENDPOINT_GROUP: &str = "/v1/group";
pub const ENDPOINT_PERSON: &str = "/v1/person";
pub const ENDPOINT_OAUTH2: &str = "/v1/oauth2";

trait ResponseExt {
    fn get_json_response(self) -> Result<Value>;
}

impl ResponseExt for Response {
    fn get_json_response(self) -> Result<Value> {
        let status = self.status();
        let json: Result<Value> = self
            .text()
            .wrap_err("Response had no body")
            .and_then(|x| serde_json::from_str(&x).wrap_err("Response wasn't json"));

        if !status.is_success() {
            return Err(
                eyre!("Server returned unsuccessful HTTP status ({status})").note(match json {
                    Ok(ref value) => value.to_string(),
                    Err(ref e) => e.to_string(),
                }),
            );
        }

        json
    }
}

pub struct KanidmClient {
    url: String,
    client: Client,
    idm_admin_headers: HeaderMap,
}

impl KanidmClient {
    pub fn new(url: &str, accept_invalid_certs: bool) -> Result<KanidmClient> {
        let mut client = KanidmClient {
            url: url.to_string(),
            client: Client::builder()
                .danger_accept_invalid_certs(accept_invalid_certs)
                .build()?,
            idm_admin_headers: HeaderMap::new(),
        };

        let (session_id, token) = client.auth(
            "idm_admin",
            &std::env::var("KANIDM_PROVISION_IDM_ADMIN_TOKEN").context("KANIDM_PROVISION_IDM_ADMIN_TOKEN missing")?,
        )?;
        client
            .idm_admin_headers
            .insert("X-KANIDM-AUTH-SESSION-ID", HeaderValue::from_str(&session_id)?);
        client
            .idm_admin_headers
            .insert("Authorization", HeaderValue::from_str(&format!("Bearer {token}"))?);

        Ok(client)
    }

    pub fn auth(&self, user: &str, password: &str) -> Result<(String, String)> {
        let init_response = self
            .client
            .post(format!("{}{ENDPOINT_AUTH}", self.url))
            .json(&json!({ "step": { "init": user } }))
            .send()?
            .error_for_status()?;

        let session_id = init_response
            .headers()
            .get("X-KANIDM-AUTH-SESSION-ID")
            .ok_or_eyre("No session id was returned by the server!")?;

        let _begin_response = self
            .client
            .post(format!("{}{ENDPOINT_AUTH}", self.url))
            .header("X-KANIDM-AUTH-SESSION-ID", session_id)
            .json(&json!({ "step": { "begin": "password" } }))
            .send()?
            .get_json_response()?;

        let cred_response = self
            .client
            .post(format!("{}{ENDPOINT_AUTH}", self.url))
            .header("X-KANIDM-AUTH-SESSION-ID", session_id)
            .json(&json!({ "step": { "cred": { "password": password } } }))
            .send()?
            .get_json_response()?;

        let token = cred_response
            .pointer("/state/success")
            .and_then(|x| x.as_str())
            .map(|x| x.to_string())
            .ok_or_else(|| eyre!("No token found in response (incorrect password?): {cred_response:?}"))?;

        Ok((session_id.to_str()?.to_string(), token))
    }

    pub fn get_json(&self, endpoint: &str) -> Result<Value> {
        assert!(endpoint.starts_with('/'));
        self.client
            .get(format!("{}{endpoint}", self.url))
            .headers(self.idm_admin_headers.clone())
            .send()?
            .get_json_response()
    }

    pub fn get_entities(&self, endpoint: &str) -> Result<HashMap<String, Value>> {
        let serde_json::Value::Array(entities) = self.get_json(endpoint)? else {
            bail!("Invalid json response: Toplevel is not an array");
        };

        Ok(entities
            .iter()
            .filter_map(|e| {
                let name = e
                    .pointer("/attrs/name/0")
                    .and_then(|x| x.as_str())
                    .map(|x| x.to_string());
                name.map(|x| (x, e.clone()))
            })
            .collect())
    }

    pub fn update_entity_attrs(
        &self,
        endpoint: &str,
        existing_entities: &HashMap<String, Value>,
        name: &str,
        attr: &str,
        mut values: Vec<String>,
        append: bool,
    ) -> Result<()> {
        let entity = existing_entities
            .get(name)
            .ok_or_else(|| eyre!("Cannot update unknown entity {name} in {endpoint}"))?;
        let uuid = entity
            .pointer("/attrs/uuid/0")
            .and_then(|x| x.as_str())
            .map(|x| x.to_string())
            .ok_or_else(|| eyre!("Could not find uuid for {name}"))?;

        let mut current_values: Vec<String> = match entity.pointer(&format!("/attrs/{attr}")) {
            Some(Value::Array(x)) => x.iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect(),
            None => vec![],
            other => bail!("Invalid attr value for {attr} of entity {endpoint}/{name}: {other:?}"),
        };

        if attr == "member" {
            current_values = current_values
                .iter()
                .map(|x| x.split_once('@').map(|x| x.0).unwrap_or(x).to_string())
                .collect();
            current_values.sort_unstable();
            values.sort_unstable();
        }

        if current_values != values {
            log_event("Updating", &format!("{endpoint}/{name}/_attr/{attr}"));

            if values.is_empty() {
                self.client
                    .delete(format!("{}{endpoint}/{uuid}/_attr/{attr}", self.url))
                    .headers(self.idm_admin_headers.clone())
                    .send()?
                    .error_for_status()?;
            } else if append {
                self.client
                    .post(format!("{}{endpoint}/{uuid}/_attr/{attr}", self.url))
                    .headers(self.idm_admin_headers.clone())
                    .json(&values)
                    .send()?
                    .error_for_status()?;
            } else {
                self.client
                    .put(format!("{}{endpoint}/{uuid}/_attr/{attr}", self.url))
                    .headers(self.idm_admin_headers.clone())
                    .json(&values)
                    .send()?
                    .error_for_status()?;
            }
        }

        Ok(())
    }

    pub fn create_entity(&self, endpoint: &str, name: &str, payload: &Value) -> Result<()> {
        log_event("Creating", &format!("{endpoint}/{name}"));
        self.client
            .post(format!("{}{endpoint}", self.url))
            .headers(self.idm_admin_headers.clone())
            .json(payload)
            .send()?
            .error_for_status()?;
        Ok(())
    }

    pub fn update_oauth2_attrs(
        &self,
        existing_entities: &HashMap<String, Value>,
        name: &str,
        attr: &str,
        values: Vec<String>,
    ) -> Result<()> {
        let entity = existing_entities
            .get(name)
            .ok_or_else(|| eyre!("Cannot update unknown oauth2 resource server {name}"))?;

        let current_values: Vec<String> = match entity.pointer(&format!("/attrs/{attr}")) {
            Some(Value::Array(x)) => x.iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect(),
            None => vec![],
            other => bail!("Invalid attr value for {attr} of entity {ENDPOINT_OAUTH2}/{name}: {other:?}"),
        };

        if current_values != values {
            log_event("Updating", &format!("{ENDPOINT_OAUTH2}/{name} {attr}"));

            self.client
                .patch(format!("{}{ENDPOINT_OAUTH2}/{name}", self.url))
                .headers(self.idm_admin_headers.clone())
                .json(&json!({ "attrs": { attr: values } }))
                .send()?
                .error_for_status()?;
        }

        Ok(())
    }

    pub fn update_oauth2_map(
        &self,
        endpoint_name: &str,
        attr_name: &str,
        existing_entities: &HashMap<String, Value>,
        name: &str,
        group: &str,
        mut scopes: Vec<String>,
    ) -> Result<()> {
        let entity = existing_entities
            .get(name)
            .ok_or_else(|| eyre!("Cannot update unknown oauth2 resource server {name}"))?;

        let current_values: Vec<String> = match entity.pointer(&format!("/attrs/{attr_name}")) {
            Some(Value::Array(x)) => x.iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect(),
            None => vec![],
            other => bail!("Invalid map value for {attr_name} of entity {ENDPOINT_OAUTH2}/{name}: {other:?}"),
        };

        let mut current_values: Vec<_> = current_values
            .iter()
            .find(|x| x.starts_with(&format!("{}@", group)))
            .map(|x| {
                x.split_once(": ")
                    .map(|x| x.1)
                    .unwrap_or(x)
                    .trim_start_matches('{')
                    .trim_end_matches('}')
                    .split(", ")
                    .map(|e| e.trim_matches('"'))
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        current_values.sort_unstable();
        scopes.sort_unstable();

        if current_values != scopes {
            log_event("Updating", &format!("{ENDPOINT_OAUTH2}/{name} {attr_name}/{group}"));

            if scopes.is_empty() {
                self.client
                    .delete(format!("{}{ENDPOINT_OAUTH2}/{name}/{endpoint_name}/{group}", self.url))
                    .headers(self.idm_admin_headers.clone())
                    .send()?
                    .error_for_status()?;
            } else {
                self.client
                    .post(format!("{}{ENDPOINT_OAUTH2}/{name}/{endpoint_name}/{group}", self.url))
                    .headers(self.idm_admin_headers.clone())
                    .json(&scopes)
                    .send()?
                    .error_for_status()?;
            }
        }

        Ok(())
    }

    pub fn update_oauth2_claim_map(
        &self,
        existing_entities: &HashMap<String, Value>,
        name: &str,
        claim: &str,
        group: &str,
        mut values: Vec<String>,
    ) -> Result<()> {
        let entity = existing_entities
            .get(name)
            .ok_or_else(|| eyre!("Cannot update unknown oauth2 resource server {name}"))?;

        let current_values: Vec<String> = match entity.pointer("/attrs/oauth2_rs_claim_map") {
            Some(Value::Array(x)) => x.iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect(),
            None => vec![],
            other => bail!("Invalid map value for oauth2_rs_claim_map of entity {ENDPOINT_OAUTH2}/{name}: {other:?}"),
        };

        let mut current_values: Vec<_> = current_values
            .iter()
            .find(|x| x.starts_with(&format!("{claim}:{group}@")))
            .map(|x| x.split(':').nth(3).unwrap_or(x).trim_matches('"').split(',').collect())
            .unwrap_or_else(Vec::new);

        current_values.sort_unstable();
        values.sort_unstable();

        if current_values != values {
            log_event(
                "Updating",
                &format!("{ENDPOINT_OAUTH2}/{name} oauth2_rs_claim_map/{claim}/{group}"),
            );

            if values.is_empty() {
                self.client
                    .delete(format!(
                        "{}{ENDPOINT_OAUTH2}/{name}/_claimmap/{claim}/{group}",
                        self.url
                    ))
                    .headers(self.idm_admin_headers.clone())
                    .send()?
                    .error_for_status()?;
            } else {
                self.client
                    .post(format!(
                        "{}{ENDPOINT_OAUTH2}/{name}/_claimmap/{claim}/{group}",
                        self.url
                    ))
                    .headers(self.idm_admin_headers.clone())
                    .json(&values)
                    .send()?
                    .error_for_status()?;
            }
        }

        Ok(())
    }

    pub fn update_oauth2_claim_map_join(
        &self,
        existing_entities: &HashMap<String, Value>,
        name: &str,
        claim: &str,
        join_type: &str,
    ) -> Result<()> {
        let entity = existing_entities
            .get(name)
            .ok_or_else(|| eyre!("Cannot update unknown oauth2 resource server {name}"))?;

        let current_values: Vec<String> = match entity.pointer("/attrs/oauth2_rs_claim_map") {
            Some(Value::Array(x)) => x.iter().filter_map(|x| x.as_str().map(|x| x.to_string())).collect(),
            None => vec![],
            other => bail!("Invalid map value for oauth2_rs_claim_map of entity {ENDPOINT_OAUTH2}/{name}: {other:?}"),
        };

        let delimiter: Option<&str> = current_values
            .iter()
            .find(|x| x.starts_with(&format!("{claim}:")))
            .and_then(|x| x.split(':').nth(2));

        let current = match delimiter {
            Some(" ") => "ssv",
            Some(",") => "csv",
            Some(";") => "array",
            _ => "array",
        };

        if !matches!(join_type, "ssv" | "csv" | "array") {
            bail!("Invalid join_type ({join_type}) for oauth {name} claim {claim}");
        }

        if current != join_type {
            log_event(
                "Updating",
                &format!("{ENDPOINT_OAUTH2}/{name} oauth2_rs_claim_map_join/{claim}"),
            );

            self.client
                .post(format!("{}{ENDPOINT_OAUTH2}/{name}/_claimmap/{claim}", self.url))
                .headers(self.idm_admin_headers.clone())
                .json(&join_type)
                .send()?
                .error_for_status()?;
        }

        Ok(())
    }

    pub fn delete_entity(&self, endpoint: &str, entity: &str) -> Result<()> {
        log_event("Deleting", &format!("{endpoint}/{entity}"));
        self.client
            .delete(format!("{}{endpoint}/{entity}", self.url))
            .headers(self.idm_admin_headers.clone())
            .send()?
            .error_for_status()
            .note("Is the name already in use by another entity?")?;
        Ok(())
    }
}
