use std::{collections::HashMap, path::PathBuf};

use clap::Parser;
use color_eyre::{
    eyre::{bail, eyre, Context, OptionExt, Result},
    Section,
};
use reqwest::{
    blocking::{Client, Response},
    header::{HeaderMap, HeaderValue},
};
use serde_json::{json, Value};
use state::State;

mod state;

const ENDPOINT_AUTH: &str = "/v1/auth";
const ENDPOINT_GROUP: &str = "/v1/group";
const ENDPOINT_PERSON: &str = "/v1/person";

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    url: String,

    #[arg(long)]
    state: PathBuf,

    #[arg(long)]
    accept_invalid_certs: bool,
}

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

struct KanidmClient {
    url: String,
    client: Client,
    idm_admin_headers: HeaderMap,
}

impl KanidmClient {
    fn new(url: &str, accept_invalid_certs: bool) -> Result<KanidmClient> {
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

    fn auth(&self, user: &str, password: &str) -> Result<(String, String)> {
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

    fn get_json(&self, endpoint: &str) -> Result<Value> {
        assert!(endpoint.starts_with('/'));
        self.client
            .get(format!("{}{endpoint}", self.url))
            .headers(self.idm_admin_headers.clone())
            .send()?
            .get_json_response()
    }

    fn get_entities(&self, endpoint: &str) -> Result<HashMap<String, Value>> {
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

    fn update_entity_attrs(
        &self,
        endpoint: &str,
        existing_entities: &HashMap<String, Value>,
        name: &str,
        attr: &str,
        mut values: Vec<String>,
    ) -> Result<()> {
        let entity = existing_entities
            .get(name)
            .ok_or_else(|| eyre!("Cannot update unknown user {name}"))?;
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

        println!("c {current_values:?}");
        println!("v {values:?}");

        if current_values != values {
            println!("Updating {attr} on {endpoint}/{name}");

            self.client
                .put(format!("{}{endpoint}/{uuid}/_attr/{attr}", self.url))
                .headers(self.idm_admin_headers.clone())
                .json(&values)
                .send()?
                .error_for_status()?;
        }

        Ok(())
    }

    fn create_entity(&self, endpoint: &str, payload: &Value) -> Result<()> {
        self.client
            .post(format!("{}{endpoint}", self.url))
            .headers(self.idm_admin_headers.clone())
            .json(payload)
            .send()?
            .error_for_status()?;
        Ok(())
    }

    fn delete_entity(&self, endpoint: &str, entity: &str) -> Result<()> {
        self.client
            .delete(format!("{}{endpoint}/{entity}", self.url))
            .headers(self.idm_admin_headers.clone())
            .send()?
            .error_for_status()?;
        Ok(())
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();
    let state = State::new(args.state)?;
    let kanidm_client = KanidmClient::new(&args.url, args.accept_invalid_certs)?;

    macro_rules! update_attrs {
        ($endpoint:expr, $existing:expr, $name:expr, [ $( $key:literal : $value:expr ),*, ]) => {
            $(
                kanidm_client.update_entity_attrs($endpoint, $existing, $name, $key, $value)?;
            )*
        };
    }

    let mut existing_groups = kanidm_client.get_entities(ENDPOINT_GROUP)?;
    for (name, group) in &state.groups {
        if group.present {
            if !existing_groups.contains_key(name) {
                kanidm_client.create_entity(ENDPOINT_GROUP, &json!({ "attrs": { "name": [ name ] } }))?;
                // Update existing
                existing_groups = kanidm_client.get_entities(ENDPOINT_GROUP)?;
            }
        } else if existing_groups.contains_key(name) {
            kanidm_client.delete_entity(ENDPOINT_GROUP, name)?;
        }
    }

    let mut existing_persons = kanidm_client.get_entities(ENDPOINT_PERSON)?;
    for (name, person) in &state.persons {
        if person.present {
            if !existing_persons.contains_key(name) {
                kanidm_client.create_entity(
                    ENDPOINT_PERSON,
                    &json!({ "attrs": { "name": [ name ], "displayname": [ person.display_name ] } }),
                )?;
                // Update existing
                existing_persons = kanidm_client.get_entities(ENDPOINT_PERSON)?;
            }

            update_attrs!(ENDPOINT_PERSON, &existing_persons, &name, [
                "displayname": vec![person.display_name.clone()],
                "legalname": vec![person.legal_name.clone()],
                "mail": person.mail_addresses.clone(),
            ]);
        } else if existing_persons.contains_key(name) {
            kanidm_client.delete_entity(ENDPOINT_PERSON, name)?;
        }
    }

    for (name, group) in state.groups {
        if group.present {
            update_attrs!(ENDPOINT_GROUP, &existing_groups, &name, [
                "member": group.members,
            ]);
        }
    }

    Ok(())
}
