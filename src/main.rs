use std::{collections::HashSet, path::PathBuf};

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

const PERSON_ATTRS: &[&str] = &[""];

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    url: String,

    #[arg(long)]
    state: PathBuf,
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
    fn new(url: &str) -> Result<KanidmClient> {
        let mut client = KanidmClient {
            url: url.to_string(),
            client: Client::new(),
            idm_admin_headers: HeaderMap::new(),
        };

        let (session_id, token) = client.auth("idm_admin", &std::env::var("KANIDM_PROVISION_IDM_ADMIN_TOKEN")?)?;
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

    fn get_entities(&self, endpoint: &str) -> Result<Vec<Value>> {
        let serde_json::Value::Array(entities) = self.get_json(endpoint)? else {
            bail!("Invalid json response: Toplevel is not an array");
        };

        Ok(entities)
    }

    fn update_entity_attr(&self, endpoint: &str, existing_entities: &[Value], uuid: &str, attr: &str) -> Result<()> {
        self.client
            .post(format!("{}{endpoint}/{uuid}/_attr/{attr}", self.url))
            .headers(self.idm_admin_headers.clone())
            // TODO: .json()
            .send()?
            .error_for_status()?;
        Ok(())
    }

    fn create_entity(&self, endpoint: &str, entity: &str) -> Result<()> {
        self.client
            .post(format!("{}{endpoint}/{entity}", self.url))
            .headers(self.idm_admin_headers.clone())
            .json(&json!({ "attrs": { "name": [ entity ] } }))
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

fn entity_names(entities: &[Value]) -> Result<HashSet<String>> {
    Ok(entities
        .iter()
        .filter_map(|x| {
            x.pointer("/attrs/name/0")
                .and_then(|x| x.as_str())
                .map(|x| x.to_string())
        })
        .collect())
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();
    let state = State::new(args.state)?;
    let kanidm_client = KanidmClient::new(&args.url)?;

    let existing_groups = kanidm_client.get_entities(ENDPOINT_GROUP)?;
    let existing_group_names = entity_names(&existing_groups)?;
    for (name, group) in state.groups {
        if group.present {
            if !existing_group_names.contains(&name) {
                kanidm_client.create_entity(ENDPOINT_GROUP, &name)?;
            }

            // TODO: Update
        } else if existing_group_names.contains(&name) {
            kanidm_client.delete_entity(ENDPOINT_GROUP, &name)?;
        }
    }

    let existing_persons = kanidm_client.get_entities(ENDPOINT_PERSON)?;
    let existing_person_names = entity_names(&existing_persons)?;
    for (name, person) in state.persons {
        if person.present {
            if !existing_person_names.contains(&name) {
                kanidm_client.create_entity(ENDPOINT_PERSON, &name)?;
            }

            for attr in PERSON_ATTRS {
                kanidm_client.update_entity_attr(ENDPOINT_PERSON, &existing_persons, &name, attr)?;
            }
        } else if existing_person_names.contains(&name) {
            kanidm_client.delete_entity(ENDPOINT_PERSON, &name)?;
        }
    }

    Ok(())
}
