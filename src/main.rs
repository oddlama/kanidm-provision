#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

use clap::Parser;
use color_eyre::{
    eyre::{bail, eyre, Context, OptionExt, Result},
    owo_colors::OwoColorize,
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
const ENDPOINT_OAUTH2: &str = "/v1/oauth2";
const PROVISION_TRACKING_GROUP: &str = "ext_idm_provisioned_entities";

fn log_status(message: &str) {
    println!("{}", message.blue().bold());
}

fn log_event(event: &str, message: &str) {
    println!("{:>12} {}", event.green().bold(), message);
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// The URL of the kanidm instance
    #[arg(long)]
    url: String,

    /// A JSON file describing the desired target state. Refer to the README for a description of
    /// the required schema.
    #[arg(long)]
    state: PathBuf,

    /// DANGEROUS! Accept invalid TLS certificates, e.g. for testing instances.
    #[arg(long)]
    accept_invalid_certs: bool,

    /// Automatically remove orphaned entities that were provisioned previously but have since been removed
    /// from the state file. This works by assigning all provisioned entities to a common group and
    /// deleting any entities in that group that are not found in the state file.
    #[arg(long)]
    auto_remove: bool,
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

            if append {
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

    fn create_entity(&self, endpoint: &str, name: &str, payload: &Value) -> Result<()> {
        log_event("Creating", &format!("{endpoint}/{name}"));
        self.client
            .post(format!("{}{endpoint}", self.url))
            .headers(self.idm_admin_headers.clone())
            .json(payload)
            .send()?
            .error_for_status()?;
        Ok(())
    }

    fn update_oauth2_attrs(
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

    fn update_oauth2_map(
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

            self.client
                .post(format!("{}{ENDPOINT_OAUTH2}/{name}/{endpoint_name}/{group}", self.url))
                .headers(self.idm_admin_headers.clone())
                .json(&scopes)
                .send()?
                .error_for_status()?;
        }

        Ok(())
    }

    fn delete_entity(&self, endpoint: &str, entity: &str) -> Result<()> {
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

/// Return a map of all tracked entities and ensure that their names are unique.
fn all_tracked_entities(state: &State) -> Result<Vec<String>> {
    let mut entity_names: HashMap<_, Vec<&str>> = HashMap::new();
    for i in state.groups.keys() {
        entity_names.entry(i.to_owned()).or_default().push("group");
    }
    for i in state.persons.keys() {
        entity_names.entry(i.to_owned()).or_default().push("person");
    }
    for i in state.systems.oauth2.keys() {
        entity_names.entry(i.to_owned()).or_default().push("oauth2");
    }

    let mut error = eyre!("One or more entities have the same name (see notes)");
    let mut any_bad = false;
    for (k, v) in &entity_names {
        if v.len() > 1 {
            error = error.note(format!("{k} is used multiple times as {v:?}"));
            any_bad = true;
        }
    }

    if any_bad {
        return Err(error);
    }

    Ok(entity_names.keys().cloned().collect())
}

macro_rules! update_attrs {
    ($kanidm_client:expr, $endpoint:expr, $existing:expr, $name:expr, [ $( $key:literal : $value:expr ),*, ]) => {
        $(
            $kanidm_client.update_entity_attrs($endpoint, $existing, $name, $key, $value, false)?;
        )*
    };
}

macro_rules! update_oauth2 {
    ($kanidm_client:expr, $existing:expr, $name:expr, [ $( $key:literal : $value:expr ),*, ]) => {
        $(
            if let Some(value) = $value {
                $kanidm_client.update_oauth2_attrs($existing, $name, $key, vec![value])?;
            } else {
                $kanidm_client.update_oauth2_attrs($existing, $name, $key, vec![])?;
            }
        )*
    };
}

fn sync_groups(
    state: &State,
    kanidm_client: &KanidmClient,
    existing_groups: &mut HashMap<String, Value>,
    preexisting_entity_names: &HashSet<String>,
) -> Result<()> {
    log_status("Syncing groups");
    for (name, group) in &state.groups {
        if group.present {
            if !existing_groups.contains_key(name) {
                if preexisting_entity_names.contains(name) {
                    bail!("Cannot create group '{name}' because the name is already in use by another entity!");
                }

                kanidm_client.create_entity(ENDPOINT_GROUP, name, &json!({ "attrs": { "name": [ name ] } }))?;
                existing_groups.clear();
                existing_groups.extend(kanidm_client.get_entities(ENDPOINT_GROUP)?);
            }
        } else if existing_groups.contains_key(name) {
            kanidm_client.delete_entity(ENDPOINT_GROUP, name)?;
        }
    }

    Ok(())
}

fn sync_persons(
    state: &State,
    kanidm_client: &KanidmClient,
    existing_persons: &mut HashMap<String, Value>,
    preexisting_entity_names: &HashSet<String>,
) -> Result<()> {
    log_status("Syncing persons");
    for (name, person) in &state.persons {
        if person.present {
            if !existing_persons.contains_key(name) {
                if preexisting_entity_names.contains(name) {
                    bail!("Cannot create person '{name}' because the name is already in use by another entity!");
                }

                kanidm_client.create_entity(
                    ENDPOINT_PERSON,
                    name,
                    &json!({ "attrs": {
                        "name": [ name ],
                        "displayname": [ person.display_name ]
                    }}),
                )?;
                existing_persons.clear();
                existing_persons.extend(kanidm_client.get_entities(ENDPOINT_PERSON)?);
            }

            update_attrs!(kanidm_client, ENDPOINT_PERSON, &existing_persons, &name, [
                "displayname": vec![person.display_name.clone()],
                "legalname": vec![person.legal_name.clone()],
                "mail": person.mail_addresses.clone(),
            ]);
        } else if existing_persons.contains_key(name) {
            kanidm_client.delete_entity(ENDPOINT_PERSON, name)?;
        }
    }

    Ok(())
}

fn sync_oauth2s(
    state: &State,
    kanidm_client: &KanidmClient,
    existing_oauth2s: &mut HashMap<String, Value>,
    preexisting_entity_names: &HashSet<String>,
) -> Result<()> {
    log_status("Syncing oauth2 resource servers");
    for (name, oauth2) in &state.systems.oauth2 {
        if oauth2.present {
            if !existing_oauth2s.contains_key(name) {
                if preexisting_entity_names.contains(name) {
                    bail!("Cannot create oauth2 resource server '{name}' because the name is already in use by another entity!");
                }

                kanidm_client.create_entity(
                    &format!("{ENDPOINT_OAUTH2}/_basic"),
                    name,
                    &json!({ "attrs": {
                        "name": [name],
                        "oauth2_rs_origin": [oauth2.origin_url],
                        "displayname": [oauth2.display_name],
                    }}),
                )?;
                existing_oauth2s.clear();
                existing_oauth2s.extend(kanidm_client.get_entities(ENDPOINT_OAUTH2)?);
            }

            if !oauth2.origin_url.ends_with('/') {
                println!("{}", format!("WARN: origin_url ({}) of oauth2 resource server '{name}' should end in a slash! This will lead to unnecessary updates.", oauth2.origin_url).yellow().bold());
            }

            update_oauth2!(kanidm_client, &existing_oauth2s, &name, [
                "displayname": Some(oauth2.display_name.clone()),
                "oauth2_rs_origin": Some(oauth2.origin_url.clone()),
                "oauth2_rs_origin_landing": oauth2.origin_landing.clone(),
                "oauth2_allow_insecure_client_disable_pkce": Some(oauth2.allow_insecure_client_disable_pkce.to_string()),
                "oauth2_prefer_short_username": Some(oauth2.prefer_short_username.to_string()),
            ]);

            for (group, scopes) in &oauth2.scope_maps {
                kanidm_client.update_oauth2_map(
                    "_scopemap",
                    "oauth2_rs_scope_map",
                    existing_oauth2s,
                    name,
                    group,
                    scopes.clone(),
                )?;
            }

            for (group, scopes) in &oauth2.supplementary_scope_maps {
                kanidm_client.update_oauth2_map(
                    "_sup_scopemap",
                    "oauth2_rs_sup_scope_map",
                    existing_oauth2s,
                    name,
                    group,
                    scopes.clone(),
                )?;
            }

            // TODO claim maps
            // TODO secret
        } else if existing_oauth2s.contains_key(name) {
            kanidm_client.delete_entity(ENDPOINT_OAUTH2, name)?;
        }
    }

    Ok(())
}

fn setup_provision_tracking(
    kanidm_client: &KanidmClient,
    existing_groups: &mut HashMap<String, Value>,
) -> Result<HashSet<String>> {
    if !existing_groups.contains_key(PROVISION_TRACKING_GROUP) {
        kanidm_client.create_entity(
            ENDPOINT_GROUP,
            PROVISION_TRACKING_GROUP,
            &json!({ "attrs": { "name": [ PROVISION_TRACKING_GROUP ] } }),
        )?;
        existing_groups.clear();
        existing_groups.extend(kanidm_client.get_entities(ENDPOINT_GROUP)?);
    }

    let entity = existing_groups.get(PROVISION_TRACKING_GROUP).ok_or_else(|| {
        eyre!("Could not find provision tracking group '{PROVISION_TRACKING_GROUP}' in {ENDPOINT_GROUP}")
    })?;

    let mut current_values = match entity.pointer("/attrs/member") {
        Some(Value::Array(x)) => x
            .iter()
            .filter_map(|x| x.as_str())
            .map(|x| x.split_once('@').map(|x| x.0).unwrap_or(x).to_string())
            .collect(),
        None => vec![],
        other => {
            bail!("Invalid attr value for members of entity {ENDPOINT_GROUP}/{PROVISION_TRACKING_GROUP}: {other:?}")
        }
    };

    Ok(HashSet::from_iter(current_values.drain(0..)))
}

fn remove_orphaned_entities(
    kanidm_client: &KanidmClient,
    provisioned_entities: &HashSet<String>,
    existing_groups: &HashMap<String, Value>,
    existing_persons: &HashMap<String, Value>,
    existing_oauth2s: &HashMap<String, Value>,
    tracked_entities: &[String],
) -> Result<()> {
    log_status("Removing orphaned entities");
    // Remove any entities that are no longer provisioned
    let tracked_entities = HashSet::from_iter(tracked_entities.iter().cloned());
    let orphaned_entities = provisioned_entities.difference(&tracked_entities);
    for orphan in orphaned_entities {
        if existing_groups.contains_key(orphan) {
            kanidm_client.delete_entity(ENDPOINT_GROUP, orphan)?;
        } else if existing_persons.contains_key(orphan) {
            kanidm_client.delete_entity(ENDPOINT_PERSON, orphan)?;
        } else if existing_oauth2s.contains_key(orphan) {
            kanidm_client.delete_entity(ENDPOINT_OAUTH2, orphan)?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();
    let state = State::new(args.state)?;
    let tracked_entities = all_tracked_entities(&state)?;
    let kanidm_client = KanidmClient::new(&args.url, args.accept_invalid_certs)?;

    // Retrieve known entities so we can check for duplicates dynamically
    let mut existing_groups = kanidm_client.get_entities(ENDPOINT_GROUP)?;
    let mut existing_persons = kanidm_client.get_entities(ENDPOINT_PERSON)?;
    let mut existing_oauth2s = kanidm_client.get_entities(ENDPOINT_OAUTH2)?;

    let mut preexisting_entity_names = HashSet::new();
    preexisting_entity_names.extend(existing_groups.keys().cloned());
    preexisting_entity_names.extend(existing_persons.keys().cloned());
    preexisting_entity_names.extend(existing_oauth2s.keys().cloned());

    // Create and query a group that contains all (previously) provisioned entities.
    let provisioned_entities = setup_provision_tracking(&kanidm_client, &mut existing_groups)?;

    sync_groups(&state, &kanidm_client, &mut existing_groups, &preexisting_entity_names)?;
    sync_persons(&state, &kanidm_client, &mut existing_persons, &preexisting_entity_names)?;
    sync_oauth2s(&state, &kanidm_client, &mut existing_oauth2s, &preexisting_entity_names)?;

    // Sync group members
    log_status("Syncing group members");
    for (name, group) in &state.groups {
        if group.present {
            update_attrs!(kanidm_client, ENDPOINT_GROUP, &existing_groups, &name, [
                "member": group.members.clone(),
            ]);
        }
    }

    // Update entity tracking group now that new entities exist.
    // Always add to this group's member, and never overwrite so
    // we can be sure to never lose any entries in case of unexpected errors.
    // Members can thus only be removed by removing the entity itself.
    log_status("Tracking provisioned entities");
    kanidm_client.update_entity_attrs(
        ENDPOINT_GROUP,
        &existing_groups,
        PROVISION_TRACKING_GROUP,
        "member",
        tracked_entities.clone(),
        true,
    )?;

    if args.auto_remove {
        // Now, remove the orphaned entities that were in the tracking group but
        // no longer exist in our state description.
        remove_orphaned_entities(
            &kanidm_client,
            &provisioned_entities,
            &existing_groups,
            &existing_persons,
            &existing_oauth2s,
            &tracked_entities,
        )?;
    }

    Ok(())
}
