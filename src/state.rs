use std::collections::HashMap;
use std::path::Path;

use color_eyre::eyre::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    #[serde(default = "default_true")]
    pub present: bool,
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    #[serde(default = "default_true")]
    pub present: bool,
    pub display_name: String,
    pub legal_name: Option<String>,
    pub mail_addresses: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimMap {
    pub join_type: String,
    pub values_by_group: HashMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum StringOrStrings {
    String(String),
    Strings(Vec<String>),
}

impl StringOrStrings {
    pub fn strings(self) -> Vec<String> {
        match self {
            StringOrStrings::String(x) => vec![x],
            StringOrStrings::Strings(xs) => xs,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Oauth2System {
    #[serde(default = "default_true")]
    pub present: bool,
    #[serde(default = "default_false")]
    pub public: bool,
    pub display_name: String,
    pub basic_secret_file: Option<String>,
    pub origin_url: StringOrStrings,
    pub origin_landing: String,
    #[serde(default = "default_false")]
    pub enable_localhost_redirects: bool,
    #[serde(default = "default_false")]
    pub enable_legacy_crypto: bool,
    #[serde(default = "default_false")]
    pub allow_insecure_client_disable_pkce: bool,
    #[serde(default = "default_false")]
    pub prefer_short_username: bool,
    #[serde(default)]
    pub scope_maps: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub supplementary_scope_maps: HashMap<String, Vec<String>>,
    #[serde(default = "default_true")]
    pub remove_orphaned_claim_maps: bool,
    #[serde(default)]
    pub claim_maps: HashMap<String, ClaimMap>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Systems {
    pub oauth2: HashMap<String, Oauth2System>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub groups: HashMap<String, Group>,
    pub persons: HashMap<String, Person>,
    pub systems: Systems,
}

fn default_false() -> bool {
    false
}
fn default_true() -> bool {
    true
}

impl State {
    pub fn new(filename: impl AsRef<Path>) -> Result<State> {
        let file_content = std::fs::read_to_string(filename.as_ref())
            .context(format!("Failed to read state file: {}", filename.as_ref().display()))?;
        let state: State = serde_json::from_str(&file_content).context("Failed to parse state")?;
        Ok(state)
    }
}
