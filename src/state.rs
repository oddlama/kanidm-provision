use std::collections::HashMap;
use std::path::Path;

use color_eyre::eyre::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub present: bool,
    pub members: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    pub present: bool,
    pub display_name: String,
    pub legal_name: String,
    pub mail_addresses: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Oauth2System {
    pub present: bool,
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

impl State {
    pub fn new(filename: impl AsRef<Path>) -> Result<State> {
        let file_content = std::fs::read_to_string(filename.as_ref())
            .context(format!("Failed to read state file: {}", filename.as_ref().display()))?;
        let state: State = serde_json::from_str(&file_content).context("Failed to parse state")?;
        Ok(state)
    }
}
