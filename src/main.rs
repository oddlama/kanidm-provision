use std::path::PathBuf;

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
            .post(format!("{}/v1/auth", self.url))
            .json(&json!({ "step": { "init": user } }))
            .send()?
            .error_for_status()?;

        let session_id = init_response
            .headers()
            .get("X-KANIDM-AUTH-SESSION-ID")
            .ok_or_eyre("No session id was returned by the server!")?;

        let _begin_response = self
            .client
            .post(format!("{}/v1/auth", self.url))
            .json(&json!({ "step": { "begin": "password" } }))
            .header("X-KANIDM-AUTH-SESSION-ID", session_id)
            .send()?
            .get_json_response()?;

        let cred_response = self
            .client
            .post(format!("{}/v1/auth", self.url))
            .json(&json!({ "step": { "cred": { "password": password } } }))
            .header("X-KANIDM-AUTH-SESSION-ID", session_id)
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

    fn groups(&self) -> Result<Vec<String>> {
        let serde_json::Value::Array(groups) = self.get_json("/v1/group")? else {
            bail!("Invalid json response: Toplevel is not an array");
        };

        Ok(groups
            .iter()
            .filter_map(|x| {
                x.pointer("/attrs/name/0")
                    .and_then(|x| x.as_str())
                    .map(|x| x.to_string())
            })
            .collect())
    }
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();
    let kanidm_client = KanidmClient::new(&args.url)?;

    let groups = kanidm_client.groups()?;

    Ok(())
}
