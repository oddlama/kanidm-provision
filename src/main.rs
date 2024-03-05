use std::path::PathBuf;

use clap::Parser;
use color_eyre::eyre::Result;
use serde_json::json;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    url: String,

    #[arg(long)]
    state: PathBuf,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Cli::parse();

    let client = reqwest::blocking::Client::new();
    let url = args.url;
    let _ = client
        .post(format!("{url}/v1/auth"))
        .json(&json!({
            "a": "b"
        }))
        .send();

    Ok(())
}
