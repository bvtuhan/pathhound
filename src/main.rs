use std::collections::HashMap;

use clap::Parser;

use crate::client::Client;

pub(crate) mod ad_graph;
pub(crate) mod cli;
pub(crate) mod client;

fn main() {
    let args = crate::cli::Cli::parse();
    let creds: HashMap<String, String> = serde_json::from_slice(
        &std::fs::read(&args.credentials_path)
            .expect("Failed to read credentials from the JSON file"),
    )
    .expect("Failed to serialize the credentials");

    let client = Client::new(
        creds
            .get("key")
            .expect("Expected 'key' field in credentials"),
        creds.get("id").expect("Expected 'id' field in credentials"),
        creds.get("url"),
    );

    let graph = client.fetch_complete_ad_graph(true);

    println!("{:#?}", graph);
}
