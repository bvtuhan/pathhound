use std::collections::HashMap;

use clap::Parser;
use itertools::Itertools;

use crate::{ad_graph::ADGraphExt, cli::fmt_table_print, client::Client};

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

    let graph = client.fetch_complete_ad_graph(!args.no_filter);

    if args.construct_subgraph {
        unimplemented!()
    } else {
        let start_nodes = &args
            .source_nodes
            .iter()
            .map(|node_value| graph.get_node(node_value).expect("Could not find the node"))
            .collect::<Vec<_>>();
        let target_nodes = &args
            .target_nodes
            .iter()
            .map(|node_value| graph.get_node(node_value).expect("Could not find the node"))
            .collect::<Vec<_>>();

        for (src, dest) in start_nodes.iter().cartesian_product(target_nodes) {
            let shortest_path = graph.run_astar(*src, *dest).unwrap_or_default();

            fmt_table_print(&graph, &src.name, &dest.name, &shortest_path);
        }
    }
}
