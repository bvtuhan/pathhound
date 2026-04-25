use std::collections::HashMap;

use clap::Parser;
use itertools::Itertools;
use petgraph::dot::Dot;
use rustworkx_core::centrality::betweenness_centrality;

use crate::{
    ad_graph::{ADGraphExt, Node},
    cli::{centrality_print, default_print},
    client::Client,
};

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

    let mut start_nodes: Vec<&Node> = Vec::new();
    let mut target_nodes: Vec<&Node> = Vec::new();

    for src_node in args.source_nodes.iter() {
        let src_node = src_node.trim();
        if "ALL-NON-TIER-0".eq(src_node) {
            start_nodes.extend(graph.find_non_tier_zero_nodes());
            continue;
        }

        let node = graph
            .find_node_by_value(src_node)
            .unwrap_or_else(|| panic!("Failed to find the node {} in graph", src_node));

        start_nodes.push(node);

        // TODO: Maybe duplicate check?
    }

    for target_node in args.target_nodes.iter() {
        let target_node = target_node.trim();
        if "ALL-TIER-0".eq(target_node) {
            target_nodes.extend(graph.find_tier_zero_nodes());
            continue;
        } else if "DOMAIN-ADMINS".eq(target_node) {
            target_nodes.extend(graph.find_domain_admins());
            continue;
        }

        let node = graph
            .find_node_by_value(target_node)
            .unwrap_or_else(|| panic!("Failed to find the node {} in graph", target_node));

        target_nodes.push(node);

        // TODO: Maybe duplicate check?
    }

    if args.attack_graph {
        let attack_graph = graph.create_attack_graph(&start_nodes, &target_nodes);

        if attack_graph.edge_count() == 0 {
            println!(
                "Failed to create an attack graph with given start and target nodes. Presumably there is no path between any of the start and target nodes."
            );
            println!("No DOT file will be generated.");
        } else {
            let dot_body = format!("{}", Dot::with_config(&attack_graph, &[]));
            std::fs::write("./attack-graph.dot", dot_body)
                .expect("Failed to save the attack graph into the current working directory.");
        }
    } else if args.centrality {
        let attack_graph = graph.create_attack_graph(&start_nodes, &target_nodes);
        let centrality_rates = betweenness_centrality(&attack_graph, false, true, 50);
        centrality_print(&attack_graph, &centrality_rates);
    } else {
        for (src, dest) in start_nodes.iter().cartesian_product(&target_nodes) {
            let shortest_path = graph.run_astar(src, dest).unwrap_or_default();

            if !shortest_path.1.is_empty() {
                default_print(&graph, &src.name, &dest.name, &shortest_path);
            } else {
                println!("No path found between {} and {}", &src.name, &dest.name);
            }
        }
    }
}
