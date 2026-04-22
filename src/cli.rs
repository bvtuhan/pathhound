use core::f64;
use std::path::PathBuf;

use clap::Parser;
use itertools::Itertools;
use prettytable::{Table, row};

use crate::ad_graph::{ADGraph, ADGraphExt};

/// Pathhound -- Simple Bloodhound attack path enumerator
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    /// Tool's default behavior is to filter out "non-traversable" edges. Set this flag to disable the default filtering
    #[arg(short='x', long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    pub(crate) no_filter: bool,

    /// Path to the Bloodhound credentials file (in JSON format, {"key": ..., "id": ..., "url": <opt>})
    #[arg(short, long="credentials", default_value="./credentials.json", value_hint=clap::ValueHint::FilePath)]
    pub(crate) credentials_path: PathBuf,

    /// Source nodes (comma-separated, e.g. "A@COMP.COM,S-123-431-1234"; template: ALL-NON-TIER-0)
    #[arg(short, long, value_delimiter = ',')]
    pub(crate) source_nodes: Vec<String>,

    /// Target nodes (comma-separated, e.g. "DOMAIN ADMINS@COMP.COM,S-123-431-1234"; templates: DOMAIN-ADMINS,ALL-TIER-0)
    #[arg(short, long, value_delimiter = ',')]
    pub(crate) target_nodes: Vec<String>,

    /// Export subgraph containing only attack-path nodes/edges as JSON without printing the table(s) to standard output
    #[arg(short='a',long="export-attack-graph", action = clap::ArgAction::SetTrue, default_value_t = false)]
    pub(crate) attack_graph: bool,

    /// Find the top-10 Non-Tier-0 nodes with the highest centrality between source and target nodes
    #[arg(short='b',long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    pub(crate) centrality: bool,
}

/// Prints a formatted table to standard output showing the shortest path from `from` to `to` in the given `graph`,
/// along with the relationships and costs of each step in the path.
///
// The `shortest_path` parameter is directly forwarded from the output of `ADGraph::create_attack_graph`
pub(crate) fn default_print(
    graph: &ADGraph,
    from: &String,
    to: &String,
    shortest_path: &(usize, Vec<petgraph::prelude::NodeIndex>),
) {
    let mut table = prettytable::Table::new();
    let banner = format!("Starting Node: {from} --> Target Node: {to}");
    table.add_row(row![banner]);
    let mut subtable = prettytable::Table::new();
    subtable.add_row(row!["Step", "Current Node", "Relationship", "Next Hop"]);

    let mut step = 1;
    for path in shortest_path.1.windows(2) {
        let source = path[0];
        let dest = path[1];

        let source_node = &graph.node_weight(source).unwrap();
        let dest_node = &graph.node_weight(dest).unwrap();

        let source_name = if source_node.is_tier_zero {
            &format!("{}(★)", source_node.name)
        } else {
            &source_node.name
        };

        let dest_name = if dest_node.is_tier_zero {
            &format!("{}(★)", dest_node.name)
        } else {
            &dest_node.name
        };

        let rel = graph.find_min_relationship(source, dest).unwrap();
        let rel_cost = rel.cost();
        let rel_str: &str = rel.into();
        let rel_fmt = format!("-{}({})->", rel_str, rel_cost);

        subtable.add_row(row![step, source_name, rel_fmt, dest_name]);

        step += 1;
    }

    table.add_row(row![subtable]);

    table
        .print_tty(false)
        .expect("Failed not print the table to standard output");
}

pub(crate) fn centrality_print(graph: &ADGraph, centrality_rates: &Vec<Option<f64>>) {
    let mut node_rate_list = centrality_rates.iter().enumerate().sorted_by(
        |(_, centrality_rate1), (_, centrality_rate2)| {
            centrality_rate1
                .unwrap_or(f64::MIN)
                .partial_cmp(&centrality_rate2.unwrap_or(f64::MIN))
                .unwrap() // cannot panic
        },
    );

    let mut table = Table::new();
    table.add_row(row!["Node Name", "Centrality Rate"]);

    let mut step = 0;

    while let Some((node_idx, centrality_rate)) = node_rate_list.next() {
        // print only top 10
        if step == 10 {
            break;
        }

        let node_weight = graph
            .node_weight(petgraph::prelude::NodeIndex::from(node_idx as u32))
            .expect("Failed to locate the node with the given index");
        let centrality_rate = centrality_rate.unwrap_or(f64::MIN);

        table.add_row(row![node_weight.name, centrality_rate]);
        step += 1;
    }

    table
        .print_tty(false)
        .expect("Failed not print the table to standard output");
}
