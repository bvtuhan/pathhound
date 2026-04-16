use std::path::PathBuf;

use clap::Parser;
use prettytable::row;

use crate::ad_graph::{ADGraph, ADGraphExt};

/// Pathhound
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    /// If this option is set, non-traversable edges will not be filtered out
    #[arg(short='x', long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    pub(crate) no_filter: bool,

    #[arg(short, long, default_value="./credentials.json", value_hint=clap::ValueHint::FilePath)]
    pub(crate) credentials_path: PathBuf,

    #[arg(short, long, value_delimiter = ',')]
    pub(crate) source_nodes: Vec<String>,

    #[arg(short, long, value_delimiter = ',')]
    pub(crate) target_nodes: Vec<String>,

    #[arg(long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    pub(crate) construct_subgraph: bool,
}

pub(crate) fn fmt_table_print(
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

        let source_name = &graph.node_weight(source).unwrap().name;
        let dest_name = &graph.node_weight(dest).unwrap().name;

        let rel = graph.find_min_relationship(source, dest).unwrap();
        let rel_cost = rel.cost();
        let rel_str: &str = rel.into();
        let rel_fmt = format!("-{}({})->", rel_cost, rel_str);

        subtable.add_row(row![step, source_name, rel_fmt, dest_name]);

        step += 1;
    }

    table.add_row(row![subtable]);

    table
        .print_tty(false)
        .expect("Failed not print the table to standard output");
}
