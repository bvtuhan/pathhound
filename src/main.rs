use petgraph::Graph;

use crate::{ad_graph::Relationship, client::Client};

pub(crate) mod ad_graph;
pub(crate) mod client;

fn main() {
    let client = Client::new(
        "mu8NveEKoTqqpF3/QjG6yBYOGllPoE5P8EQjHCr6V+shiXeV/HcczA==",
        "95a03c4c-1605-41dc-ad25-16bf7f635cf4",
        None::<String>,
    );

    let graph = client.fetch_complete_ad_graph();

    println!("{:#?}", graph);
}
