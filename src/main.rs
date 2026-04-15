use crate::client::Client;

pub(crate) mod client;

fn main() {
    let client = Client::new(
        "NMouy6tO67iTm7iYutX+6Ek4DuXPhXPmSawEQMWG2o+8h1r4nH8ZRA==",
        "aa924e9e-e4e8-4387-8c8e-9ee4c1707563",
        None::<String>,
    );

    let json = serde_json::json!({
        "query": "MATCH (n:User) RETURN n LIMIT 100",
        "include_properties": false
    });

    let req = client.execute_cypher_query("/api/v2/graphs/cypher", json);

    // let req = client.get(
    //     "/api/v2/bloodhound-users",
    //     None::<std::iter::Empty<(String, String)>>, // i mean what the fuck?
    // );

    println!("{:#?}", req);
}
