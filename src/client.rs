use std::collections::HashMap;

use base64::{engine::general_purpose, Engine};
use chrono::{DateTime, Local};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, USER_AGENT},
    Url,
};
use serde::Serialize;
use sha2::Sha256;

use crate::ad_graph::{ADGraph, GraphResponse};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    key: String,
    id: String,
    base_url: Url,
}

#[allow(dead_code)]
impl Client {
    pub(crate) fn new(
        key: impl Into<String>,
        id: impl Into<String>,
        url: Option<impl reqwest::IntoUrl>,
    ) -> Self {
        let url = url
            .map(|u| u.into_url().unwrap())
            .unwrap_or_else(|| Url::parse("http://127.0.0.1:8080").unwrap());

        Self {
            key: key.into(),
            id: id.into(),
            base_url: url,
        }
    }

    pub(crate) fn get<Q, K, V>(
        &self,
        path: impl AsRef<str>,
        query: Option<Q>,
    ) -> HashMap<String, serde_json::Value>
    where
        Q: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let url = self.build_url(&path, query);

        let client = reqwest::blocking::Client::builder()
            .build()
            .expect("Could not build the client");

        let headers = self.create_header(
            reqwest::Method::GET,
            path,
            &Local::now(),
            &reqwest::blocking::Body::from(""),
        );

        client
            .get(url)
            .headers(headers)
            .send()
            .expect("Could not request GET")
            .json::<HashMap<String, serde_json::Value>>()
            .expect("Could not parse JSON into HashMap")
    }

    pub(crate) fn execute_cypher_query(&self, json: impl Serialize) -> GraphResponse {
        let path = "/api/v2/graphs/cypher";
        let url = self.build_url(&path, None::<Vec<(String, String)>>);

        let client = reqwest::blocking::Client::builder()
            .build()
            .expect("Could not build the client");

        let body_json = serde_json::to_vec(&json).expect("Failed to serialize request body");
        let body = reqwest::blocking::Body::from(body_json);

        let headers = self.create_header(reqwest::Method::POST, path, &Local::now(), &body);

        client
            .post(url)
            .headers(headers)
            .body(body)
            .send()
            .expect("Could not request GET")
            .json::<GraphResponse>()
            .expect("Could not parse JSON into HashMap")
    }

    pub(crate) fn fetch_complete_ad_graph(&self, filter_non_traversable_edges: bool) -> ADGraph {
        let json = serde_json::json!({
            "query": "MATCH p=(n)-[r]->(m) WHERE n<>m RETURN p",
            "include_properties": false
        });

        self.execute_cypher_query(json)
            .to_graph(filter_non_traversable_edges)
    }

    fn build_url<Q, K, V>(&self, path: &impl AsRef<str>, query: Option<Q>) -> Url
    where
        Q: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let url = self
            .base_url
            .join(path.as_ref())
            .expect("Could not append path to base");

        if let Some(query) = query {
            reqwest::Url::parse_with_params(url.as_str(), query)
                .expect("Could not append the query parameters");
        };
        url
    }

    fn create_header(
        &self,
        method: reqwest::Method,
        path: impl AsRef<str>,
        date_time: &DateTime<Local>,
        body: &reqwest::blocking::Body,
    ) -> HeaderMap {
        let mut header_map = HeaderMap::new();

        header_map.insert(USER_AGENT, HeaderValue::from_static("rust-sdk 001"));
        header_map.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("bhesignature {}", self.id))
                .expect("Could not create HeaderValue for authorization"),
        );

        header_map.insert(
            "RequestDate",
            HeaderValue::from_str(&date_time.to_rfc3339())
                .expect("Could not create HeaderValue for request date"),
        );

        header_map.insert(
            "Signature",
            HeaderValue::from_str(&self.authorize(method, path, date_time, body))
                .expect("Could not create HeaderValue for Signature"),
        );

        header_map.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        header_map
    }

    fn authorize(
        &self,
        method: reqwest::Method,
        path: impl AsRef<str>,
        date_time: &DateTime<Local>,
        body: &reqwest::blocking::Body,
    ) -> String {
        let mut digester = HmacSha256::new_from_slice(self.key.as_bytes())
            .expect("Could not create the HmacSha256 from the key");

        digester.update(format!("{}{}", method, path.as_ref()).as_bytes());

        let mut digester_bytes = digester.finalize().into_bytes();

        digester = HmacSha256::new_from_slice(&digester_bytes)
            .expect("Could not create the HmacSha256 from the digester bytes");

        digester.update(&date_time.to_rfc3339().as_bytes()[..13]);

        digester_bytes = digester.finalize().into_bytes();

        digester = HmacSha256::new_from_slice(&digester_bytes)
            .expect("Could not create the HmacSha256 from the digester bytes");

        digester.update(body.as_bytes().unwrap_or_default());

        digester_bytes = digester.finalize().into_bytes();

        general_purpose::STANDARD.encode(digester_bytes)
    }
}
