//! DigitalOcean DNS provider plugin for caddy-wit.
//!
//! Registers `dns.providers.digitalocean`. Implements the DigitalOcean DNS API
//! directly using the WIT `host-http` import — no libdns/godo dependency.
//!
//! Config: `{"auth_token":"..."}`
//! Caddyfile: `digitalocean <auth_token>` or `digitalocean { auth_token <tok> }`

use serde::{Deserialize, Serialize};
use std::cell::RefCell;

wit_bindgen::generate!({
    path: "../../../wit",
    world: "dns-provider-plugin",
});

use caddy::plugin::host_http;
use caddy::plugin::log;
use exports::caddy::plugin::config as cfg;
use exports::caddy::plugin::dns_provider;
use exports::caddy::plugin::lifecycle;
use exports::caddy::plugin::manifest;

const MODULE_ID: &str = "dns.providers.digitalocean";
const DO_BASE: &str = "https://api.digitalocean.com/v2";

struct Component;

#[derive(Deserialize, Serialize, Default, Clone)]
struct Config {
    #[serde(default)]
    auth_token: String,
}

thread_local! {
    static INSTANCE: RefCell<Option<Config>> = RefCell::new(None);
}

// ── DigitalOcean API helpers ────────────────────────────────────────────

fn do_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    token: &str,
) -> Result<(u16, Vec<u8>), String> {
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {token}")),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let resp = host_http::send(method, url, &headers, body.unwrap_or(&[]), None)?;
    if resp.status < 200 || resp.status >= 300 {
        let body_str = String::from_utf8_lossy(&resp.body);
        return Err(format!(
            "digitalocean API error: HTTP {} {}",
            resp.status, body_str
        ));
    }
    Ok((resp.status, resp.body))
}

fn do_to_dns_record(rec: &serde_json::Value) -> dns_provider::DnsRecord {
    let rr_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let name = rec.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // DO uses "@" for apex
    let name = if name == "@" { String::new() } else { name };
    let value = rec.get("data").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let ttl = rec.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let priority = rec.get("priority").and_then(|v| v.as_u64()).map(|v| v as u16);
    dns_provider::DnsRecord {
        rr_type,
        name,
        value,
        ttl_seconds: ttl,
        priority,
    }
}

// ── WIT trait implementations ───────────────────────────────────────────

impl manifest::Guest for Component {
    fn describe() -> manifest::PluginInfo {
        manifest::PluginInfo {
            name: "dns-digitalocean".to_string(),
            version: Some("0.1.0".to_string()),
            modules: vec![manifest::ModuleDecl {
                id: MODULE_ID.to_string(),
                docs: Some(
                    "DigitalOcean DNS provider for ACME DNS-01 and record management".to_string(),
                ),
                caddyfile_order: None,
            }],
        }
    }
}

impl lifecycle::Guest for Component {
    type Instance = ConfigInstance;
}

struct ConfigInstance;

impl lifecycle::GuestInstance for ConfigInstance {
    fn provision(module_id: String, config: String) -> Result<lifecycle::Instance, String> {
        if module_id != MODULE_ID {
            return Err(format!("unknown module id: {module_id}"));
        }
        let parsed: Config = if config.trim().is_empty() {
            Config::default()
        } else {
            serde_json::from_str(&config).map_err(|e| format!("invalid config: {e}"))?
        };
        if parsed.auth_token.is_empty() {
            return Err("auth_token is required".to_string());
        }
        INSTANCE.with(|cell| *cell.borrow_mut() = Some(parsed));
        log::log(log::Level::Info, "digitalocean provisioned", &[]);
        Ok(lifecycle::Instance::new(ConfigInstance))
    }

    fn validate(&self) -> Result<(), String> {
        Ok(())
    }

    fn cleanup(&self) {
        INSTANCE.with(|cell| *cell.borrow_mut() = None);
    }
}

impl cfg::Guest for Component {
    fn unmarshal_caddyfile(module_id: String, tokens: Vec<cfg::Token>) -> Result<String, String> {
        use caddy_wit_caddyfile::{Dispenser, Token};

        if module_id != MODULE_ID {
            return Err(format!("unknown module: {module_id}"));
        }
        let toks = tokens.iter().map(|t| Token::new(&t.file, t.line, &t.text, t.quoted)).collect();
        let mut d = Dispenser::new(toks);
        d.next(); // directive name

        let mut auth_token = String::new();

        if d.next_arg() {
            auth_token = d.val().to_string();
        } else {
            while d.next_block(0) {
                match d.val() {
                    "auth_token" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        auth_token = d.val().to_string();
                    }
                    _ => return Err(d.errf(&format!("unrecognized subdirective '{}'", d.val()))),
                }
            }
        }

        if auth_token.is_empty() {
            return Err("missing auth_token".to_string());
        }

        let cfg = Config { auth_token };
        serde_json::to_string(&cfg).map_err(|e| e.to_string())
    }
}

fn with_instance<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&Config) -> Result<T, String>,
{
    INSTANCE.with(|cell| {
        let borrow = cell.borrow();
        let cfg = borrow.as_ref().ok_or("not provisioned")?;
        f(cfg)
    })
}

impl dns_provider::Guest for Component {
    fn get_records(
        _inst: dns_provider::InstanceBorrow<'_>,
        zone: String,
    ) -> Result<Vec<dns_provider::DnsRecord>, String> {
        with_instance(|cfg| {
            let domain = zone.trim_end_matches('.');
            let mut all_records = Vec::new();
            let mut page = 1u32;
            loop {
                let url = format!(
                    "{DO_BASE}/domains/{domain}/records?page={page}&per_page=100"
                );
                let (_, body) = do_request("GET", &url, None, &cfg.auth_token)?;
                let val: serde_json::Value =
                    serde_json::from_slice(&body).map_err(|e| format!("json decode: {e}"))?;
                let recs = val
                    .get("domain_records")
                    .and_then(|v| v.as_array())
                    .ok_or("no domain_records array")?;
                if recs.is_empty() {
                    break;
                }
                for rec in recs {
                    all_records.push(do_to_dns_record(rec));
                }
                // Check pagination via links.pages.next
                let has_next = val
                    .pointer("/links/pages/next")
                    .and_then(|v| v.as_str())
                    .is_some();
                if !has_next {
                    break;
                }
                page += 1;
            }
            Ok(all_records)
        })
    }

    fn append_records(
        _inst: dns_provider::InstanceBorrow<'_>,
        zone: String,
        records: Vec<dns_provider::DnsRecord>,
    ) -> Result<Vec<dns_provider::DnsRecord>, String> {
        with_instance(|cfg| {
            let domain = zone.trim_end_matches('.');
            let mut created = Vec::new();
            for rec in &records {
                let name = if rec.name.is_empty() {
                    "@".to_string()
                } else {
                    rec.name.clone()
                };
                let mut body = serde_json::json!({
                    "type": rec.rr_type,
                    "name": name,
                    "data": rec.value,
                    "ttl": rec.ttl_seconds,
                });
                if let Some(pri) = rec.priority {
                    body["priority"] = serde_json::json!(pri);
                }
                let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
                let url = format!("{DO_BASE}/domains/{domain}/records");
                let (_, resp_body) =
                    do_request("POST", &url, Some(&body_bytes), &cfg.auth_token)?;
                let val: serde_json::Value = serde_json::from_slice(&resp_body)
                    .map_err(|e| format!("json decode: {e}"))?;
                let result = val
                    .get("domain_record")
                    .ok_or("no domain_record in create response")?;
                created.push(do_to_dns_record(result));
            }
            Ok(created)
        })
    }

    fn set_records(
        _inst: dns_provider::InstanceBorrow<'_>,
        zone: String,
        records: Vec<dns_provider::DnsRecord>,
    ) -> Result<Vec<dns_provider::DnsRecord>, String> {
        with_instance(|cfg| {
            let domain = zone.trim_end_matches('.');
            // Fetch all existing records
            let list_url = format!("{DO_BASE}/domains/{domain}/records?per_page=200");
            let (_, list_body) = do_request("GET", &list_url, None, &cfg.auth_token)?;
            let list_val: serde_json::Value = serde_json::from_slice(&list_body)
                .map_err(|e| format!("json decode: {e}"))?;
            let all_recs = list_val
                .get("domain_records")
                .and_then(|v| v.as_array())
                .ok_or("no domain_records array")?;

            let mut results = Vec::new();
            for rec in &records {
                let name = if rec.name.is_empty() {
                    "@".to_string()
                } else {
                    rec.name.clone()
                };
                // Find existing by type+name
                let existing_id = all_recs.iter().find_map(|r| {
                    let t = r.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let n = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if t == rec.rr_type && n == name {
                        r.get("id").and_then(|v| v.as_u64())
                    } else {
                        None
                    }
                });

                let mut body = serde_json::json!({
                    "type": rec.rr_type,
                    "name": name,
                    "data": rec.value,
                    "ttl": rec.ttl_seconds,
                });
                if let Some(pri) = rec.priority {
                    body["priority"] = serde_json::json!(pri);
                }
                let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

                if let Some(id) = existing_id {
                    let url = format!("{DO_BASE}/domains/{domain}/records/{id}");
                    let (_, resp_body) =
                        do_request("PUT", &url, Some(&body_bytes), &cfg.auth_token)?;
                    let val: serde_json::Value = serde_json::from_slice(&resp_body)
                        .map_err(|e| format!("json decode: {e}"))?;
                    let result = val
                        .get("domain_record")
                        .ok_or("no domain_record in update response")?;
                    results.push(do_to_dns_record(result));
                } else {
                    let url = format!("{DO_BASE}/domains/{domain}/records");
                    let (_, resp_body) =
                        do_request("POST", &url, Some(&body_bytes), &cfg.auth_token)?;
                    let val: serde_json::Value = serde_json::from_slice(&resp_body)
                        .map_err(|e| format!("json decode: {e}"))?;
                    let result = val
                        .get("domain_record")
                        .ok_or("no domain_record in create response")?;
                    results.push(do_to_dns_record(result));
                }
            }
            Ok(results)
        })
    }

    fn delete_records(
        _inst: dns_provider::InstanceBorrow<'_>,
        zone: String,
        records: Vec<dns_provider::DnsRecord>,
    ) -> Result<Vec<dns_provider::DnsRecord>, String> {
        with_instance(|cfg| {
            let domain = zone.trim_end_matches('.');
            // Fetch all existing records for matching
            let list_url = format!("{DO_BASE}/domains/{domain}/records?per_page=200");
            let (_, list_body) = do_request("GET", &list_url, None, &cfg.auth_token)?;
            let list_val: serde_json::Value = serde_json::from_slice(&list_body)
                .map_err(|e| format!("json decode: {e}"))?;
            let all_recs = list_val
                .get("domain_records")
                .and_then(|v| v.as_array())
                .ok_or("no domain_records array")?;

            let mut deleted = Vec::new();
            for rec in &records {
                let name = if rec.name.is_empty() {
                    "@".to_string()
                } else {
                    rec.name.clone()
                };
                // Find by type+name+data
                let existing_id = all_recs.iter().find_map(|r| {
                    let t = r.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let n = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let d = r.get("data").and_then(|v| v.as_str()).unwrap_or("");
                    if t == rec.rr_type && n == name && d == rec.value {
                        r.get("id").and_then(|v| v.as_u64())
                    } else {
                        None
                    }
                });

                if let Some(id) = existing_id {
                    let url = format!("{DO_BASE}/domains/{domain}/records/{id}");
                    do_request("DELETE", &url, None, &cfg.auth_token)?;
                    deleted.push(rec.clone());
                } else {
                    return Err(format!("record not found: {} {} {}", rec.rr_type, rec.name, rec.value));
                }
            }
            Ok(deleted)
        })
    }
}

export!(Component);
