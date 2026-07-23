//! Hetzner DNS provider plugin for caddy-wit.
//!
//! Registers `dns.providers.hetzner`. Implements the Hetzner DNS API
//! directly using the WIT `host-http` import — no libdns dependency.
//!
//! Config: `{"auth_api_token":"..."}`
//! Caddyfile: `hetzner <auth_api_token>` or `hetzner { auth_api_token <tok> }`

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

const MODULE_ID: &str = "dns.providers.hetzner";
const HZ_BASE: &str = "https://dns.hetzner.com/api/v1";

struct Component;

#[derive(Deserialize, Serialize, Default, Clone)]
struct Config {
    #[serde(default)]
    auth_api_token: String,
}

thread_local! {
    static INSTANCE: RefCell<Option<Config>> = RefCell::new(None);
}

// ── Hetzner API helpers ─────────────────────────────────────────────────

fn hz_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    token: &str,
) -> Result<(u16, Vec<u8>), String> {
    let headers = vec![
        ("Auth-API-Token".to_string(), token.to_string()),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let resp = host_http::send(method, url, &headers, body.unwrap_or(&[]), None)?;
    if resp.status < 200 || resp.status >= 300 {
        return Err(format!("hetzner API error: HTTP {}", resp.status));
    }
    Ok((resp.status, resp.body))
}

fn get_zone_id(zone: &str, token: &str) -> Result<String, String> {
    let trimmed = zone.trim_end_matches('.');
    let url = format!("{HZ_BASE}/zones?name={trimmed}");
    let (_, body) = hz_request("GET", &url, None, token)?;
    let val: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| format!("json decode: {e}"))?;
    let zones = val
        .get("zones")
        .and_then(|v| v.as_array())
        .ok_or("no zones array in response")?;
    if zones.is_empty() {
        return Err(format!("no zone found for {trimmed}"));
    }
    if zones.len() > 1 {
        return Err("zone is ambiguous".to_string());
    }
    zones[0]
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "zone id missing".to_string())
}

/// Normalize a record name for Hetzner (relative, no trailing dot, "@" for apex).
fn normalize_name(name: &str, zone: &str) -> String {
    let zone_bare = zone.trim_end_matches('.');
    let n = name.trim_end_matches('.');
    let n = n
        .strip_suffix(&format!(".{zone_bare}"))
        .unwrap_or(n);
    let n = n.trim_end_matches('.');
    if n.is_empty() {
        "@".to_string()
    } else {
        n.to_string()
    }
}

fn hz_to_dns_record(rec: &serde_json::Value, _zone: &str) -> dns_provider::DnsRecord {
    let rr_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let name = rec.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // Convert "@" back to empty string (zone apex)
    let name = if name == "@" { String::new() } else { name };
    let value = rec.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let ttl = rec.get("ttl").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    dns_provider::DnsRecord {
        rr_type,
        name,
        value,
        ttl_seconds: ttl,
        priority: None,
    }
}

// ── WIT trait implementations ───────────────────────────────────────────

impl manifest::Guest for Component {
    fn describe() -> manifest::PluginInfo {
        manifest::PluginInfo {
            name: "dns-hetzner".to_string(),
            version: Some("0.1.0".to_string()),
            modules: vec![manifest::ModuleDecl {
                id: MODULE_ID.to_string(),
                docs: Some(
                    "Hetzner DNS provider for ACME DNS-01 and record management".to_string(),
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
        if parsed.auth_api_token.is_empty() {
            return Err("auth_api_token is required".to_string());
        }
        INSTANCE.with(|cell| *cell.borrow_mut() = Some(parsed));
        log::log(log::Level::Info, "hetzner provisioned", &[]);
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

        let mut auth_api_token = String::new();

        if d.next_arg() {
            auth_api_token = d.val().to_string();
        } else {
            while d.next_block(0) {
                match d.val() {
                    "auth_api_token" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        auth_api_token = d.val().to_string();
                    }
                    _ => return Err(d.errf(&format!("unrecognized subdirective '{}'", d.val()))),
                }
            }
        }

        if auth_api_token.is_empty() {
            return Err("missing auth_api_token".to_string());
        }

        let cfg = Config { auth_api_token };
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
            let zone_id = get_zone_id(&zone, &cfg.auth_api_token)?;
            let url = format!("{HZ_BASE}/records?zone_id={zone_id}");
            let (_, body) = hz_request("GET", &url, None, &cfg.auth_api_token)?;
            let val: serde_json::Value =
                serde_json::from_slice(&body).map_err(|e| format!("json decode: {e}"))?;
            let recs = val
                .get("records")
                .and_then(|v| v.as_array())
                .ok_or("no records array")?;
            Ok(recs.iter().map(|r| hz_to_dns_record(r, &zone)).collect())
        })
    }

    fn append_records(
        _inst: dns_provider::InstanceBorrow<'_>,
        zone: String,
        records: Vec<dns_provider::DnsRecord>,
    ) -> Result<Vec<dns_provider::DnsRecord>, String> {
        with_instance(|cfg| {
            let zone_id = get_zone_id(&zone, &cfg.auth_api_token)?;
            let mut created = Vec::new();
            for rec in &records {
                let name = normalize_name(&rec.name, &zone);
                let body = serde_json::json!({
                    "zone_id": zone_id,
                    "type": rec.rr_type,
                    "name": name,
                    "value": rec.value,
                    "ttl": rec.ttl_seconds,
                });
                let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
                let url = format!("{HZ_BASE}/records");
                let (_, resp_body) =
                    hz_request("POST", &url, Some(&body_bytes), &cfg.auth_api_token)?;
                let val: serde_json::Value = serde_json::from_slice(&resp_body)
                    .map_err(|e| format!("json decode: {e}"))?;
                let result = val.get("record").ok_or("no record in create response")?;
                created.push(hz_to_dns_record(result, &zone));
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
            let zone_id = get_zone_id(&zone, &cfg.auth_api_token)?;
            // Fetch all existing records for matching
            let list_url = format!("{HZ_BASE}/records?zone_id={zone_id}");
            let (_, list_body) = hz_request("GET", &list_url, None, &cfg.auth_api_token)?;
            let list_val: serde_json::Value = serde_json::from_slice(&list_body)
                .map_err(|e| format!("json decode: {e}"))?;
            let all_recs = list_val
                .get("records")
                .and_then(|v| v.as_array())
                .ok_or("no records array")?;

            let mut results = Vec::new();
            for rec in &records {
                let name = normalize_name(&rec.name, &zone);
                // Find existing by type+name
                let existing_id = all_recs.iter().find_map(|r| {
                    let t = r.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let n = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if t == rec.rr_type && n == name {
                        r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
                    } else {
                        None
                    }
                });

                let body = serde_json::json!({
                    "zone_id": zone_id,
                    "type": rec.rr_type,
                    "name": name,
                    "value": rec.value,
                    "ttl": rec.ttl_seconds,
                });
                let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;

                let (_, resp_body) = if let Some(id) = existing_id {
                    let url = format!("{HZ_BASE}/records/{id}");
                    hz_request("PUT", &url, Some(&body_bytes), &cfg.auth_api_token)?
                } else {
                    let url = format!("{HZ_BASE}/records");
                    hz_request("POST", &url, Some(&body_bytes), &cfg.auth_api_token)?
                };
                let val: serde_json::Value = serde_json::from_slice(&resp_body)
                    .map_err(|e| format!("json decode: {e}"))?;
                let result = val.get("record").ok_or("no record in response")?;
                results.push(hz_to_dns_record(result, &zone));
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
            let zone_id = get_zone_id(&zone, &cfg.auth_api_token)?;
            // Fetch all existing records for matching
            let list_url = format!("{HZ_BASE}/records?zone_id={zone_id}");
            let (_, list_body) = hz_request("GET", &list_url, None, &cfg.auth_api_token)?;
            let list_val: serde_json::Value = serde_json::from_slice(&list_body)
                .map_err(|e| format!("json decode: {e}"))?;
            let all_recs = list_val
                .get("records")
                .and_then(|v| v.as_array())
                .ok_or("no records array")?;

            let mut deleted = Vec::new();
            for rec in &records {
                let name = normalize_name(&rec.name, &zone);
                // Find by type+name
                let existing_id = all_recs.iter().find_map(|r| {
                    let t = r.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    let n = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    if t == rec.rr_type && n == name {
                        r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())
                    } else {
                        None
                    }
                });

                if let Some(id) = existing_id {
                    let url = format!("{HZ_BASE}/records/{id}");
                    hz_request("DELETE", &url, None, &cfg.auth_api_token)?;
                    deleted.push(rec.clone());
                } else {
                    return Err(format!("record ID not found: {}", rec.name));
                }
            }
            Ok(deleted)
        })
    }
}

export!(Component);
