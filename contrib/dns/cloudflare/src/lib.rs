//! Cloudflare DNS provider plugin for caddy-wit.
//!
//! Registers `dns.providers.cloudflare`. Implements the Cloudflare v4 API
//! directly using the WIT `host-http` import — no libdns dependency.
//!
//! Config: `{"api_token":"...","zone_token":"..."}`
//! Caddyfile: `cloudflare <api_token>` or `cloudflare { api_token <tok>; zone_token <tok> }`

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

const MODULE_ID: &str = "dns.providers.cloudflare";
const CF_BASE: &str = "https://api.cloudflare.com/client/v4";

struct Component;

#[derive(Deserialize, Serialize, Default, Clone)]
struct Config {
    #[serde(default)]
    api_token: String,
    #[serde(default)]
    zone_token: String,
}

thread_local! {
    static INSTANCE: RefCell<Option<Config>> = RefCell::new(None);
}

// ── Cloudflare API helpers ──────────────────────────────────────────────

fn cf_request(
    method: &str,
    url: &str,
    body: Option<&[u8]>,
    token: &str,
) -> Result<serde_json::Value, String> {
    let headers = vec![
        ("Authorization".to_string(), format!("Bearer {token}")),
        ("Content-Type".to_string(), "application/json".to_string()),
    ];
    let resp = host_http::send(
        method,
        url,
        &headers,
        body.unwrap_or(&[]),
        None,
    )?;
    let val: serde_json::Value =
        serde_json::from_slice(&resp.body).map_err(|e| format!("json decode: {e}"))?;
    if val.get("success").and_then(|v| v.as_bool()) != Some(true) {
        let errors = val.get("errors").cloned().unwrap_or(serde_json::Value::Null);
        return Err(format!("cloudflare API error: {errors}"));
    }
    Ok(val)
}

fn get_zone_id(zone: &str, cfg: &Config) -> Result<String, String> {
    let trimmed = zone.trim_end_matches('.');
    let url = format!("{CF_BASE}/zones?name={trimmed}");
    let token = if cfg.zone_token.is_empty() {
        &cfg.api_token
    } else {
        &cfg.zone_token
    };
    let val = cf_request("GET", &url, None, token)?;
    let zones = val
        .get("result")
        .and_then(|v| v.as_array())
        .ok_or("no result array in zone lookup")?;
    if zones.len() != 1 {
        return Err(format!("expected 1 zone, got {} for {trimmed}", zones.len()));
    }
    zones[0]
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "zone id missing".to_string())
}

fn cf_to_dns_record(rec: &serde_json::Value, zone: &str) -> dns_provider::DnsRecord {
    let rr_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let full_name = rec.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let zone_bare = zone.trim_end_matches('.');
    // Make name relative to zone
    let name = if full_name == zone_bare {
        String::new()
    } else {
        full_name
            .strip_suffix(&format!(".{zone_bare}"))
            .unwrap_or(full_name)
            .to_string()
    };
    let mut value = rec.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
    // Unwrap TXT record quotes (Cloudflare wraps TXT content in quotes)
    if rr_type == "TXT" {
        if let Some(s) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            value = s.to_string();
        }
    }
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

fn dns_record_to_cf_json(rec: &dns_provider::DnsRecord, zone: &str) -> serde_json::Value {
    let zone_bare = zone.trim_end_matches('.');
    let full_name = if rec.name.is_empty() {
        zone_bare.to_string()
    } else {
        format!("{}.{zone_bare}", rec.name)
    };
    let mut content = rec.value.clone();
    // Wrap TXT content in quotes for Cloudflare
    if rec.rr_type == "TXT" && !content.starts_with('"') {
        content = format!("\"{}\"", content);
    }
    let mut obj = serde_json::json!({
        "type": rec.rr_type,
        "name": full_name,
        "content": content,
        "ttl": rec.ttl_seconds,
    });
    if let Some(pri) = rec.priority {
        obj["priority"] = serde_json::json!(pri);
    }
    obj
}

// ── WIT trait implementations ───────────────────────────────────────────

impl manifest::Guest for Component {
    fn describe() -> manifest::PluginInfo {
        manifest::PluginInfo {
            name: "dns-cloudflare".to_string(),
            version: Some("0.1.0".to_string()),
            modules: vec![manifest::ModuleDecl {
                id: MODULE_ID.to_string(),
                docs: Some(
                    "Cloudflare DNS provider for ACME DNS-01 and record management".to_string(),
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
            return Err(format!("unknown module: {module_id}"));
        }
        let parsed: Config = if config.trim().is_empty() {
            Config::default()
        } else {
            serde_json::from_str(&config).map_err(|e| format!("invalid config: {e}"))?
        };
        if parsed.api_token.is_empty() {
            return Err("api_token is required".to_string());
        }
        INSTANCE.with(|cell| *cell.borrow_mut() = Some(parsed));
        log::log(log::Level::Info, "cloudflare provisioned", &[]);
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

        let mut api_token = String::new();
        let mut zone_token = String::new();

        if d.next_arg() {
            api_token = d.val().to_string();
        } else {
            while d.next_block(0) {
                match d.val() {
                    "api_token" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        api_token = d.val().to_string();
                    }
                    "zone_token" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        zone_token = d.val().to_string();
                    }
                    _ => return Err(d.errf(&format!("unrecognized subdirective '{}'", d.val()))),
                }
            }
        }

        if api_token.is_empty() {
            return Err("missing API token".to_string());
        }

        let cfg = Config { api_token, zone_token };
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
            let zone_id = get_zone_id(&zone, cfg)?;
            let mut all_records = Vec::new();
            // Hard cap at 1000 pages to prevent infinite loops on unexpected API responses.
            for page in 1..=1000u32 {
                let url = format!(
                    "{CF_BASE}/zones/{zone_id}/dns_records?page={page}&per_page=100"
                );
                let val = cf_request("GET", &url, None, &cfg.api_token)?;
                let recs = val
                    .get("result")
                    .and_then(|v| v.as_array())
                    .ok_or("no result array")?;
                if recs.is_empty() {
                    break;
                }
                for rec in recs {
                    all_records.push(cf_to_dns_record(rec, &zone));
                }
                // Stop if we've fetched all pages.
                let total_count = val
                    .pointer("/result_info/total_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                if (page * 100) >= total_count {
                    break;
                }
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
            let zone_id = get_zone_id(&zone, cfg)?;
            let mut created = Vec::new();
            for rec in &records {
                let body = dns_record_to_cf_json(rec, &zone);
                let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
                let url = format!("{CF_BASE}/zones/{zone_id}/dns_records");
                let val = cf_request("POST", &url, Some(&body_bytes), &cfg.api_token)?;
                let result = val.get("result").ok_or("no result in create response")?;
                created.push(cf_to_dns_record(result, &zone));
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
            let zone_id = get_zone_id(&zone, cfg)?;
            let zone_bare = zone.trim_end_matches('.');
            let mut results = Vec::new();
            for rec in &records {
                let full_name = if rec.name.is_empty() {
                    zone_bare.to_string()
                } else {
                    format!("{}.{zone_bare}", rec.name)
                };
                // Look up existing by type+name
                let lookup_url = format!(
                    "{CF_BASE}/zones/{zone_id}/dns_records?type={}&name={}",
                    rec.rr_type, full_name
                );
                let val = cf_request("GET", &lookup_url, None, &cfg.api_token)?;
                let matches = val
                    .get("result")
                    .and_then(|v| v.as_array())
                    .ok_or("no result array")?;
                let body = dns_record_to_cf_json(rec, &zone);
                let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
                if matches.is_empty() {
                    // Create new
                    let url = format!("{CF_BASE}/zones/{zone_id}/dns_records");
                    let val = cf_request("POST", &url, Some(&body_bytes), &cfg.api_token)?;
                    let result = val.get("result").ok_or("no result in create response")?;
                    results.push(cf_to_dns_record(result, &zone));
                } else {
                    // Update existing (use first match)
                    let existing_id = matches[0]
                        .get("id")
                        .and_then(|v| v.as_str())
                        .ok_or("missing record id")?;
                    let url =
                        format!("{CF_BASE}/zones/{zone_id}/dns_records/{existing_id}");
                    let val =
                        cf_request("PATCH", &url, Some(&body_bytes), &cfg.api_token)?;
                    let result = val.get("result").ok_or("no result in update response")?;
                    results.push(cf_to_dns_record(result, &zone));
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
            let zone_id = get_zone_id(&zone, cfg)?;
            let zone_bare = zone.trim_end_matches('.');
            let mut deleted = Vec::new();
            for rec in &records {
                let full_name = if rec.name.is_empty() {
                    zone_bare.to_string()
                } else {
                    format!("{}.{zone_bare}", rec.name)
                };
                // Look up by type+name+content
                let mut content = rec.value.clone();
                if rec.rr_type == "TXT" && !content.starts_with('"') {
                    content = format!("\"{}\"", content);
                }
                let lookup_url = if rec.rr_type == "TXT" {
                    // Use contains search for TXT (Cloudflare wraps in quotes)
                    format!(
                        "{CF_BASE}/zones/{zone_id}/dns_records?type={}&name={}&content.contains={}",
                        rec.rr_type, full_name, rec.value
                    )
                } else {
                    format!(
                        "{CF_BASE}/zones/{zone_id}/dns_records?type={}&name={}&content.exact={}",
                        rec.rr_type, full_name, rec.value
                    )
                };
                let val = cf_request("GET", &lookup_url, None, &cfg.api_token)?;
                let matches = val
                    .get("result")
                    .and_then(|v| v.as_array())
                    .ok_or("no result array")?;

                // For TXT, do exact matching on the content
                let exact_matches: Vec<&serde_json::Value> = if rec.rr_type == "TXT" {
                    matches
                        .iter()
                        .filter(|m| {
                            let c = m.get("content").and_then(|v| v.as_str()).unwrap_or("");
                            c == content || c == rec.value
                        })
                        .collect()
                } else {
                    matches.iter().collect()
                };

                for m in &exact_matches {
                    let rid = m
                        .get("id")
                        .and_then(|v| v.as_str())
                        .ok_or("missing record id")?;
                    let url = format!("{CF_BASE}/zones/{zone_id}/dns_records/{rid}");
                    let del_val = cf_request("DELETE", &url, None, &cfg.api_token)?;
                    let result = del_val.get("result").ok_or("no result in delete response")?;
                    deleted.push(cf_to_dns_record(result, &zone));
                }
            }
            Ok(deleted)
        })
    }
}

export!(Component);
