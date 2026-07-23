//! Sliding-window rate limiter plugin for caddy-wit.
//!
//! Registers `http.handlers.rate_limit`. Uses host-kv `increment` with TTL
//! to implement a fixed-window counter that auto-expires.
//!
//! Config: {"requests_per_window": 100, "window_seconds": 60,
//!          "key_template": "{remote_addr}", "status_code": 429}

use serde::Deserialize;

wit_bindgen::generate!({
    path: "../../../wit",
    world: "http-handler-plugin",
});

use caddy::plugin::host_kv;
use caddy::plugin::http_types;
use caddy::plugin::log;
use exports::caddy::plugin::config as cfg;
use exports::caddy::plugin::http_handler;
use exports::caddy::plugin::lifecycle;
use exports::caddy::plugin::manifest;

struct Component;

const MODULE_ID: &str = "http.handlers.rate_limit";

#[derive(Deserialize)]
struct RateLimitConfig {
    #[serde(default = "default_requests_per_window")]
    requests_per_window: i64,
    #[serde(default = "default_window_seconds")]
    window_seconds: u64,
    #[serde(default = "default_key_template")]
    key_template: String,
    #[serde(default = "default_status_code")]
    status_code: u16,
}

fn default_requests_per_window() -> i64 { 100 }
fn default_window_seconds() -> u64 { 60 }
fn default_key_template() -> String { "{remote_addr}".to_string() }
fn default_status_code() -> u16 { 429 }

struct RateLimitInstance {
    requests_per_window: i64,
    window_seconds: u64,
    key_template: String,
    status_code: u16,
}

impl manifest::Guest for Component {
    fn describe() -> manifest::PluginInfo {
        manifest::PluginInfo {
            name: "rate-limit".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            modules: vec![manifest::ModuleDecl {
                id: MODULE_ID.to_string(),
                docs: Some("Fixed-window rate limiter using host-kv counters".to_string()),
                caddyfile_order: Some(manifest::CaddyfileOrder {
                    position: manifest::DirectivePosition::Before,
                    relative_to: "respond".to_string(),
                }),
            }],
        }
    }
}

impl lifecycle::Guest for Component {
    type Instance = RateLimitInstance;
}

impl lifecycle::GuestInstance for RateLimitInstance {
    fn provision(module_id: String, config: String) -> Result<lifecycle::Instance, String> {
        if module_id != MODULE_ID {
            return Err(format!("unknown module id: {module_id}"));
        }
        let parsed: RateLimitConfig = if config.trim().is_empty() {
            serde_json::from_str("{}").unwrap()
        } else {
            serde_json::from_str(&config).map_err(|e| format!("invalid config: {e}"))?
        };

        log::log(
            log::Level::Info,
            "rate_limit provisioned",
            &[
                ("requests_per_window".into(), parsed.requests_per_window.to_string()),
                ("window_seconds".into(), parsed.window_seconds.to_string()),
            ],
        );

        Ok(lifecycle::Instance::new(RateLimitInstance {
            requests_per_window: parsed.requests_per_window,
            window_seconds: parsed.window_seconds,
            key_template: parsed.key_template,
            status_code: parsed.status_code,
        }))
    }

    fn validate(&self) -> Result<(), String> {
        if self.requests_per_window <= 0 {
            return Err("requests_per_window must be positive".to_string());
        }
        if self.window_seconds == 0 {
            return Err("window_seconds must be > 0".to_string());
        }
        Ok(())
    }

    fn cleanup(&self) {
        log::log(log::Level::Debug, "rate_limit cleaned up", &[]);
    }
}

impl cfg::Guest for Component {
    fn unmarshal_caddyfile(module_id: String, tokens: Vec<cfg::Token>) -> Result<String, String> {
        use caddy_wit_caddyfile::{Dispenser, Token};

        if module_id != MODULE_ID {
            return Err(format!("unknown module id: {module_id}"));
        }
        let toks = tokens.iter().map(|t| Token::new(&t.file, t.line, &t.text, t.quoted)).collect();
        let mut d = Dispenser::new(toks);
        d.next(); // directive name

        let mut obj = serde_json::Map::new();

        // Inline form: rate_limit <requests_per_window> <window_seconds>
        if d.next_arg() {
            let rpw: i64 = d.val().parse().map_err(|e| d.errf(&format!("bad requests_per_window: {e}")))?;
            obj.insert("requests_per_window".into(), serde_json::json!(rpw));
            if d.next_arg() {
                let ws: u64 = d.val().parse().map_err(|e| d.errf(&format!("bad window_seconds: {e}")))?;
                obj.insert("window_seconds".into(), serde_json::json!(ws));
            }
        } else {
            // Block form
            while d.next_block(0) {
                match d.val() {
                    "requests_per_window" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        let rpw: i64 = d.val().parse().map_err(|e| d.errf(&format!("bad requests_per_window: {e}")))?;
                        obj.insert("requests_per_window".into(), serde_json::json!(rpw));
                    }
                    "window_seconds" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        let ws: u64 = d.val().parse().map_err(|e| d.errf(&format!("bad window_seconds: {e}")))?;
                        obj.insert("window_seconds".into(), serde_json::json!(ws));
                    }
                    "key_template" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        obj.insert("key_template".into(), serde_json::json!(d.val()));
                    }
                    "status_code" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        let sc: u16 = d.val().parse().map_err(|e| d.errf(&format!("bad status_code: {e}")))?;
                        obj.insert("status_code".into(), serde_json::json!(sc));
                    }
                    _ => return Err(d.errf(&format!("unrecognized subdirective '{}'", d.val()))),
                }
            }
        }

        serde_json::to_string(&obj).map_err(|e| e.to_string())
    }
}

/// Resolve the rate-limit key from the template. For v1 we support
/// `{remote_addr}` by substituting the request's remote address (with
/// port stripped). Any other template is passed to `request.replace()`.
fn resolve_key(req: &http_types::Request, template: &str) -> String {
    if template == "{remote_addr}" {
        let addr = req.remote_addr();
        // Strip port if present (e.g. "1.2.3.4:5678" → "1.2.3.4").
        if let Some(idx) = addr.rfind(':') {
            // Guard against IPv6 with brackets like "[::1]:1234".
            if addr.starts_with('[') {
                if let Some(bracket) = addr.rfind(']') {
                    if idx > bracket {
                        return addr[..idx].to_string();
                    }
                }
                return addr;
            }
            return addr[..idx].to_string();
        }
        addr
    } else {
        req.replace(template, "")
    }
}

impl http_handler::Guest for Component {
    fn serve(
        inst: lifecycle::InstanceBorrow<'_>,
        req: &http_types::Request,
        resp: &http_types::ResponseWriter,
    ) -> Result<(), http_types::PluginError> {
        let this: &RateLimitInstance = inst.get();

        let resolved = resolve_key(req, &this.key_template);
        let kv_key = format!("rl:{}", resolved);
        let ttl_ms = Some(this.window_seconds * 1000);

        let count = host_kv::increment(&kv_key, 1, ttl_ms);

        if count > this.requests_per_window {
            resp.set_header("Retry-After", &this.window_seconds.to_string());
            resp.set_header("X-RateLimit-Limit", &this.requests_per_window.to_string());
            resp.set_header("X-RateLimit-Remaining", "0");
            return Err(http_types::PluginError {
                status: Some(this.status_code),
                message: "rate limit exceeded".to_string(),
            });
        }

        let remaining = this.requests_per_window - count;
        resp.set_header("X-RateLimit-Limit", &this.requests_per_window.to_string());
        resp.set_header("X-RateLimit-Remaining", &remaining.to_string());

        http_types::next(req, resp)
    }
}

export!(Component);
