//! CORS middleware plugin for caddy-wit (http.handlers.cors).
//!
//! Handles preflight (OPTIONS + Origin + Access-Control-Request-Method) with
//! an immediate 204, and decorates simple/actual requests with CORS headers.

use serde::Deserialize;

wit_bindgen::generate!({
    path: "../../../wit",
    world: "http-handler-plugin",
});

use caddy::plugin::http_types;
use caddy::plugin::log;
use exports::caddy::plugin::config as cfg;
use exports::caddy::plugin::http_handler;
use exports::caddy::plugin::lifecycle;
use exports::caddy::plugin::manifest;

struct Component;

#[derive(Deserialize, Clone)]
struct CorsConfig {
    #[serde(default = "default_origins")]
    allowed_origins: Vec<String>,
    #[serde(default = "default_methods")]
    allowed_methods: Vec<String>,
    #[serde(default = "default_headers")]
    allowed_headers: Vec<String>,
    #[serde(default)]
    expose_headers: Vec<String>,
    #[serde(default = "default_max_age")]
    max_age: u64,
    #[serde(default)]
    allow_credentials: bool,
}

fn default_origins() -> Vec<String> {
    vec!["*".to_string()]
}
fn default_methods() -> Vec<String> {
    vec![
        "GET".into(),
        "POST".into(),
        "PUT".into(),
        "DELETE".into(),
        "PATCH".into(),
        "OPTIONS".into(),
    ]
}
fn default_headers() -> Vec<String> {
    vec!["*".to_string()]
}
fn default_max_age() -> u64 {
    86400
}

impl Default for CorsConfig {
    fn default() -> Self {
        CorsConfig {
            allowed_origins: default_origins(),
            allowed_methods: default_methods(),
            allowed_headers: default_headers(),
            expose_headers: Vec::new(),
            max_age: default_max_age(),
            allow_credentials: false,
        }
    }
}

struct CorsInstance {
    cfg: CorsConfig,
}

impl CorsInstance {
    /// Check if the given origin is allowed.
    fn origin_allowed(&self, origin: &str) -> bool {
        for o in &self.cfg.allowed_origins {
            if o == "*" || o == origin {
                return true;
            }
        }
        false
    }

    /// Determine the value of Access-Control-Allow-Origin for the given
    /// request origin.
    fn allow_origin_value(&self, origin: &str) -> String {
        // Spec: when credentials are allowed, must echo origin, not "*".
        if self.cfg.allow_credentials {
            return origin.to_string();
        }
        // If wildcard is configured, return "*"; otherwise echo the origin.
        if self.cfg.allowed_origins.iter().any(|o| o == "*") {
            return "*".to_string();
        }
        origin.to_string()
    }

    /// Set CORS response headers on the given response writer.
    fn set_cors_headers(&self, resp: &http_types::ResponseWriter, origin: &str) {
        resp.set_header("Access-Control-Allow-Origin", &self.allow_origin_value(origin));
        resp.set_header(
            "Access-Control-Allow-Methods",
            &self.cfg.allowed_methods.join(", "),
        );
        resp.set_header(
            "Access-Control-Allow-Headers",
            &self.cfg.allowed_headers.join(", "),
        );
        if !self.cfg.expose_headers.is_empty() {
            resp.set_header(
                "Access-Control-Expose-Headers",
                &self.cfg.expose_headers.join(", "),
            );
        }
        resp.set_header("Access-Control-Max-Age", &self.cfg.max_age.to_string());
        if self.cfg.allow_credentials {
            resp.set_header("Access-Control-Allow-Credentials", "true");
        }
    }
}

impl manifest::Guest for Component {
    fn describe() -> manifest::PluginInfo {
        manifest::PluginInfo {
            name: "cors".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            modules: vec![manifest::ModuleDecl {
                id: "http.handlers.cors".to_string(),
                docs: Some("CORS middleware for caddy-wit".to_string()),
                caddyfile_order: Some(manifest::CaddyfileOrder {
                    position: manifest::DirectivePosition::Before,
                    relative_to: "respond".to_string(),
                }),
            }],
        }
    }
}

impl lifecycle::Guest for Component {
    type Instance = CorsInstance;
}

impl lifecycle::GuestInstance for CorsInstance {
    fn provision(module_id: String, config: String) -> Result<lifecycle::Instance, String> {
        if module_id != "http.handlers.cors" {
            return Err(format!("unknown module id: {module_id}"));
        }
        let parsed: CorsConfig = if config.trim().is_empty() {
            CorsConfig::default()
        } else {
            serde_json::from_str(&config).map_err(|e| format!("invalid config: {e}"))?
        };
        log::log(
            log::Level::Info,
            "cors provisioned",
            &[
                (
                    "allowed_origins".to_string(),
                    parsed.allowed_origins.join(","),
                ),
            ],
        );
        Ok(lifecycle::Instance::new(CorsInstance { cfg: parsed }))
    }

    fn validate(&self) -> Result<(), String> {
        Ok(())
    }

    fn cleanup(&self) {
        log::log(log::Level::Debug, "cors cleaned up", &[]);
    }
}

impl cfg::Guest for Component {
    fn unmarshal_caddyfile(_module_id: String, tokens: Vec<cfg::Token>) -> Result<String, String> {
        use caddy_wit_caddyfile::{Dispenser, Token};

        let toks = tokens.iter().map(|t| Token::new(&t.file, t.line, &t.text, t.quoted)).collect();
        let mut d = Dispenser::new(toks);
        d.next(); // directive name

        let mut obj = serde_json::Map::new();

        while d.next_block(0) {
            match d.val() {
                "allowed_origins" => {
                    let args = d.remaining_args();
                    if args.is_empty() { return Err(d.arg_err()); }
                    obj.insert("allowed_origins".into(), serde_json::json!(args));
                }
                "allowed_methods" => {
                    let args = d.remaining_args();
                    if args.is_empty() { return Err(d.arg_err()); }
                    obj.insert("allowed_methods".into(), serde_json::json!(args));
                }
                "allowed_headers" => {
                    let args = d.remaining_args();
                    if args.is_empty() { return Err(d.arg_err()); }
                    obj.insert("allowed_headers".into(), serde_json::json!(args));
                }
                "expose_headers" => {
                    let args = d.remaining_args();
                    if args.is_empty() { return Err(d.arg_err()); }
                    obj.insert("expose_headers".into(), serde_json::json!(args));
                }
                "max_age" => {
                    if !d.next_arg() { return Err(d.arg_err()); }
                    let v: u64 = d.val().parse().map_err(|e| d.errf(&format!("bad max_age: {e}")))?;
                    obj.insert("max_age".into(), serde_json::json!(v));
                }
                "allow_credentials" => {
                    if !d.next_arg() { return Err(d.arg_err()); }
                    let v: bool = d.val().parse().map_err(|e| d.errf(&format!("bad allow_credentials: {e}")))?;
                    obj.insert("allow_credentials".into(), serde_json::json!(v));
                }
                _ => return Err(d.errf(&format!("unrecognized subdirective '{}'", d.val()))),
            }
        }

        serde_json::to_string(&obj).map_err(|e| e.to_string())
    }
}

impl http_handler::Guest for Component {
    fn serve(
        inst: lifecycle::InstanceBorrow<'_>,
        req: &http_types::Request,
        resp: &http_types::ResponseWriter,
    ) -> Result<(), http_types::PluginError> {
        let this: &CorsInstance = inst.get();

        // Check for Origin header.
        let origin_vals = req.header("Origin");
        let origin = match origin_vals.first() {
            Some(o) if !o.is_empty() => o.clone(),
            _ => {
                // No Origin header: pass through unchanged.
                return http_types::next(req, resp);
            }
        };

        // Check if origin is allowed.
        if !this.origin_allowed(&origin) {
            // Origin not allowed: pass through without CORS headers.
            return http_types::next(req, resp);
        }

        // Preflight detection: OPTIONS + Origin + Access-Control-Request-Method.
        let is_preflight = req.method() == "OPTIONS"
            && !req.header("Access-Control-Request-Method").is_empty();

        if is_preflight {
            // Respond immediately with 204 + CORS headers.
            this.set_cors_headers(resp, &origin);
            resp.write_status(204);
            return Ok(());
        }

        // Simple/actual request: set CORS headers BEFORE calling next,
        // because next() writes to the response writer and headers must
        // be set before write-status/write.
        this.set_cors_headers(resp, &origin);
        http_types::next(req, resp)
    }
}

export!(Component);
