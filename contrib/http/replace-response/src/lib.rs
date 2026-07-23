//! Replace-response middleware plugin for caddy-wit
//! (http.handlers.replace_response).
//!
//! Uses `next-buffered` to capture the downstream response, applies string
//! replacements to the body if the Content-Type matches, and writes the
//! (possibly modified) response through the real response-writer.

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
struct Replacement {
    search: String,
    replace: String,
}

#[derive(Deserialize, Clone)]
struct ReplaceResponseConfig {
    #[serde(default)]
    replacements: Vec<Replacement>,
    #[serde(default = "default_content_types")]
    content_types: Vec<String>,
}

fn default_content_types() -> Vec<String> {
    vec![
        "text/html".to_string(),
        "text/plain".to_string(),
        "application/json".to_string(),
    ]
}

impl Default for ReplaceResponseConfig {
    fn default() -> Self {
        ReplaceResponseConfig {
            replacements: Vec::new(),
            content_types: default_content_types(),
        }
    }
}

struct ReplaceResponseInstance {
    cfg: ReplaceResponseConfig,
}

impl ReplaceResponseInstance {
    /// Check if a Content-Type header value matches any of the configured
    /// content types (prefix match, ignoring charset parameters).
    fn content_type_matches(&self, ct: &str) -> bool {
        // Extract the media type part before any ';' (e.g. "text/html" from
        // "text/html; charset=utf-8").
        let media_type = ct.split(';').next().unwrap_or("").trim();
        self.cfg
            .content_types
            .iter()
            .any(|allowed| media_type.starts_with(allowed.as_str()))
    }
}

impl manifest::Guest for Component {
    fn describe() -> manifest::PluginInfo {
        manifest::PluginInfo {
            name: "replace-response".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            modules: vec![manifest::ModuleDecl {
                id: "http.handlers.replace_response".to_string(),
                docs: Some(
                    "Response body string replacement middleware for caddy-wit".to_string(),
                ),
                caddyfile_order: Some(manifest::CaddyfileOrder {
                    position: manifest::DirectivePosition::Before,
                    relative_to: "respond".to_string(),
                }),
            }],
        }
    }
}

impl lifecycle::Guest for Component {
    type Instance = ReplaceResponseInstance;
}

impl lifecycle::GuestInstance for ReplaceResponseInstance {
    fn provision(module_id: String, config: String) -> Result<lifecycle::Instance, String> {
        if module_id != "http.handlers.replace_response" {
            return Err(format!("unknown module id: {module_id}"));
        }
        let parsed: ReplaceResponseConfig = if config.trim().is_empty() {
            ReplaceResponseConfig::default()
        } else {
            serde_json::from_str(&config).map_err(|e| format!("invalid config: {e}"))?
        };
        log::log(
            log::Level::Info,
            "replace_response provisioned",
            &[(
                "replacements".to_string(),
                parsed.replacements.len().to_string(),
            )],
        );
        Ok(lifecycle::Instance::new(ReplaceResponseInstance {
            cfg: parsed,
        }))
    }

    fn validate(&self) -> Result<(), String> {
        Ok(())
    }

    fn cleanup(&self) {
        log::log(log::Level::Debug, "replace_response cleaned up", &[]);
    }
}

impl cfg::Guest for Component {
    fn unmarshal_caddyfile(_module_id: String, tokens: Vec<cfg::Token>) -> Result<String, String> {
        use caddy_wit_caddyfile::{Dispenser, Token};

        let toks = tokens.iter().map(|t| Token::new(&t.file, t.line, &t.text, t.quoted)).collect();
        let mut d = Dispenser::new(toks);
        d.next(); // directive name

        let mut replacements = Vec::<serde_json::Value>::new();
        let mut content_types = Vec::<String>::new();

        while d.next_block(0) {
            match d.val() {
                "search" => {
                    if !d.next_arg() { return Err(d.arg_err()); }
                    let search = d.val().to_string();
                    // Expect "replace" subdirective on the same line or next token
                    let replace = if d.next_arg() {
                        d.val().to_string()
                    } else {
                        String::new()
                    };
                    replacements.push(serde_json::json!({
                        "search": search,
                        "replace": replace,
                    }));
                }
                "replace" => {
                    // standalone replace is a shorthand: search <s> replace <r>
                    if !d.next_arg() { return Err(d.arg_err()); }
                    let search = d.val().to_string();
                    if !d.next_arg() { return Err(d.arg_err()); }
                    let replace = d.val().to_string();
                    replacements.push(serde_json::json!({
                        "search": search,
                        "replace": replace,
                    }));
                }
                "content_type" => {
                    let args = d.remaining_args();
                    if args.is_empty() { return Err(d.arg_err()); }
                    content_types.extend(args);
                }
                _ => return Err(d.errf(&format!("unrecognized subdirective '{}'", d.val()))),
            }
        }

        let mut obj = serde_json::Map::new();
        if !replacements.is_empty() {
            obj.insert("replacements".into(), serde_json::json!(replacements));
        }
        if !content_types.is_empty() {
            obj.insert("content_types".into(), serde_json::json!(content_types));
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
        let this: &ReplaceResponseInstance = inst.get();

        // Use next-buffered to capture the downstream response.
        let buffered = http_types::next_buffered(req)?;

        let status = buffered.status();
        let headers = buffered.headers();
        let body = buffered.body();

        // Find Content-Type in the buffered response headers.
        let content_type = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Content-Type"))
            .map(|(_, v)| v.as_str())
            .unwrap_or("");

        let should_replace =
            !this.cfg.replacements.is_empty() && this.content_type_matches(content_type);

        let final_body = if should_replace {
            // Apply all replacements in order.
            let mut text = String::from_utf8_lossy(&body).into_owned();
            for r in &this.cfg.replacements {
                text = text.replace(&r.search, &r.replace);
            }
            text.into_bytes()
        } else {
            body
        };

        // Write headers from the buffered response to the real
        // response-writer, skipping Content-Length (we'll set our own).
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("Content-Length") {
                continue;
            }
            resp.set_header(k, v);
        }
        // Set correct Content-Length.
        resp.set_header("Content-Length", &final_body.len().to_string());

        resp.write_status(status);
        resp.write(&final_body).map_err(|e| http_types::PluginError {
            message: e,
            status: None,
        })?;

        Ok(())
    }
}

export!(Component);
