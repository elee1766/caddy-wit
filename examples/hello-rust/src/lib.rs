//! Reference caddy-wit plugin: a tiny HTTP middleware with custom Caddyfile
//! syntax, written against the caddy:plugin WIT package.
//!
//! Registers `http.handlers.wit_hello`. Config: {"message": "..."}.
//! Caddyfile:  wit_hello <message>
//!
//! Behavior: adds an X-Wit-Hello header; requests to /hello are answered
//! directly with the configured message; everything else continues down the
//! middleware chain.

use serde::Deserialize;

wit_bindgen::generate!({
    path: "../../wit",
    world: "http-handler-plugin",
});

use caddy::plugin::http_types;
use caddy::plugin::log;
use exports::caddy::plugin::config as cfg;
use exports::caddy::plugin::http_handler;
use exports::caddy::plugin::lifecycle;
use exports::caddy::plugin::manifest;

struct Component;

#[derive(Deserialize, Default)]
struct HelloConfig {
    #[serde(default)]
    message: String,
}

struct HelloInstance {
    message: String,
}

impl manifest::Guest for Component {
    fn describe() -> manifest::PluginInfo {
        manifest::PluginInfo {
            name: "hello-rust".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            modules: vec![manifest::ModuleDecl {
                id: "http.handlers.wit_hello".to_string(),
                docs: Some("Hello-world middleware demonstrating caddy-wit".to_string()),
                // Order the directive before `respond` so it runs even when
                // a terminal standard directive follows it in the site block
                // (no `order` global needed).
                caddyfile_order: Some(manifest::CaddyfileOrder {
                    position: manifest::DirectivePosition::Before,
                    relative_to: "respond".to_string(),
                }),
            }],
        }
    }
}

impl lifecycle::Guest for Component {
    type Instance = HelloInstance;
}

impl lifecycle::GuestInstance for HelloInstance {
    fn provision(module_id: String, config: String) -> Result<lifecycle::Instance, String> {
        if module_id != "http.handlers.wit_hello" {
            return Err(format!("unknown module id: {module_id}"));
        }
        let parsed: HelloConfig = if config.trim().is_empty() {
            HelloConfig::default()
        } else {
            serde_json::from_str(&config).map_err(|e| format!("invalid config: {e}"))?
        };
        let message = if parsed.message.is_empty() {
            "hello from wasm".to_string()
        } else {
            parsed.message
        };
        log::log(
            log::Level::Info,
            "wit_hello provisioned",
            &[("message".to_string(), message.clone())],
        );
        Ok(lifecycle::Instance::new(HelloInstance { message }))
    }

    fn validate(&self) -> Result<(), String> {
        if self.message.is_empty() {
            return Err("message must not be empty".to_string());
        }
        Ok(())
    }

    fn cleanup(&self) {
        log::log(log::Level::Debug, "wit_hello cleaned up", &[]);
    }
}

impl cfg::Guest for Component {
    fn unmarshal_caddyfile(module_id: String, tokens: Vec<cfg::Token>) -> Result<String, String> {
        if module_id != "http.handlers.wit_hello" {
            return Err(format!("unknown module id: {module_id}"));
        }
        // Expected: wit_hello <message...>
        let args: Vec<&str> = tokens.iter().skip(1).map(|t| t.text.as_str()).collect();
        let message = args.join(" ");
        serde_json::to_string(&serde_json::json!({ "message": message }))
            .map_err(|e| e.to_string())
    }
}

impl http_handler::Guest for Component {
    fn serve(
        inst: lifecycle::InstanceBorrow<'_>,
        req: &http_types::Request,
        resp: &http_types::ResponseWriter,
    ) -> Result<(), http_types::PluginError> {
        let this: &HelloInstance = inst.get();

        resp.set_header("X-Wit-Hello", "1");

        if req.path() == "/hello" {
            resp.set_header("Content-Type", "text/plain; charset=utf-8");
            resp.write_status(200);
            resp.write(this.message.as_bytes())
                .map_err(|e| http_types::PluginError {
                    message: e,
                    status: None,
                })?;
            return Ok(());
        }

        // Demonstrate request mutation visible to downstream handlers.
        req.set_header("X-Wit-Saw", req.method().as_str());

        http_types::next(req, resp)
    }
}

export!(Component);
