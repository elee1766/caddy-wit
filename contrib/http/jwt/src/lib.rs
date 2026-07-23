//! JWT validation middleware for caddy-wit.
//!
//! Registers `http.handlers.jwt`. Validates HS256 JWTs and passes decoded
//! claims to downstream handlers via request variables and headers.
//!
//! Config: {"secret": "...", "algorithm": "HS256", "header_name": "Authorization",
//!          "header_prefix": "Bearer ", "claims_var": "jwt_claims",
//!          "reject_status": 401}
//!
//! Limitations (v1):
//! - Only HS256 is supported.
//! - `exp` claim is NOT validated (no clock import available in the WIT
//!   interface). Signature verification is the sole gate.
//! - `set-var` stores claims for downstream, but host wiring for get-var
//!   may not be complete in all environments.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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

const MODULE_ID: &str = "http.handlers.jwt";

#[derive(Deserialize)]
struct JwtConfig {
    #[serde(default)]
    secret: String,
    #[serde(default = "default_algorithm")]
    algorithm: String,
    #[serde(default = "default_header_name")]
    header_name: String,
    #[serde(default = "default_header_prefix")]
    header_prefix: String,
    #[serde(default = "default_claims_var")]
    claims_var: String,
    #[serde(default = "default_reject_status")]
    reject_status: u16,
}

fn default_algorithm() -> String { "HS256".to_string() }
fn default_header_name() -> String { "Authorization".to_string() }
fn default_header_prefix() -> String { "Bearer ".to_string() }
fn default_claims_var() -> String { "jwt_claims".to_string() }
fn default_reject_status() -> u16 { 401 }

struct JwtInstance {
    /// Raw secret bytes (decoded from base64 if the config value is valid
    /// base64, otherwise used as raw UTF-8 bytes).
    secret: Vec<u8>,
    algorithm: String,
    header_name: String,
    header_prefix: String,
    claims_var: String,
    reject_status: u16,
}

impl manifest::Guest for Component {
    fn describe() -> manifest::PluginInfo {
        manifest::PluginInfo {
            name: "jwt".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            modules: vec![manifest::ModuleDecl {
                id: MODULE_ID.to_string(),
                docs: Some("JWT (HS256) validation middleware".to_string()),
                caddyfile_order: Some(manifest::CaddyfileOrder {
                    position: manifest::DirectivePosition::Before,
                    relative_to: "respond".to_string(),
                }),
            }],
        }
    }
}

impl lifecycle::Guest for Component {
    type Instance = JwtInstance;
}

impl lifecycle::GuestInstance for JwtInstance {
    fn provision(module_id: String, config: String) -> Result<lifecycle::Instance, String> {
        if module_id != MODULE_ID {
            return Err(format!("unknown module id: {module_id}"));
        }
        let parsed: JwtConfig = if config.trim().is_empty() {
            return Err("secret is required".to_string());
        } else {
            serde_json::from_str(&config).map_err(|e| format!("invalid config: {e}"))?
        };

        if parsed.secret.is_empty() {
            return Err("secret must not be empty".to_string());
        }

        // Use the secret as raw UTF-8 bytes, matching Go behavior.
        let secret = parsed.secret.into_bytes();

        log::log(
            log::Level::Info,
            "jwt provisioned",
            &[("algorithm".into(), parsed.algorithm.clone())],
        );

        Ok(lifecycle::Instance::new(JwtInstance {
            secret,
            algorithm: parsed.algorithm,
            header_name: parsed.header_name,
            header_prefix: parsed.header_prefix,
            claims_var: parsed.claims_var,
            reject_status: parsed.reject_status,
        }))
    }

    fn validate(&self) -> Result<(), String> {
        if self.algorithm != "HS256" {
            return Err(format!(
                "unsupported algorithm {:?}; only HS256 is supported in v1",
                self.algorithm
            ));
        }
        if self.secret.is_empty() {
            return Err("secret must not be empty".to_string());
        }
        Ok(())
    }

    fn cleanup(&self) {
        log::log(log::Level::Debug, "jwt cleaned up", &[]);
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

        if d.next_arg() {
            // Inline form: jwt <secret>
            obj.insert("secret".into(), serde_json::json!(d.val()));
        } else {
            // Block form
            while d.next_block(0) {
                match d.val() {
                    "secret" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        obj.insert("secret".into(), serde_json::json!(d.val()));
                    }
                    "algorithm" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        obj.insert("algorithm".into(), serde_json::json!(d.val()));
                    }
                    "header_name" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        obj.insert("header_name".into(), serde_json::json!(d.val()));
                    }
                    "header_prefix" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        obj.insert("header_prefix".into(), serde_json::json!(d.val()));
                    }
                    "claims_var" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        obj.insert("claims_var".into(), serde_json::json!(d.val()));
                    }
                    "reject_status" => {
                        if !d.next_arg() { return Err(d.arg_err()); }
                        let v: u16 = d.val().parse().map_err(|e| d.errf(&format!("bad reject_status: {e}")))?;
                        obj.insert("reject_status".into(), serde_json::json!(v));
                    }
                    _ => return Err(d.errf(&format!("unrecognized subdirective '{}'", d.val()))),
                }
            }
        }

        if !obj.contains_key("secret") {
            return Err("jwt directive requires a secret".to_string());
        }

        serde_json::to_string(&obj).map_err(|e| e.to_string())
    }
}

/// Reject helper — returns a PluginError with the configured status.
fn reject(status: u16, message: &str) -> http_types::PluginError {
    http_types::PluginError {
        status: Some(status),
        message: message.to_string(),
    }
}

/// Base64url-decode (no padding).
fn b64url_decode(input: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| format!("base64url decode error: {e}"))
}

/// Verify an HS256 JWT. Returns the raw payload JSON bytes on success.
fn verify_hs256(token: &str, secret: &[u8]) -> Result<Vec<u8>, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed token: expected 3 parts".to_string());
    }

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let sig_b64 = parts[2];

    // Decode signature.
    let signature = b64url_decode(sig_b64)?;

    // Verify HMAC-SHA256 over "header.payload".
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| format!("hmac init error: {e}"))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| "invalid signature".to_string())?;

    // Decode payload.
    let payload = b64url_decode(payload_b64)?;

    // TODO(v1): exp claim is NOT validated — no clock import in the WIT
    // interface. Signature is the sole validation gate.

    Ok(payload)
}

impl http_handler::Guest for Component {
    fn serve(
        inst: lifecycle::InstanceBorrow<'_>,
        req: &http_types::Request,
        resp: &http_types::ResponseWriter,
    ) -> Result<(), http_types::PluginError> {
        let this: &JwtInstance = inst.get();

        // Extract token from the configured header.
        let header_values = req.header(&this.header_name);
        let header_value = header_values
            .first()
            .ok_or_else(|| reject(this.reject_status, "missing or malformed token"))?;

        let token = if !this.header_prefix.is_empty() {
            header_value
                .strip_prefix(&this.header_prefix)
                .ok_or_else(|| reject(this.reject_status, "missing or malformed token"))?
        } else {
            header_value.as_str()
        };

        if token.is_empty() {
            return Err(reject(this.reject_status, "missing or malformed token"));
        }

        // Verify signature.
        let payload = verify_hs256(token, &this.secret).map_err(|msg| {
            log::log(log::Level::Debug, &msg, &[]);
            reject(this.reject_status, &msg)
        })?;

        // Convert payload bytes to a JSON string for downstream.
        let payload_str = String::from_utf8(payload)
            .map_err(|_| reject(this.reject_status, "invalid token payload encoding"))?;

        // Store claims in a request variable for downstream handlers.
        // NOTE: host wiring for get-var/set-var may not be complete in all
        // test environments.
        req.set_var(&this.claims_var, &payload_str);

        resp.set_header("X-JWT-Valid", "true");

        http_types::next(req, resp)
    }
}

export!(Component);
