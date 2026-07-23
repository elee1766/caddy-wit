# dns-digitalocean

DigitalOcean DNS provider plugin for caddy-wit.

Implements the [DigitalOcean DNS API](https://docs.digitalocean.com/reference/api/api-reference/#tag/Domain-Records)
directly in Rust using the WIT `host-http` import — no libdns/godo dependency.

## Build

```sh
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/caddy_wit_dns_digitalocean.wasm plugin.wasm
```

## Caddyfile

```
digitalocean <auth_token>
```

or block syntax:

```
digitalocean {
    auth_token <tok>
}
```
