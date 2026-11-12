// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Web listener configuration. Unset `RAMFLUX_GATEWAY_WEB_LISTEN` means no web listener.

use ramflux_protocol::custody::{
    MAX_WEB_LISTENER_ORIGINS, is_canonical_web_listener_url, is_canonical_web_origin,
    web_listener_authority,
};
use std::net::SocketAddr;
use std::path::PathBuf;

pub(crate) const LISTEN_ENV: &str = "RAMFLUX_GATEWAY_WEB_LISTEN";
pub(crate) const TLS_CERT_ENV: &str = "RAMFLUX_GATEWAY_WEB_TLS_CERT";
pub(crate) const TLS_KEY_ENV: &str = "RAMFLUX_GATEWAY_WEB_TLS_KEY";
pub(crate) const URL_ENV: &str = "RAMFLUX_GATEWAY_WEB_URL";
pub(crate) const ORIGINS_ENV: &str = "RAMFLUX_GATEWAY_WEB_ORIGINS";
pub(crate) const DEV_ORIGINS_ENV: &str = "RAMFLUX_GATEWAY_WEB_DEV_ORIGINS";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WebIngressConfig {
    pub(crate) listen: SocketAddr,
    pub(crate) tls_cert: PathBuf,
    pub(crate) tls_key: PathBuf,
    /// The exact canonical string clients dial; signed inside every binding context.
    pub(crate) listener_url: String,
    /// `host[:port]` of `listener_url`, compared with the `Host` header.
    pub(crate) authority: String,
    /// Exact serialized origins, sorted and unique.
    pub(crate) origins: Vec<String>,
    pub(crate) dev_origins: bool,
}

/// Raw settings, so parsing is testable without touching the process environment.
#[derive(Clone, Debug, Default)]
pub(crate) struct RawSettings {
    pub(crate) listen: Option<String>,
    pub(crate) tls_cert: Option<String>,
    pub(crate) tls_key: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) origins: Option<String>,
    pub(crate) dev_origins: Option<String>,
}

fn setting(name: &str) -> Option<String> {
    ramflux_node_core::environment::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

impl RawSettings {
    pub(crate) fn from_env() -> Self {
        Self {
            listen: setting(LISTEN_ENV),
            tls_cert: setting(TLS_CERT_ENV),
            tls_key: setting(TLS_KEY_ENV),
            url: setting(URL_ENV),
            origins: setting(ORIGINS_ENV),
            dev_origins: setting(DEV_ORIGINS_ENV),
        }
    }
}

impl WebIngressConfig {
    /// `Ok(None)` when the listener is switched off (the default).
    ///
    /// # Errors
    /// Refuses a partial or unsafe configuration: a wildcard, `null`, non-`https` or
    /// duplicate origin, an empty or oversized origin list, or a non-canonical URL.
    pub(crate) fn parse(raw: &RawSettings) -> anyhow::Result<Option<Self>> {
        let Some(listen) = raw.listen.as_deref() else {
            return Ok(None);
        };
        let listen: SocketAddr =
            listen.parse().map_err(|_| anyhow::anyhow!("{LISTEN_ENV} must be a socket address"))?;
        let required = |value: &Option<String>, name: &str| {
            value.clone().ok_or_else(|| anyhow::anyhow!("{name} is required with {LISTEN_ENV}"))
        };
        let tls_cert = PathBuf::from(required(&raw.tls_cert, TLS_CERT_ENV)?);
        let tls_key = PathBuf::from(required(&raw.tls_key, TLS_KEY_ENV)?);
        let listener_url = required(&raw.url, URL_ENV)?;
        if !is_canonical_web_listener_url(&listener_url) {
            anyhow::bail!("{URL_ENV} must be the canonical wss://<authority>/v1/session string");
        }
        let authority = web_listener_authority(&listener_url)
            .ok_or_else(|| anyhow::anyhow!("{URL_ENV} has no authority"))?
            .to_owned();
        let dev_origins = match raw.dev_origins.as_deref() {
            None | Some("0") => false,
            Some("1") => true,
            Some(_) => anyhow::bail!("{DEV_ORIGINS_ENV} must be 0 or 1"),
        };
        let mut origins: Vec<String> = required(&raw.origins, ORIGINS_ENV)?
            .split(',')
            .map(|origin| origin.trim().to_owned())
            .collect();
        if origins.is_empty() || origins.len() > MAX_WEB_LISTENER_ORIGINS {
            anyhow::bail!("{ORIGINS_ENV} must list 1 to {MAX_WEB_LISTENER_ORIGINS} origins");
        }
        if let Some(origin) =
            origins.iter().find(|origin| !is_canonical_web_origin(origin, dev_origins))
        {
            // `*`, `null`, `http:` outside the development switch, paths and trailing
            // slashes all land here.
            anyhow::bail!("{ORIGINS_ENV} entry is not an exact https origin: {origin:?}");
        }
        origins.sort();
        if origins.windows(2).any(|pair| pair[0] == pair[1]) {
            anyhow::bail!("{ORIGINS_ENV} lists an origin twice");
        }
        Ok(Some(Self { listen, tls_cert, tls_key, listener_url, authority, origins, dev_origins }))
    }

    /// Exact byte comparison against the allow-list: no case folding, suffix or wildcard.
    #[must_use]
    pub(crate) fn origin_allowed(&self, origin: &str) -> bool {
        self.origins.iter().any(|allowed| allowed == origin)
    }

    /// `Host` equals the configured authority; host case-insensitive, default port optional.
    #[must_use]
    pub(crate) fn host_matches(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix(":443").unwrap_or(&host);
        host == self.authority
    }
}

#[cfg(test)]
mod tests {
    use super::{RawSettings, WebIngressConfig};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn raw(origins: &str) -> RawSettings {
        RawSettings {
            listen: Some("127.0.0.1:8443".to_owned()),
            tls_cert: Some("/run/web/cert.pem".to_owned()),
            tls_key: Some("/run/web/key.pem".to_owned()),
            url: Some("wss://gw.example.org/v1/session".to_owned()),
            origins: Some(origins.to_owned()),
            dev_origins: None,
        }
    }

    #[test]
    fn web_listener_is_off_unless_the_listen_address_is_set() -> TestResult {
        assert_eq!(WebIngressConfig::parse(&RawSettings::default())?, None);
        let mut partial = raw("https://app.example.org");
        partial.listen = None;
        assert_eq!(WebIngressConfig::parse(&partial)?, None);
        Ok(())
    }

    #[test]
    fn accepts_exact_https_origins_and_sorts_them() -> TestResult {
        let config = WebIngressConfig::parse(&raw("https://b.example.org, https://a.example.org"))?
            .ok_or("listener must be configured")?;
        assert_eq!(config.origins, ["https://a.example.org", "https://b.example.org"]);
        assert_eq!(config.authority, "gw.example.org");
        assert!(config.origin_allowed("https://a.example.org"));
        Ok(())
    }

    #[test]
    fn refuses_wildcard_null_http_empty_and_decorated_origins() {
        for origins in [
            "*",
            "null",
            "http://app.example.org",
            "https://app.example.org/",
            "https://app.example.org/path",
            "https://app.example.org:443",
            "https://APP.example.org",
            "https://*.example.org",
            "https://a.example.org,https://a.example.org",
            "http://localhost:5173",
            ",",
        ] {
            assert!(WebIngressConfig::parse(&raw(origins)).is_err(), "{origins}");
        }
        let mut missing = raw("https://app.example.org");
        missing.origins = None;
        assert!(WebIngressConfig::parse(&missing).is_err());
    }

    #[test]
    fn loopback_http_origin_needs_the_development_switch() -> TestResult {
        let mut dev = raw("http://localhost:5173");
        dev.dev_origins = Some("1".to_owned());
        assert!(WebIngressConfig::parse(&dev)?.is_some());
        let mut remote = raw("http://app.example.org");
        remote.dev_origins = Some("1".to_owned());
        assert!(WebIngressConfig::parse(&remote).is_err());
        Ok(())
    }

    #[test]
    fn refuses_a_non_canonical_listener_url_or_a_partial_configuration() {
        for url in [
            "wss://gw.example.org/v1/session/",
            "wss://gw.example.org:443/v1/session",
            "wss://GW.example.org/v1/session",
            "ws://gw.example.org/v1/session",
            "wss://user@gw.example.org/v1/session",
            "wss://gw.example.org/v1/session?x=1",
            "wss://gw.example.org/other",
        ] {
            let mut settings = raw("https://app.example.org");
            settings.url = Some(url.to_owned());
            assert!(WebIngressConfig::parse(&settings).is_err(), "{url}");
        }
        let mut no_key = raw("https://app.example.org");
        no_key.tls_key = None;
        assert!(WebIngressConfig::parse(&no_key).is_err());
    }

    #[test]
    fn origin_match_is_exact_and_host_match_normalises_only_case_and_default_port() -> TestResult {
        let config = WebIngressConfig::parse(&raw("https://app.example.org"))?
            .ok_or("listener must be configured")?;
        for foreign in [
            "https://app.example.org.evil.test",
            "https://evil.app.example.org",
            "https://APP.example.org",
            "https://app.example.org/",
            "null",
            "",
        ] {
            assert!(!config.origin_allowed(foreign), "{foreign}");
        }
        assert!(config.host_matches("gw.example.org"));
        assert!(config.host_matches("GW.Example.org:443"));
        assert!(!config.host_matches("gw.example.org:8443"));
        assert!(!config.host_matches("other.example.org"));
        Ok(())
    }
}
