// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use super::*;

#[test]
fn parses_and_validates_service_config() -> Result<(), Box<dyn std::error::Error>> {
    let config: NodeServiceConfig = toml::from_str(
        r#"
node_id = "localhost"
service_id = "ramflux-gateway"
redb_path = "/var/lib/ramflux/gateway/gateway.redb"

[mesh]
listen_addr = "0.0.0.0:7443"
ca_cert = "/etc/ramflux/mesh/ca.pem"
service_cert = "/etc/ramflux/mesh/gateway.pem"
service_key = "/etc/ramflux/mesh/gateway-key.pem"
allowed_service_ids = ["ramflux-gateway"]

[mesh.endpoints]
gateway = "ramflux-gateway:7443"
"#,
    )?;
    validate_config(&config, "ramflux-gateway")?;
    assert_eq!(config.mesh.endpoints.get("gateway"), Some(&"ramflux-gateway:7443".to_owned()));
    Ok(())
}

#[test]
fn rejects_wrong_service_id() -> Result<(), Box<dyn std::error::Error>> {
    let config: NodeServiceConfig = toml::from_str(
        r#"
node_id = "localhost"
service_id = "ramflux-router"
redb_path = "/var/lib/ramflux/router/router.redb"

[mesh]
listen_addr = "0.0.0.0:7443"
ca_cert = "/etc/ramflux/mesh/ca.pem"
service_cert = "/etc/ramflux/mesh/router.pem"
service_key = "/etc/ramflux/mesh/router-key.pem"
allowed_service_ids = ["ramflux-router"]

[mesh.endpoints]
router = "ramflux-router:7443"
"#,
    )?;
    assert!(validate_config(&config, "ramflux-gateway").is_err());
    Ok(())
}

#[test]
fn effective_redb_path_can_use_state_root_override() -> Result<(), Box<dyn std::error::Error>> {
    let config: NodeServiceConfig = toml::from_str(
        r#"
node_id = "localhost"
service_id = "ramflux-router"
redb_path = "/var/lib/ramflux/router/router.redb"

[mesh]
listen_addr = "0.0.0.0:7443"
ca_cert = "/etc/ramflux/mesh/ca.pem"
service_cert = "/etc/ramflux/mesh/router.pem"
service_key = "/etc/ramflux/mesh/router-key.pem"
allowed_service_ids = ["ramflux-router"]

[mesh.endpoints]
router = "ramflux-router:7443"
"#,
    )?;
    let root = temp_store_path("effective_redb_path_can_use_state_root_override")?;
    let path =
        effective_redb_path_with_state_root(&config, Some(root.to_string_lossy().into_owned()));
    assert_eq!(path, root.join("ramflux-router.redb"));
    Ok(())
}

#[test]
fn node_id_override_replaces_localhost_config_value() -> Result<(), Box<dyn std::error::Error>> {
    let mut config: NodeServiceConfig = toml::from_str(
        r#"
node_id = "localhost"
service_id = "ramflux-federation"
redb_path = "/var/lib/ramflux/federation/federation.redb"

[mesh]
listen_addr = "0.0.0.0:7443"
ca_cert = "/etc/ramflux/mesh/ca.pem"
service_cert = "/etc/ramflux/mesh/federation.pem"
service_key = "/etc/ramflux/mesh/federation-key.pem"
allowed_service_ids = ["ramflux-federation"]

[mesh.endpoints]
federation = "ramflux-federation:7443"
"#,
    )?;
    apply_node_id_override(&mut config, Some("node_b.realnet"));
    validate_config(&config, "ramflux-federation")?;
    assert_eq!(config.node_id, "node_b.realnet");
    Ok(())
}
