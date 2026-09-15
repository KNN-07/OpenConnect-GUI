//! Validated, privileged and journaled network lifecycle boundary.
//! Field semantics follow OpenConnect 9.21 script.c::prepare_script_env and
//! vpnc-scripts ce9e961bd0f6b867e1c7c35f78f6fb973f6ff101.
pub mod interface;
pub(crate) mod journal;
pub mod monitor;
mod routes;
mod secure;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionId {
    pub service_instance_id: uuid::Uuid,
    pub attempt_id: uuid::Uuid,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleReport {
    pub transaction: TransactionId,
    pub reason: ocvpn_model::NetworkReason,
    pub result: ocvpn_model::Result<Option<ocvpn_model::NetworkObservation>>,
}

pub fn recover(transaction: TransactionId) -> ocvpn_model::Result<Vec<ocvpn_model::Error>> {
    journal::recover(transaction)
}
pub fn recover_all() -> ocvpn_model::Result<Vec<ocvpn_model::Error>> {
    journal::recover_all()
}

fn failure(message: &str) -> ocvpn_model::Error {
    ocvpn_model::Error::new(ocvpn_model::ErrorCode::NetworkFailure, message)
}

use ocvpn_model::{Error, IpPrefix, MAX_NETWORK_ITEMS, NetworkConfig, NetworkReason, Result};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
const MAX_ENV_ENTRIES: usize = 4096;
const MAX_VALUE_BYTES: usize = 65536;

/// Connect and reconnect require complete negotiated input. Pre-init and
/// attempt-reconnect are observation-only. Disconnect restores the durable
/// transaction, so interface deletion cannot prevent cleanup.
#[derive(Debug)]
pub struct LifecycleInput {
    pub reason: NetworkReason,
    pub config: Option<NetworkConfig>,
}

/// Parses a bounded snapshot, not the mutable process environment. Unrelated
/// inherited variables are ignored, never forwarded to a child or shell.
/// VPNGATEWAY must be the actual numeric transport peer supplied by OpenConnect.
pub fn parse_environment<'a>(
    input: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<LifecycleInput> {
    let mut fields = BTreeMap::new();
    let mut bytes = 0usize;
    for (n, (key, value)) in input.into_iter().enumerate() {
        bytes = bytes
            .checked_add(key.len())
            .and_then(|v| v.checked_add(value.len()))
            .ok_or_else(|| Error::invalid("Network environment exceeds limits"))?;
        if n >= MAX_ENV_ENTRIES
            || bytes > MAX_INPUT_BYTES
            || key.len() > 256
            || value.len() > MAX_VALUE_BYTES
        {
            return Err(Error::invalid("Network environment exceeds limits"));
        }
        if recognized(key) {
            if value.contains('\0') || fields.insert(key, value).is_some() {
                return Err(Error::invalid(
                    "Invalid or duplicate network environment field",
                ));
            }
        }
    }
    let mut env = Fields(fields);
    let reason = match env.required("reason")? {
        "pre-init" => NetworkReason::PreInit,
        "connect" => NetworkReason::Connect,
        "reconnect" => NetworkReason::Reconnect,
        "attempt-reconnect" => NetworkReason::AttemptReconnect,
        "disconnect" => NetworkReason::Disconnect,
        _ => return Err(Error::invalid("Unsupported network lifecycle reason")),
    };
    if matches!(
        reason,
        NetworkReason::PreInit | NetworkReason::AttemptReconnect | NetworkReason::Disconnect
    ) {
        return Ok(LifecycleInput {
            reason,
            config: None,
        });
    }
    let name = env.required("TUNDEV")?;
    let mtu = number(env.required("INTERNAL_IP4_MTU")?)?;
    let transport_peer = number(env.required("VPNGATEWAY")?)?;
    let mut addresses = Vec::new();
    let v4 = env.take("INTERNAL_IP4_ADDRESS");
    let mask = env.take("INTERNAL_IP4_NETMASK");
    let len = env.take("INTERNAL_IP4_NETMASKLEN");
    let net = env.take("INTERNAL_IP4_NETADDR");
    let mut split_includes = Vec::new();
    let mut ipv4_subnet = None;
    if let Some(address) = v4 {
        let address: Ipv4Addr = number(address)?;
        addresses.push(IpPrefix {
            address: address.into(),
            prefix: 32,
        });
        // vpnc-script configures IPv4 point-to-point /32, then adds the
        // negotiated legacy subnet as an interface route separately.
        if mask.is_some() || len.is_some() || net.is_some() {
            let prefix = ipv4_prefix(mask, len)?;
            let network = u32::from(address) & mask_bits(prefix);
            if let Some(net) = net {
                if u32::from(number::<Ipv4Addr>(net)?) != network {
                    return Err(Error::invalid("Inconsistent negotiated IPv4 network"));
                }
            }
            ipv4_subnet = Some(IpPrefix {
                address: Ipv4Addr::from(network).into(),
                prefix,
            });
        }
    } else if mask.is_some() || len.is_some() || net.is_some() {
        return Err(Error::invalid(
            "IPv4 subnet is missing its interface address",
        ));
    }
    let v6 = env.take("INTERNAL_IP6_ADDRESS");
    let v6_net = env.take("INTERNAL_IP6_NETMASK");
    if let Some(net) = v6_net {
        let (ip, prefix) = net
            .split_once('/')
            .ok_or_else(|| Error::invalid("IPv6 netmask must contain address and prefix"))?;
        let address = number::<std::net::Ipv6Addr>(ip)?;
        if let Some(v6) = v6 {
            if number::<std::net::Ipv6Addr>(v6)? != address {
                return Err(Error::invalid("Inconsistent negotiated IPv6 address"));
            }
        }
        addresses.push(IpPrefix {
            address: address.into(),
            prefix: number(prefix)?,
        });
    } else if let Some(ip) = v6 {
        addresses.push(IpPrefix {
            address: number::<std::net::Ipv6Addr>(ip)?.into(),
            prefix: 128,
        });
    }
    // Despite its name, OpenConnect exports both families in INTERNAL_IP4_DNS.
    let mut dns_servers = ip_list(env.take("INTERNAL_IP4_DNS"))?;
    dns_servers.extend(ip_list(env.take("INTERNAL_IP6_DNS"))?);
    let search_domains = domains(env.take("CISCO_DEF_DOMAIN"), false)?;
    let split_dns = domains(env.take("CISCO_SPLIT_DNS"), true)?;
    let full_tunnel_ipv4 =
        addresses.iter().any(|a| a.address.is_ipv4()) && !env.0.contains_key("CISCO_SPLIT_INC");
    let full_tunnel_ipv6 = addresses.iter().any(|a| a.address.is_ipv6())
        && !env.0.contains_key("CISCO_IPV6_SPLIT_INC");
    split_includes.extend(routes(&mut env, "CISCO_SPLIT_INC", false)?);
    split_includes.extend(routes(&mut env, "CISCO_IPV6_SPLIT_INC", true)?);
    let mut split_excludes = routes(&mut env, "CISCO_SPLIT_EXC", false)?;
    split_excludes.extend(routes(&mut env, "CISCO_IPV6_SPLIT_EXC", true)?);
    if env.take("INTERNAL_IP4_NBNS").is_some() || env.take("CISCO_PROXY_PAC").is_some() {
        return Err(Error::invalid(
            "Negotiated WINS or proxy PAC configuration is not supported",
        ));
    }
    if !env.0.is_empty() {
        return Err(Error::invalid(
            "Unexpected or unconsumed network configuration field",
        ));
    }
    let config = NetworkConfig {
        interface: interface::resolve(name)?,
        mtu,
        addresses,
        dns_servers,
        ipv4_subnet,
        full_tunnel_ipv4,
        full_tunnel_ipv6,
        search_domains,
        split_dns,
        split_includes,
        split_excludes,
        transport_peer,
    };
    config.validate()?;
    Ok(LifecycleInput {
        reason,
        config: Some(config),
    })
}

/// Validate JSON shape and negotiated values without querying or mutating the OS.
/// Native identity resolution is performed separately at lifecycle ingestion.
pub fn validate_json(input: &[u8]) -> Result<NetworkConfig> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(Error::invalid("Network JSON exceeds input limit"));
    }
    // Do not expose serde errors: they may include attacker-controlled values.
    let config: NetworkConfig = serde_json::from_slice(input)
        .map_err(|_| Error::invalid("Invalid network configuration JSON"))?;
    config.validate()?;
    Ok(config)
}

fn recognized(key: &str) -> bool {
    matches!(
        key,
        "reason"
            | "TUNDEV"
            | "VPNGATEWAY"
            | "INTERNAL_IP4_MTU"
            | "INTERNAL_IP4_ADDRESS"
            | "INTERNAL_IP4_NETMASK"
            | "INTERNAL_IP4_NETMASKLEN"
            | "INTERNAL_IP4_NETADDR"
            | "INTERNAL_IP6_ADDRESS"
            | "INTERNAL_IP6_NETMASK"
            | "INTERNAL_IP4_DNS"
            | "INTERNAL_IP6_DNS"
            | "CISCO_DEF_DOMAIN"
            | "CISCO_SPLIT_DNS"
            | "INTERNAL_IP4_NBNS"
            | "CISCO_PROXY_PAC"
    ) || [
        "CISCO_SPLIT_INC",
        "CISCO_SPLIT_EXC",
        "CISCO_IPV6_SPLIT_INC",
        "CISCO_IPV6_SPLIT_EXC",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
}

struct Fields<'a>(BTreeMap<&'a str, &'a str>);
impl<'a> Fields<'a> {
    fn take(&mut self, key: &str) -> Option<&'a str> {
        self.0.remove(key).filter(|v| !v.is_empty())
    }
    fn required(&mut self, key: &str) -> Result<&'a str> {
        self.take(key)
            .ok_or_else(|| Error::invalid("Missing required network configuration field"))
    }
}
fn number<T: FromStr>(value: &str) -> Result<T> {
    value
        .parse()
        .map_err(|_| Error::invalid("Invalid network address or numeric value"))
}
fn mask_bits(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}
fn ipv4_prefix(mask: Option<&str>, len: Option<&str>) -> Result<u8> {
    let from_mask = mask
        .map(|s| {
            let bits = u32::from(number::<Ipv4Addr>(s)?);
            let prefix = bits.leading_ones() as u8;
            if bits != mask_bits(prefix) {
                return Err(Error::invalid("Noncontiguous IPv4 netmask"));
            }
            Ok(prefix)
        })
        .transpose()?;
    let from_len = len.map(number::<u8>).transpose()?;
    let prefix = from_len
        .or(from_mask)
        .ok_or_else(|| Error::invalid("Missing IPv4 route prefix"))?;
    if prefix > 32 || from_mask.is_some_and(|m| m != prefix) {
        return Err(Error::invalid("Invalid or inconsistent IPv4 prefix"));
    }
    Ok(prefix)
}
fn ip_list(value: Option<&str>) -> Result<Vec<IpAddr>> {
    value
        .unwrap_or("")
        .split_ascii_whitespace()
        .enumerate()
        .map(|(i, value)| {
            if i >= MAX_NETWORK_ITEMS {
                return Err(Error::invalid("Too many DNS servers"));
            }
            number(value)
        })
        .collect()
}
fn domains(value: Option<&str>, comma: bool) -> Result<Vec<String>> {
    let mut domains = Vec::new();
    if let Some(value) = value {
        for domain in value.split(|c: char| c.is_ascii_whitespace() || (comma && c == ',')) {
            if domain.is_empty() {
                continue;
            }
            if domains.len() >= MAX_NETWORK_ITEMS {
                return Err(Error::invalid("Too many DNS domains"));
            }
            ocvpn_model::network::validate_domain(domain)?;
            domains.push(domain.to_owned());
        }
    }
    Ok(domains)
}
fn routes(env: &mut Fields<'_>, base: &str, ipv6: bool) -> Result<Vec<IpPrefix>> {
    let count = env
        .take(base)
        .map(number::<usize>)
        .transpose()?
        .unwrap_or(0);
    if count > MAX_NETWORK_ITEMS {
        return Err(Error::invalid("Too many split routes"));
    }
    let mut routes = Vec::with_capacity(count);
    for i in 0..count {
        let address: IpAddr = number(env.required(&format!("{base}_{i}_ADDR"))?)?;
        if address.is_ipv6() != ipv6 {
            return Err(Error::invalid("Split route has wrong address family"));
        }
        let len = env.take(&format!("{base}_{i}_MASKLEN"));
        let prefix = if ipv6 {
            number(len.ok_or_else(|| Error::invalid("Missing IPv6 route prefix"))?)?
        } else {
            ipv4_prefix(env.take(&format!("{base}_{i}_MASK")), len)?
        };
        // Port/protocol constrained routes cannot be represented as IP routes.
        for suffix in ["PROTOCOL", "SPORT", "DPORT"] {
            if let Some(value) = env.take(&format!("{base}_{i}_{suffix}")) {
                if number::<u16>(value)? != 0 {
                    return Err(Error::invalid(
                        "Port or protocol constrained split routes are unsupported",
                    ));
                }
            }
        }
        let route = IpPrefix { address, prefix };
        route.validate()?;
        routes.push(route);
    }
    Ok(routes)
}
