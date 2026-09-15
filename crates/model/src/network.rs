use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const MAX_NETWORK_ITEMS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct IpPrefix {
    pub address: IpAddr,
    pub prefix: u8,
}
impl IpPrefix {
    pub fn validate(&self) -> Result<()> {
        if self.prefix > if self.address.is_ipv4() { 32 } else { 128 } {
            return Err(Error::invalid(
                "IP prefix length is outside address family bounds",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InterfaceIdentity {
    pub name: String,
    pub index: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub interface: InterfaceIdentity,
    pub mtu: u16,
    pub addresses: Vec<IpPrefix>,
    /// Legacy negotiated interface subnet; it does not select split-tunnel mode.
    #[serde(default)]
    pub ipv4_subnet: Option<IpPrefix>,
    pub dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub split_dns: Vec<String>,
    #[serde(default)]
    pub full_tunnel_ipv4: bool,
    #[serde(default)]
    pub full_tunnel_ipv6: bool,
    pub split_includes: Vec<IpPrefix>,
    pub split_excludes: Vec<IpPrefix>,
    pub transport_peer: IpAddr,
}
impl NetworkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.interface.index == 0
            || self.interface.name.is_empty()
            || self.interface.name.len() > 256
            || self
                .interface
                .name
                .chars()
                .any(|c| c.is_control() || c == '/' || c == '\\')
        {
            return Err(Error::invalid("Invalid tunnel interface identity"));
        }
        if self.addresses.is_empty()
            || self.addresses.len() > MAX_NETWORK_ITEMS
            || self.dns_servers.len() > MAX_NETWORK_ITEMS
            || self.search_domains.len() > MAX_NETWORK_ITEMS
            || self.split_dns.len() > MAX_NETWORK_ITEMS
            || self.split_includes.len() > MAX_NETWORK_ITEMS
            || self.split_excludes.len() > MAX_NETWORK_ITEMS
        {
            return Err(Error::invalid(
                "Network configuration has missing addresses or too many entries",
            ));
        }
        let ipv6 = self.addresses.iter().any(|a| a.address.is_ipv6());
        if !(if ipv6 { 1280 } else { 576 }..=9000).contains(&self.mtu) {
            return Err(Error::invalid("Invalid negotiated MTU"));
        }
        if (self.full_tunnel_ipv4 && !self.addresses.iter().any(|a| a.address.is_ipv4()))
            || (self.full_tunnel_ipv6 && !ipv6)
        {
            return Err(Error::invalid(
                "Full tunnel requires a negotiated address in that family",
            ));
        }
        for address in self
            .addresses
            .iter()
            .chain(&self.split_includes)
            .chain(&self.split_excludes)
        {
            address.validate()?;
        }
        if let Some(subnet) = &self.ipv4_subnet {
            subnet.validate()?;
            let IpAddr::V4(address) = subnet.address else {
                return Err(Error::invalid("IPv4 subnet has wrong address family"));
            };
            let mask = if subnet.prefix == 0 {
                0
            } else {
                u32::MAX << (32 - subnet.prefix)
            };
            if u32::from(address) & !mask != 0 {
                return Err(Error::invalid("IPv4 subnet is not a network address"));
            }
            if !self.addresses.iter().any(|value| matches!(value.address, IpAddr::V4(ip) if u32::from(ip) & mask == u32::from(address))) {
                return Err(Error::invalid("IPv4 subnet does not contain the tunnel address"));
            }
        }
        for domain in self.search_domains.iter().chain(&self.split_dns) {
            validate_domain(domain)?;
        }
        if std::iter::once(&self.transport_peer)
            .chain(&self.dns_servers)
            .chain(self.addresses.iter().map(|address| &address.address))
            .any(|ip| {
                ip.is_unspecified()
                    || ip.is_multicast()
                    || matches!(ip,IpAddr::V4(address) if address.is_broadcast())
            })
        {
            return Err(Error::invalid(
                "Tunnel, transport peer and DNS addresses must be unicast",
            ));
        }
        if self
            .addresses
            .iter()
            .any(|address| address.address == self.transport_peer)
        {
            return Err(Error::invalid(
                "Tunnel address cannot equal its transport peer",
            ));
        }
        Ok(())
    }
}

pub fn validate_domain(domain: &str) -> Result<()> {
    let value = domain.strip_suffix('.').unwrap_or(domain);
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
    {
        return Err(Error::invalid(
            "Invalid DNS domain; use ASCII or IDNA A-label form",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkReason {
    PreInit,
    Connect,
    Reconnect,
    AttemptReconnect,
    Disconnect,
}
