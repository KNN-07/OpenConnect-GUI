//! VPN traffic policy expressed without overwriting physical default routes.
//! Exclusions take precedence over includes regardless of prefix length. The
//! actual transport host is excluded before any platform mutates its routes.
use ocvpn_model::{Error, IpPrefix, NetworkConfig, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_POLICY_ROUTES: usize = 4096;
fn width(prefix: &IpPrefix) -> u8 {
    if prefix.address.is_ipv4() { 32 } else { 128 }
}
fn bits(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(address) => u32::from(address).into(),
        IpAddr::V6(address) => u128::from(address),
    }
}
fn normalize(prefix: &IpPrefix) -> IpPrefix {
    let host = width(prefix) - prefix.prefix;
    let network = if host == 128 {
        0
    } else {
        (bits(prefix.address) >> host) << host
    };
    IpPrefix {
        address: if prefix.address.is_ipv4() {
            Ipv4Addr::from(network as u32).into()
        } else {
            Ipv6Addr::from(network).into()
        },
        prefix: prefix.prefix,
    }
}
pub(crate) fn contains(outer: &IpPrefix, inner: &IpPrefix) -> bool {
    outer.address.is_ipv4() == inner.address.is_ipv4()
        && outer.prefix <= inner.prefix
        && normalize(&IpPrefix {
            address: inner.address,
            prefix: outer.prefix,
        })
        .address
            == outer.address
}
fn append(output: &mut Vec<IpPrefix>, prefix: IpPrefix) -> Result<()> {
    if output.len() >= MAX_POLICY_ROUTES {
        return Err(Error::invalid(
            "VPN route policy exceeds the bounded native route expansion",
        ));
    }
    output.push(prefix);
    Ok(())
}
pub(crate) fn tunnel_routes(config: &NetworkConfig) -> Result<Vec<IpPrefix>> {
    config.validate()?;
    let mut includes = config
        .split_includes
        .iter()
        .map(normalize)
        .collect::<Vec<_>>();
    if let Some(subnet) = &config.ipv4_subnet {
        includes.push(normalize(subnet));
    }
    if config.full_tunnel_ipv4 {
        includes.push(IpPrefix {
            address: Ipv4Addr::UNSPECIFIED.into(),
            prefix: 0,
        });
    }
    if config.full_tunnel_ipv6 {
        includes.push(IpPrefix {
            address: Ipv6Addr::UNSPECIFIED.into(),
            prefix: 0,
        });
    }
    let mut normalized = Vec::<IpPrefix>::new();
    for include in includes {
        let halves = if include.prefix == 0 {
            let high = if include.address.is_ipv4() {
                IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0))
            } else {
                IpAddr::V6(Ipv6Addr::from(1u128 << 127))
            };
            [
                Some(IpPrefix {
                    address: include.address,
                    prefix: 1,
                }),
                Some(IpPrefix {
                    address: high,
                    prefix: 1,
                }),
            ]
        } else {
            [Some(include), None]
        };
        for prefix in halves.into_iter().flatten() {
            if normalized
                .iter()
                .any(|existing| contains(existing, &prefix))
            {
                continue;
            }
            normalized.retain(|existing| !contains(&prefix, existing));
            append(&mut normalized, prefix)?;
        }
    }
    let mut excludes = config
        .split_excludes
        .iter()
        .map(normalize)
        .collect::<Vec<_>>();
    excludes.push(IpPrefix {
        address: config.transport_peer,
        prefix: if config.transport_peer.is_ipv4() {
            32
        } else {
            128
        },
    });
    // Every platform installs physical bypasses before these routes. A narrower
    // bypass already wins by longest-prefix lookup; carving it out would turn
    // one IPv6 exclusion into dozens of synchronous native mutations. Remove
    // only includes covered by an equal or broader exclusion. Normalization
    // above also removes more-specific includes that could outrank a bypass.
    normalized.retain(|include| !excludes.iter().any(|exclude| contains(exclude, include)));
    normalized.sort_unstable_by_key(|prefix| {
        (
            prefix.address.is_ipv6(),
            bits(prefix.address),
            prefix.prefix,
        )
    });
    normalized.dedup();
    Ok(normalized)
}

/// Physical bypass policy, including children that outrank unavoidable
/// kernel-connected routes while preserving the negotiated address prefix.
pub(crate) fn bypass_routes(config: &NetworkConfig) -> Result<Vec<IpPrefix>> {
    config.validate()?;
    let mut bypass = config
        .split_excludes
        .iter()
        .map(normalize)
        .collect::<Vec<_>>();
    for address in &config.addresses {
        if address.prefix == width(address) {
            continue;
        }
        let connected = normalize(address);
        if !config
            .split_excludes
            .iter()
            .map(normalize)
            .any(|exclude| contains(&exclude, &connected))
        {
            continue;
        }
        let prefix = connected.prefix + 1;
        let upper = bits(connected.address) | (1u128 << (width(&connected) - prefix));
        append(
            &mut bypass,
            IpPrefix {
                address: connected.address,
                prefix,
            },
        )?;
        append(
            &mut bypass,
            IpPrefix {
                address: if connected.address.is_ipv4() {
                    Ipv4Addr::from(upper as u32).into()
                } else {
                    Ipv6Addr::from(upper).into()
                },
                prefix,
            },
        )?;
    }
    // A local address remains local even when its surrounding range is excluded.
    bypass.retain(|route| {
        route.prefix != width(route)
            || !config
                .addresses
                .iter()
                .any(|address| address.address == route.address)
    });
    bypass.sort_unstable_by_key(|prefix| {
        (
            prefix.address.is_ipv6(),
            bits(prefix.address),
            prefix.prefix,
        )
    });
    bypass.dedup();
    Ok(bypass)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocvpn_model::InterfaceIdentity;

    fn prefix(value: &str) -> IpPrefix {
        let (address, prefix) = value.split_once('/').unwrap();
        IpPrefix {
            address: address.parse().unwrap(),
            prefix: prefix.parse().unwrap(),
        }
    }

    fn config() -> NetworkConfig {
        NetworkConfig {
            interface: InterfaceIdentity {
                name: "tun0".into(),
                index: 1,
            },
            mtu: 1400,
            addresses: vec![prefix("10.78.0.2/32"), prefix("fd00:78::2/128")],
            ipv4_subnet: None,
            dns_servers: vec![],
            search_domains: vec![],
            split_dns: vec![],
            full_tunnel_ipv4: false,
            full_tunnel_ipv6: false,
            split_includes: vec![],
            split_excludes: vec![],
            transport_peer: "10.8.0.1".parse().unwrap(),
        }
    }

    fn table(config: &NetworkConfig) -> Vec<(IpPrefix, bool)> {
        let mut table: Vec<_> = tunnel_routes(config)
            .unwrap()
            .into_iter()
            .map(|route| (route, true))
            .collect();
        table.extend(
            bypass_routes(config)
                .unwrap()
                .into_iter()
                .map(|route| (route, false)),
        );
        table.push((
            IpPrefix {
                address: config.transport_peer,
                prefix: if config.transport_peer.is_ipv4() {
                    32
                } else {
                    128
                },
            },
            false,
        ));
        table
    }

    fn tunneled(table: &[(IpPrefix, bool)], destination: &str) -> bool {
        let address: IpAddr = destination.parse().unwrap();
        let host = IpPrefix {
            address,
            prefix: if address.is_ipv4() { 32 } else { 128 },
        };
        table
            .iter()
            .filter(|(route, _)| contains(route, &host))
            .max_by_key(|(route, _)| route.prefix)
            .is_some_and(|(_, tunnel)| *tunnel)
    }

    #[test]
    fn exclusions_and_transport_win_at_every_prefix_relationship() {
        let mut config = config();
        config.split_includes = [
            "10.0.0.0/8",
            "172.16.1.0/24",
            "192.168.2.0/24",
            "fd00:abcd::/32",
        ]
        .map(prefix)
        .to_vec();
        config.split_excludes = [
            "10.7.0.0/16",
            "172.16.0.0/16",
            "192.168.2.0/24",
            "fd00:abcd:20::/48",
        ]
        .map(prefix)
        .to_vec();
        let table = table(&config);
        assert!(tunneled(&table, "10.6.0.1"));
        assert!(!tunneled(&table, "10.7.0.1"));
        assert!(!tunneled(&table, "172.16.1.1"));
        assert!(!tunneled(&table, "192.168.2.1"));
        assert!(!tunneled(&table, "10.8.0.1"));
        assert!(tunneled(&table, "10.8.0.2"));
        assert!(!tunneled(&table, "fd00:abcd:20::1"));
        assert!(tunneled(&table, "fd00:abcd:21::1"));
    }

    #[test]
    fn full_policy_routes_both_families_except_physical_bypasses() {
        let mut config = config();
        config.full_tunnel_ipv4 = true;
        config.full_tunnel_ipv6 = true;
        config.split_excludes = ["198.51.100.0/24", "fd00:99::/64"].map(prefix).to_vec();
        let table = table(&config);
        assert!(tunneled(&table, "203.0.113.1"));
        assert!(tunneled(&table, "fd00:88::1"));
        assert!(!tunneled(&table, "198.51.100.1"));
        assert!(!tunneled(&table, "fd00:99::1"));
        assert!(!tunneled(&table, "10.8.0.1"));
    }
}
