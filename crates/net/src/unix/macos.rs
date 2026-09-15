use super::*;
use ocvpn_model::IpPrefix;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[path = "macos_routes.rs"]
mod automatic;

fn prefix(value: &IpPrefix) -> String {
    match value.address {
        IpAddr::V4(a) => format!(
            "{}/{}",
            Ipv4Addr::from(
                u32::from(a)
                    & if value.prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - value.prefix)
                    }
            ),
            value.prefix
        ),
        IpAddr::V6(a) => format!(
            "{}/{}",
            Ipv6Addr::from(
                u128::from(a)
                    & if value.prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - value.prefix)
                    }
            ),
            value.prefix
        ),
    }
}
fn parse_prefix(value: &str) -> Result<IpPrefix> {
    let (address, bits) = value
        .split_once('/')
        .ok_or_else(|| failure("Invalid macOS route prefix"))?;
    let result = IpPrefix {
        address: address
            .parse()
            .map_err(|_| failure("Invalid macOS address"))?,
        prefix: bits.parse().map_err(|_| failure("Invalid macOS prefix"))?,
    };
    result.validate()?;
    Ok(result)
}
fn family(value: &str) -> &'static str {
    if value.contains(':') {
        "-inet6"
    } else {
        "-inet"
    }
}
fn interface_state(name: &str) -> Result<String> {
    safe_name(name)?;
    run("/sbin/ifconfig", &[name])
}
fn mtu(name: &str) -> Result<u64> {
    let output = interface_state(name)?;
    let mut words = output.split_ascii_whitespace();
    while let Some(word) = words.next() {
        if word == "mtu" {
            return words
                .next()
                .ok_or_else(|| failure("Missing interface MTU"))?
                .parse()
                .map_err(|_| failure("Invalid interface MTU"));
        }
    }
    Err(failure("Missing interface MTU"))
}
fn address_list(name: &str) -> Result<Vec<Value>> {
    safe_name(name)?;
    let output = interface_state(name)?;
    let mut values = Vec::new();
    for line in output.lines() {
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        if !matches!(words.first(), Some(&"inet") | Some(&"inet6")) {
            continue;
        }
        let address = words
            .get(1)
            .ok_or_else(|| failure("Malformed macOS interface address"))?;
        let raw_address = address.split('%').next().unwrap_or(address);
        let address: IpAddr = raw_address
            .parse()
            .map_err(|_| failure("Invalid macOS interface address"))?;
        let at = |token| {
            words
                .iter()
                .position(|s| *s == token)
                .and_then(|n| words.get(n + 1))
                .copied()
        };
        let bits = if address.is_ipv4() {
            let mask = at("netmask").ok_or_else(|| failure("Missing IPv4 netmask"))?;
            let mask = u32::from_str_radix(mask.trim_start_matches("0x"), 16)
                .map_err(|_| failure("Invalid IPv4 netmask"))?;
            let bits = mask.leading_ones();
            if mask
                != if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                }
            {
                return Err(failure("Noncontiguous native netmask"));
            }
            bits
        } else {
            at("prefixlen")
                .ok_or_else(|| failure("Missing IPv6 prefix"))?
                .parse()
                .map_err(|_| failure("Invalid IPv6 prefix"))?
        };
        let mut value = json!({"address":address.to_string(),"prefix":bits});
        if let Some(peer) = at("-->") {
            peer.parse::<IpAddr>()
                .map_err(|_| failure("Invalid point-to-point peer"))?;
            value["peer"] = json!(peer);
        }
        if let Some(broadcast) = at("broadcast") {
            value["broadcast"] = json!(broadcast);
        }
        if words
            .iter()
            .any(|v| matches!(*v, "tentative" | "duplicated" | "detached"))
        {
            value["unusable"] = json!(true);
        }
        if words
            .iter()
            .any(|v| matches!(*v, "autoconf" | "temporary" | "deprecated"))
        {
            value["dynamic"] = json!(true);
        }
        values.push(value);
    }
    Ok(values)
}
fn address_key(name: &str) -> Result<(&str, IpPrefix)> {
    let (interface, address) = name
        .split_once('|')
        .ok_or_else(|| failure("Invalid macOS address journal key"))?;
    safe_name(interface)?;
    Ok((interface, parse_prefix(address)?))
}
fn address_state(name: &str) -> Result<Option<Value>> {
    let (interface, address) = address_key(name)?;
    let values = address_list(interface)?;
    let mut values = values
        .into_iter()
        .filter(|v| v["address"] == address.address.to_string() && v["prefix"] == address.prefix);
    let value = values.next();
    if values.next().is_some() {
        return Err(failure("Ambiguous macOS address"));
    }
    if value.as_ref().is_some_and(|v| v.get("dynamic").is_some()) {
        return Err(failure("Dynamic macOS addresses cannot be safely replaced"));
    }
    Ok(value)
}
fn route_destination(value: &str, v6: bool) -> Result<String> {
    if value == "default" {
        return Ok(if v6 { "::/0" } else { "0.0.0.0/0" }.into());
    }
    let (value, bits) = value
        .split_once('/')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    let value = value.split('%').next().unwrap_or(value);
    let address: IpAddr = if v6 {
        value
            .parse()
            .map_err(|_| failure("Invalid IPv6 route destination"))?
    } else {
        let mut parts: Vec<_> = value.split('.').collect();
        if parts.len() > 4 {
            return Err(failure("Invalid IPv4 route destination"));
        }
        while parts.len() < 4 {
            parts.push("0");
        }
        parts
            .join(".")
            .parse()
            .map_err(|_| failure("Invalid IPv4 route destination"))?
    };
    let bits = if let Some(bits) = bits {
        bits.parse().map_err(|_| failure("Invalid route mask"))?
    } else if v6 {
        128
    } else {
        (value.split('.').count() * 8) as u8
    };
    let value = IpPrefix {
        address,
        prefix: bits,
    };
    value.validate()?;
    Ok(prefix(&value))
}
fn route_rows(v6: bool) -> Result<Vec<(String, String, String, String)>> {
    let output = run(
        "/usr/sbin/netstat",
        &["-rn", "-f", if v6 { "inet6" } else { "inet" }],
    )?;
    let mut rows = Vec::new();
    let mut interface_column = None;
    for line in output.lines() {
        let columns: Vec<_> = line.split_ascii_whitespace().collect();
        if columns.first() == Some(&"Destination") {
            interface_column = columns.iter().position(|s| *s == "Netif");
            continue;
        }
        let Some(index) = interface_column else {
            continue;
        };
        if columns.len() <= index {
            continue;
        }
        if columns[0].ends_with(':') && !v6 {
            continue;
        }
        let destination = route_destination(columns[0], v6)?;
        safe_name(columns[index])?;
        rows.push((
            destination,
            columns[1].to_owned(),
            columns[2].to_owned(),
            columns[index].to_owned(),
        ));
    }
    if interface_column.is_none() {
        return Err(failure("Cannot parse native macOS routing table"));
    }
    Ok(rows)
}
fn route_detail(destination: &str, interface: Option<&str>, lookup: bool) -> Result<Value> {
    let mut args = vec!["-n".to_owned(), "get".into(), family(destination).into()];
    if let Some(interface) = interface {
        args.push("-ifscope".into());
        args.push(interface.into());
    }
    args.push(
        destination
            .split('/')
            .next()
            .ok_or_else(|| failure("Invalid route destination"))?
            .into(),
    );
    let output = checked_output("/sbin/route", command("/sbin/route", &args, None, false)?)?;
    let field = |key: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
    };
    let interface =
        field("interface:").ok_or_else(|| failure("Route has no physical interface"))?;
    safe_name(interface)?;
    let flags = field("flags:").ok_or_else(|| failure("Route has no flags"))?;
    // Reject dynamic, cloned, multipath and protocol-owned entries rather than
    // lose their lifetime/ownership metadata when rolling back a replacement.
    let supported = [
        "UP",
        "GATEWAY",
        "HOST",
        "STATIC",
        "DONE",
        "IFSCOPE",
        "PRCLONING",
        "CLONING",
        "IFREF",
        "GLOBAL",
    ];
    let flags: Vec<_> = flags.trim_matches(['<', '>']).split(',').collect();
    if !lookup && flags.iter().any(|flag| !supported.contains(flag)) {
        return Err(failure("macOS route flags cannot be restored precisely"));
    }
    let gateway = field("gateway:").unwrap_or(interface);
    if !gateway.starts_with("link#") && gateway != interface {
        gateway
            .split('%')
            .next()
            .unwrap_or(gateway)
            .parse::<IpAddr>()
            .map_err(|_| failure("Invalid native route gateway"))?;
    }
    // Route metrics are normally zero except interface MTU. Nonzero expiration,
    // RTT or locked metrics are not representable by the journal's static route.
    let lines: Vec<_> = output.lines().collect();
    let mut route_mtu = 0u64;
    for pair in lines.windows(2) {
        let headings: Vec<_> = pair[0].split_ascii_whitespace().collect();
        if headings.first() != Some(&"recvpipe") {
            continue;
        }
        let values: Vec<_> = pair[1].split_ascii_whitespace().collect();
        if headings.len() != values.len() {
            return Err(failure("Malformed macOS route metrics"));
        }
        for (heading, value) in headings.iter().zip(values) {
            let n: u64 = value
                .parse()
                .map_err(|_| failure("Locked macOS route metrics cannot be restored"))?;
            if *heading == "mtu" {
                route_mtu = n;
            } else if n != 0 && !lookup {
                return Err(failure("Dynamic macOS route metrics cannot be restored"));
            }
        }
    }
    Ok(
        json!({"gateway": if gateway.starts_with("link#") { interface } else { gateway }, "interface":interface, "interface_index":crate::interface::resolve(interface)?.index, "interface_route": !flags.contains(&"GATEWAY"), "scoped":flags.contains(&"IFSCOPE"), "mtu":route_mtu, "cloning":flags.contains(&"CLONING"), "prcloning":flags.contains(&"PRCLONING")}),
    )
}
fn route_state(destination: &str) -> Result<Option<Value>> {
    let parsed = parse_prefix(destination)?;
    let rows = route_rows(parsed.address.is_ipv6())?;
    let rows: Vec<_> = rows
        .into_iter()
        .filter(|r| r.0 == destination && !r.2.contains('I'))
        .collect();
    if rows.len() > 1 {
        return Err(failure("Ambiguous unscoped macOS route"));
    }
    if rows.is_empty() {
        return Ok(None);
    }
    route_detail(destination, None, false).map(Some)
}
fn new_route(
    destination: &str,
    interface: &str,
    gateway: &str,
    interface_route: bool,
    mtu: u64,
) -> Result<Value> {
    let network = !destination.contains(':') && !destination.ends_with("/32");
    Ok(
        json!({"gateway":gateway,"interface":interface,"interface_index":crate::interface::resolve(interface)?.index,"interface_route":interface_route,"scoped":false,"mtu":mtu,"cloning":network && interface_route,"prcloning":network && !interface_route}),
    )
}
fn bypass(destination: &str, tunnel: &str) -> Result<Value> {
    if let Some(existing) = route_state(destination)? {
        if existing["interface"] == tunnel {
            return Err(failure("Existing bypass route points into tunnel"));
        }
        return Ok(existing);
    }
    let requested = parse_prefix(destination)?;
    if requested.prefix < if requested.address.is_ipv4() { 32 } else { 128 } {
        let mut selected = None;
        let mut selected_length = 0;
        for row in route_rows(requested.address.is_ipv6())? {
            if row.3 == tunnel || row.2.contains('I') {
                continue;
            }
            let covering = parse_prefix(&row.0)?;
            if covering.prefix > requested.prefix
                || prefix(&IpPrefix {
                    address: requested.address,
                    prefix: covering.prefix,
                }) != row.0
            {
                continue;
            }
            if selected.is_none() || covering.prefix > selected_length {
                selected_length = covering.prefix;
                selected = Some(row);
            }
        }
        let row = selected
            .ok_or_else(|| failure("No physical route covers the complete VPN exclusion"))?;
        let interface_route = !row.2.contains('G');
        let gateway = if interface_route {
            row.3.as_str()
        } else {
            row.1.as_str()
        };
        return new_route(destination, &row.3, gateway, interface_route, mtu(&row.3)?);
    }
    let route = route_detail(destination, None, true)?;
    if route["interface"] == tunnel {
        return Err(failure("Transport peer resolves through VPN tunnel"));
    }
    new_route(
        destination,
        text(&route["interface"])?,
        text(&route["gateway"])?,
        route["interface_route"] == true,
        route["mtu"]
            .as_u64()
            .ok_or_else(|| failure("Invalid physical route MTU"))?,
    )
}
fn store_parts(name: &str) -> Result<(&str, &str)> {
    let (store, field) = name
        .split_once('|')
        .ok_or_else(|| failure("Invalid dynamic-store journal key"))?;
    let rest = store
        .strip_prefix("State:/Network/Service/")
        .ok_or_else(|| failure("Invalid dynamic-store service path"))?;
    let (interface, family) = rest
        .split_once('/')
        .ok_or_else(|| failure("Invalid dynamic-store service path"))?;
    safe_name(interface)?;
    if !matches!(family, "DNS" | "IPv4" | "IPv6")
        || !matches!(
            field,
            "ServerAddresses"
                | "SearchDomains"
                | "SupplementalMatchDomains"
                | "DomainName"
                | "Addresses"
                | "SubnetMasks"
                | "InterfaceName"
                | "OverridePrimary"
                | "Router"
        )
    {
        return Err(failure("Dynamic-store field is not allowlisted"));
    }
    Ok((store, field))
}
fn store_state(name: &str) -> Result<Option<Value>> {
    let (store, field) = store_parts(name)?;
    let output = checked_output(
        "/usr/sbin/scutil",
        command(
            "/usr/sbin/scutil",
            &[],
            Some(&format!("show {store}\nquit\n")),
            false,
        )?,
    )?;
    if output.contains("No such key") {
        return Ok(None);
    }
    if !output.trim_start().starts_with("<dictionary> {") {
        return Err(failure("Malformed dynamic-store dictionary"));
    }
    let marker = format!("{field} : ");
    let mut lines = output.lines();
    while let Some(line) = lines.next() {
        let Some(value) = line.trim().strip_prefix(&marker) else {
            continue;
        };
        if value == "<array> {" {
            let mut values = Vec::new();
            for line in lines.by_ref() {
                if line.trim() == "}" {
                    return Ok(Some(json!(values)));
                }
                let (_, value) = line
                    .trim()
                    .split_once(" :")
                    .ok_or_else(|| failure("Malformed dynamic-store array"))?;
                let value = value.trim_start();
                if !(value.is_empty() && field == "SupplementalMatchDomains") {
                    store_token(value)?;
                }
                values.push(value.to_owned());
            }
            return Err(failure("Unterminated dynamic-store array"));
        }
        store_token(value)?;
        return Ok(Some(if field == "OverridePrimary" {
            json!(
                value
                    .parse::<u64>()
                    .map_err(|_| failure("Invalid dynamic-store number"))?
            )
        } else {
            json!(value)
        }));
    }
    Ok(None)
}
fn store_token(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 1024
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/%~-".contains(&b))
    {
        return Err(failure("Dynamic-store value cannot be encoded safely"));
    }
    Ok(())
}
fn store_mutation(interface: &str, family: &str, field: &str, value: Value) -> Result<Mutation> {
    mutation(
        "mac-store",
        format!("State:/Network/Service/{interface}/{family}|{field}"),
        Some(value),
    )
}
pub(super) fn plan(config: &NetworkConfig) -> Result<Vec<Mutation>> {
    let name = &config.interface.name;
    // utun is already created by OpenConnect. Never create/destroy a guessed
    // device, and never substitute Linux iproute2 for Darwin route semantics.
    // xnu bsd/net/if_utun.c::utun_ctl_connect sets IFF_UP and
    // IFEF_NOAUTOIPV6LL before exposing the interface. Thus negotiated address
    // operations, not unpredictable automatic link-local generation, own the
    // additional local/connected routes inventoried through NET_RT_DUMP.
    if !name
        .strip_prefix("utun")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(failure(
            "macOS network transactions require a resolved utun interface",
        ));
    }
    let mut plan = Vec::new();
    let peer = format!(
        "{}/{}",
        config.transport_peer,
        if config.transport_peer.is_ipv4() {
            32
        } else {
            128
        }
    );
    if !config.transport_peer.is_loopback() {
        plan.push(mutation(
            "mac-route",
            peer.clone(),
            Some(bypass(&peer, name)?),
        )?);
    }
    for exclude in crate::routes::bypass_routes(config)? {
        let destination = prefix(&exclude);
        if destination != peer {
            plan.push(mutation(
                "mac-route",
                destination.clone(),
                Some(bypass(&destination, name)?),
            )?);
        }
    }
    plan.push(mutation("mac-mtu", name.clone(), Some(json!(config.mtu)))?);
    plan.push(mutation("mac-up", name.clone(), Some(json!(true)))?);
    for address in &config.addresses {
        if address.address.is_ipv4() && address.prefix != 32 {
            return Err(failure("Darwin point-to-point IPv4 requires /32"));
        }
        let mut value = json!({"address":address.address.to_string(),"prefix":address.prefix});
        if address.address.is_ipv4() {
            value["peer"] = json!(address.address.to_string());
        }
        let item = mutation(
            "mac-address",
            format!("{name}|{}/{}", address.address, address.prefix),
            Some(value),
        )?;
        if item.before.is_some() && item.before != item.intended {
            return Err(failure(
                "Existing utun address cannot be atomically replaced without losing native flags",
            ));
        }
        let existing_address = item.before.is_some();
        plan.push(item);
        let mut derived = mutation(
            "mac-auto-route",
            format!("{name}|{}/{}", address.address, address.prefix),
            Some(automatic::intended(config, address)),
        )?;
        let previous = derived
            .before
            .as_ref()
            .and_then(|v| v.get("routes"))
            .and_then(Value::as_array)
            .ok_or_else(|| failure("Invalid automatic-route baseline"))?;
        if existing_address {
            derived.intended = derived.before.clone();
        } else if !previous.is_empty() {
            return Err(failure(
                "Negotiated address collides with preexisting native route ownership",
            ));
        }
        plan.push(derived);
    }
    for route in crate::routes::tunnel_routes(config)? {
        let destination = prefix(&route);
        // The address transaction already owns this kernel connected route.
        // Do not replace it with a static route sharing the same destination.
        if config
            .addresses
            .iter()
            .any(|address| prefix(address) == destination)
        {
            continue;
        }
        let route = new_route(&destination, name, name, true, config.mtu.into())?;
        plan.push(mutation("mac-route", destination, Some(route))?);
    }
    if !config.dns_servers.is_empty() {
        plan.push(store_mutation(
            name,
            "DNS",
            "ServerAddresses",
            json!(
                config
                    .dns_servers
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            ),
        )?);
        if !config.search_domains.is_empty() {
            plan.push(store_mutation(
                name,
                "DNS",
                "SearchDomains",
                json!(config.search_domains),
            )?);
            plan.push(store_mutation(
                name,
                "DNS",
                "DomainName",
                json!(config.search_domains[0]),
            )?);
        }
        let matches = if config.split_dns.is_empty() {
            vec![String::new()]
        } else {
            config.split_dns.clone()
        };
        if !matches.is_empty() {
            plan.push(store_mutation(
                name,
                "DNS",
                "SupplementalMatchDomains",
                json!(matches),
            )?);
        }
        // The pinned Darwin DNS service needs an IPv4/IPv6 service identity.
        // Restrict ownership to the utun service; never rewrite physical service
        // DNS or networksetup preferences which do not belong to this session.
        for v6 in [false, true] {
            let addresses: Vec<_> = config
                .addresses
                .iter()
                .filter(|p| p.address.is_ipv6() == v6)
                .map(|p| p.address.to_string())
                .collect();
            if addresses.is_empty() {
                continue;
            }
            let family = if v6 { "IPv6" } else { "IPv4" };
            plan.push(store_mutation(name, family, "Addresses", json!(addresses))?);
            plan.push(store_mutation(name, family, "InterfaceName", json!(name))?);
            if !v6 {
                plan.push(store_mutation(
                    name,
                    family,
                    "SubnetMasks",
                    json!(vec!["255.255.255.255"; addresses.len()]),
                )?);
            }
            if config.split_dns.is_empty() {
                plan.push(store_mutation(name, family, "OverridePrimary", json!(1))?);
            }
        }
    }
    Ok(plan)
}
pub(super) fn read(key: &Key) -> Result<Option<Value>> {
    match key.kind.as_str() {
        "mac-route" => route_state(&key.name),
        "mac-address" => address_state(&key.name),
        "mac-auto-route" => automatic::state(&key.name).map(Some),
        "mac-mtu" => Ok(Some(json!(mtu(&key.name)?))),
        "mac-up" => {
            let output = interface_state(&key.name)?;
            let flags = output
                .lines()
                .next()
                .and_then(|s| s.split_once('<'))
                .and_then(|(_, s)| s.split_once('>'))
                .map(|(s, _)| s)
                .ok_or_else(|| failure("Missing macOS interface flags"))?;
            Ok(Some(json!(flags.split(',').any(|flag| flag == "UP"))))
        }
        "mac-store" => store_state(&key.name),
        _ => Err(failure("Unknown macOS network journal key")),
    }
}
fn route_args(action: &str, destination: &str, value: &Value) -> Result<Vec<String>> {
    let parsed = parse_prefix(destination)?;
    if value["interface_index"] != crate::interface::resolve(text(&value["interface"])?)?.index {
        return Err(failure("Journaled route interface identity changed"));
    }
    let host = parsed.prefix == if parsed.address.is_ipv4() { 32 } else { 128 };
    let mut args = vec![
        "-n".into(),
        action.into(),
        family(destination).into(),
        if host { "-host" } else { "-net" }.into(),
        if host {
            parsed.address.to_string()
        } else {
            destination.into()
        },
    ];
    if value["interface_route"] == true {
        args.push("-interface".into());
        args.push(text(&value["interface"])?.into());
    } else {
        args.push(text(&value["gateway"])?.into());
    }
    if value["scoped"] == true {
        args.push("-ifscope".into());
        args.push(text(&value["interface"])?.into());
    }
    if action != "delete" {
        if value["cloning"] == true {
            args.push("-cloning".into());
        }
        let mtu = value["mtu"]
            .as_u64()
            .ok_or_else(|| failure("Invalid route MTU"))?;
        if mtu != 0 {
            args.push("-mtu".into());
            args.push(mtu.to_string());
        }
    }
    Ok(args)
}
pub(super) fn write(key: &Key, value: Option<&Value>) -> Result<()> {
    match key.kind.as_str() {
        "mac-route" => {
            let current = route_state(&key.name)?;
            match (current.as_ref(), value) {
                (Some(current), None) => change(
                    "/sbin/route",
                    &route_args("delete", &key.name, current)?,
                    None,
                )?,
                (Some(_), Some(value)) => change(
                    "/sbin/route",
                    &route_args("change", &key.name, value)?,
                    None,
                )?,
                (None, Some(value)) => {
                    change("/sbin/route", &route_args("add", &key.name, value)?, None)?
                }
                (None, None) => {}
            }
            Ok(())
        }
        "mac-auto-route" => automatic::restore(&key.name, value),
        "mac-address" => {
            let (name, address) = address_key(&key.name)?;
            let family = if address.address.is_ipv6() {
                "inet6"
            } else {
                "inet"
            };
            if value.is_none() && address_state(&key.name)?.is_some() {
                change(
                    "/sbin/ifconfig",
                    &[
                        name.into(),
                        family.into(),
                        address.address.to_string(),
                        "-alias".into(),
                    ],
                    None,
                )?;
            }
            if let Some(value) = value {
                let mut args = vec![
                    name.into(),
                    family.into(),
                    format!("{}/{}", address.address, address.prefix),
                ];
                if let Some(peer) = value.get("peer") {
                    args.push(text(peer)?.into());
                }
                if let Some(broadcast) = value.get("broadcast") {
                    args.push("broadcast".into());
                    args.push(text(broadcast)?.into());
                }
                args.push("alias".into());
                change("/sbin/ifconfig", &args, None)?;
            }
            Ok(())
        }
        "mac-mtu" | "mac-up" => {
            safe_name(&key.name)?;
            let value = value.ok_or_else(|| failure("Missing macOS interface journal value"))?;
            let mut args = vec![key.name.clone()];
            if key.kind == "mac-mtu" {
                args.push("mtu".into());
                args.push(
                    value
                        .as_u64()
                        .filter(|v| *v >= 68 && *v <= 65535)
                        .ok_or_else(|| failure("Invalid MTU"))?
                        .to_string(),
                );
            } else {
                args.push(
                    if value
                        .as_bool()
                        .ok_or_else(|| failure("Invalid interface state"))?
                    {
                        "up"
                    } else {
                        "down"
                    }
                    .into(),
                );
            }
            change("/sbin/ifconfig", &args, None)
        }
        "mac-store" => {
            let (store, field) = store_parts(&key.name)?;
            let mut input = format!("get {store}\n");
            // get on a missing key leaves the current dictionary unchanged. A
            // fresh scutil process plus d.init makes that behavior unambiguous.
            input.insert_str(0, "d.init\n");
            input.push_str(&format!("d.remove {field}\n"));
            if let Some(value) = value {
                input.push_str(&format!("d.add {field}"));
                if value.is_array() {
                    input.push_str(" *");
                    for value in strings(value)? {
                        input.push(' ');
                        if value.is_empty() && field == "SupplementalMatchDomains" {
                            input.push_str("\"\"");
                        } else {
                            store_token(&value)?;
                            input.push_str(&value);
                        }
                    }
                } else if let Some(value) = value.as_u64() {
                    input.push_str(&format!(" # {value}"));
                } else {
                    let value = text(value)?;
                    store_token(value)?;
                    input.push(' ');
                    input.push_str(value);
                }
                input.push('\n');
            }
            input.push_str(&format!("set {store}\nquit\n"));
            change("/usr/sbin/scutil", &[], Some(&input))?;
            if value.is_none() {
                let remaining = checked_output(
                    "/usr/sbin/scutil",
                    command(
                        "/usr/sbin/scutil",
                        &[],
                        Some(&format!("show {store}\nquit\n")),
                        false,
                    )?,
                )?;
                if remaining.split_ascii_whitespace().collect::<Vec<_>>()
                    == ["<dictionary>", "{", "}"]
                {
                    change(
                        "/usr/sbin/scutil",
                        &[],
                        Some(&format!("remove {store}\nquit\n")),
                    )?;
                }
            }
            Ok(())
        }
        _ => Err(failure("Unknown macOS network journal key")),
    }
}
pub(super) fn automatic_equivalent(actual: Option<&Value>, expected: Option<&Value>) -> bool {
    automatic::equivalent(actual, expected)
}
pub(super) fn implicit_address_route(
    config: &NetworkConfig,
    key: &Key,
    current: Option<&Value>,
    before: Option<&Value>,
) -> bool {
    if key.kind != "mac-route" || before.is_some() {
        return false;
    }
    let Some(current) = current else {
        return false;
    };
    config
        .addresses
        .iter()
        .any(|address| prefix(address) == key.name)
        && current["interface"] == config.interface.name
        && current["interface_route"] == true
}
fn active_dns(index: u32) -> Result<(Vec<String>, Vec<String>)> {
    let output = run("/usr/sbin/scutil", &["--dns"])?;
    let mut servers = Vec::new();
    let mut domains = Vec::new();
    for resolver in output.split("resolver #").skip(1) {
        let matching = resolver.lines().find_map(|line| {
            line.trim()
                .strip_prefix("if_index")
                .and_then(|s| s.split_once(':'))
                .and_then(|(_, s)| s.split_ascii_whitespace().next())
                .and_then(|s| s.parse::<u32>().ok())
        }) == Some(index);
        if !matching {
            continue;
        }
        for line in resolver.lines().map(str::trim) {
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim();
                if key.starts_with("nameserver[") {
                    value
                        .split('%')
                        .next()
                        .unwrap_or(value)
                        .parse::<IpAddr>()
                        .map_err(|_| failure("Invalid active macOS DNS address"))?;
                    if !servers.iter().any(|s| s == value) {
                        servers.push(value.to_owned());
                    }
                } else if key.starts_with("search domain[") {
                    ocvpn_model::network::validate_domain(value)?;
                    if !domains.iter().any(|s| s == value) {
                        domains.push(value.to_owned());
                    }
                }
            }
        }
    }
    Ok((servers, domains))
}
pub(super) fn observe(config: &NetworkConfig) -> Result<NetworkObservation> {
    let addresses = address_list(&config.interface.name)?
        .into_iter()
        .filter(|v| v.get("unusable").is_none())
        .map(|v| {
            Ok(format!(
                "{}/{}",
                text(&v["address"])?,
                v["prefix"]
                    .as_u64()
                    .ok_or_else(|| failure("Invalid observed prefix"))?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut routes = Vec::new();
    for v6 in [false, true] {
        routes.extend(
            route_rows(v6)?
                .into_iter()
                .filter(|r| r.3 == config.interface.name)
                .map(|r| r.0),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let (dns_servers, search_domains) = loop {
        let observed = active_dns(config.interface.index)?;
        if config.dns_servers.is_empty() || !observed.0.is_empty() {
            break observed;
        }
        if Instant::now() >= deadline {
            return Err(failure("macOS did not activate the tunnel DNS service"));
        }
        thread::sleep(Duration::from_millis(50));
    };
    Ok(NetworkObservation {
        interface: config.interface.name.clone(),
        addresses,
        dns_servers,
        search_domains,
        routes,
        transport: String::new(),
    })
}
