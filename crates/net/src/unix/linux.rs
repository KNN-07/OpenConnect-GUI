use super::*;
use ocvpn_model::IpPrefix;
use serde_json::{Map, json};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn ip() -> Result<&'static str> {
    for path in ["/usr/sbin/ip", "/sbin/ip"] {
        if Path::new(path).is_file() {
            return Ok(path);
        }
    }
    Err(failure("Linux transactions require installed iproute2"))
}
fn json_run(args: &[&str]) -> Result<Value> {
    serde_json::from_str(&run(ip()?, args)?).map_err(|_| failure("Invalid iproute2 JSON state"))
}
fn family(prefix: &str) -> &'static str {
    if prefix.contains(':') { "-6" } else { "-4" }
}
fn canonical(prefix: &IpPrefix) -> String {
    match prefix.address {
        IpAddr::V4(a) => format!(
            "{}/{}",
            Ipv4Addr::from(
                u32::from(a)
                    & if prefix.prefix == 0 {
                        0
                    } else {
                        u32::MAX << (32 - prefix.prefix)
                    }
            ),
            prefix.prefix
        ),
        IpAddr::V6(a) => format!(
            "{}/{}",
            Ipv6Addr::from(
                u128::from(a)
                    & if prefix.prefix == 0 {
                        0
                    } else {
                        u128::MAX << (128 - prefix.prefix)
                    }
            ),
            prefix.prefix
        ),
    }
}
fn route_key(prefix: &str) -> String {
    format!("main|{prefix}")
}
fn route_parts(name: &str) -> Result<(&str, &str)> {
    let (table, prefix) = name
        .split_once('|')
        .ok_or_else(|| failure("Invalid route journal key"))?;
    if !matches!(table, "main" | "local") {
        return Err(failure("Unsupported route table"));
    }
    validate_prefix(prefix)?;
    Ok((table, prefix))
}
fn validate_prefix(value: &str) -> Result<()> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| failure("Invalid native prefix"))?;
    let prefix = IpPrefix {
        address: address
            .parse()
            .map_err(|_| failure("Invalid native address"))?,
        prefix: prefix
            .parse()
            .map_err(|_| failure("Invalid native prefix"))?,
    };
    prefix.validate()
}
fn canonical_route(value: &Value, prefix: &str) -> Result<Value> {
    let source = value
        .as_object()
        .ok_or_else(|| failure("Invalid route state"))?;
    let mut out = Map::new();
    for (key, value) in source {
        match key.as_str() {
            "dst" | "table" => {}
            "flags" if value.as_array().is_some_and(|a| a.is_empty()) => {}
            "dev" | "gateway" | "prefsrc" | "protocol" | "scope" | "type" | "metric" | "pref" => {
                out.insert(key.clone(), value.clone());
            }
            _ => {
                return Err(failure(
                    "Route attributes cannot be safely journaled by this adapter",
                ));
            }
        }
    }
    out.entry("type").or_insert(json!("unicast"));
    out.entry("protocol").or_insert(json!("boot"));
    out.entry("scope").or_insert(json!("global"));
    out.entry("metric")
        .or_insert(json!(if prefix.contains(':') { 1024 } else { 0 }));
    if prefix.contains(':') {
        out.entry("pref").or_insert(json!("medium"));
    }
    if let Some(device) = source.get("dev").and_then(Value::as_str) {
        out.insert(
            "interface_index".into(),
            json!(crate::interface::resolve(device)?.index),
        );
    }
    Ok(Value::Object(out))
}
fn route_state(name: &str) -> Result<Value> {
    let (table, prefix) = route_parts(name)?;
    let routes = json_run(&[
        family(prefix),
        "-j",
        "route",
        "show",
        "table",
        table,
        "exact",
        prefix,
    ])?;
    let mut values = routes
        .as_array()
        .ok_or_else(|| failure("Invalid route list"))?
        .iter()
        .map(|v| canonical_route(v, prefix))
        .collect::<Result<Vec<_>>>()?;
    values.sort_by_cached_key(Value::to_string);
    Ok(Value::Array(values))
}
fn intended_route(
    prefix: &str,
    interface: &str,
    gateway: Option<&str>,
    metric: Option<u32>,
) -> Result<Value> {
    let mut value = json!({"type":"unicast", "protocol":"boot", "scope": if gateway.is_some() || prefix.contains(':') { "global" } else { "link" }, "dev":interface, "metric":metric.unwrap_or(if prefix.contains(':') { 1024 } else { 0 })});
    value["interface_index"] = json!(crate::interface::resolve(interface)?.index);
    if let Some(gateway) = gateway {
        value["gateway"] = json!(gateway);
    }
    if prefix.contains(':') {
        value["pref"] = json!("medium");
    }
    Ok(value)
}
fn bypass(prefix: &str, interface: &str) -> Result<Value> {
    let existing = route_state(&route_key(prefix))?;
    let host = prefix.ends_with(if prefix.contains(':') { "/128" } else { "/32" });
    if !host
        && existing.as_array().is_some_and(|routes| {
            !routes.is_empty() && routes.iter().all(|route| route["dev"] != interface)
        })
    {
        return Ok(existing);
    }
    // Hosts use the real forwarding decision. Networks use a covering prefix,
    // never an unrelated more-specific route matching only their first address.
    let address = prefix
        .split('/')
        .next()
        .ok_or_else(|| failure("Invalid bypass prefix"))?;
    let result = if host {
        json_run(&[family(prefix), "-j", "route", "get", address])?
    } else {
        json_run(&[
            family(prefix),
            "-j",
            "route",
            "show",
            "table",
            "main",
            "match",
            prefix,
        ])?
    };
    let rows = result
        .as_array()
        .ok_or_else(|| failure("Invalid physical route lookup"))?;
    let row = if host {
        let row = rows
            .first()
            .ok_or_else(|| failure("No physical route for VPN transport"))?;
        if row.get("table").is_some_and(|v| v != "main" && v != 254) {
            return Err(failure(
                "Policy-table bypass requires a policy-aware network adapter",
            ));
        }
        row
    } else {
        rows.iter()
            .filter(|row| {
                row.get("dev")
                    .and_then(Value::as_str)
                    .is_some_and(|dev| dev != interface)
            })
            .min_by_key(|row| {
                let destination = row.get("dst").and_then(Value::as_str).unwrap_or("default");
                let length = if destination == "default" {
                    0
                } else {
                    destination
                        .split_once('/')
                        .and_then(|(_, n)| n.parse::<u8>().ok())
                        .unwrap_or(if prefix.contains(':') { 128 } else { 32 })
                };
                (
                    std::cmp::Reverse(length),
                    row.get("metric").and_then(Value::as_u64).unwrap_or(0),
                )
            })
            .ok_or_else(|| failure("No physical route covers the complete VPN exclusion"))?
    };
    let dev = row
        .get("dev")
        .and_then(Value::as_str)
        .ok_or_else(|| failure("VPN bypass route has no interface"))?;
    safe_name(dev)?;
    if dev == interface {
        return Err(failure("Transport bypass resolves through the VPN tunnel"));
    }
    let gateway = row.get("gateway").and_then(Value::as_str);
    if let Some(gateway) = gateway {
        gateway
            .parse::<IpAddr>()
            .map_err(|_| failure("Invalid physical gateway"))?;
    }
    let mut route = intended_route(
        prefix,
        dev,
        gateway,
        row.get("metric").and_then(Value::as_u64).map(|v| v as u32),
    )?;
    if let Some(source) = row.get("prefsrc") {
        route["prefsrc"] = source.clone();
    }
    if existing.as_array().is_some_and(|r| !r.is_empty()) {
        return Ok(existing);
    }
    Ok(json!([route]))
}
fn interface(name: &str) -> Result<Value> {
    safe_name(name)?;
    json_run(&["-j", "address", "show", "dev", name])?
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .ok_or_else(|| failure("Tunnel interface is absent"))
}
fn address_parts(name: &str) -> Result<(&str, &str)> {
    let (name, prefix) = name
        .split_once('|')
        .ok_or_else(|| failure("Invalid address journal key"))?;
    safe_name(name)?;
    validate_prefix(prefix)?;
    Ok((name, prefix))
}
fn address_state(name: &str) -> Result<Option<Value>> {
    let (name, prefix) = address_parts(name)?;
    let (address, bits) = prefix
        .split_once('/')
        .ok_or_else(|| failure("Invalid address journal key"))?;
    let bits: u64 = bits.parse().map_err(|_| failure("Invalid prefix"))?;
    let state = interface(name)?;
    let entries = state["addr_info"]
        .as_array()
        .ok_or_else(|| failure("Invalid interface address state"))?;
    let mut found = entries
        .iter()
        .filter(|v| v["local"] == address && v["prefixlen"] == bits);
    let Some(value) = found.next() else {
        return Ok(None);
    };
    if found.next().is_some() {
        return Err(failure("Ambiguous interface address state"));
    }
    if value.get("dynamic").is_some_and(|v| v == true)
        || value
            .get("valid_life_time")
            .is_some_and(|v| v != 4294967295u64 && v != "forever")
        || value
            .get("preferred_life_time")
            .is_some_and(|v| v != 4294967295u64 && v != "forever")
    {
        return Err(failure(
            "Expiring interface addresses cannot be safely replaced",
        ));
    }
    let mut result = json!({"local":address, "prefixlen":bits, "scope":value.get("scope").and_then(Value::as_str).unwrap_or("global")});
    for key in ["peer", "broadcast", "label", "nodad"] {
        if let Some(value) = value.get(key) {
            result[key] = value.clone();
        }
    }
    if value.get("tentative").is_some_and(|v| v == true)
        || value.get("dadfailed").is_some_and(|v| v == true)
    {
        result["unusable"] = json!(true);
    }
    Ok(Some(result))
}
fn resolver_value(kind: &str, name: &str) -> Result<Value> {
    safe_name(name)?;
    let verb = match kind {
        "linux-dns" => "dns",
        "linux-domains" => "domain",
        "linux-default-dns" => "default-route",
        _ => return Err(failure("Invalid resolver key")),
    };
    let output = run("/usr/bin/resolvectl", &[verb, name])?;
    let (_, values) = output
        .split_once(':')
        .ok_or_else(|| failure("Invalid per-link resolver response"))?;
    let values: Vec<_> = values.split_ascii_whitespace().collect();
    if kind == "linux-default-dns" {
        return match values.as_slice() {
            ["yes"] => Ok(json!(true)),
            ["no"] => Ok(json!(false)),
            _ => Err(failure("Invalid resolver default-route state")),
        };
    }
    for value in &values {
        if kind == "linux-dns" {
            value
                .parse::<IpAddr>()
                .map_err(|_| failure("Unsupported scoped resolver address"))?;
        } else if *value != "~." {
            ocvpn_model::network::validate_domain(value.trim_start_matches('~'))?;
        }
    }
    Ok(json!(
        values
            .into_iter()
            .map(|value| if kind == "linux-domains" && value != "~." {
                value.trim_end_matches('.').to_ascii_lowercase()
            } else {
                value.to_owned()
            })
            .collect::<Vec<_>>()
    ))
}
fn unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut result = Vec::new();
    for value in values {
        if !result.contains(&value) {
            result.push(value);
        }
    }
    result
}
fn resolver_kind() -> Result<&'static str> {
    // Match pinned detection: nss-resolve, or nss-dns with resolved's managed
    // resolv.conf. Do not select resolvectl merely because it is installed.
    let nss = fs::read_to_string("/etc/nsswitch.conf")
        .map_err(|_| failure("Cannot determine active Linux resolver"))?;
    let hosts = nss.lines().find(|l| l.starts_with("hosts:")).unwrap_or("");
    let target = fs::read_link("/etc/resolv.conf").ok();
    let resolved = hosts.split_ascii_whitespace().any(|v| v == "resolve")
        || (hosts.split_ascii_whitespace().any(|v| v == "dns")
            && target.as_ref().is_some_and(|p| {
                [
                    "/run/systemd/resolve/stub-resolv.conf",
                    "/usr/lib/systemd/resolv.conf",
                    "/run/systemd/resolve/resolv.conf",
                    "../run/systemd/resolve/stub-resolv.conf",
                    "../run/systemd/resolve/resolv.conf",
                ]
                .iter()
                .any(|s| p == Path::new(s))
            }));
    if resolved && Path::new("/usr/bin/resolvectl").is_file() {
        run("/usr/bin/resolvectl", &["status"])?;
        return Ok("resolved");
    }
    if Path::new("/sbin/resolvconf").is_file()
        && !fs::read_link("/sbin/resolvconf")
            .ok()
            .is_some_and(|p| p.file_name().is_some_and(|s| s == "resolvectl"))
    {
        return Ok("resolvconf");
    }
    Err(failure(
        "Active resolver is not supported safely; systemd-resolved or resolvconf is required",
    ))
}
fn resolvconf_record(name: &str) -> Result<Option<Value>> {
    safe_name(name)?;
    // Only openresolv exposes the per-key listing and missing-key status used
    // here. Other implementations must not turn unsupported options into an
    // apparently absent record during recovery.
    let program = "/sbin/resolvconf";
    if !run(program, &["--version"])?.starts_with("openresolv ") {
        return Err(failure("Transactional resolver records require openresolv"));
    }
    let result = command(
        program,
        &["-f".into(), "-l".into(), name.into()],
        None,
        false,
    )?;
    // With -f, openresolv 3.12 returns 1 for no records; newer releases return 2.
    // Diagnostics, output, signals and all other failures must remain errors.
    if matches!(result.status.code(), Some(1 | 2))
        && result.stdout.is_empty()
        && result.stderr.is_empty()
    {
        return Ok(None);
    }
    let output = checked_output(program, result)?;
    let header = format!("# resolv.conf from {name}");
    if output.trim().is_empty() {
        return Ok(None);
    }
    let mut lines = output.lines();
    if lines.next() != Some(header.as_str()) {
        return Err(failure(
            "resolvconf does not expose an unambiguous per-interface record",
        ));
    }
    let body = lines.collect::<Vec<_>>().join("\n");
    if body.lines().any(|l| l.starts_with("# resolv.conf from ")) {
        return Err(failure("Ambiguous resolvconf record"));
    }
    Ok(Some(json!(format!("{}\n", body.trim_end()))))
}
fn add_route(plan: &mut Vec<Mutation>, table: &str, prefix: &str, route: Value) -> Result<()> {
    let name = format!("{table}|{prefix}");
    if let Some(item) = plan
        .iter_mut()
        .find(|m| m.key.kind == "linux-route" && m.key.name == name)
    {
        let values = item
            .intended
            .as_mut()
            .and_then(Value::as_array_mut)
            .ok_or_else(|| failure("Invalid planned route state"))?;
        values.retain(|v| v["metric"] != route["metric"]);
        values.push(route);
        values.sort_by_cached_key(Value::to_string);
        return Ok(());
    }
    let mut intended = route_state(&name)?
        .as_array()
        .cloned()
        .ok_or_else(|| failure("Invalid route state"))?;
    intended.retain(|v| v["metric"] != route["metric"]);
    intended.push(route);
    intended.sort_by_cached_key(Value::to_string);
    plan.push(mutation("linux-route", name, Some(json!(intended)))?);
    Ok(())
}
pub(super) fn plan(config: &NetworkConfig) -> Result<Vec<Mutation>> {
    let name = &config.interface.name;
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
    // The local routing table already preserves a loopback proxy endpoint.
    if !config.transport_peer.is_loopback() {
        plan.push(mutation(
            "linux-route",
            route_key(&peer),
            Some(bypass(&peer, name)?),
        )?);
    }
    for prefix in crate::routes::bypass_routes(config)? {
        let prefix = canonical(&prefix);
        if prefix != peer {
            plan.push(mutation(
                "linux-route",
                route_key(&prefix),
                Some(bypass(&prefix, name)?),
            )?);
        }
    }
    plan.push(mutation(
        "linux-mtu",
        name.clone(),
        Some(json!(config.mtu)),
    )?);
    // Prevent raising a previously-down TUN from generating an unpredictable
    // link-local address and route outside the durable mutation inventory.
    if Path::new(&format!("/proc/sys/net/ipv6/conf/{name}/addr_gen_mode")).exists() {
        plan.push(mutation("linux-addrgen", name.clone(), Some(json!(1)))?);
    }
    plan.push(mutation("linux-up", name.clone(), Some(json!(true)))?);
    for address in &config.addresses {
        if address.address.is_ipv4() && address.prefix != 32 {
            return Err(failure("vpnc point-to-point IPv4 requires a /32 address"));
        }
        let prefix = format!("{}/{}", address.address, address.prefix);
        let mut value = json!({"local": address.address.to_string(), "prefixlen":address.prefix,"scope":"global"});
        if address.address.is_ipv4() {
            value["label"] = json!(name);
            value["peer"] = json!(address.address.to_string());
        }
        // iproute2 omits a peer equal to the local address from JSON output.
        if address.address.is_ipv4() {
            value.as_object_mut().unwrap().remove("peer");
        }
        let mut item = mutation("linux-address", format!("{name}|{prefix}"), Some(value))?;
        if let Some(flag) = item.before.as_ref().and_then(|v| v.get("nodad")) {
            if let Some(intended) = item.intended.as_mut() {
                intended["nodad"] = flag.clone();
            }
        }
        if item.before.is_some() && item.before != item.intended {
            return Err(failure(
                "Existing tunnel address has attributes outside the negotiated contract",
            ));
        }
        plan.push(item);
        // Linux creates these routes implicitly with RTM_NEWADDR. Journal them
        // before changing the address, and preserve all unrelated metric slots.
        let mut connected = intended_route(
            &canonical(address),
            name,
            None,
            Some(if address.address.is_ipv6() { 256 } else { 0 }),
        )?;
        connected["protocol"] = json!("kernel");
        if address.address.is_ipv4() {
            connected["prefsrc"] = json!(address.address.to_string());
        }
        add_route(&mut plan, "main", &canonical(address), connected)?;
        let host = format!(
            "{}/{}",
            address.address,
            if address.address.is_ipv6() { 128 } else { 32 }
        );
        let mut local = intended_route(&host, name, None, Some(0))?;
        local["protocol"] = json!("kernel");
        local["type"] = json!("local");
        local["scope"] = json!(if address.address.is_ipv6() {
            "global"
        } else {
            "host"
        });
        if address.address.is_ipv4() {
            local["prefsrc"] = json!(address.address.to_string());
        }
        add_route(&mut plan, "local", &host, local)?;
    }
    for route in crate::routes::tunnel_routes(config)? {
        let prefix = canonical(&route);
        if config.addresses.iter().any(|a| canonical(a) == prefix) {
            continue;
        }
        let route = intended_route(&prefix, name, None, None)?;
        // Paired /1s implement full traffic policy without replacing physical defaults.
        add_route(&mut plan, "main", &prefix, route)?;
    }
    if !config.dns_servers.is_empty() {
        match resolver_kind()? {
            "resolved" => {
                plan.push(mutation(
                    "linux-dns",
                    name.clone(),
                    Some(json!(unique(
                        config.dns_servers.iter().map(ToString::to_string)
                    ))),
                )?);
                let mut domains = unique(
                    config
                        .search_domains
                        .iter()
                        .map(|s| s.trim_end_matches('.').to_ascii_lowercase()),
                );
                for domain in config
                    .split_dns
                    .iter()
                    .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
                {
                    // Search domains already route their suffix through this
                    // link. Duplicating it as route-only would lose search use.
                    let routing = format!("~{domain}");
                    if !domains.contains(&domain) && !domains.contains(&routing) {
                        domains.push(routing);
                    }
                }
                let full = config.split_dns.is_empty()
                    && (config.full_tunnel_ipv4
                        || config.full_tunnel_ipv6
                        || config.split_includes.iter().any(|p| p.prefix == 0));
                if full {
                    domains.push("~.".to_owned());
                }
                plan.push(mutation(
                    "linux-domains",
                    name.clone(),
                    Some(json!(domains)),
                )?);
                plan.push(mutation(
                    "linux-default-dns",
                    name.clone(),
                    Some(json!(full)),
                )?);
            }
            "resolvconf" => {
                if !config.split_dns.is_empty() {
                    return Err(failure(
                        "resolvconf cannot represent split DNS routing domains",
                    ));
                }
                let mut record = String::new();
                for server in &config.dns_servers {
                    record.push_str(&format!("nameserver {server}\n"));
                }
                if !config.search_domains.is_empty() {
                    record.push_str(&format!("search {}\n", config.search_domains.join(" ")));
                }
                plan.push(mutation(
                    "linux-resolvconf",
                    name.clone(),
                    Some(json!(record)),
                )?);
            }
            _ => return Err(failure("Unsupported resolver")),
        }
    }
    Ok(plan)
}
pub(super) fn read(key: &Key) -> Result<Option<Value>> {
    match key.kind.as_str() {
        "linux-route" => Ok(Some(route_state(&key.name)?)),
        "linux-address" => address_state(&key.name),
        "linux-addrgen" => {
            safe_name(&key.name)?;
            let value = fs::read_to_string(format!(
                "/proc/sys/net/ipv6/conf/{}/addr_gen_mode",
                key.name
            ))
            .map_err(|_| failure("Cannot read tunnel IPv6 address-generation mode"))?;
            Ok(Some(json!(value.trim().parse::<u8>().map_err(|_| {
                failure("Invalid IPv6 address-generation mode")
            })?)))
        }
        "linux-mtu" => Ok(Some(interface(&key.name)?["mtu"].clone())),
        "linux-up" => Ok(Some(json!(
            interface(&key.name)?["flags"]
                .as_array()
                .ok_or_else(|| failure("Invalid interface flags"))?
                .iter()
                .any(|v| v == "UP")
        ))),
        "linux-dns" | "linux-domains" | "linux-default-dns" => {
            Ok(Some(resolver_value(&key.kind, &key.name)?))
        }
        "linux-resolvconf" => resolvconf_record(&key.name),
        _ => Err(failure("Unknown Linux network journal key")),
    }
}
fn route_args(action: &str, table: &str, prefix: &str, route: &Value) -> Result<Vec<String>> {
    if let Some(device) = route.get("dev").and_then(Value::as_str) {
        if route["interface_index"] != crate::interface::resolve(device)?.index {
            return Err(failure("Journaled route interface identity changed"));
        }
    }
    let mut args = vec![
        family(prefix).to_owned(),
        "route".to_owned(),
        action.to_owned(),
        text(&route["type"])?.to_owned(),
        prefix.to_owned(),
        "table".to_owned(),
        table.to_owned(),
    ];
    for (key, arg) in [
        ("gateway", "via"),
        ("dev", "dev"),
        ("prefsrc", "src"),
        ("protocol", "proto"),
        ("scope", "scope"),
        ("metric", "metric"),
        ("pref", "pref"),
    ] {
        if let Some(value) = route.get(key) {
            let value = if let Some(value) = value.as_str() {
                value.to_owned()
            } else if let Some(value) = value.as_u64() {
                value.to_string()
            } else {
                return Err(failure("Invalid route journal attribute"));
            };
            if value.starts_with('-') || value.chars().any(char::is_whitespace) {
                return Err(failure("Invalid route journal argument"));
            }
            args.push(arg.to_owned());
            args.push(value);
        }
    }
    Ok(args)
}
pub(super) fn write(key: &Key, value: Option<&Value>) -> Result<()> {
    match key.kind.as_str() {
        "linux-route" => {
            let (table, prefix) = route_parts(&key.name)?;
            let current = route_state(&key.name)?;
            let target = value
                .and_then(Value::as_array)
                .ok_or_else(|| failure("Route journal requires an array"))?;
            let current = current
                .as_array()
                .ok_or_else(|| failure("Invalid route state"))?;
            // Every planned route changes one metric slot. RTM_NEWROUTE with
            // replace is atomic; never delete a physical default before adding
            // its replacement, which would leave an unowned crash state.
            for route in target {
                if !current.contains(route) {
                    change(ip()?, &route_args("replace", table, prefix, route)?, None)?;
                }
            }
            for route in current {
                if !target.iter().any(|v| v["metric"] == route["metric"]) {
                    change(ip()?, &route_args("del", table, prefix, route)?, None)?;
                }
            }
            Ok(())
        }
        "linux-address" => {
            let (name, prefix) = address_parts(&key.name)?;
            if value.is_none() && address_state(&key.name)?.is_some() {
                change(
                    ip()?,
                    &[
                        family(prefix).into(),
                        "address".into(),
                        "del".into(),
                        prefix.into(),
                        "dev".into(),
                        name.into(),
                    ],
                    None,
                )?;
            }
            if let Some(value) = value {
                let mut args = vec![
                    family(prefix).into(),
                    "address".into(),
                    "replace".into(),
                    prefix.into(),
                    "dev".into(),
                    name.into(),
                    "scope".into(),
                    text(&value["scope"])?.into(),
                ];
                for key in ["peer", "broadcast", "label"] {
                    if let Some(value) = value.get(key) {
                        args.push(key.into());
                        args.push(text(value)?.into());
                    }
                }
                if prefix.contains(':') {
                    if value.get("nodad").is_some_and(|v| v == true) {
                        args.push("nodad".into());
                    }
                } else if value.get("peer").is_none() {
                    args.push("peer".into());
                    args.push(text(&value["local"])?.into());
                }
                change(ip()?, &args, None)?;
            }
            Ok(())
        }
        "linux-addrgen" => {
            safe_name(&key.name)?;
            let mode = value
                .and_then(Value::as_u64)
                .filter(|m| *m <= 3)
                .ok_or_else(|| failure("Invalid IPv6 address-generation mode"))?;
            change(
                "/ocgui/addrgen",
                &[key.name.clone(), mode.to_string()],
                None,
            )
        }
        "linux-mtu" | "linux-up" => {
            safe_name(&key.name)?;
            let value = value.ok_or_else(|| failure("Missing interface journal value"))?;
            let mut args = vec!["link".into(), "set".into(), "dev".into(), key.name.clone()];
            if key.kind == "linux-mtu" {
                args.push("mtu".into());
                args.push(
                    value
                        .as_u64()
                        .filter(|n| *n >= 68 && *n <= 65535)
                        .ok_or_else(|| failure("Invalid MTU journal value"))?
                        .to_string(),
                );
            } else {
                args.push(
                    if value
                        .as_bool()
                        .ok_or_else(|| failure("Invalid link journal value"))?
                    {
                        "up"
                    } else {
                        "down"
                    }
                    .into(),
                );
            }
            change(ip()?, &args, None)
        }
        "linux-dns" | "linux-domains" | "linux-default-dns" => {
            safe_name(&key.name)?;
            let value = value.ok_or_else(|| failure("Missing resolver journal value"))?;
            let mut args = vec![
                match key.kind.as_str() {
                    "linux-dns" => "dns",
                    "linux-domains" => "domain",
                    _ => "default-route",
                }
                .into(),
                key.name.clone(),
            ];
            if key.kind == "linux-default-dns" {
                args.push(
                    if value
                        .as_bool()
                        .ok_or_else(|| failure("Invalid resolver journal value"))?
                    {
                        "yes"
                    } else {
                        "no"
                    }
                    .into(),
                );
            } else {
                let values = strings(value)?;
                if values.is_empty() {
                    args.push(String::new());
                } else {
                    args.extend(values);
                }
            }
            change("/usr/bin/resolvectl", &args, None)
        }
        "linux-resolvconf" => {
            safe_name(&key.name)?;
            change(
                "/sbin/resolvconf",
                &[
                    if value.is_some() { "-a" } else { "-d" }.into(),
                    key.name.clone(),
                ],
                value.map(text).transpose()?,
            )
        }
        _ => Err(failure("Unknown Linux network journal key")),
    }
}
pub(super) fn implicit_address_route(
    config: &NetworkConfig,
    key: &Key,
    current: Option<&Value>,
    before: Option<&Value>,
) -> bool {
    if key.kind != "linux-route" {
        return false;
    }
    let Ok((table, destination)) = route_parts(&key.name) else {
        return false;
    };
    let Some(current) = current.and_then(Value::as_array) else {
        return false;
    };
    let Some(before) = before.and_then(Value::as_array) else {
        return false;
    };
    let owned = config.addresses.iter().any(|address| {
        let expected = if table == "local" {
            format!(
                "{}/{}",
                address.address,
                if address.address.is_ipv4() { 32 } else { 128 }
            )
        } else {
            canonical(address)
        };
        expected == destination
    });
    owned
        && before.iter().all(|v| current.contains(v))
        && current.iter().all(|v| {
            before.contains(v) || (v["protocol"] == "kernel" && v["dev"] == config.interface.name)
        })
}
pub(super) fn observe(config: &NetworkConfig) -> Result<NetworkObservation> {
    let state = interface(&config.interface.name)?;
    let entries = state["addr_info"]
        .as_array()
        .ok_or_else(|| failure("Invalid interface address observation"))?;
    let addresses = entries
        .iter()
        .filter(|v| {
            !v.get("tentative").is_some_and(|v| v == true)
                && !v.get("dadfailed").is_some_and(|v| v == true)
        })
        .map(|v| {
            Ok(format!(
                "{}/{}",
                text(&v["local"])?,
                v["prefixlen"]
                    .as_u64()
                    .ok_or_else(|| failure("Invalid observed address prefix"))?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut routes = Vec::new();
    for family in ["-4", "-6"] {
        let rows = json_run(&[family, "-j", "route", "show", "dev", &config.interface.name])?;
        for row in rows
            .as_array()
            .ok_or_else(|| failure("Invalid observed routes"))?
        {
            let dst = text(&row["dst"])?;
            routes.push(if dst == "default" {
                if family == "-6" { "::/0" } else { "0.0.0.0/0" }.into()
            } else {
                dst.into()
            });
        }
    }
    let (dns_servers, search_domains) = {
        match resolver_kind()? {
            "resolved" => (
                strings(&resolver_value("linux-dns", &config.interface.name)?)?,
                strings(&resolver_value("linux-domains", &config.interface.name)?)?
                    .into_iter()
                    .filter(|s| !s.starts_with('~'))
                    .collect(),
            ),
            "resolvconf" => {
                let record = resolvconf_record(&config.interface.name)?;
                let mut servers = Vec::new();
                let mut domains = Vec::new();
                for line in record.as_ref().map(text).transpose()?.unwrap_or("").lines() {
                    if let Some(value) = line.strip_prefix("nameserver ") {
                        servers.push(value.to_owned());
                    }
                    if let Some(value) = line.strip_prefix("search ") {
                        domains.extend(value.split_ascii_whitespace().map(str::to_owned));
                    }
                }
                (servers, domains)
            }
            _ => return Err(failure("Unsupported resolver observation")),
        }
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
