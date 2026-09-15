//! Native IP Helper transactions. Every key contains a LUID, never just a reusable index.
use crate::journal::{Key, Mutation};
use ocvpn_model::{Error, ErrorCode, IpPrefix, NetworkConfig, NetworkObservation, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::*,
};
mod trusted;
pub(crate) fn journal_root() -> Result<std::path::PathBuf> {
    trusted::journal_root()
}

fn fail() -> Error {
    Error::new(
        ErrorCode::NetworkFailure,
        "Windows network operation failed",
    )
}
fn check(code: u32) -> Result<()> {
    if code == 0 { Ok(()) } else { Err(fail()) }
}
fn missing(code: u32) -> Result<bool> {
    if code == 1168 || code == 2 {
        Ok(true)
    } else {
        check(code)?;
        Ok(false)
    }
}
fn encode<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| fail())
}
fn decode<T: for<'a> Deserialize<'a>>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| fail())
}
fn val<T: for<'a> Deserialize<'a>>(value: &Value) -> Result<T> {
    serde_json::from_value(value.clone()).map_err(|_| fail())
}
fn luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}
/// A removed adapter cannot be restored by recreating its old addresses or settings.
pub(crate) fn vanished(key: &Key) -> Result<bool> {
    let id = match key.kind.as_str() {
        "win-route" => decode::<RouteKey>(&key.name)?.luid,
        "win-address" => decode::<(u64, IpAddr)>(&key.name)?.0,
        "win-mtu" | "win-dns" => decode::<(u64, bool)>(&key.name)?.0,
        "win-nrpt" => return Ok(false),
        _ => return Err(Error::invalid("Unknown Windows journal key")),
    };
    if id == 0 {
        return Err(Error::invalid("Invalid journal interface identity"));
    }
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid = luid(id);
    missing(unsafe { GetIfEntry2(&mut row) })
}
fn identity(config: &NetworkConfig) -> Result<u64> {
    let actual = crate::interface::resolve(&config.interface.name)?;
    if actual != config.interface {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Tunnel interface identity changed",
        ));
    }
    let mut value = unsafe { std::mem::zeroed() };
    check(unsafe { ConvertInterfaceIndexToLuid(actual.index, &mut value) })?;
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceLuid = value;
    check(unsafe { GetIfEntry2(&mut row) })?;
    let description = String::from_utf16_lossy(
        &row.Description[..row
            .Description
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(row.Description.len())],
    );
    if !description.to_ascii_lowercase().contains("wintun") {
        return Err(Error::invalid("Tunnel adapter is not Wintun"));
    }
    Ok(unsafe { value.Value })
}
fn socket(ip: IpAddr) -> SOCKADDR_INET {
    let mut out: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(ip) => {
            out.Ipv4.sin_family = AF_INET;
            out.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            out.Ipv6.sin6_family = AF_INET6;
            out.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    out
}
fn ip(socket: SOCKADDR_INET) -> IpAddr {
    unsafe {
        if socket.si_family == AF_INET {
            Ipv4Addr::from(socket.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()
        } else {
            Ipv6Addr::from(socket.Ipv6.sin6_addr.u.Byte).into()
        }
    }
}
#[derive(Serialize, Deserialize, Clone)]
struct RouteKey {
    luid: u64,
    destination: IpPrefix,
    gateway: IpAddr,
    scope: u32,
}
fn route_row(key: &RouteKey) -> MIB_IPFORWARD_ROW2 {
    let mut row = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid(key.luid);
    row.DestinationPrefix.Prefix = socket(key.destination.address);
    row.DestinationPrefix.PrefixLength = key.destination.prefix;
    row.NextHop = socket(key.gateway);
    if key.gateway.is_ipv6() {
        row.NextHop.Ipv6.Anonymous.sin6_scope_id = key.scope;
    }
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}
fn route_value(row: &MIB_IPFORWARD_ROW2) -> Value {
    json!({"metric":row.Metric,"protocol":row.Protocol,"site":row.SitePrefixLength,"loopback":row.Loopback,"autoconfigure":row.AutoconfigureAddress,"publish":row.Publish,"immortal":row.Immortal})
}
fn prefix(address: IpAddr, bits: u8) -> IpPrefix {
    IpPrefix {
        address,
        prefix: bits,
    }
}
fn physical(destination: IpPrefix, tunnel: u64) -> Result<RouteKey> {
    let address = socket(destination.address);
    let mut row = unsafe { std::mem::zeroed() };
    let mut source = unsafe { std::mem::zeroed() };
    check(unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &address,
            0,
            &mut row,
            &mut source,
        )
    })?;
    if row.DestinationPrefix.PrefixLength > destination.prefix {
        // A host-specific first-address lookup is not a route for the entire
        // excluded CIDR. Select its longest covering physical route instead.
        let family = if destination.address.is_ipv4() {
            AF_INET
        } else {
            AF_INET6
        };
        let mut table = ptr::null_mut();
        check(unsafe { GetIpForwardTable2(family, &mut table) })?;
        let mut selected: Option<(MIB_IPFORWARD_ROW2, u64)> = None;
        for candidate in unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        } {
            if unsafe { candidate.InterfaceLuid.Value } == tunnel {
                continue;
            }
            let network = prefix(
                ip(candidate.DestinationPrefix.Prefix),
                candidate.DestinationPrefix.PrefixLength,
            );
            if !crate::routes::contains(&network, &destination) {
                continue;
            }
            let mut interface: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
            interface.InterfaceLuid = candidate.InterfaceLuid;
            interface.Family = family;
            if unsafe { GetIpInterfaceEntry(&mut interface) } != 0 || !interface.Connected {
                continue;
            }
            let metric = u64::from(candidate.Metric) + u64::from(interface.Metric);
            if selected.as_ref().is_none_or(|(prior, prior_metric)| {
                candidate.DestinationPrefix.PrefixLength > prior.DestinationPrefix.PrefixLength
                    || (candidate.DestinationPrefix.PrefixLength
                        == prior.DestinationPrefix.PrefixLength
                        && metric < *prior_metric)
            }) {
                selected = Some((*candidate, metric));
            }
        }
        unsafe { FreeMibTable(table.cast()) };
        row = selected
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::NetworkFailure,
                    "No physical route covers the excluded network",
                )
            })?
            .0;
    }
    if unsafe { row.InterfaceLuid.Value } == tunnel {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Transport bypass resolves through tunnel",
        ));
    }
    Ok(RouteKey {
        luid: unsafe { row.InterfaceLuid.Value },
        destination,
        gateway: ip(row.NextHop),
        scope: unsafe {
            if row.NextHop.si_family == AF_INET6 {
                row.NextHop.Ipv6.Anonymous.sin6_scope_id
            } else {
                0
            }
        },
    })
}
fn add(out: &mut Vec<Mutation>, kind: &str, name: String, intended: Value) -> Result<()> {
    let key = Key {
        kind: kind.into(),
        name,
    };
    if out
        .iter()
        .any(|m| m.key.kind == key.kind && m.key.name == key.name)
    {
        return Ok(());
    }
    let before = read(&key)?;
    // Existing routes/addresses are shared state: do not replace their lifetime or policy.
    if kind == "win-address" && before.is_some() && before.as_ref() != Some(&intended) {
        return Err(Error::new(
            ErrorCode::Conflict,
            "Existing network entry conflicts with tunnel",
        ));
    }
    let intended = if kind == "win-route" {
        before.clone().unwrap_or(intended)
    } else {
        intended
    };
    out.push(Mutation {
        key,
        before,
        intended: Some(intended),
        applied: None,
    });
    Ok(())
}
pub(crate) fn plan(
    config: &NetworkConfig,
    transaction: crate::TransactionId,
) -> Result<Vec<Mutation>> {
    config.validate()?;
    trusted::privileged()?;
    let id = identity(config)?;
    let mut out = Vec::new();
    // Pin the actual connected proxy/peer before adding any tunnel route.
    let peer = physical(
        prefix(
            config.transport_peer,
            if config.transport_peer.is_ipv4() {
                32
            } else {
                128
            },
        ),
        id,
    )?;
    add(
        &mut out,
        "win-route",
        encode(&peer)?,
        route_value(&route_row(&peer)),
    )?;
    for exclude in crate::routes::bypass_routes(config)? {
        let route = physical(exclude, id)?;
        add(
            &mut out,
            "win-route",
            encode(&route)?,
            route_value(&route_row(&route)),
        )?;
    }
    for v6 in [false, true] {
        if !config.addresses.iter().any(|a| a.address.is_ipv6() == v6) {
            continue;
        }
        add(&mut out, "win-mtu", encode(&(id, v6))?, json!(config.mtu))?;
    }
    for address in &config.addresses {
        add(
            &mut out,
            "win-address",
            encode(&(id, address.address))?,
            json!({"prefix":address.prefix,"skip":false,"prefix_origin":1,"suffix_origin":1}),
        )?;
    }
    let routes = crate::routes::tunnel_routes(config)?;
    for destination in routes {
        let gateway = if destination.address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let route = RouteKey {
            luid: id,
            destination,
            gateway,
            scope: 0,
        };
        let mut row = route_row(&route);
        row.Metric = 0;
        add(&mut out, "win-route", encode(&route)?, route_value(&row))?;
    }
    if config.split_dns.is_empty() {
        for v6 in [false, true] {
            if config.addresses.iter().any(|a| a.address.is_ipv6() == v6) {
                let servers = config
                    .dns_servers
                    .iter()
                    .filter(|ip| ip.is_ipv6() == v6)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                add(
                    &mut out,
                    "win-dns",
                    encode(&(id, v6))?,
                    json!({"servers":servers,"search":config.search_domains.join(",")}),
                )?;
            }
        }
    } else {
        if config.dns_servers.is_empty() {
            return Err(Error::invalid("Split DNS requires DNS servers"));
        }
        for v6 in [false, true] {
            if !config.addresses.iter().any(|a| a.address.is_ipv6() == v6) {
                continue;
            }
            let name = encode(&(id, v6))?;
            let key = Key {
                kind: "win-dns".into(),
                name: name.clone(),
            };
            let mut settings = read(&key)?.ok_or_else(fail)?;
            settings["search"] = json!(config.search_domains.join(","));
            add(&mut out, "win-dns", name, settings)?;
        }
        let tag = format!("ocvpn:{}", transaction.attempt_id);
        let mut suffixes: Vec<_> = config
            .split_dns
            .iter()
            .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        suffixes.sort();
        suffixes.dedup();
        let mut servers: Vec<_> = config.dns_servers.iter().map(ToString::to_string).collect();
        servers.sort();
        servers.dedup();
        let intended = json!({"tag":tag,"suffixes":suffixes,"servers":servers});
        trusted::nrpt(&json!({"operation":"check","value":intended}))?;
        add(&mut out, "win-nrpt", tag, intended)?;
    }
    Ok(out)
}
fn dns_guid(id: u64) -> Result<windows_sys::core::GUID> {
    let mut guid = unsafe { std::mem::zeroed() };
    check(unsafe { ConvertInterfaceLuidToGuid(&luid(id), &mut guid) })?;
    Ok(guid)
}
unsafe fn wide_string(value: *const u16) -> Result<String> {
    if value.is_null() {
        return Ok(String::new());
    }
    let mut len = 0;
    while len < 65536 && unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    if len == 65536 {
        return Err(fail());
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, len) }).map_err(|_| fail())
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
pub(crate) fn read(key: &Key) -> Result<Option<Value>> {
    match key.kind.as_str() {
        "win-route" => {
            let mut row = route_row(&decode(&key.name)?);
            if missing(unsafe { GetIpForwardEntry2(&mut row) })? {
                Ok(None)
            } else {
                Ok(Some(route_value(&row)))
            }
        }
        "win-address" => {
            let (id, address): (u64, IpAddr) = decode(&key.name)?;
            let mut row = unsafe { std::mem::zeroed() };
            unsafe { InitializeUnicastIpAddressEntry(&mut row) };
            row.InterfaceLuid = luid(id);
            row.Address = socket(address);
            if missing(unsafe { GetUnicastIpAddressEntry(&mut row) })? {
                Ok(None)
            } else {
                Ok(Some(
                    json!({"prefix":row.OnLinkPrefixLength,"skip":row.SkipAsSource,"prefix_origin":row.PrefixOrigin,"suffix_origin":row.SuffixOrigin}),
                ))
            }
        }
        "win-mtu" => {
            let (id, v6): (u64, bool) = decode(&key.name)?;
            let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
            row.InterfaceLuid = luid(id);
            row.Family = if v6 { AF_INET6 } else { AF_INET };
            check(unsafe { GetIpInterfaceEntry(&mut row) })?;
            Ok(Some(json!(row.NlMtu)))
        }
        "win-dns" => {
            let (id, v6): (u64, bool) = decode(&key.name)?;
            let mut settings: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
            settings.Version = 1;
            settings.Flags = if v6 { DNS_SETTING_IPV6 as u64 } else { 0 };
            check(unsafe { GetInterfaceDnsSettings(dns_guid(id)?, &mut settings) })?;
            let result = (|| {
                Ok(Some(
                    json!({"servers":unsafe {wide_string(settings.NameServer)}?,"search":unsafe {wide_string(settings.SearchList)}?}),
                ))
            })();
            unsafe { FreeInterfaceDnsSettings(&mut settings) };
            result
        }
        "win-nrpt" => {
            let value = trusted::nrpt(&json!({"operation":"read","tag":key.name}))?;
            Ok(if value.is_null() { None } else { Some(value) })
        }
        _ => Err(Error::invalid("Unknown Windows journal key")),
    }
}
pub(crate) fn write(key: &Key, value: Option<&Value>) -> Result<()> {
    trusted::privileged()?;
    match key.kind.as_str() {
        "win-route" => {
            let mut row = route_row(&decode(&key.name)?);
            if let Some(v) = value {
                row.Metric = val(&v["metric"])?;
                row.Protocol = val(&v["protocol"])?;
                row.SitePrefixLength = val(&v["site"])?;
                row.Loopback = val(&v["loopback"])?;
                row.AutoconfigureAddress = val(&v["autoconfigure"])?;
                row.Publish = val(&v["publish"])?;
                row.Immortal = val(&v["immortal"])?;
                let code = unsafe { CreateIpForwardEntry2(&row) };
                if code == 5010 {
                    check(unsafe { SetIpForwardEntry2(&row) })
                } else {
                    check(code)
                }
            } else {
                missing(unsafe { DeleteIpForwardEntry2(&row) }).map(|_| ())
            }
        }
        "win-address" => {
            let (id, address): (u64, IpAddr) = decode(&key.name)?;
            let mut row = unsafe { std::mem::zeroed() };
            unsafe { InitializeUnicastIpAddressEntry(&mut row) };
            row.InterfaceLuid = luid(id);
            row.Address = socket(address);
            if let Some(v) = value {
                row.OnLinkPrefixLength = val(&v["prefix"])?;
                row.SkipAsSource = val(&v["skip"])?;
                row.PrefixOrigin = val(&v["prefix_origin"])?;
                row.SuffixOrigin = val(&v["suffix_origin"])?;
                let code = unsafe { CreateUnicastIpAddressEntry(&row) };
                if code == 5010 {
                    check(unsafe { SetUnicastIpAddressEntry(&row) })
                } else {
                    check(code)
                }
            } else {
                missing(unsafe { DeleteUnicastIpAddressEntry(&row) }).map(|_| ())
            }
        }
        "win-mtu" => {
            let (id, v6): (u64, bool) = decode(&key.name)?;
            let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
            row.InterfaceLuid = luid(id);
            row.Family = if v6 { AF_INET6 } else { AF_INET };
            check(unsafe { GetIpInterfaceEntry(&mut row) })?;
            row.NlMtu = val(value.ok_or_else(fail)?)?;
            check(unsafe { SetIpInterfaceEntry(&mut row) })
        }
        "win-dns" => {
            let (id, v6): (u64, bool) = decode(&key.name)?;
            let v = value.ok_or_else(fail)?;
            let mut servers = wide(v["servers"].as_str().ok_or_else(fail)?);
            let mut search = wide(v["search"].as_str().ok_or_else(fail)?);
            let mut settings: DNS_INTERFACE_SETTINGS = unsafe { std::mem::zeroed() };
            settings.Version = 1;
            settings.Flags = (DNS_SETTING_NAMESERVER
                | DNS_SETTING_SEARCHLIST
                | if v6 { DNS_SETTING_IPV6 } else { 0 }) as u64;
            settings.NameServer = servers.as_mut_ptr();
            settings.SearchList = search.as_mut_ptr();
            check(unsafe { SetInterfaceDnsSettings(dns_guid(id)?, &settings) })
        }
        "win-nrpt" => {
            let value = value
                .ok_or_else(|| Error::invalid("NRPT removal requires journal-owned rule Names"))?;
            trusted::nrpt(&json!({"operation":"set","tag":key.name,"value":value}))?;
            Ok(())
        }
        _ => Err(Error::invalid("Unknown Windows journal key")),
    }
}
pub(crate) fn restore(key: &Key, value: Option<&Value>, current: Option<&Value>) -> Result<()> {
    if key.kind == "win-nrpt" && value.is_none() {
        trusted::nrpt(&json!({"operation":"remove","tag":key.name,"expected":current}))?;
        Ok(())
    } else {
        write(key, value)
    }
}
pub(crate) fn equivalent(key: &Key, actual: Option<&Value>, expected: Option<&Value>) -> bool {
    if key.kind != "win-nrpt" {
        return actual == expected;
    }
    fn same(a: &Value, b: &Value) -> bool {
        match (a.as_array(), b.as_array()) {
            (Some(a), Some(b)) => a.len() == b.len() && b.iter().all(|v| a.contains(v)),
            _ => false,
        }
    }
    match (actual, expected) {
        (Some(a), Some(e)) => {
            a["tag"] == e["tag"]
                && same(&a["suffixes"], &e["suffixes"])
                && same(&a["servers"], &e["servers"])
                && (e.get("names").is_none() || same(&a["names"], &e["names"]))
        }
        (None, None) => true,
        _ => false,
    }
}
pub(crate) fn apply_planned(mutations: &[Mutation]) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    for mutation in mutations {
        if std::time::Instant::now() >= deadline {
            return Err(Error::new(
                ErrorCode::NetworkFailure,
                "Network application timed out",
            ));
        }
        if read(&mutation.key)? != mutation.before {
            return Err(Error::new(
                ErrorCode::Conflict,
                "Network state changed before apply",
            ));
        }
        if mutation.before != mutation.intended {
            write(&mutation.key, mutation.intended.as_ref())?;
        }
    }
    Ok(())
}
pub(crate) fn observe(config: &NetworkConfig) -> Result<NetworkObservation> {
    let id = identity(config)?;
    let mut addresses = Vec::new();
    let mut routes = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut tentative = false;
        for address in &config.addresses {
            let mut row = unsafe { std::mem::zeroed() };
            unsafe { InitializeUnicastIpAddressEntry(&mut row) };
            row.InterfaceLuid = luid(id);
            row.Address = socket(address.address);
            check(unsafe { GetUnicastIpAddressEntry(&mut row) })?;
            if row.DadState == IpDadStateTentative {
                tentative = true;
            } else if row.DadState != IpDadStatePreferred {
                return Err(Error::new(
                    ErrorCode::NetworkFailure,
                    "Tunnel address failed duplicate-address detection",
                ));
            }
        }
        if !tentative {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(Error::new(
                ErrorCode::NetworkFailure,
                "Tunnel address readiness timed out",
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    unsafe {
        let mut table = ptr::null_mut();
        check(GetUnicastIpAddressTable(AF_UNSPEC, &mut table))?;
        for row in std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        {
            if row.InterfaceLuid.Value == id {
                addresses.push(format!("{}/{}", ip(row.Address), row.OnLinkPrefixLength));
            }
        }
        FreeMibTable(table.cast());
        let mut table = ptr::null_mut();
        check(GetIpForwardTable2(AF_UNSPEC, &mut table))?;
        for row in std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        {
            if row.InterfaceLuid.Value == id {
                routes.push(format!(
                    "{}/{} via {}",
                    ip(row.DestinationPrefix.Prefix),
                    row.DestinationPrefix.PrefixLength,
                    ip(row.NextHop)
                ));
            }
        }
        FreeMibTable(table.cast());
    }
    let mut dns_servers = Vec::new();
    let mut search_domains = Vec::new();
    for v6 in [false, true] {
        if !config.addresses.iter().any(|a| a.address.is_ipv6() == v6) {
            continue;
        }
        let settings = read(&Key {
            kind: "win-dns".into(),
            name: encode(&(id, v6))?,
        })?
        .ok_or_else(fail)?;
        for (field, target) in [
            ("servers", &mut dns_servers),
            ("search", &mut search_domains),
        ] {
            for item in settings[field]
                .as_str()
                .ok_or_else(fail)?
                .split([',', ';', ' '])
                .filter(|s| !s.is_empty())
            {
                if !target.iter().any(|s| s == item) {
                    target.push(item.to_owned());
                }
            }
        }
    }
    if !config.split_dns.is_empty() {
        let rules = trusted::nrpt(&json!({"operation":"observe","suffixes":config.split_dns}))?;
        for server in rules["servers"].as_array().ok_or_else(fail)? {
            let s = server.as_str().ok_or_else(fail)?.to_owned();
            if !dns_servers.contains(&s) {
                dns_servers.push(s);
            }
        }
        for suffix in rules["suffixes"].as_array().ok_or_else(fail)? {
            search_domains.push(suffix.as_str().ok_or_else(fail)?.to_owned());
        }
    }
    let target = socket(config.transport_peer);
    let mut route = unsafe { std::mem::zeroed() };
    let mut source = unsafe { std::mem::zeroed() };
    check(unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &target,
            0,
            &mut route,
            &mut source,
        )
    })?;
    if unsafe { route.InterfaceLuid.Value } == id {
        return Err(Error::new(
            ErrorCode::NetworkFailure,
            "Transport peer would be routed through its own tunnel",
        ));
    }
    Ok(NetworkObservation {
        interface: config.interface.name.clone(),
        addresses,
        dns_servers,
        search_domains,
        routes,
        transport: String::new(),
    })
}
