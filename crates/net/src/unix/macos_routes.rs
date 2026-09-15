//! Darwin NET_RT_DUMP supplies RTAX_IFA, unlike netstat text. That ties
//! automatic connected/local routes to the exact negotiated address owner.
//! ABI: xnu bsd/net/route.h; ownership: rtsock.c::sysctl_dumpentry.
use super::*;
use serde_json::json;
use std::{mem, ptr};

fn number(bytes: &[u8]) -> Result<u16> {
    Ok(u16::from_ne_bytes(
        bytes
            .try_into()
            .map_err(|_| failure("Truncated native route length"))?,
    ))
}
fn ip_address(bytes: &[u8], hint: i32) -> Result<Option<IpAddr>> {
    if bytes.len() < 2 {
        return Ok(None);
    }
    let family = if bytes[1] == 0 { hint } else { bytes[1] as i32 };
    match family {
        libc::AF_INET => {
            let mut address = [0u8; 4];
            for (n, value) in bytes.iter().skip(4).take(4).enumerate() {
                address[n] = *value;
            }
            Ok(Some(Ipv4Addr::from(address).into()))
        }
        libc::AF_INET6 => {
            let mut address = [0u8; 16];
            for (n, value) in bytes.iter().skip(8).take(16).enumerate() {
                address[n] = *value;
            }
            // Darwin embeds the link scope in bytes 2..4 for link-local IPv6.
            if address[0] == 0xfe && address[1] & 0xc0 == 0x80 {
                address[2] = 0;
                address[3] = 0;
            }
            Ok(Some(Ipv6Addr::from(address).into()))
        }
        _ => Ok(None),
    }
}
fn dump() -> Result<Vec<Value>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_UNSPEC,
        libc::NET_RT_DUMP,
        0,
    ];
    let mut bytes = vec![0u8; LIMIT];
    let mut length = bytes.len();
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            bytes.as_mut_ptr().cast(),
            &mut length,
            ptr::null_mut(),
            0,
        )
    } != 0
        || length > bytes.len()
    {
        return Err(failure("Cannot obtain bounded Darwin routing snapshot"));
    }
    bytes.truncate(length);
    let header_size = mem::size_of::<libc::rt_msghdr>();
    let mut offset = 0usize;
    let mut routes = Vec::new();
    while offset < bytes.len() {
        let available = &bytes[offset..];
        if available.len() < header_size {
            return Err(failure("Truncated Darwin route message"));
        }
        let header = unsafe { ptr::read_unaligned(available.as_ptr().cast::<libc::rt_msghdr>()) };
        let message_length = header.rtm_msglen as usize;
        if message_length < header_size
            || message_length > available.len()
            || header.rtm_version != libc::RTM_VERSION as u8
        {
            return Err(failure("Unsupported Darwin route message ABI"));
        }
        let message = &available[..message_length];
        let mut addresses: [Option<&[u8]>; 8] = [None; 8];
        let mut cursor = header_size;
        for (slot, address) in addresses.iter_mut().enumerate() {
            if header.rtm_addrs & (1 << slot) == 0 {
                continue;
            }
            if cursor >= message.len() {
                return Err(failure("Missing Darwin route sockaddr"));
            }
            let size = message[cursor] as usize;
            let padded = if size == 0 { 4 } else { (size + 3) & !3 };
            if cursor
                .checked_add(padded)
                .is_none_or(|end| end > message.len())
            {
                return Err(failure("Truncated Darwin route sockaddr"));
            }
            *address = Some(&message[cursor..cursor + size]);
            cursor += padded;
        }
        offset += message_length;
        let Some(destination) = addresses[0]
            .and_then(|a| ip_address(a, 0).transpose())
            .transpose()?
        else {
            continue;
        };
        let hint = if destination.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        let mask = addresses[2]
            .map(|a| ip_address(a, hint))
            .transpose()?
            .flatten();
        let bits = if header.rtm_flags & libc::RTF_HOST != 0 {
            if destination.is_ipv4() { 32 } else { 128 }
        } else {
            match mask {
                Some(IpAddr::V4(mask)) => {
                    let mask = u32::from(mask);
                    let n = mask.leading_ones();
                    if mask != if n == 0 { 0 } else { u32::MAX << (32 - n) } {
                        return Err(failure("Noncontiguous Darwin route netmask"));
                    }
                    n as u8
                }
                Some(IpAddr::V6(mask)) => {
                    let mask = u128::from(mask);
                    let n = mask.leading_ones();
                    if mask != if n == 0 { 0 } else { u128::MAX << (128 - n) } {
                        return Err(failure("Noncontiguous Darwin route netmask"));
                    }
                    n as u8
                }
                None => 0,
            }
        };
        let owner = addresses[5]
            .map(|a| ip_address(a, hint))
            .transpose()?
            .flatten()
            .map(|a| a.to_string());
        let gateway = if let Some(gateway) = addresses[1] {
            if let Some(address) = ip_address(gateway, 0)? {
                json!(address.to_string())
            } else if gateway.len() >= 4 && gateway[1] as i32 == libc::AF_LINK {
                json!({"link_index":number(&gateway[2..4])?})
            } else {
                return Err(failure("Unsupported Darwin route gateway family"));
            }
        } else {
            Value::Null
        };
        let metrics = header.rtm_rmx;
        routes.push(json!({
            "destination":prefix(&IpPrefix {address:destination,prefix:bits}), "owner":owner,
            "interface_index":header.rtm_index, "gateway":gateway,
            // Reference counts, packet counters, pid and seq are observations,
            // not configuration. Excluding them does not weaken ownership.
            "flags":header.rtm_flags & !(libc::RTF_DONE | libc::RTF_IFREF),
            "metrics":{"locks":metrics.rmx_locks,"mtu":metrics.rmx_mtu,"hopcount":metrics.rmx_hopcount,
                "expire":metrics.rmx_expire,"recvpipe":metrics.rmx_recvpipe,"sendpipe":metrics.rmx_sendpipe,
                "ssthresh":metrics.rmx_ssthresh,"rtt":metrics.rmx_rtt,"rttvar":metrics.rmx_rttvar}
        }));
    }
    Ok(routes)
}
fn parts(name: &str) -> Result<(&str, IpPrefix)> {
    address_key(name)
}
pub(super) fn state(name: &str) -> Result<Value> {
    let (interface, address) = parts(name)?;
    let identity = crate::interface::resolve(interface)?;
    let mut routes: Vec<_> = dump()?
        .into_iter()
        .filter(|route| {
            route["owner"] == address.address.to_string()
                && route["flags"].as_i64().is_some_and(|flags| {
                    flags & i64::from(libc::RTF_STATIC | libc::RTF_GATEWAY) == 0
                        && (route["interface_index"] == identity.index
                            || flags & i64::from(libc::RTF_LOCAL) != 0)
                })
        })
        .collect();
    routes.sort_by_cached_key(Value::to_string);
    Ok(
        json!({"interface_index":identity.index,"owner":address.address.to_string(),"routes":routes}),
    )
}
pub(super) fn intended(config: &NetworkConfig, address: &IpPrefix) -> Value {
    json!({"automatic_projection":true,"interface_index":config.interface.index,"owner":address.address.to_string(),
        "destination":prefix(address),"host_destination":format!("{}/{}",address.address,if address.address.is_ipv4() {32} else {128}),"mtu":config.mtu})
}
pub(super) fn equivalent(actual: Option<&Value>, expected: Option<&Value>) -> bool {
    let (Some(actual), Some(expected)) = (actual, expected) else {
        return actual == expected;
    };
    if expected.get("automatic_projection") != Some(&Value::Bool(true)) {
        return actual == expected;
    }
    if actual["interface_index"] != expected["interface_index"]
        || actual["owner"] != expected["owner"]
    {
        return false;
    }
    let Some(routes) = actual["routes"].as_array() else {
        return false;
    };
    if !routes
        .iter()
        .any(|route| route["destination"] == expected["destination"])
    {
        return false;
    }
    routes.iter().all(|route| {
        let flags = route["flags"].as_i64().unwrap_or(-1);
        let allowed = i64::from(
            libc::RTF_UP
                | libc::RTF_HOST
                | libc::RTF_CLONING
                | libc::RTF_PRCLONING
                | libc::RTF_LLINFO
                | libc::RTF_LOCAL
                | libc::RTF_IFSCOPE
                | libc::RTF_GLOBAL,
        );
        let metrics = &route["metrics"];
        flags >= 0
            && flags & !allowed == 0
            && route["owner"] == expected["owner"]
            && (route["destination"] == expected["destination"]
                || route["destination"] == expected["host_destination"])
            && (route["interface_index"] == expected["interface_index"]
                || flags & i64::from(libc::RTF_LOCAL) != 0)
            && [
                "locks", "hopcount", "expire", "recvpipe", "sendpipe", "ssthresh", "rtt", "rttvar",
            ]
            .iter()
            .all(|key| metrics[*key] == 0)
            && (metrics["mtu"] == expected["mtu"]
                || metrics["mtu"] == 0
                || flags & i64::from(libc::RTF_LOCAL) != 0)
    })
}
pub(super) fn restore(name: &str, target: Option<&Value>) -> Result<()> {
    let (interface, _) = parts(name)?;
    let current = state(name)?;
    let target_routes = target
        .and_then(|v| v.get("routes"))
        .and_then(Value::as_array)
        .ok_or_else(|| failure("Automatic-route rollback requires a full native snapshot"))?;
    // New address transactions require an empty baseline. Existing owners are
    // untouched; arbitrary native dynamic routes are never reconstructed from
    // guessed text flags. Their unchanged baseline must still match exactly.
    if !target_routes.is_empty() {
        if Some(&current) == target {
            return Ok(());
        }
        return Err(failure("Preexisting automatic routes changed ownership"));
    }
    if address_state(name)?.is_none() {
        if current["routes"]
            .as_array()
            .is_some_and(|routes| routes.is_empty())
        {
            return Ok(());
        }
        return Err(failure("Automatic route address owner disappeared"));
    }
    for route in current["routes"]
        .as_array()
        .ok_or_else(|| failure("Invalid automatic route snapshot"))?
    {
        let flags = route["flags"]
            .as_i64()
            .ok_or_else(|| failure("Invalid automatic route flags"))?;
        let destination = text(&route["destination"])?;
        let parsed = parse_prefix(destination)?;
        let host = parsed.prefix == if parsed.address.is_ipv4() { 32 } else { 128 };
        let mut args = vec![
            "-n".into(),
            "delete".into(),
            family(destination).into(),
            if host { "-host" } else { "-net" }.into(),
            if host {
                parsed.address.to_string()
            } else {
                destination.into()
            },
        ];
        if flags & i64::from(libc::RTF_IFSCOPE) != 0 {
            args.push("-ifscope".into());
            args.push(interface.into());
        }
        change("/sbin/route", &args, None)?;
    }
    Ok(())
}
