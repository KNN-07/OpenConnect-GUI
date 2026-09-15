//! Private lockstep protocol: the reviewed shell chooses lifecycle operations;
//! only the journal owner can turn a request into a preflighted native mutation.
use super::*;
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    sync::mpsc,
};

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn execute(
    config: &NetworkConfig,
    reason: NetworkReason,
    mutations: &[Mutation],
    mut operation: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    let _deadline = DeadlineGuard::new(Duration::from_secs(120));
    let until = Instant::now() + Duration::from_secs(120);
    let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    let first_interface = mutations
        .iter()
        .position(|m| m.key.kind.contains("-mtu@"))
        .unwrap_or(mutations.len());
    let peer = format!(
        "{}/{}",
        config.transport_peer,
        if config.transport_peer.is_ipv4() {
            32
        } else {
            128
        }
    );
    let mut excludes = Vec::new();
    let mut includes = Vec::new();
    let mut resolver = "none";
    for (i, m) in mutations.iter().enumerate() {
        let route = matches!(m.key.kind.as_str(), "linux-route" | "mac-route");
        let automatic_route = i >= first_interface
            && m.key.kind == "linux-route"
            && m.intended
                .as_ref()
                .and_then(Value::as_array)
                .is_some_and(|routes| {
                    routes.iter().any(|r| {
                        r.get("protocol").and_then(Value::as_str) == Some("kernel")
                            && r.get("dev").and_then(Value::as_str)
                                == Some(config.interface.name.as_str())
                    })
                });
        let interface_key = ["-mtu@", "-up@", "-address@", "-addrgen@", "-auto-route@"]
            .iter()
            .any(|kind| m.key.kind.contains(kind));
        let group = if interface_key || automatic_route {
            "interface".to_owned()
        } else if route {
            let prefix = m
                .key
                .name
                .rsplit('|')
                .next()
                .ok_or_else(|| failure("Invalid planned route"))?;
            if i < first_interface && prefix == peer {
                "gateway".to_owned()
            } else {
                if i < first_interface {
                    excludes.push(prefix.to_owned());
                } else {
                    includes.push(prefix.to_owned());
                }
                format!("route {prefix}")
            }
        } else if m.key.kind.starts_with("linux-resolvconf") {
            resolver = "resolvconf";
            resolver.to_owned()
        } else if m.key.kind.starts_with("linux-dns@")
            || m.key.kind.starts_with("linux-domains@")
            || m.key.kind.starts_with("linux-default-dns@")
        {
            resolver = "resolved";
            resolver.to_owned()
        } else if m.key.kind == "mac-store" {
            resolver = "darwin";
            resolver.to_owned()
        } else {
            return Err(failure("Unclassified journal mutation"));
        };
        groups.entry(group).or_default().push(i);
    }
    let script = trusted_script()?;
    let mut command = Command::new("/bin/sh");
    command
        .arg("/dev/fd/3")
        .arg("ocgui-lifecycle")
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env(
            "reason",
            match reason {
                NetworkReason::Connect => "connect",
                NetworkReason::Reconnect => "reconnect",
                NetworkReason::Disconnect => "disconnect",
                _ => return Err(failure("Unexpected configuring lifecycle")),
            },
        )
        .env("OCGUI_RESOLVER", resolver)
        .env("VPNGATEWAY", config.transport_peer.to_string())
        .env("TUNDEV", &config.interface.name)
        .env("CISCO_BANNER", "")
        .env("INTERNAL_IP4_ADDRESS", "")
        .env("INTERNAL_IP6_ADDRESS", "")
        .env("INTERNAL_IP6_NETMASK", "")
        .env(
            "INTERNAL_IP4_DNS",
            if config.dns_servers.is_empty() {
                ""
            } else {
                "planned"
            },
        )
        .env("INTERNAL_IP6_DNS", "");
    for (suffix, routes) in [("EXC", excludes), ("INC", includes)] {
        for v6 in [false, true] {
            let base = format!(
                "{}SPLIT_{suffix}",
                if v6 { "CISCO_IPV6_" } else { "CISCO_" }
            );
            let routes: Vec<_> = routes.iter().filter(|p| p.contains(':') == v6).collect();
            // Explicit zero prevents upstream fallback to a default route.
            command.env(&base, routes.len().to_string());
            for (i, route) in routes.iter().enumerate() {
                let (address, prefix) = route
                    .split_once('/')
                    .ok_or_else(|| failure("Invalid route inventory"))?;
                command
                    .env(format!("{base}_{i}_ADDR"), address)
                    .env(format!("{base}_{i}_MASKLEN"), prefix)
                    .env(format!("{base}_{i}_MASK"), "");
            }
        }
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let fd = script.as_raw_fd();
    #[cfg(target_os = "linux")]
    let parent = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            #[cfg(target_os = "linux")]
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 || libc::getppid() != parent {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(fd, 3) < 0
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
                || libc::lseek(3, 0, libc::SEEK_SET) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = Child(
        command
            .spawn()
            .map_err(|_| failure("Cannot launch journaled vpnc lifecycle"))?,
    );
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| failure("Missing lifecycle requests"))?;
    let mut stdin = child
        .0
        .stdin
        .take()
        .ok_or_else(|| failure("Missing lifecycle acknowledgements"))?;
    let (tx, rx) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || {
        let mut input = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            let result = (&mut input).take(513).read_line(&mut line);
            match result {
                Ok(0) => break,
                Ok(_) if line.len() <= 512 && line.ends_with('\n') => {
                    if tx.send(Ok(line)).is_err() {
                        break;
                    }
                }
                _ => {
                    let _ = tx.send(Err(failure("Malformed lifecycle operation")));
                    break;
                }
            }
        }
    });
    let mut visited = vec![false; mutations.len()];
    loop {
        let remaining = until.saturating_duration_since(Instant::now());
        let line = match rx.recv_timeout(remaining) {
            Ok(line) => line?,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(_) => return Err(failure("vpnc lifecycle exceeded deadline")),
        };
        let request = line.trim_end_matches('\n');
        let key = request.strip_suffix(" -").unwrap_or(request);
        if key == "gateway" && !groups.contains_key(key) && config.transport_peer.is_loopback() {
            // Upstream disconnect calls this even when connect skipped loopback.
        } else {
            let indices = groups
                .get(key)
                .ok_or_else(|| failure("Unplanned vpnc lifecycle operation"))?;
            let ordered: Vec<_> = if reason == NetworkReason::Disconnect {
                indices.iter().rev().copied().collect()
            } else {
                indices.clone()
            };
            for i in ordered {
                if visited[i] {
                    return Err(failure("Replayed vpnc lifecycle operation"));
                }
                operation(i)?;
                visited[i] = true;
            }
        }
        stdin
            .write_all(b"ok\n")
            .map_err(|_| failure("Lifecycle acknowledgement failed"))?;
    }
    drop(stdin);
    loop {
        match child.0.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return Err(failure("vpnc lifecycle failed")),
            Ok(None) if Instant::now() < until => thread::sleep(Duration::from_millis(10)),
            _ => return Err(failure("vpnc lifecycle exceeded deadline")),
        }
    }
    reader
        .join()
        .map_err(|_| failure("Lifecycle request reader failed"))?;
    if visited.iter().any(|v| !v) {
        return Err(failure("vpnc lifecycle omitted a planned mutation"));
    }
    Ok(())
}
