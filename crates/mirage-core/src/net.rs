//! TCP connect: address family selection, source address binding and a simple
//! Happy Eyeballs (RFC 8305 style): addresses are interleaved by family and a new
//! attempt starts every 250 ms (or as soon as the previous one fails); first success wins.

use crate::error::{Error, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;

const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum IpFamily {
    /// Both families, Happy Eyeballs.
    #[default]
    Auto,
    V4,
    V6,
}

impl IpFamily {
    pub fn parse(s: &str) -> Result<IpFamily> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "" | "auto" => IpFamily::Auto,
            "ipv4" | "v4" | "4" => IpFamily::V4,
            "ipv6" | "v6" | "6" => IpFamily::V6,
            other => return Err(Error::Url(format!("invalid ipFamily '{other}' (auto | ipv4 | ipv6)"))),
        })
    }

    fn allows(self, ip: &IpAddr) -> bool {
        match self {
            IpFamily::Auto => true,
            IpFamily::V4 => ip.is_ipv4(),
            IpFamily::V6 => ip.is_ipv6(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NetOptions {
    pub local_address: Option<IpAddr>,
    pub family: IpFamily,
}

impl NetOptions {
    /// Address family actually usable (a bound source address fixes it).
    fn family(&self) -> IpFamily {
        match self.local_address {
            Some(IpAddr::V4(_)) => IpFamily::V4,
            Some(IpAddr::V6(_)) => IpFamily::V6,
            None => self.family,
        }
    }
}

/// Resolve `host` and keep the addresses allowed by `opts`, in connect order.
pub async fn resolve(host: &str, port: u16, opts: &NetOptions) -> Result<Vec<SocketAddr>> {
    let family = opts.family();
    if opts.local_address.is_some() && opts.family != IpFamily::Auto && opts.family != family {
        return Err(Error::Url("localAddress does not match ipFamily".into()));
    }
    let all: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => tokio::net::lookup_host((host, port)).await?.collect(),
    };
    let addrs: Vec<SocketAddr> = all.into_iter().filter(|a| family.allows(&a.ip())).collect();
    if addrs.is_empty() {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{host}: no {} address", match family {
                IpFamily::V4 => "IPv4",
                IpFamily::V6 => "IPv6",
                IpFamily::Auto => "usable",
            }),
        )));
    }
    Ok(interleave(addrs))
}

/// Alternate families, starting with the family of the first resolved address.
fn interleave(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_v6 = addrs[0].is_ipv6();
    let (mut a, mut b): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|x| x.is_ipv6() == first_v6);
    let mut out = Vec::with_capacity(a.len() + b.len());
    a.reverse();
    b.reverse();
    loop {
        match (a.pop(), b.pop()) {
            (None, None) => return out,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
}

async fn connect_one(addr: SocketAddr, local: Option<IpAddr>) -> std::io::Result<TcpStream> {
    let s = match local {
        None => TcpStream::connect(addr).await?,
        Some(ip) => {
            let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
            sock.bind(SocketAddr::new(ip, 0))?;
            sock.connect(addr).await?
        }
    };
    s.set_nodelay(true)?;
    Ok(s)
}

/// Connect to the first reachable address (staggered attempts).
pub async fn connect_addrs(addrs: Vec<SocketAddr>, local: Option<IpAddr>) -> Result<TcpStream> {
    let mut pending = addrs.into_iter();
    let mut set = JoinSet::new();
    let mut last_err: Option<std::io::Error> = None;
    let mut start_next = true;
    loop {
        if start_next {
            if let Some(a) = pending.next() {
                set.spawn(connect_one(a, local));
            }
        }
        if set.is_empty() {
            return Err(last_err
                .map(Error::Io)
                .unwrap_or_else(|| Error::Http("no address to connect to".into())));
        }
        let more = pending.len() > 0;
        tokio::select! {
            res = set.join_next() => match res {
                Some(Ok(Ok(s))) => return Ok(s), // dropping the set aborts the other attempts
                Some(Ok(Err(e))) => { last_err = Some(e); start_next = true; }
                Some(Err(e)) => { last_err = Some(std::io::Error::other(e.to_string())); start_next = true; }
                None => start_next = true,
            },
            _ = tokio::time::sleep(ATTEMPT_DELAY), if more => start_next = true,
        }
    }
}

pub async fn connect(host: &str, port: u16, opts: &NetOptions) -> Result<TcpStream> {
    let addrs = resolve(host, port, opts).await?;
    connect_addrs(addrs, opts.local_address).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interleaves_families() {
        let v4 = |n| SocketAddr::new(IpAddr::from([10, 0, 0, n]), 1);
        let v6 = |n| SocketAddr::new(IpAddr::from([0, 0, 0, 0, 0, 0, 0, n as u16]), 1);
        let out = interleave(vec![v6(1), v6(2), v6(3), v4(1)]);
        assert_eq!(out, vec![v6(1), v4(1), v6(2), v6(3)]);
    }

    #[tokio::test]
    async fn falls_through_dead_addresses() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good = l.local_addr().unwrap();
        // A closed port first: refused immediately, then the next address is tried.
        let dead = {
            let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            t.local_addr().unwrap()
        };
        let s = connect_addrs(vec![dead, good], Some("127.0.0.1".parse().unwrap())).await.unwrap();
        assert_eq!(s.peer_addr().unwrap(), good);
        let opts = NetOptions { local_address: None, family: IpFamily::V6 };
        assert!(resolve("127.0.0.1", 80, &opts).await.is_err());
    }
}
