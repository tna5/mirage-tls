//! Fetch-metadata computed like Chromium: `Sec-Fetch-Site`, `Referer` (referrer policy)
//! and `Origin`, re-evaluated on every redirect hop.
//!
//! - Sec-Fetch-Site (services/network/sec_header_helpers.cc): requests without an initiator
//!   (browser-initiated navigations) send `none` on every hop; otherwise the value is the
//!   "most cross" relation between the initiator and every URL of the redirect chain:
//!   same-origin < same-site (schemeful: same scheme and registrable domain, private
//!   registries included, crbug.com/979257) < cross-site.
//! - Referer: the original referrer is re-stripped for each hop according to the policy
//!   (default `strict-origin-when-cross-origin`).
//! - Origin (Fetch "append a request Origin header"): sent for CORS-mode requests to
//!   another origin, and for every method other than GET/HEAD; becomes `null` once a
//!   redirect chain is tainted (cross-origin hop away from a cross-origin URL).

use url::{Origin, Url};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
}

impl ReferrerPolicy {
    /// Unknown / empty values fall back to the default, as browsers do.
    pub fn parse(s: &str) -> ReferrerPolicy {
        match s.trim().to_ascii_lowercase().as_str() {
            "no-referrer" => ReferrerPolicy::NoReferrer,
            "no-referrer-when-downgrade" => ReferrerPolicy::NoReferrerWhenDowngrade,
            "origin" => ReferrerPolicy::Origin,
            "origin-when-cross-origin" => ReferrerPolicy::OriginWhenCrossOrigin,
            "same-origin" => ReferrerPolicy::SameOrigin,
            "strict-origin" => ReferrerPolicy::StrictOrigin,
            "unsafe-url" => ReferrerPolicy::UnsafeUrl,
            _ => ReferrerPolicy::StrictOriginWhenCrossOrigin,
        }
    }
}

/// Registrable domain ("site") of a host; IPs and hosts without a public suffix are
/// their own site.
pub fn site(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return host;
    }
    psl::domain_str(&host).map(String::from).unwrap_or(host)
}

fn same_site(a: &Origin, b: &Origin) -> bool {
    match (a, b) {
        (Origin::Tuple(sa, ha, _), Origin::Tuple(sb, hb, _)) => {
            sa == sb && site(&ha.to_string()) == site(&hb.to_string())
        }
        _ => false,
    }
}

/// `Sec-Fetch-Site` for a request whose redirect chain so far is `urls` (current last).
pub fn sec_fetch_site(initiator: Option<&Origin>, urls: &[Url]) -> &'static str {
    let Some(init) = initiator else { return "none" };
    let mut v = 0;
    for u in urls {
        let o = u.origin();
        let rel = if &o == init {
            0
        } else if same_site(init, &o) {
            1
        } else {
            2
        };
        v = v.max(rel);
    }
    ["same-origin", "same-site", "cross-site"][v]
}

fn is_secure(u: &Url) -> bool {
    matches!(u.scheme(), "https" | "wss")
}

fn origin_only(u: &Url) -> Option<String> {
    let o = u.origin();
    o.is_tuple().then(|| format!("{}/", o.ascii_serialization()))
}

/// The `Referer` value for a request to `target` (None = header omitted).
pub fn referrer_value(referrer: &Url, target: &Url, policy: ReferrerPolicy) -> Option<String> {
    if !matches!(referrer.scheme(), "http" | "https") {
        return None;
    }
    let mut full = referrer.clone();
    full.set_fragment(None);
    let _ = full.set_username("");
    let _ = full.set_password(None);
    let full = full.to_string();
    let same = referrer.origin() == target.origin();
    let downgrade = is_secure(referrer) && !is_secure(target);
    use ReferrerPolicy::*;
    match policy {
        NoReferrer => None,
        UnsafeUrl => Some(full),
        Origin => origin_only(referrer),
        NoReferrerWhenDowngrade => (!downgrade).then_some(full),
        SameOrigin => same.then_some(full),
        OriginWhenCrossOrigin => if same { Some(full) } else { origin_only(referrer) },
        StrictOrigin => if downgrade { None } else { origin_only(referrer) },
        StrictOriginWhenCrossOrigin => {
            if same {
                Some(full)
            } else if downgrade {
                None
            } else {
                origin_only(referrer)
            }
        }
    }
}

/// True once a redirect chain is "tainted" (Fetch: redirect-tainted origin).
pub fn redirect_tainted(initiator: &Origin, urls: &[Url]) -> bool {
    urls.windows(2).any(|w| {
        let (last, cur) = (w[0].origin(), w[1].origin());
        last != cur && &last != initiator
    })
}

/// The `Origin` header value, if one must be sent.
pub fn origin_value(
    initiator: Option<&Origin>,
    urls: &[Url],
    method: &str,
    cors: bool,
    policy: ReferrerPolicy,
) -> Option<String> {
    let init = initiator?;
    let target = urls.last()?;
    let ser = || {
        if redirect_tainted(init, urls) || !init.is_tuple() {
            "null".to_string()
        } else {
            init.ascii_serialization()
        }
    };
    let cross = &target.origin() != init;
    if cors && (cross || redirect_tainted(init, urls)) {
        return Some(ser());
    }
    if matches!(method, "GET" | "HEAD") {
        return None;
    }
    // Non-CORS requests: the referrer policy may hide the origin.
    let secure_init = matches!(init, Origin::Tuple(s, _, _) if s == "https");
    let hide = match policy {
        ReferrerPolicy::NoReferrer => true,
        ReferrerPolicy::NoReferrerWhenDowngrade
        | ReferrerPolicy::StrictOrigin
        | ReferrerPolicy::StrictOriginWhenCrossOrigin => secure_init && !is_secure(target),
        ReferrerPolicy::SameOrigin => cross,
        _ => false,
    };
    Some(if hide { "null".into() } else { ser() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn sites() {
        assert_eq!(site("www.example.co.uk"), "example.co.uk");
        assert_eq!(site("a.b.github.io"), "b.github.io"); // private registry
        assert_eq!(site("localhost"), "localhost");
        assert_eq!(site("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn fetch_site_across_redirects() {
        let init = u("https://www.example.com/page").origin();
        let a = u("https://www.example.com/a");
        let b = u("https://api.example.com/b");
        let c = u("https://other.org/c");
        assert_eq!(sec_fetch_site(Some(&init), &[a.clone()]), "same-origin");
        assert_eq!(sec_fetch_site(Some(&init), &[b.clone()]), "same-site");
        assert_eq!(sec_fetch_site(Some(&init), &[a.clone(), b.clone()]), "same-site");
        // Back to same-origin after a cross-site hop stays cross-site.
        assert_eq!(sec_fetch_site(Some(&init), &[c.clone(), a.clone()]), "cross-site");
        // Schemeful same-site.
        assert_eq!(sec_fetch_site(Some(&init), &[u("http://api.example.com/")]), "cross-site");
        assert_eq!(sec_fetch_site(None, &[a, c]), "none");
    }

    #[test]
    fn referrer_policies() {
        let r = u("https://user:pw@a.com/x/y?q=1#frag");
        let same = u("https://a.com/z");
        let cross = u("https://b.com/");
        let down = u("http://a.com/");
        let p = ReferrerPolicy::parse("");
        assert_eq!(referrer_value(&r, &same, p).as_deref(), Some("https://a.com/x/y?q=1"));
        assert_eq!(referrer_value(&r, &cross, p).as_deref(), Some("https://a.com/"));
        assert_eq!(referrer_value(&r, &down, p), None);
        assert_eq!(referrer_value(&r, &cross, ReferrerPolicy::NoReferrer), None);
        assert_eq!(
            referrer_value(&r, &down, ReferrerPolicy::UnsafeUrl).as_deref(),
            Some("https://a.com/x/y?q=1")
        );
        assert_eq!(referrer_value(&r, &cross, ReferrerPolicy::SameOrigin), None);
    }

    #[test]
    fn origin_rules() {
        let init = u("https://a.com/").origin();
        let p = ReferrerPolicy::StrictOriginWhenCrossOrigin;
        let same = [u("https://a.com/api")];
        let cross = [u("https://b.com/api")];
        assert_eq!(origin_value(Some(&init), &same, "GET", true, p), None);
        assert_eq!(origin_value(Some(&init), &cross, "GET", true, p).as_deref(), Some("https://a.com"));
        assert_eq!(origin_value(Some(&init), &same, "POST", true, p).as_deref(), Some("https://a.com"));
        assert_eq!(origin_value(Some(&init), &cross, "GET", false, p), None);
        assert_eq!(origin_value(Some(&init), &same, "POST", false, p).as_deref(), Some("https://a.com"));
        let tainted = [u("https://b.com/"), u("https://c.com/")];
        assert_eq!(origin_value(Some(&init), &tainted, "GET", true, p).as_deref(), Some("null"));
        assert_eq!(origin_value(None, &same, "POST", true, p), None);
    }
}
