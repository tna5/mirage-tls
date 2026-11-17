//! Browser fingerprint profiles.
//!
//! A profile is resolved from a *family* file (`profiles/<family>.toml`) by name:
//!
//! ```text
//! <family>[_<major>][_<platform>]      e.g. chrome, chrome_157, chrome_157_windows, safari_ios_26
//! ```
//!
//! The family file contains the TLS / HTTP2 / header fingerprint, a `[meta]` table,
//! optional `[vars]` used for `{placeholder}` substitution, and `[platforms.<name>]`
//! overlays that are deep-merged on top of the base profile.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use toml::Value;

/// Built-in family files, embedded at compile time.
const FAMILIES: &[(&str, &str)] = &[
    ("chrome", include_str!("../../../profiles/chrome.toml")),
    ("edge", include_str!("../../../profiles/edge.toml")),
    ("firefox", include_str!("../../../profiles/firefox.toml")),
    ("safari", include_str!("../../../profiles/safari.toml")),
    ("safari_ios", include_str!("../../../profiles/safari_ios.toml")),
    ("okhttp", include_str!("../../../profiles/okhttp.toml")),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub name: String,
    pub tls: TlsProfile,
    pub http2: Http2Profile,
    pub headers: HeaderProfile,
    #[serde(default)]
    pub meta: ProfileMeta,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfileMeta {
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub major: u32,
    #[serde(default)]
    pub platform: String,
    /// true once the profile was checked against a real capture of the browser.
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub notes: String,
}

fn t() -> bool {
    true
}
fn v12() -> String {
    "1.2".into()
}
fn v13() -> String {
    "1.3".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsProfile {
    #[serde(default = "v12")]
    pub min_version: String,
    #[serde(default = "v13")]
    pub max_version: String,
    /// Cipher suites, IANA names, in ClientHello order (TLS 1.3 suites included).
    pub ciphers: Vec<String>,
    /// Supported groups, BoringSSL names (X25519MLKEM768, X25519, P-256, ffdhe2048...).
    pub curves: Vec<String>,
    /// Signature algorithms in ClientHello order: names (ecdsa_secp256r1_sha256, mldsa65...)
    /// or hex codepoints ("0x0905"). Codepoints unknown to BoringSSL are only advertised.
    pub sigalgs: Vec<String>,
    /// Prepend a GREASE value to signature_algorithms (Chrome).
    #[serde(default)]
    pub sigalgs_grease: bool,
    /// Raw body of the trust_anchors extension (0xca34), hex encoded (Chrome).
    #[serde(default)]
    pub trust_anchors: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Protocols advertised in the ALPS (application_settings) extension.
    #[serde(default)]
    pub alps: Vec<String>,
    #[serde(default)]
    pub alps_new_codepoint: bool,
    #[serde(default)]
    pub grease: bool,
    /// Randomly permute extensions on every connection (Chrome >= 110).
    #[serde(default)]
    pub permute_extensions: bool,
    /// Fixed extension order (Firefox, Safari, OkHttp). Ignored when permute_extensions = true.
    #[serde(default)]
    pub extension_order: Option<Vec<String>>,
    #[serde(default)]
    pub ech_grease: bool,
    /// brotli | zlib | zstd, in order.
    #[serde(default)]
    pub cert_compression: Vec<String>,
    #[serde(default)]
    pub ocsp_stapling: bool,
    #[serde(default)]
    pub signed_cert_timestamps: bool,
    #[serde(default = "t")]
    pub session_ticket: bool,
    /// Resume sessions with PSK (pre_shared_key extension on reconnect).
    #[serde(default = "t")]
    pub resumption: bool,
    #[serde(default)]
    pub record_size_limit: Option<u16>,
    #[serde(default)]
    pub delegated_credentials: Option<Vec<String>>,
    #[serde(default)]
    pub key_shares_limit: Option<u8>,
    #[serde(default)]
    pub aes_hw_override: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Priority {
    /// 1..=256 (the wire value is weight - 1).
    pub weight: u16,
    #[serde(default)]
    pub depends_on: u32,
    #[serde(default)]
    pub exclusive: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PriorityFrame {
    pub stream_id: u32,
    pub weight: u16,
    #[serde(default)]
    pub depends_on: u32,
    #[serde(default)]
    pub exclusive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Profile {
    /// SETTINGS frame, in order: [id, value].
    pub settings: Vec<(u16, u32)>,
    /// Connection-level WINDOW_UPDATE increment sent after SETTINGS (0 = none).
    #[serde(default)]
    pub window_update: u32,
    /// Order of :method :authority :scheme :path, given as "m","a","s","p" or full names.
    pub pseudo_header_order: Vec<String>,
    /// Priority flag carried on HEADERS frames.
    #[serde(default)]
    pub headers_priority: Option<Priority>,
    /// PRIORITY frames sent right after the preface (old Firefox style).
    #[serde(default)]
    pub priority_frames: Vec<PriorityFrame>,
    /// Stream id of the first request (default 1).
    #[serde(default)]
    pub initial_stream_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderProfile {
    /// Default headers, in browser order. Names keep their casing for HTTP/1.1.
    pub default: Vec<(String, String)>,
    /// Header order (lowercase). Headers not listed keep insertion order at the end.
    /// Defaults to the order of `default`.
    #[serde(default)]
    pub order: Vec<String>,
    /// Exact casing used on HTTP/1.1 (e.g. "User-Agent"). HTTP/2 always lowercases.
    #[serde(default)]
    pub h1_case: Vec<String>,
}

impl Profile {
    /// Resolve a built-in profile by name.
    pub fn get(name: &str) -> Result<Profile> {
        let (family, src) = FAMILIES
            .iter()
            .filter(|(f, _)| name == *f || name.starts_with(&format!("{f}_")))
            .max_by_key(|(f, _)| f.len())
            .ok_or_else(|| Error::Profile(format!("unknown profile '{name}'")))?;
        let rest: Vec<&str> = name[family.len()..]
            .split('_')
            .filter(|s| !s.is_empty())
            .collect();
        let mut major = None;
        let mut platform = None;
        for part in rest {
            if let Ok(n) = part.parse::<u32>() {
                if major.is_some() {
                    return Err(Error::Profile(format!("bad profile name '{name}'")));
                }
                major = Some(n);
            } else if platform.is_none() {
                platform = Some(part.to_string());
            } else {
                return Err(Error::Profile(format!("bad profile name '{name}'")));
            }
        }
        let doc: Value = toml::from_str(src)
            .map_err(|e| Error::Profile(format!("{family}.toml: {e}")))?;
        let mut p = resolve(doc, major, platform.as_deref())?;
        p.name = name.to_string();
        Ok(p)
    }

    /// Build a profile from a JSON document. It may contain `"extends": "<builtin name>"`,
    /// in which case the given fields are deep-merged on top of that profile.
    pub fn from_json(json: &str) -> Result<Profile> {
        let v: serde_json::Value = serde_json::from_str(json)?;
        let mut v: Value = serde_json::from_value(v)
            .map_err(|e| Error::Profile(format!("invalid profile: {e}")))?;
        let base = v
            .as_table_mut()
            .and_then(|t| t.remove("extends"))
            .and_then(|e| e.as_str().map(String::from));
        let merged = match base {
            Some(b) => {
                let base = Profile::get(&b)?;
                let mut bv = Value::try_from(&base)
                    .map_err(|e| Error::Profile(e.to_string()))?;
                merge(&mut bv, v);
                bv
            }
            None => v,
        };
        let mut p: Profile = merged
            .try_into()
            .map_err(|e| Error::Profile(format!("invalid profile: {e}")))?;
        if p.name.is_empty() {
            p.name = "custom".into();
        }
        Ok(p)
    }

    /// Names of the built-in families with their default and supported versions.
    pub fn families() -> Vec<FamilyInfo> {
        FAMILIES
            .iter()
            .filter_map(|(name, src)| {
                let doc: Value = toml::from_str(src).ok()?;
                let meta = doc.get("meta")?;
                let int = |k: &str| meta.get(k).and_then(|v| v.as_integer()).unwrap_or(0) as u32;
                let platforms = doc
                    .get("platforms")
                    .and_then(|p| p.as_table())
                    .map(|t| t.keys().cloned().collect())
                    .unwrap_or_default();
                Some(FamilyInfo {
                    family: name.to_string(),
                    default_major: int("default_major"),
                    min_major: int("min_major"),
                    max_major: int("max_major"),
                    default_platform: meta
                        .get("default_platform")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    platforms,
                    verified: meta.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
                })
            })
            .collect()
    }

    /// Header order as lowercase names.
    pub fn header_order(&self) -> Vec<String> {
        if self.headers.order.is_empty() {
            self.headers.default.iter().map(|(k, _)| k.to_ascii_lowercase()).collect()
        } else {
            self.headers.order.iter().map(|k| k.to_ascii_lowercase()).collect()
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FamilyInfo {
    pub family: String,
    pub default_major: u32,
    pub min_major: u32,
    pub max_major: u32,
    pub default_platform: String,
    pub platforms: Vec<String>,
    pub verified: bool,
}

fn resolve(mut doc: Value, major: Option<u32>, platform: Option<&str>) -> Result<Profile> {
    let table = doc
        .as_table_mut()
        .ok_or_else(|| Error::Profile("profile must be a table".into()))?;
    let meta = table.get("meta").cloned().unwrap_or(Value::Table(Default::default()));
    let get_int = |k: &str| meta.get(k).and_then(|v| v.as_integer()).map(|v| v as u32);
    let get_str = |k: &str| meta.get(k).and_then(|v| v.as_str()).map(String::from);
    let family = get_str("family").unwrap_or_default();

    let major = major.or(get_int("default_major")).unwrap_or(0);
    if let Some(min) = get_int("min_major") {
        if major < min {
            return Err(Error::Profile(format!(
                "{family} {major} is not supported (minimum {min}: older versions use a different fingerprint)"
            )));
        }
    }
    if let Some(max) = get_int("max_major") {
        if major > max {
            return Err(Error::Profile(format!("{family} {major} is not supported (maximum {max})")));
        }
    }

    let platform = platform
        .map(String::from)
        .or(get_str("default_platform"))
        .unwrap_or_default();
    let platforms = table.remove("platforms");
    if let Some(Value::Table(mut ps)) = platforms {
        match ps.remove(&platform) {
            Some(overlay) => merge(&mut doc, overlay),
            None if !ps.is_empty() || !platform.is_empty() => {
                let mut names: Vec<_> = ps.keys().cloned().collect();
                names.sort();
                return Err(Error::Profile(format!(
                    "unknown platform '{platform}' for {family} (available: {})",
                    names.join(", ")
                )));
            }
            None => {}
        }
    }

    // [before.<N>] overlays apply when major < N; lower N wins.
    if let Some(Value::Table(before)) = doc.as_table_mut().unwrap().remove("before") {
        let mut overlays: Vec<(u32, Value)> = before
            .into_iter()
            .filter_map(|(k, v)| k.parse::<u32>().ok().map(|n| (n, v)))
            .filter(|(n, _)| major < *n)
            .collect();
        overlays.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, o) in overlays {
            merge(&mut doc, o);
        }
    }

    let table = doc.as_table_mut().unwrap();
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    if let Some(Value::Table(v)) = table.remove("vars") {
        for (k, v) in v {
            let s = match v {
                Value::String(s) => s,
                other => other.to_string(),
            };
            vars.insert(k, s);
        }
    }
    vars.insert("major".into(), major.to_string());
    if let Some(brand) = vars.get("brand").cloned() {
        vars.insert("sec_ch_ua".into(), chromium_sec_ch_ua(&brand, major));
    }
    // Vars may reference each other once (e.g. ua uses {major}).
    let snapshot = vars.clone();
    for v in vars.values_mut() {
        *v = substitute(v, &snapshot);
    }
    substitute_all(&mut doc, &vars);

    let t = doc.as_table_mut().unwrap();
    let mut meta_out = ProfileMeta {
        family,
        major,
        platform,
        verified: meta.get("verified").and_then(|v| v.as_bool()).unwrap_or(false),
        notes: get_str("notes").unwrap_or_default(),
    };
    t.remove("meta");
    let mut p: Profile = doc
        .try_into()
        .map_err(|e| Error::Profile(format!("invalid profile: {e}")))?;
    std::mem::swap(&mut p.meta, &mut meta_out);
    Ok(p)
}

/// Deep merge `over` into `base`: tables are merged, everything else replaced.
fn merge(base: &mut Value, over: Value) {
    match (base, over) {
        (Value::Table(b), Value::Table(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(existing) => merge(existing, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (b, o) => *b = o,
    }
}

fn substitute(s: &str, vars: &BTreeMap<String, String>) -> String {
    if !s.contains('{') {
        return s.to_string();
    }
    let mut out = s.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

fn substitute_all(v: &mut Value, vars: &BTreeMap<String, String>) {
    match v {
        Value::String(s) => *s = substitute(s, vars),
        Value::Array(a) => a.iter_mut().for_each(|x| substitute_all(x, vars)),
        Value::Table(t) => t.iter_mut().for_each(|(_, x)| substitute_all(x, vars)),
        _ => {}
    }
}

/// Reproduces Chromium's `sec-ch-ua` brand list GREASE algorithm
/// (components/embedder_support/user_agent_utils.cc), seeded by the major version.
pub fn chromium_sec_ch_ua(brand: &str, major: u32) -> String {
    const CHARS: [char; 11] = [' ', '(', ':', '-', '.', '/', ')', ';', '=', '?', '_'];
    const VERSIONS: [&str; 3] = ["8", "99", "24"];
    const ORDERS: [[usize; 3]; 6] = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
    let seed = major as usize;
    let grease_brand = format!(
        "Not{}A{}Brand",
        CHARS[seed % CHARS.len()],
        CHARS[(seed + 1) % CHARS.len()]
    );
    let grease_version = VERSIONS[seed % VERSIONS.len()];
    let order = ORDERS[seed % ORDERS.len()];
    let items = [
        format!("\"{grease_brand}\";v=\"{grease_version}\""),
        format!("\"Chromium\";v=\"{major}\""),
        format!("\"{brand}\";v=\"{major}\""),
    ];
    let mut out: [String; 3] = Default::default();
    for (i, item) in items.into_iter().enumerate() {
        out[order[i]] = item;
    }
    out.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_ch_ua_matches_real_chrome() {
        // Values observed on real Chrome builds.
        assert_eq!(
            chromium_sec_ch_ua("Google Chrome", 131),
            r#""Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24""#
        );
        assert_eq!(
            chromium_sec_ch_ua("Google Chrome", 120),
            r#""Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120""#
        );
    }

    #[test]
    fn all_families_resolve() {
        for f in Profile::families() {
            let p = Profile::get(&f.family).unwrap();
            assert!(!p.tls.ciphers.is_empty(), "{}", f.family);
            for plat in &f.platforms {
                Profile::get(&format!("{}_{}", f.family, plat)).unwrap();
            }
        }
        let p = Profile::get("chrome_157_windows").unwrap();
        assert_eq!(p.meta.major, 157);
        assert!(p
            .headers
            .default
            .iter()
            .any(|(k, v)| k == "user-agent" && v.contains("Chrome/157.0.0.0") && v.contains("Windows")));
        assert!(Profile::get("chrome_100").is_err());
        assert!(Profile::get("nope").is_err());
    }

    #[test]
    fn json_extends() {
        let p = Profile::from_json(r#"{"extends":"firefox","http2":{"window_update":1}}"#).unwrap();
        assert_eq!(p.http2.window_update, 1);
        assert!(!p.tls.ciphers.is_empty());
    }
}
