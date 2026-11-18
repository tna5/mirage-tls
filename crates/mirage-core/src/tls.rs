//! BoringSSL connector configured from a [`TlsProfile`].

use crate::error::{Error, Result};
use crate::profile::{Profile, TlsProfile};
use boring2::ssl::{
    CertCompressionAlgorithm, ExtensionType, SslConnector, SslMethod, SslOptions, SslSession,
    SslSessionCacheMode, SslVerifyMode, SslVersion,
};
use boring2::x509::X509;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_boring2::SslStream;

type SessionCache = Arc<Mutex<HashMap<String, SslSession>>>;

#[derive(Clone)]
pub struct TlsConnector {
    connector: SslConnector,
    profile: Arc<Profile>,
    sessions: SessionCache,
    resumption: bool,
    ech_grease: bool,
}

#[derive(Debug, Clone)]
pub struct TlsOptions {
    /// Skip certificate verification.
    pub insecure: bool,
    /// Extra PEM CA bundle.
    pub ca_pem: Option<Vec<u8>>,
    /// Override ALPN (e.g. force http/1.1).
    pub alpn: Option<Vec<String>>,
    /// Allow session resumption (when the profile does). The session_ticket extension is
    /// still advertised as the profile says; only cached sessions are not offered.
    pub resumption: bool,
    /// Allow ECH GREASE (when the profile does). Turning it off changes the fingerprint.
    pub ech_grease: bool,
}

impl Default for TlsOptions {
    fn default() -> Self {
        TlsOptions { insecure: false, ca_pem: None, alpn: None, resumption: true, ech_grease: true }
    }
}

fn session_key_index() -> boring2::ex_data::Index<boring2::ssl::Ssl, String> {
    static IDX: OnceLock<boring2::ex_data::Index<boring2::ssl::Ssl, String>> = OnceLock::new();
    *IDX.get_or_init(|| boring2::ssl::Ssl::new_ex_index().expect("ex index"))
}

fn version(v: &str) -> Result<SslVersion> {
    Ok(match v {
        "1.0" => SslVersion::TLS1,
        "1.1" => SslVersion::TLS1_1,
        "1.2" => SslVersion::TLS1_2,
        "1.3" => SslVersion::TLS1_3,
        other => return Err(Error::Profile(format!("unknown TLS version '{other}'"))),
    })
}

fn extension(name: &str) -> Result<ExtensionType> {
    Ok(match name {
        "server_name" => ExtensionType::SERVER_NAME,
        "status_request" => ExtensionType::STATUS_REQUEST,
        "ec_point_formats" => ExtensionType::EC_POINT_FORMATS,
        "signature_algorithms" => ExtensionType::SIGNATURE_ALGORITHMS,
        "srtp" => ExtensionType::SRTP,
        "application_layer_protocol_negotiation" | "alpn" => {
            ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        }
        "padding" => ExtensionType::PADDING,
        "extended_master_secret" => ExtensionType::EXTENDED_MASTER_SECRET,
        "cert_compression" | "compress_certificate" => ExtensionType::CERT_COMPRESSION,
        "session_ticket" => ExtensionType::SESSION_TICKET,
        "supported_groups" => ExtensionType::SUPPORTED_GROUPS,
        "pre_shared_key" => ExtensionType::PRE_SHARED_KEY,
        "early_data" => ExtensionType::EARLY_DATA,
        "supported_versions" => ExtensionType::SUPPORTED_VERSIONS,
        "cookie" => ExtensionType::COOKIE,
        "psk_key_exchange_modes" => ExtensionType::PSK_KEY_EXCHANGE_MODES,
        "certificate_authorities" => ExtensionType::CERTIFICATE_AUTHORITIES,
        "signature_algorithms_cert" => ExtensionType::SIGNATURE_ALGORITHMS_CERT,
        "key_share" => ExtensionType::KEY_SHARE,
        "renegotiate" | "renegotiation_info" => ExtensionType::RENEGOTIATE,
        "delegated_credential" | "delegated_credentials" => ExtensionType::DELEGATED_CREDENTIAL,
        "application_settings" => ExtensionType::APPLICATION_SETTINGS,
        "application_settings_new" => ExtensionType::APPLICATION_SETTINGS_NEW,
        "encrypted_client_hello" => ExtensionType::ENCRYPTED_CLIENT_HELLO,
        "certificate_timestamp" | "signed_certificate_timestamp" => {
            ExtensionType::CERTIFICATE_TIMESTAMP
        }
        "next_proto_neg" => ExtensionType::NEXT_PROTO_NEG,
        "channel_id" => ExtensionType::CHANNEL_ID,
        "record_size_limit" => ExtensionType::RECORD_SIZE_LIMIT,
        other => {
            if let Ok(n) = other.parse::<u16>() {
                ExtensionType::from(n)
            } else {
                return Err(Error::Profile(format!("unknown TLS extension '{other}'")));
            }
        }
    })
}

/// (name, codepoint, known to BoringSSL for verification)
const SIGALGS: &[(&str, u16, bool)] = &[
    ("rsa_pkcs1_sha1", 0x0201, true),
    ("ecdsa_sha1", 0x0203, true),
    ("rsa_pkcs1_sha256", 0x0401, true),
    ("ecdsa_secp256r1_sha256", 0x0403, true),
    ("rsa_pkcs1_sha384", 0x0501, true),
    ("ecdsa_secp384r1_sha384", 0x0503, true),
    ("rsa_pkcs1_sha512", 0x0601, true),
    ("ecdsa_secp521r1_sha512", 0x0603, true),
    ("rsa_pss_rsae_sha256", 0x0804, true),
    ("rsa_pss_rsae_sha384", 0x0805, true),
    ("rsa_pss_rsae_sha512", 0x0806, true),
    ("ed25519", 0x0807, true),
    ("ed448", 0x0808, false),
    ("rsa_pss_pss_sha256", 0x0809, false),
    ("rsa_pss_pss_sha384", 0x080a, false),
    ("rsa_pss_pss_sha512", 0x080b, false),
    ("mldsa44", 0x0904, false),
    ("mldsa65", 0x0905, false),
    ("mldsa87", 0x0906, false),
];

/// Resolve sigalgs to (advertised codepoints, names usable for verification).
fn sigalgs(list: &[String]) -> Result<(Vec<u16>, Vec<&'static str>, bool)> {
    let mut codes = Vec::new();
    let mut verify = Vec::new();
    let mut needs_raw = false;
    for s in list {
        let entry = if let Some(hex) = s.strip_prefix("0x") {
            let code = u16::from_str_radix(hex, 16)
                .map_err(|_| Error::Profile(format!("bad sigalg '{s}'")))?;
            SIGALGS.iter().find(|(_, c, _)| *c == code).copied().map(Ok).unwrap_or(Ok(("", code, false)))
        } else {
            SIGALGS
                .iter()
                .find(|(n, _, _)| *n == s)
                .copied()
                .ok_or_else(|| Error::Profile(format!("unknown sigalg '{s}'")))
        }?;
        codes.push(entry.1);
        if entry.2 {
            verify.push(entry.0);
        } else {
            needs_raw = true;
        }
    }
    Ok((codes, verify, needs_raw))
}

/// Index of an extension in the (patched) BoringSSL kExtensions table.
fn extension_index(name: &str) -> Result<u8> {
    if matches!(name, "trust_anchors" | "51764" | "0xca34") {
        return Ok(ExtensionType::BORING_SSLEXTENSION_PERMUTATION.len() as u8);
    }
    let ext = extension(name)?;
    ExtensionType::index_of(ext)
        .map(|i| i as u8)
        .ok_or_else(|| Error::Profile(format!("extension '{name}' cannot be ordered")))
}

fn hex(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return Err(Error::Profile("odd hex length".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::Profile("bad hex".into())))
        .collect()
}

fn alpn_wire(protos: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in protos {
        out.push(p.len() as u8);
        out.extend_from_slice(p.as_bytes());
    }
    out
}

fn root_store_der() -> &'static [Vec<u8>] {
    static ROOTS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|c| c.as_ref().to_vec())
            .collect()
    })
}

impl TlsConnector {
    pub fn new(profile: Arc<Profile>, opts: &TlsOptions) -> Result<Self> {
        let tls: &TlsProfile = &profile.tls;
        let mut b = SslConnector::builder(SslMethod::tls_client())?;

        b.set_min_proto_version(Some(version(&tls.min_version)?))?;
        b.set_max_proto_version(Some(version(&tls.max_version)?))?;
        b.set_cipher_list(&tls.ciphers.join(":"))?;
        b.set_curves_list(&tls.curves.join(":"))?;
        let (sig_codes, sig_verify, sig_raw) = sigalgs(&tls.sigalgs)?;
        b.set_sigalgs_list(&sig_verify.join(":"))?;
        // SAFETY: plain setters on a live SSL_CTX (functions added by vendor/.../mirage.patch).
        unsafe {
            let ctx = b.as_ptr();
            if sig_raw || tls.sigalgs_grease {
                if boring_sys2::SSL_CTX_mirage_set_advertised_sigalgs(ctx, sig_codes.as_ptr(), sig_codes.len()) != 1 {
                    return Err(Error::Profile("cannot set advertised sigalgs".into()));
                }
            }
            boring_sys2::SSL_CTX_mirage_set_grease_sigalgs(ctx, tls.sigalgs_grease as _);
            if let Some(ta) = tls.trust_anchors.as_deref().filter(|s| !s.is_empty()) {
                let data = hex(ta)?;
                if boring_sys2::SSL_CTX_mirage_set_trust_anchors(ctx, data.as_ptr(), data.len()) != 1 {
                    return Err(Error::Profile("cannot set trust anchors".into()));
                }
            }
        }

        let alpn = opts.alpn.as_ref().unwrap_or(&tls.alpn);
        if !alpn.is_empty() {
            b.set_alpn_protos(&alpn_wire(alpn))?;
        }
        b.set_grease_enabled(tls.grease);
        if tls.permute_extensions {
            b.set_permute_extensions(true);
        } else if let Some(order) = &tls.extension_order {
            let idx = order.iter().map(|e| extension_index(e)).collect::<Result<Vec<_>>>()?;
            b.set_extension_permutation_indices(&idx)?;
        }
        if tls.ocsp_stapling {
            b.enable_ocsp_stapling();
        }
        if tls.signed_cert_timestamps {
            b.enable_signed_cert_timestamps();
        }
        for alg in &tls.cert_compression {
            let alg = match alg.as_str() {
                "brotli" => CertCompressionAlgorithm::Brotli,
                "zlib" => CertCompressionAlgorithm::Zlib,
                "zstd" => CertCompressionAlgorithm::Zstd,
                other => return Err(Error::Profile(format!("unknown cert compression '{other}'"))),
            };
            b.add_cert_compression_alg(alg)?;
        }
        if let Some(limit) = tls.record_size_limit {
            b.set_record_size_limit(limit);
        }
        if let Some(dc) = &tls.delegated_credentials {
            b.set_delegated_credentials(&dc.join(":"))?;
        }
        if let Some(limit) = tls.key_shares_limit {
            b.set_key_shares_limit(limit);
        }
        if let Some(aes) = tls.aes_hw_override {
            b.set_aes_hw_override(aes);
        }
        if !tls.session_ticket {
            b.set_options(SslOptions::NO_TICKET);
        }
        // Browsers never offer renegotiation-capable legacy behaviour beyond the RI extension.
        b.set_options(SslOptions::NO_COMPRESSION);

        if opts.insecure {
            b.set_verify(SslVerifyMode::NONE);
        } else {
            let store = b.cert_store_mut();
            for der in root_store_der() {
                if let Ok(cert) = X509::from_der(der) {
                    let _ = store.add_cert(cert);
                }
            }
            if let Some(pem) = &opts.ca_pem {
                for cert in X509::stack_from_pem(pem)? {
                    let _ = b.cert_store_mut().add_cert(cert);
                }
            }
            b.set_verify(SslVerifyMode::PEER);
        }

        let sessions: SessionCache = Arc::new(Mutex::new(HashMap::new()));
        let resumption = tls.resumption && opts.resumption;
        let ech_grease = tls.ech_grease && opts.ech_grease;
        if resumption {
            b.set_session_cache_mode(SslSessionCacheMode::CLIENT);
            let cache = sessions.clone();
            b.set_new_session_callback(move |ssl, session| {
                if let Some(key) = ssl.ex_data(session_key_index()) {
                    cache.lock().unwrap().insert(key.clone(), session);
                }
            });
        }

        Ok(TlsConnector {
            connector: b.build(),
            profile,
            sessions,
            resumption,
            ech_grease,
        })
    }

    /// Run the TLS handshake on `stream` for `host`.
    pub async fn connect<S>(&self, host: &str, port: u16, stream: S) -> Result<SslStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tls = &self.profile.tls;
        let mut cfg = self.connector.configure()?;
        if self.ech_grease {
            cfg.set_enable_ech_grease(true);
        }
        if !tls.alps.is_empty() {
            for proto in &tls.alps {
                cfg.add_application_settings(proto.as_bytes())?;
            }
            cfg.set_alps_use_new_codepoint(tls.alps_new_codepoint);
        }
        // IP literals: no SNI (browsers do the same).
        if host.parse::<std::net::IpAddr>().is_ok() {
            cfg.set_use_server_name_indication(false);
            cfg.set_verify_hostname(false);
        }
        let key = format!("{host}:{port}");
        let mut ssl = cfg.into_ssl(host)?;
        ssl.set_ex_data(session_key_index(), key.clone());
        if self.resumption {
            if let Some(sess) = self.sessions.lock().unwrap().get(&key) {
                // SAFETY: the session comes from a context built by this connector.
                unsafe {
                    let _ = ssl.set_session(sess);
                }
            }
        }
        let stream = tokio_boring2::SslStreamBuilder::new(ssl, stream)
            .connect()
            .await
            .map_err(|e| {
                let detail = e
                    .ssl()
                    .and_then(|s| s.verify_result().err().map(|v| v.to_string()))
                    .map(|v| format!(" (certificate: {v})"))
                    .unwrap_or_default();
                Error::Tls(format!("handshake with {host} failed: {e}{detail}"))
            })?;
        Ok(stream)
    }
}
