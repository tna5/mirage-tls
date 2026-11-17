//! HPACK encoder (RFC 7541) reproducing Chrome's choices, i.e. the defaults of quiche's
//! `HpackEncoder` (quiche/http2/hpack/hpack_encoder.cc) as used by Chromium:
//!
//! - an exact (name, value) match in the static table, then in the dynamic table (most
//!   recent entry), is sent as an indexed field;
//! - otherwise `DefaultPolicy` decides: pseudo headers are indexed only for `:authority`,
//!   every regular header is a literal *with incremental indexing*; the rest (`:path`,
//!   `:method` other than GET/POST, ...) are literals *without indexing*;
//! - name references use the static table first (lowest index), then the dynamic table;
//! - strings are Huffman coded only when that is strictly shorter;
//! - the `cookie` header is split into crumbs (`CookieToCrumbs`), one field per crumb;
//! - "never indexed" literals are never emitted: quiche has no sensitive-header policy,
//!   so we don't either (doing so would itself be a fingerprint);
//! - a SETTINGS_HEADER_TABLE_SIZE change from the peer is acknowledged with dynamic table
//!   size update(s) at the start of the next block (`MaybeEmitTableSize`).

use std::collections::VecDeque;

const STATIC: [(&str, &str); 61] = [
    (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"),
    (":path", "/index.html"), (":scheme", "http"), (":scheme", "https"), (":status", "200"),
    (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""), ("accept-ranges", ""),
    ("accept", ""), ("access-control-allow-origin", ""), ("age", ""), ("allow", ""),
    ("authorization", ""), ("cache-control", ""), ("content-disposition", ""),
    ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
    ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""),
    ("date", ""), ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
    ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""), ("location", ""),
    ("max-forwards", ""), ("proxy-authenticate", ""), ("proxy-authorization", ""),
    ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""), ("transfer-encoding", ""),
    ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
];

/// RFC 7541 Appendix B: (code, bit length) per symbol, 256 = EOS.
static HUFFMAN: [(u32, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28),
    (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28),
    (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28),
    (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28),
    (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28),
    (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
    (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb, 10),
    (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6),
    (0x0, 5), (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6),
    (0x1c, 6), (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13), (0x21, 6),
    (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7),
    (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7), (0x67, 7), (0x68, 7),
    (0x69, 7), (0x6a, 7), (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
    (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6),
    (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5),
    (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7),
    (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7),
    (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14),
    (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23),
    (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
    (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22), (0x1fffdd, 21),
    (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22),
    (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20), (0x3fffe2, 22),
    (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23),
    (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27),
    (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21),
    (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
    (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27),
    (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20), (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21),
    (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22),
    (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27),
    (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
    (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26), (0x3fffffff, 30),
];

pub fn huffman_encoded_len(s: &[u8]) -> usize {
    let bits: usize = s.iter().map(|&b| HUFFMAN[b as usize].1 as usize).sum();
    bits.div_ceil(8)
}

pub fn huffman_encode(s: &[u8], out: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut n = 0u32;
    for &b in s {
        let (code, len) = HUFFMAN[b as usize];
        acc = (acc << len) | code as u64;
        n += len as u32;
        while n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
        }
        acc &= (1u64 << n) - 1;
    }
    if n > 0 {
        // Pad with the most significant bits of EOS (all ones).
        out.push(((acc << (8 - n)) | ((1u64 << (8 - n)) - 1)) as u8);
    }
}

fn encode_int(out: &mut Vec<u8>, first: u8, prefix_bits: u8, mut v: usize) {
    let max = (1usize << prefix_bits) - 1;
    if v < max {
        out.push(first | v as u8);
        return;
    }
    out.push(first | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

fn encode_str(out: &mut Vec<u8>, s: &[u8]) {
    let h = huffman_encoded_len(s);
    if h < s.len() {
        encode_int(out, 0x80, 7, h);
        huffman_encode(s, out);
    } else {
        encode_int(out, 0, 7, s.len());
        out.extend_from_slice(s);
    }
}

/// quiche `CookieToCrumbs`: trim " \t" at both ends, split on ';', drop one space after
/// each ';'. Empty crumbs are kept.
fn crumbs(v: &[u8]) -> Vec<&[u8]> {
    let ws = |c: &u8| *c == b' ' || *c == b'\t';
    let v = match (v.iter().position(|c| !ws(c)), v.iter().rposition(|c| !ws(c))) {
        (Some(a), Some(b)) => &v[a..=b],
        _ => &[][..],
    };
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        match v[pos..].iter().position(|&c| c == b';') {
            None => {
                out.push(&v[pos..]);
                return out;
            }
            Some(i) => {
                out.push(&v[pos..pos + i]);
                pos += i + 1;
                if pos < v.len() && v[pos] == b' ' {
                    pos += 1;
                }
            }
        }
    }
}

pub struct Encoder {
    /// Newest entry first (dynamic index 62 + position).
    dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
    /// Last SETTINGS_HEADER_TABLE_SIZE applied (quiche `settings_size_bound_`).
    bound: usize,
    min_received: usize,
    emit_size: bool,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    pub fn new() -> Self {
        Encoder {
            dynamic: VecDeque::new(),
            size: 0,
            max_size: 4096,
            bound: 4096,
            min_received: usize::MAX,
            emit_size: false,
        }
    }

    /// Peer's SETTINGS_HEADER_TABLE_SIZE. Mirrors quiche HpackEncoder::ApplyHeaderTableSizeSetting.
    pub fn apply_table_size_setting(&mut self, size: usize) {
        if size == self.bound {
            return;
        }
        if size < self.bound {
            self.min_received = self.min_received.min(size);
        }
        self.bound = size;
        self.max_size = size;
        self.evict(0);
        self.emit_size = true;
    }

    /// Encode one header block; headers in wire order, pseudo headers included, names lowercase.
    pub fn encode<'a, I: IntoIterator<Item = (&'a [u8], &'a [u8])>>(&mut self, headers: I) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        if self.emit_size {
            if self.min_received < self.bound {
                encode_int(&mut out, 0x20, 5, self.min_received);
            }
            encode_int(&mut out, 0x20, 5, self.bound);
            self.min_received = usize::MAX;
            self.emit_size = false;
        }
        // Only the first cookie header is crumbled: quiche's header_set is a map, so there is
        // only ever one. Values are also split on NUL (DecomposeRepresentation).
        let mut cookie_seen = false;
        for (name, value) in headers {
            if !cookie_seen && name == b"cookie" {
                cookie_seen = true;
                for c in crumbs(value) {
                    self.field(&mut out, name, c);
                }
            } else {
                for v in value.split(|&c| c == 0) {
                    self.field(&mut out, name, v);
                }
            }
        }
        out
    }

    fn field(&mut self, out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
        if let Some(i) = self.find(name, Some(value)) {
            encode_int(out, 0x80, 7, i);
            return;
        }
        let name_idx = self.find(name, None);
        let index = !name.is_empty() && (name[0] != b':' || name == b":authority");
        let (first, bits) = if index { (0x40, 6) } else { (0x00, 4) };
        match name_idx {
            Some(i) => encode_int(out, first, bits, i),
            None => {
                out.push(first);
                encode_str(out, name);
            }
        }
        encode_str(out, value);
        if index {
            self.insert(name, value);
        }
    }

    /// 1-based index of an exact match (`value` given) or of the name; static table first.
    fn find(&self, name: &[u8], value: Option<&[u8]>) -> Option<usize> {
        let hit = |n: &[u8], v: &[u8]| n == name && value.is_none_or(|x| x == v);
        STATIC
            .iter()
            .position(|(n, v)| hit(n.as_bytes(), v.as_bytes()))
            .map(|i| i + 1)
            .or_else(|| self.dynamic.iter().position(|(n, v)| hit(n, v)).map(|i| i + 62))
    }

    fn insert(&mut self, name: &[u8], value: &[u8]) {
        let sz = name.len() + value.len() + 32;
        if sz > self.max_size {
            self.dynamic.clear();
            self.size = 0;
            return;
        }
        self.evict(sz);
        self.dynamic.push_front((name.to_vec(), value.to_vec()));
        self.size += sz;
    }

    /// Evict until `extra` more bytes fit.
    fn evict(&mut self, extra: usize) {
        while self.size + extra > self.max_size {
            let Some((n, v)) = self.dynamic.pop_back() else { break };
            self.size -= n.len() + v.len() + 32;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn huff(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        huffman_encode(s.as_bytes(), &mut out);
        assert_eq!(out.len(), huffman_encoded_len(s.as_bytes()));
        out
    }

    type H = Vec<(Vec<u8>, Vec<u8>)>;

    fn hs(list: &[(&str, &str)]) -> H {
        list.iter().map(|(k, v)| (k.as_bytes().to_vec(), v.as_bytes().to_vec())).collect()
    }

    fn enc(e: &mut Encoder, h: &H) -> Vec<u8> {
        e.encode(h.iter().map(|(k, v)| (k.as_slice(), v.as_slice())))
    }

    #[test]
    fn huffman_rfc7541_vectors() {
        // C.4
        assert_eq!(huff("www.example.com"), hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff"));
        assert_eq!(huff("no-cache"), hex("a8eb 1064 9cbf"));
        assert_eq!(huff("custom-key"), hex("25a8 49e9 5ba9 7d7f"));
        assert_eq!(huff("custom-value"), hex("25a8 49e9 5bb8 e8b4 bf"));
        // C.6
        assert_eq!(huff("302"), hex("6402"));
        assert_eq!(huff("private"), hex("aec3 771a 4b"));
        assert_eq!(huff("Mon, 21 Oct 2013 20:13:21 GMT"), hex("d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff"));
        assert_eq!(huff("https://www.example.com"), hex("9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3"));
        assert_eq!(
            huff("foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
            hex("94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f 9587 3160 65c0 03ed 4ee5 b106 3d50 07")
        );
    }

    #[test]
    fn integers() {
        // C.1
        let mut o = Vec::new();
        encode_int(&mut o, 0, 5, 10);
        encode_int(&mut o, 0, 5, 1337);
        encode_int(&mut o, 0, 8, 42);
        assert_eq!(o, vec![0x0a, 0x1f, 0x9a, 0x0a, 0x2a]);
    }

    fn chrome_request(path: &str, cookie: Option<&str>) -> H {
        let mut h = vec![
            (":method", "GET"), (":authority", "tls.peet.ws"), (":scheme", "https"), (":path", path),
            ("sec-ch-ua", r#""Not-A.Brand";v="99", "Google Chrome";v="157", "Chromium";v="157""#),
            ("sec-ch-ua-mobile", "?0"), ("sec-ch-ua-platform", "\"macOS\""),
            ("accept-language", "en-US,en;q=0.9"), ("upgrade-insecure-requests", "1"),
            ("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"),
            ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("sec-fetch-site", "none"), ("sec-fetch-mode", "navigate"), ("sec-fetch-user", "?1"),
            ("sec-fetch-dest", "document"), ("accept-encoding", "gzip, deflate, br, zstd"),
        ];
        if let Some(c) = cookie {
            h.push(("cookie", c));
        }
        h.push(("priority", "u=0, i"));
        hs(&h)
    }

    #[test]
    fn chrome_like_round_trip() {
        let mut e = Encoder::new();
        let mut d = fluke_hpack::Decoder::new();
        let r1 = chrome_request("/api/all", None);
        let b1 = enc(&mut e, &r1);
        assert_eq!(b1[0], 0x82, ":method GET is static index 2");
        assert_eq!(b1[1], 0x41, ":authority: literal with indexing, name index 1");
        assert_eq!(d.decode(&b1).unwrap(), r1);
        // :scheme https is static 7; :path literal without indexing, name index 4.
        let auth_len = 2 + huffman_encoded_len(b"tls.peet.ws");
        assert_eq!(b1[1 + auth_len], 0x87);
        assert_eq!(b1[2 + auth_len], 0x04);

        let r2 = chrome_request("/api/clean", None);
        let b2 = enc(&mut e, &r2);
        assert_eq!(d.decode(&b2).unwrap(), r2);
        // Everything but :path is now a 1-byte index.
        let path_len = 2 + "/api/clean".len().min(huffman_encoded_len(b"/api/clean"));
        assert_eq!(b2.len(), (r2.len() - 1) + path_len);
        let b3 = enc(&mut e, &r2);
        assert_eq!(b3.len(), b2.len());
        assert_eq!(d.decode(&b3).unwrap(), r2);
    }

    #[test]
    fn cookie_crumbs() {
        assert_eq!(crumbs(b" a=1; b=2;c=3;  d=4 "), vec![&b"a=1"[..], b"b=2", b"c=3", b" d=4"]);
        assert_eq!(crumbs(b"a=1;"), vec![&b"a=1"[..], b""]);
        assert_eq!(crumbs(b"   "), vec![&b""[..]]);

        let mut e = Encoder::new();
        let mut d = fluke_hpack::Decoder::new();
        let r = chrome_request("/", Some("sid=abc; theme=dark; x=1"));
        let got = d.decode(&enc(&mut e, &r)).unwrap();
        let mut want = chrome_request("/", None);
        let at = want.len() - 1; // before priority
        for (i, c) in ["sid=abc", "theme=dark", "x=1"].iter().enumerate() {
            want.insert(at + i, (b"cookie".to_vec(), c.as_bytes().to_vec()));
        }
        assert_eq!(got, want);
        // Second time every field (crumbs included; ":path /" is static) is one byte.
        let again = enc(&mut e, &r);
        assert_eq!(d.decode(&again).unwrap(), want);
        assert_eq!(again.len(), want.len());
    }

    #[test]
    fn table_size_updates() {
        let mut e = Encoder::new();
        let mut d = fluke_hpack::Decoder::new();
        let r = chrome_request("/a", None);
        assert_eq!(d.decode(&enc(&mut e, &r)).unwrap(), r);

        e.apply_table_size_setting(4096); // unchanged: nothing emitted
        assert_ne!(enc(&mut e, &r)[0] & 0xe0, 0x20);

        e.apply_table_size_setting(0);
        let b = enc(&mut e, &r);
        assert_eq!(b[0], 0x20, "size update to 0");
        assert_eq!(d.decode(&b).unwrap(), r);
        assert!(e.dynamic.is_empty());

        // Shrink then grow before the next block: min first, then the final size.
        e.apply_table_size_setting(256);
        e.apply_table_size_setting(100);
        e.apply_table_size_setting(1024);
        let b = enc(&mut e, &r);
        let mut want = Vec::new();
        encode_int(&mut want, 0x20, 5, 100);
        encode_int(&mut want, 0x20, 5, 1024);
        assert_eq!(&b[..want.len()], &want[..]);
        assert_eq!(d.decode(&b).unwrap(), r);
        assert!(e.size <= 1024);

        e.apply_table_size_setting(256);
        let b = enc(&mut e, &r);
        assert_eq!(&b[..2], &[0x3f, 0xe1]); // 256 = 31 + 225
        assert_eq!(d.decode(&b).unwrap(), r);
        assert!(e.size <= 256);
        assert_eq!(d.decode(&enc(&mut e, &r)).unwrap(), r);
    }

    #[test]
    fn eviction() {
        let mut e = Encoder::new();
        let mut d = fluke_hpack::Decoder::new();
        for round in 0..20 {
            let h: H = (0..10)
                .map(|i| (format!("x-big-{}", (round + i) % 13).into_bytes(), vec![b'a' + (i as u8); 300 + round * 7]))
                .collect();
            assert_eq!(d.decode(&enc(&mut e, &h)).unwrap(), h);
            assert!(e.size <= e.max_size);
        }
        // An entry larger than the table empties it.
        let h = hs(&[("x-huge", &"z".repeat(5000))]);
        assert_eq!(d.decode(&enc(&mut e, &h)).unwrap(), h);
        assert!(e.dynamic.is_empty() && e.size == 0);
        let h = hs(&[(":method", "PATCH"), (":path", "/"), ("x-y", "1")]);
        let b = enc(&mut e, &h);
        // :method PATCH: literal without indexing (name index 2); ":path /" static index 4;
        // x-y: literal with indexing, new name.
        let mut want = vec![0x02];
        encode_str(&mut want, b"PATCH");
        want.extend_from_slice(&[0x84, 0x40]);
        encode_str(&mut want, b"x-y");
        encode_str(&mut want, b"1");
        assert_eq!(b, want);
        assert_eq!(d.decode(&b).unwrap(), h);
    }
}
