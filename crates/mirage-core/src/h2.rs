//! Minimal HTTP/2 client with full control over the connection fingerprint:
//! SETTINGS order, connection WINDOW_UPDATE, PRIORITY frames, HEADERS priority
//! and pseudo-header order (the "Akamai" fingerprint).

use crate::error::{Error, Result};
use crate::profile::Http2Profile;
use crate::RawResponse;
use bytes::{Buf, Bytes};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

const DEFAULT_WINDOW: i64 = 65_535;
const MAX_RESPONSE_HEADER_BYTES: usize = 256 * 1024;

struct Frame {
    ty: u8,
    flags: u8,
    stream: u32,
    payload: Bytes,
}

struct Cmd {
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Bytes,
    resp: oneshot::Sender<Result<RawResponse>>,
}

/// Handle to an HTTP/2 connection. Cheap to clone; the connection closes once every
/// handle is dropped and no stream is in flight.
#[derive(Clone)]
pub struct H2Conn {
    tx: mpsc::Sender<Cmd>,
    closed: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    pseudo_order: Arc<Vec<u8>>,
}

impl H2Conn {
    pub async fn handshake<S>(io: S, profile: &Http2Profile) -> Result<H2Conn>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (r, mut w) = tokio::io::split(io);

        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(PREFACE);
        let mut settings = Vec::new();
        let mut local_window = DEFAULT_WINDOW;
        let mut header_table = 4096usize;
        for &(id, val) in &profile.settings {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&val.to_be_bytes());
            match id {
                0x1 => header_table = val as usize,
                0x4 => local_window = val as i64,
                _ => {}
            }
        }
        write_frame(&mut out, SETTINGS, 0, 0, &settings);
        let mut conn_recv_window = DEFAULT_WINDOW;
        if profile.window_update > 0 {
            write_frame(&mut out, WINDOW_UPDATE, 0, 0, &profile.window_update.to_be_bytes());
            conn_recv_window += profile.window_update as i64;
        }
        for p in &profile.priority_frames {
            let mut payload = Vec::with_capacity(5);
            let dep = p.depends_on | if p.exclusive { 0x8000_0000 } else { 0 };
            payload.extend_from_slice(&dep.to_be_bytes());
            payload.push((p.weight.clamp(1, 256) - 1) as u8);
            write_frame(&mut out, PRIORITY, 0, p.stream_id, &payload);
        }
        w.write_all(&out).await?;
        w.flush().await?;

        let pseudo_order = pseudo_order(&profile.pseudo_header_order)?;
        let (tx, rx) = mpsc::channel(64);
        let (ftx, frx) = mpsc::channel(64);
        let closed = Arc::new(AtomicBool::new(false));
        let active = Arc::new(AtomicUsize::new(0));

        tokio::spawn(read_loop(r, ftx));

        let mut dec = fluke_hpack::Decoder::new();
        dec.set_max_allowed_table_size(header_table);
        let actor = Actor {
            w,
            out: Vec::new(),
            streams: HashMap::new(),
            next_id: profile.initial_stream_id.unwrap_or(1) | 1,
            conn_send_window: DEFAULT_WINDOW,
            peer_initial_window: DEFAULT_WINDOW,
            peer_max_frame: 16_384,
            enc: fluke_hpack::Encoder::new(),
            dec,
            local_stream_window: local_window,
            conn_recv_window,
            conn_recv_unacked: 0,
            priority: profile.headers_priority,
            continuation: None,
            goaway: None,
            closed: closed.clone(),
            active: active.clone(),
        };
        tokio::spawn(actor.run(rx, frx));

        Ok(H2Conn { tx, closed, active, pseudo_order: Arc::new(pseudo_order) })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.tx.is_closed()
    }

    pub fn active_streams(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Send a request. `headers` are regular headers (any case, lowercased here),
    /// already in fingerprint order.
    pub async fn request(
        &self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
        body: Bytes,
    ) -> Result<RawResponse> {
        let mut list: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(headers.len() + 4);
        for &p in self.pseudo_order.iter() {
            let (k, v): (&[u8], &str) = match p {
                b'm' => (b":method", method),
                b'a' => (b":authority", authority),
                b's' => (b":scheme", scheme),
                _ => (b":path", path),
            };
            if method == "CONNECT" && (p == b's' || p == b'p') {
                continue;
            }
            list.push((k.to_vec(), v.as_bytes().to_vec()));
        }
        for (k, v) in headers {
            let k = k.to_ascii_lowercase();
            if matches!(
                k.as_str(),
                "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade" | "host"
            ) {
                continue;
            }
            if k == "te" && !v.eq_ignore_ascii_case("trailers") {
                continue;
            }
            list.push((k.into_bytes(), v.as_bytes().to_vec()));
        }
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Cmd { headers: list, body, resp: resp_tx })
            .await
            .map_err(|_| Error::H2("connection closed".into()))?;
        resp_rx.await.map_err(|_| Error::H2("connection closed".into()))?
    }
}

fn pseudo_order(order: &[String]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for p in order {
        let c = match p.trim_start_matches(':') {
            "m" | "method" => b'm',
            "a" | "authority" => b'a',
            "s" | "scheme" => b's',
            "p" | "path" => b'p',
            other => return Err(Error::Profile(format!("unknown pseudo header '{other}'"))),
        };
        if !out.contains(&c) {
            out.push(c);
        }
    }
    for c in [b'm', b'a', b's', b'p'] {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    Ok(out)
}

fn write_frame(out: &mut Vec<u8>, ty: u8, flags: u8, stream: u32, payload: &[u8]) {
    let len = payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.push(ty);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

async fn read_loop<R: AsyncRead>(mut r: ReadHalf<R>, tx: mpsc::Sender<Result<Frame>>) {
    loop {
        let mut head = [0u8; 9];
        if let Err(e) = r.read_exact(&mut head).await {
            let _ = tx.send(Err(e.into())).await;
            return;
        }
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        if len > 16 * 1024 * 1024 {
            let _ = tx.send(Err(Error::H2("frame too large".into()))).await;
            return;
        }
        let mut payload = vec![0u8; len];
        if let Err(e) = r.read_exact(&mut payload).await {
            let _ = tx.send(Err(e.into())).await;
            return;
        }
        let frame = Frame {
            ty: head[3],
            flags: head[4],
            stream: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
            payload: payload.into(),
        };
        if tx.send(Ok(frame)).await.is_err() {
            return;
        }
    }
}

struct Stream {
    resp: Option<oneshot::Sender<Result<RawResponse>>>,
    status: u16,
    headers: Vec<(String, String)>,
    got_headers: bool,
    body: Vec<u8>,
    pending: Bytes,
    end_pending: bool,
    send_window: i64,
    recv_unacked: i64,
}

struct Actor<W> {
    w: WriteHalf<W>,
    out: Vec<u8>,
    streams: HashMap<u32, Stream>,
    next_id: u32,
    conn_send_window: i64,
    peer_initial_window: i64,
    peer_max_frame: usize,
    enc: fluke_hpack::Encoder<'static>,
    dec: fluke_hpack::Decoder<'static>,
    local_stream_window: i64,
    conn_recv_window: i64,
    conn_recv_unacked: i64,
    priority: Option<crate::profile::Priority>,
    continuation: Option<(u32, u8, Vec<u8>)>,
    goaway: Option<u32>,
    closed: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
}

impl<W: AsyncWrite> Actor<W> {
    async fn run(mut self, mut rx: mpsc::Receiver<Cmd>, mut frx: mpsc::Receiver<Result<Frame>>) {
        let mut handles_alive = true;
        let err = loop {
            tokio::select! {
                cmd = rx.recv(), if handles_alive && self.goaway.is_none() => match cmd {
                    Some(cmd) => self.start_stream(cmd),
                    None => handles_alive = false,
                },
                frame = frx.recv() => match frame {
                    Some(Ok(f)) => {
                        if let Err(e) = self.on_frame(f) {
                            break e;
                        }
                    }
                    Some(Err(e)) => break e,
                    None => break Error::H2("reader stopped".into()),
                },
            }
            if !self.out.is_empty() {
                let buf = std::mem::take(&mut self.out);
                if let Err(e) = self.w.write_all(&buf).await {
                    break e.into();
                }
                if let Err(e) = self.w.flush().await {
                    break e.into();
                }
            }
            self.active.store(self.streams.len(), Ordering::Release);
            if self.streams.is_empty() && (!handles_alive || self.goaway.is_some()) {
                break Error::H2("connection closed".into());
            }
        };
        self.closed.store(true, Ordering::Release);
        let msg = err.to_string();
        for (_, mut s) in self.streams.drain() {
            if let Some(tx) = s.resp.take() {
                let _ = tx.send(Err(Error::H2(msg.clone())));
            }
        }
        rx.close();
        while let Ok(cmd) = rx.try_recv() {
            let _ = cmd.resp.send(Err(Error::H2("connection closed".into())));
        }
        let _ = self.w.shutdown().await;
    }

    fn start_stream(&mut self, cmd: Cmd) {
        let id = self.next_id;
        if id > 0x7fff_ffff {
            let _ = cmd.resp.send(Err(Error::H2("stream ids exhausted".into())));
            return;
        }
        self.next_id += 2;
        let block = self.enc.encode(cmd.headers.iter().map(|(k, v)| (k.as_slice(), v.as_slice())));
        let end_stream = cmd.body.is_empty();

        let mut first = Vec::new();
        let mut flags = if end_stream { END_STREAM } else { 0 };
        if let Some(p) = self.priority {
            flags |= PRIORITY_FLAG;
            let dep = p.depends_on | if p.exclusive { 0x8000_0000 } else { 0 };
            first.extend_from_slice(&dep.to_be_bytes());
            first.push((p.weight.clamp(1, 256) - 1) as u8);
        }
        let room = self.peer_max_frame - first.len();
        let (head, mut rest) = block.split_at(block.len().min(room));
        first.extend_from_slice(head);
        if rest.is_empty() {
            flags |= END_HEADERS;
        }
        write_frame(&mut self.out, HEADERS, flags, id, &first);
        while !rest.is_empty() {
            let (chunk, tail) = rest.split_at(rest.len().min(self.peer_max_frame));
            rest = tail;
            let f = if rest.is_empty() { END_HEADERS } else { 0 };
            write_frame(&mut self.out, CONTINUATION, f, id, chunk);
        }

        self.streams.insert(
            id,
            Stream {
                resp: Some(cmd.resp),
                status: 0,
                headers: Vec::new(),
                got_headers: false,
                body: Vec::new(),
                pending: cmd.body,
                end_pending: !end_stream,
                send_window: self.peer_initial_window,
                recv_unacked: 0,
            },
        );
        self.flush_data(id);
    }

    /// Send as much pending request body as flow control allows.
    fn flush_data(&mut self, id: u32) {
        let Some(s) = self.streams.get_mut(&id) else { return };
        while s.end_pending {
            let allowed = s.send_window.min(self.conn_send_window).max(0) as usize;
            let n = s.pending.len().min(allowed).min(self.peer_max_frame);
            if n == 0 && !s.pending.is_empty() {
                return;
            }
            let chunk = s.pending.split_to(n);
            let last = s.pending.is_empty();
            write_frame(&mut self.out, DATA, if last { END_STREAM } else { 0 }, id, &chunk);
            s.send_window -= n as i64;
            self.conn_send_window -= n as i64;
            if last {
                s.end_pending = false;
            }
        }
    }

    fn on_frame(&mut self, f: Frame) -> Result<()> {
        if let Some((sid, _, _)) = &self.continuation {
            if f.ty != CONTINUATION || f.stream != *sid {
                return Err(Error::H2("expected CONTINUATION".into()));
            }
        }
        match f.ty {
            DATA => self.on_data(f),
            HEADERS => {
                let mut p = f.payload;
                if f.flags & PADDED != 0 {
                    p = strip_padding(p)?;
                }
                if f.flags & PRIORITY_FLAG != 0 {
                    if p.len() < 5 {
                        return Err(Error::H2("bad HEADERS".into()));
                    }
                    p.advance(5);
                }
                if f.flags & END_HEADERS != 0 {
                    self.on_header_block(f.stream, f.flags, &p)
                } else {
                    self.continuation = Some((f.stream, f.flags, p.to_vec()));
                    Ok(())
                }
            }
            CONTINUATION => {
                let Some((sid, flags, mut buf)) = self.continuation.take() else {
                    return Err(Error::H2("unexpected CONTINUATION".into()));
                };
                buf.extend_from_slice(&f.payload);
                if buf.len() > MAX_RESPONSE_HEADER_BYTES {
                    return Err(Error::H2("response headers too large".into()));
                }
                if f.flags & END_HEADERS != 0 {
                    self.on_header_block(sid, flags, &buf)
                } else {
                    self.continuation = Some((sid, flags, buf));
                    Ok(())
                }
            }
            SETTINGS => {
                if f.flags & ACK != 0 {
                    return Ok(());
                }
                let mut p = f.payload;
                while p.remaining() >= 6 {
                    let id = p.get_u16();
                    let val = p.get_u32();
                    match id {
                        0x4 => {
                            let delta = val as i64 - self.peer_initial_window;
                            self.peer_initial_window = val as i64;
                            for s in self.streams.values_mut() {
                                s.send_window += delta;
                            }
                        }
                        0x5 => self.peer_max_frame = (val as usize).clamp(16_384, 16_777_215),
                        _ => {}
                    }
                }
                write_frame(&mut self.out, SETTINGS, ACK, 0, &[]);
                let ids: Vec<u32> = self.streams.keys().copied().collect();
                ids.into_iter().for_each(|id| self.flush_data(id));
                Ok(())
            }
            PING => {
                if f.flags & ACK == 0 {
                    write_frame(&mut self.out, PING, ACK, 0, &f.payload);
                }
                Ok(())
            }
            WINDOW_UPDATE => {
                if f.payload.len() < 4 {
                    return Err(Error::H2("bad WINDOW_UPDATE".into()));
                }
                let inc = (u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                    & 0x7fff_ffff) as i64;
                if f.stream == 0 {
                    self.conn_send_window += inc;
                    let ids: Vec<u32> = self.streams.keys().copied().collect();
                    ids.into_iter().for_each(|id| self.flush_data(id));
                } else if let Some(s) = self.streams.get_mut(&f.stream) {
                    s.send_window += inc;
                    self.flush_data(f.stream);
                }
                Ok(())
            }
            RST_STREAM => {
                let code = if f.payload.len() >= 4 {
                    u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                } else {
                    0
                };
                if let Some(mut s) = self.streams.remove(&f.stream) {
                    if let Some(tx) = s.resp.take() {
                        let _ = tx.send(Err(Error::H2(format!(
                            "stream reset by server ({})",
                            error_name(code)
                        ))));
                    }
                }
                Ok(())
            }
            GOAWAY => {
                let last = if f.payload.len() >= 8 {
                    u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]) & 0x7fff_ffff
                } else {
                    0
                };
                let code = if f.payload.len() >= 8 {
                    u32::from_be_bytes([f.payload[4], f.payload[5], f.payload[6], f.payload[7]])
                } else {
                    0
                };
                self.goaway = Some(last);
                self.closed.store(true, Ordering::Release);
                let dead: Vec<u32> = self.streams.keys().copied().filter(|&id| id > last).collect();
                for id in dead {
                    if let Some(mut s) = self.streams.remove(&id) {
                        if let Some(tx) = s.resp.take() {
                            let _ = tx.send(Err(Error::H2(format!(
                                "server sent GOAWAY ({})",
                                error_name(code)
                            ))));
                        }
                    }
                }
                Ok(())
            }
            PUSH_PROMISE => Err(Error::H2("server push received but disabled".into())),
            _ => Ok(()), // PRIORITY and unknown frames are ignored
        }
    }

    fn on_data(&mut self, f: Frame) -> Result<()> {
        let flow_len = f.payload.len() as i64;
        let mut p = f.payload;
        if f.flags & PADDED != 0 {
            p = strip_padding(p)?;
        }
        self.conn_recv_unacked += flow_len;
        if self.conn_recv_unacked >= self.conn_recv_window / 2 {
            write_frame(&mut self.out, WINDOW_UPDATE, 0, 0, &(self.conn_recv_unacked as u32).to_be_bytes());
            self.conn_recv_unacked = 0;
        }
        let end = f.flags & END_STREAM != 0;
        let Some(s) = self.streams.get_mut(&f.stream) else { return Ok(()) };
        if s.resp.as_ref().map(|r| r.is_closed()).unwrap_or(true) {
            // The caller gave up (timeout / abort): cancel the stream.
            self.streams.remove(&f.stream);
            write_frame(&mut self.out, RST_STREAM, 0, f.stream, &0x8u32.to_be_bytes());
            return Ok(());
        }
        s.body.extend_from_slice(&p);
        if end {
            self.finish(f.stream);
        } else {
            s.recv_unacked += flow_len;
            if s.recv_unacked >= self.local_stream_window / 2 {
                let inc = s.recv_unacked as u32;
                s.recv_unacked = 0;
                write_frame(&mut self.out, WINDOW_UPDATE, 0, f.stream, &inc.to_be_bytes());
            }
        }
        Ok(())
    }

    fn on_header_block(&mut self, stream: u32, flags: u8, block: &[u8]) -> Result<()> {
        // The block must always be decoded to keep the HPACK state in sync.
        let decoded = self
            .dec
            .decode(block)
            .map_err(|e| Error::H2(format!("hpack: {e:?}")))?;
        let Some(s) = self.streams.get_mut(&stream) else { return Ok(()) };
        if !s.got_headers {
            let mut status = 0u16;
            let mut headers = Vec::with_capacity(decoded.len());
            for (k, v) in decoded {
                if k == b":status" {
                    status = std::str::from_utf8(&v).ok().and_then(|v| v.parse().ok()).unwrap_or(0);
                } else if !k.starts_with(b":") {
                    headers.push((
                        String::from_utf8_lossy(&k).into_owned(),
                        String::from_utf8_lossy(&v).into_owned(),
                    ));
                }
            }
            if (100..200).contains(&status) {
                return Ok(()); // informational response, wait for the final one
            }
            s.status = status;
            s.headers = headers;
            s.got_headers = true;
        }
        if flags & END_STREAM != 0 {
            self.finish(stream);
        }
        Ok(())
    }

    fn finish(&mut self, id: u32) {
        if let Some(mut s) = self.streams.remove(&id) {
            if let Some(tx) = s.resp.take() {
                let _ = tx.send(Ok(RawResponse {
                    status: s.status,
                    reason: String::new(),
                    version: "HTTP/2".into(),
                    headers: s.headers,
                    body: s.body,
                }));
            }
            if s.end_pending {
                // Server answered before we finished uploading.
                write_frame(&mut self.out, RST_STREAM, 0, id, &0u32.to_be_bytes());
            }
        }
    }
}

fn strip_padding(mut p: Bytes) -> Result<Bytes> {
    if p.is_empty() {
        return Err(Error::H2("bad padding".into()));
    }
    let pad = p[0] as usize;
    p.advance(1);
    if pad > p.len() {
        return Err(Error::H2("bad padding".into()));
    }
    p.truncate(p.len() - pad);
    Ok(p)
}

fn error_name(code: u32) -> &'static str {
    match code {
        0x0 => "NO_ERROR",
        0x1 => "PROTOCOL_ERROR",
        0x2 => "INTERNAL_ERROR",
        0x3 => "FLOW_CONTROL_ERROR",
        0x5 => "STREAM_CLOSED",
        0x6 => "FRAME_SIZE_ERROR",
        0x7 => "REFUSED_STREAM",
        0x8 => "CANCEL",
        0x9 => "COMPRESSION_ERROR",
        0xb => "ENHANCE_YOUR_CALM",
        0xc => "INADEQUATE_SECURITY",
        0xd => "HTTP_1_1_REQUIRED",
        _ => "UNKNOWN",
    }
}
