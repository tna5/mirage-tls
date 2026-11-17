//! Minimal HTTP/2 client with full control over the connection fingerprint:
//! SETTINGS order, connection WINDOW_UPDATE, PRIORITY frames, HEADERS priority
//! and pseudo-header order (the "Akamai" fingerprint). Header blocks are encoded by our
//! own Chrome-like HPACK encoder ([`crate::hpack`]).
//!
//! One actor task owns the connection state; a reader task parses frames. Responses are
//! streamed: the stream-level receive window is re-opened only as the body consumer reads
//! (so a slow reader applies backpressure), the connection-level window on receipt.
//!
//! Requests beyond the peer's SETTINGS_MAX_CONCURRENT_STREAMS are queued on the same
//! connection (as Chrome does) and started when a stream closes. Requests the server did
//! not process (REFUSED_STREAM, GOAWAY above last_stream_id, or queued when the connection
//! went away) fail with [`Error::Refused`], which the client retries on a new connection.

use crate::error::{Error, Result};
use crate::profile::Http2Profile;
use crate::ResponseHead;
use bytes::{Buf, Bytes};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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

const NO_ERROR: u32 = 0x0;
const REFUSED_STREAM: u32 = 0x7;
const CANCEL: u32 = 0x8;

const DEFAULT_WINDOW: i64 = 65_535;
/// Assumed until the server's SETTINGS arrive (Chrome: kInitialMaxConcurrentStreams).
const INITIAL_MAX_STREAMS: usize = 100;
const MAX_RESPONSE_HEADER_BYTES: usize = 256 * 1024;

struct Frame {
    ty: u8,
    flags: u8,
    stream: u32,
    payload: Bytes,
}

type RespTx = oneshot::Sender<Result<(ResponseHead, H2Body)>>;

struct Cmd {
    key: u64,
    headers: Vec<(Vec<u8>, Vec<u8>)>,
    body: Bytes,
    resp: RespTx,
}

enum Ctl {
    /// The body consumer read this many bytes.
    Consumed(u64, usize),
    /// The request / body was dropped before completion.
    Cancel(u64),
}

/// Handle to an HTTP/2 connection. Cheap to clone; the connection closes once every
/// handle is dropped and no stream is in flight.
#[derive(Clone)]
pub struct H2Conn {
    tx: mpsc::Sender<Cmd>,
    ctl: mpsc::UnboundedSender<Ctl>,
    closed: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    next_key: Arc<AtomicU64>,
    pseudo_order: Arc<Vec<u8>>,
}

/// Streaming body of an HTTP/2 response.
pub struct H2Body {
    key: u64,
    rx: mpsc::UnboundedReceiver<Result<Bytes>>,
    ctl: mpsc::UnboundedSender<Ctl>,
    done: bool,
}

impl H2Body {
    pub async fn chunk(&mut self) -> Result<Option<Bytes>> {
        if self.done {
            return Ok(None);
        }
        match self.rx.recv().await {
            Some(Ok(b)) => {
                let _ = self.ctl.send(Ctl::Consumed(self.key, b.len()));
                Ok(Some(b))
            }
            Some(Err(e)) => {
                self.done = true;
                Err(e)
            }
            None => {
                self.done = true;
                Ok(None)
            }
        }
    }
}

impl Drop for H2Body {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.ctl.send(Ctl::Cancel(self.key));
        }
    }
}

/// Cancels the stream if the request future is dropped before the response head arrives.
struct PendingGuard<'a> {
    key: u64,
    ctl: &'a mpsc::UnboundedSender<Ctl>,
    armed: bool,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.ctl.send(Ctl::Cancel(self.key));
        }
    }
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
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
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
            keys: HashMap::new(),
            queue: VecDeque::new(),
            ctl_tx: ctl_tx.clone(),
            next_id: profile.initial_stream_id.unwrap_or(1) | 1,
            conn_send_window: DEFAULT_WINDOW,
            peer_initial_window: DEFAULT_WINDOW,
            peer_max_frame: 16_384,
            peer_max_streams: INITIAL_MAX_STREAMS,
            enc: crate::hpack::Encoder::new(),
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
        tokio::spawn(actor.run(rx, ctl_rx, frx));

        Ok(H2Conn {
            tx,
            ctl: ctl_tx,
            closed,
            active,
            next_key: Arc::new(AtomicU64::new(1)),
            pseudo_order: Arc::new(pseudo_order),
        })
    }

    /// True once the connection is unusable for new requests (GOAWAY received, error,
    /// stream ids exhausted).
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.tx.is_closed()
    }

    /// Open + queued streams.
    pub fn active_streams(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    /// Send a request. `headers` are regular headers (any case, lowercased here),
    /// already in fingerprint order. Resolves once the response head arrives.
    pub async fn request(
        &self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
        body: Bytes,
    ) -> Result<(ResponseHead, H2Body)> {
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
        let key = self.next_key.fetch_add(1, Ordering::Relaxed);
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Cmd { key, headers: list, body, resp: resp_tx })
            .await
            .map_err(|_| Error::Refused("connection closed".into()))?;
        let mut guard = PendingGuard { key, ctl: &self.ctl, armed: true };
        let res = resp_rx.await.map_err(|_| Error::H2("connection closed".into()))?;
        guard.armed = false;
        res
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
    key: u64,
    /// Pending until the response head arrives.
    resp: Option<RespTx>,
    /// Body sink once the head was delivered.
    data: Option<mpsc::UnboundedSender<Result<Bytes>>>,
    pending: Bytes,
    end_pending: bool,
    send_window: i64,
    /// Bytes consumed (or padding) not yet returned with a WINDOW_UPDATE.
    recv_unacked: i64,
}

impl Stream {
    fn fail(&mut self, e: Error) {
        if let Some(tx) = self.resp.take() {
            let _ = tx.send(Err(e));
        } else if let Some(d) = self.data.take() {
            let _ = d.send(Err(e));
        }
    }
}

struct Actor<W> {
    w: WriteHalf<W>,
    out: Vec<u8>,
    streams: HashMap<u32, Stream>,
    keys: HashMap<u64, u32>,
    queue: VecDeque<Cmd>,
    ctl_tx: mpsc::UnboundedSender<Ctl>,
    next_id: u32,
    conn_send_window: i64,
    peer_initial_window: i64,
    peer_max_frame: usize,
    peer_max_streams: usize,
    enc: crate::hpack::Encoder,
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
    async fn run(
        mut self,
        mut rx: mpsc::Receiver<Cmd>,
        mut ctl: mpsc::UnboundedReceiver<Ctl>,
        mut frx: mpsc::Receiver<Result<Frame>>,
    ) {
        let mut handles_alive = true;
        let err = loop {
            tokio::select! {
                cmd = rx.recv(), if handles_alive && !self.is_closed() => match cmd {
                    Some(cmd) => self.submit(cmd),
                    None => handles_alive = false,
                },
                Some(c) = ctl.recv() => self.on_ctl(c),
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
            self.start_queued();
            if !self.out.is_empty() {
                let buf = std::mem::take(&mut self.out);
                if let Err(e) = self.w.write_all(&buf).await {
                    break e.into();
                }
                if let Err(e) = self.w.flush().await {
                    break e.into();
                }
            }
            self.active.store(self.streams.len() + self.queue.len(), Ordering::Release);
            if self.streams.is_empty() && self.queue.is_empty() && (!handles_alive || self.is_closed()) {
                break Error::H2("connection closed".into());
            }
        };
        self.closed.store(true, Ordering::Release);
        self.active.store(0, Ordering::Release);
        let msg = err.to_string();
        for (_, mut s) in self.streams.drain() {
            s.fail(Error::H2(msg.clone()));
        }
        // Never sent: safe to retry elsewhere.
        for cmd in self.queue.drain(..) {
            let _ = cmd.resp.send(Err(Error::Refused("connection closed".into())));
        }
        rx.close();
        while let Ok(cmd) = rx.try_recv() {
            let _ = cmd.resp.send(Err(Error::Refused("connection closed".into())));
        }
        let _ = self.w.shutdown().await;
    }

    fn is_closed(&self) -> bool {
        self.goaway.is_some() || self.closed.load(Ordering::Acquire)
    }

    fn submit(&mut self, cmd: Cmd) {
        if self.streams.len() >= self.peer_max_streams || !self.queue.is_empty() {
            self.queue.push_back(cmd);
        } else {
            self.start_stream(cmd);
        }
    }

    fn start_queued(&mut self) {
        while self.streams.len() < self.peer_max_streams.max(1) {
            let Some(cmd) = self.queue.pop_front() else { break };
            if self.is_closed() {
                let _ = cmd.resp.send(Err(Error::Refused("connection is going away".into())));
                continue;
            }
            self.start_stream(cmd);
        }
    }

    fn on_ctl(&mut self, c: Ctl) {
        match c {
            Ctl::Consumed(key, n) => {
                let Some(&id) = self.keys.get(&key) else { return };
                let Some(s) = self.streams.get_mut(&id) else { return };
                s.recv_unacked += n as i64;
                if s.recv_unacked >= self.local_stream_window / 2 {
                    let inc = s.recv_unacked as u32;
                    s.recv_unacked = 0;
                    write_frame(&mut self.out, WINDOW_UPDATE, 0, id, &inc.to_be_bytes());
                }
            }
            Ctl::Cancel(key) => {
                if let Some(pos) = self.queue.iter().position(|c| c.key == key) {
                    self.queue.remove(pos);
                    return;
                }
                if let Some(id) = self.keys.remove(&key) {
                    if self.streams.remove(&id).is_some() {
                        write_frame(&mut self.out, RST_STREAM, 0, id, &CANCEL.to_be_bytes());
                    }
                }
            }
        }
    }

    fn remove(&mut self, id: u32) -> Option<Stream> {
        let s = self.streams.remove(&id)?;
        self.keys.remove(&s.key);
        Some(s)
    }

    fn start_stream(&mut self, cmd: Cmd) {
        if cmd.resp.is_closed() {
            return; // caller already gone
        }
        let id = self.next_id;
        if id > 0x7fff_ffff {
            self.closed.store(true, Ordering::Release);
            let _ = cmd.resp.send(Err(Error::Refused("stream ids exhausted".into())));
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

        self.keys.insert(cmd.key, id);
        self.streams.insert(
            id,
            Stream {
                key: cmd.key,
                resp: Some(cmd.resp),
                data: None,
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

    fn flush_all(&mut self) {
        let ids: Vec<u32> = self.streams.keys().copied().collect();
        ids.into_iter().for_each(|id| self.flush_data(id));
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
                        0x1 => self.enc.apply_table_size_setting(val as usize),
                        0x3 => self.peer_max_streams = val as usize,
                        0x4 => {
                            if val > 0x7fff_ffff {
                                return Err(Error::H2("invalid SETTINGS_INITIAL_WINDOW_SIZE".into()));
                            }
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
                self.flush_all();
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
                    self.flush_all();
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
                if let Some(mut s) = self.remove(f.stream) {
                    let e = if code == REFUSED_STREAM && s.resp.is_some() {
                        Error::Refused("REFUSED_STREAM".into())
                    } else if code == NO_ERROR && s.resp.is_none() {
                        // Server finished early (e.g. answered before our upload completed).
                        s.data.take();
                        return Ok(());
                    } else {
                        Error::H2(format!("stream reset by server ({})", error_name(code)))
                    };
                    s.fail(e);
                }
                Ok(())
            }
            GOAWAY => {
                let word = |i: usize| {
                    f.payload
                        .get(i..i + 4)
                        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
                        .unwrap_or(0)
                };
                let last = word(0) & 0x7fff_ffff;
                let code = word(4);
                self.goaway = Some(last);
                self.closed.store(true, Ordering::Release);
                let dead: Vec<u32> = self.streams.keys().copied().filter(|&id| id > last).collect();
                for id in dead {
                    if let Some(mut s) = self.remove(id) {
                        s.fail(Error::Refused(format!("GOAWAY ({})", error_name(code))));
                    }
                }
                for cmd in self.queue.drain(..) {
                    let _ = cmd.resp.send(Err(Error::Refused("connection is going away".into())));
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
        let delivered = match &s.data {
            Some(d) => p.is_empty() || d.send(Ok(p.clone())).is_ok(),
            None => false, // DATA before HEADERS, or consumer gone
        };
        if !delivered {
            self.remove(f.stream);
            write_frame(&mut self.out, RST_STREAM, 0, f.stream, &CANCEL.to_be_bytes());
            return Ok(());
        }
        // Padding is never handed to the consumer: credit it right away.
        s.recv_unacked += flow_len - p.len() as i64;
        if end {
            self.finish(f.stream);
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
        if let Some(tx) = s.resp.take() {
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
                s.resp = Some(tx);
                return Ok(()); // informational response, wait for the final one
            }
            let (dtx, drx) = mpsc::unbounded_channel();
            let body = H2Body { key: s.key, rx: drx, ctl: self.ctl_tx.clone(), done: false };
            let head = ResponseHead { status, reason: String::new(), version: "HTTP/2".into(), headers };
            if tx.send(Ok((head, body))).is_err() {
                self.remove(stream);
                write_frame(&mut self.out, RST_STREAM, 0, stream, &CANCEL.to_be_bytes());
                return Ok(());
            }
            s.data = Some(dtx);
        }
        // Trailers are ignored.
        if flags & END_STREAM != 0 {
            self.finish(stream);
        }
        Ok(())
    }

    fn finish(&mut self, id: u32) {
        if let Some(s) = self.remove(id) {
            if s.end_pending {
                // Server answered before we finished uploading.
                write_frame(&mut self.out, RST_STREAM, 0, id, &NO_ERROR.to_be_bytes());
            }
            // Dropping `s.data` ends the body stream.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use tokio::io::{duplex, DuplexStream};

    /// A tiny scripted HTTP/2 server side for tests.
    struct Peer {
        io: DuplexStream,
        dec: fluke_hpack::Decoder<'static>,
        enc: fluke_hpack::Encoder<'static>,
    }

    impl Peer {
        async fn frame(&mut self) -> (u8, u8, u32, Vec<u8>) {
            let mut h = [0u8; 9];
            self.io.read_exact(&mut h).await.unwrap();
            let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
            let mut p = vec![0u8; len];
            self.io.read_exact(&mut p).await.unwrap();
            (h[3], h[4], u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff, p)
        }
        /// Next frame of the given type (others are skipped); HEADERS are decoded.
        async fn expect(&mut self, ty: u8) -> (u8, u32, Vec<u8>) {
            loop {
                let (t, fl, id, mut p) = self.frame().await;
                if t == ty {
                    if t == HEADERS {
                        if fl & PRIORITY_FLAG != 0 {
                            p.drain(..5);
                        }
                        self.dec.decode(&p).unwrap();
                    }
                    return (fl, id, p);
                }
            }
        }
        async fn send(&mut self, ty: u8, flags: u8, id: u32, p: &[u8]) {
            let mut out = Vec::new();
            write_frame(&mut out, ty, flags, id, p);
            self.io.write_all(&out).await.unwrap();
        }
        async fn respond(&mut self, id: u32, status: &str, end: bool) {
            let block = self.enc.encode([(&b":status"[..], status.as_bytes())]);
            let fl = END_HEADERS | if end { END_STREAM } else { 0 };
            self.send(HEADERS, fl, id, &block).await;
        }
    }

    async fn pair(settings: &[(u16, u32)]) -> (H2Conn, Peer) {
        let (a, mut b) = duplex(1 << 20);
        let mut pre = [0u8; 24];
        let profile = Profile::get("chrome").unwrap().http2;
        let conn = tokio::spawn(async move { H2Conn::handshake(a, &profile).await.unwrap() });
        b.read_exact(&mut pre).await.unwrap();
        assert_eq!(&pre, PREFACE);
        let mut peer = Peer { io: b, dec: fluke_hpack::Decoder::new(), enc: fluke_hpack::Encoder::new() };
        let mut s = Vec::new();
        for (k, v) in settings {
            s.extend_from_slice(&k.to_be_bytes());
            s.extend_from_slice(&v.to_be_bytes());
        }
        peer.send(SETTINGS, 0, 0, &s).await;
        (conn.await.unwrap(), peer)
    }

    fn get(c: &H2Conn) -> tokio::task::JoinHandle<Result<(ResponseHead, H2Body)>> {
        let c = c.clone();
        tokio::spawn(async move { c.request("GET", "https", "x", "/", &[], Bytes::new()).await })
    }

    #[tokio::test]
    async fn max_concurrent_streams_queues() {
        let (c, mut peer) = pair(&[(0x3, 1)]).await;
        peer.expect(SETTINGS).await; // our SETTINGS
        peer.expect(SETTINGS).await; // ACK of theirs
        let r1 = get(&c);
        let (_, id1, _) = peer.expect(HEADERS).await;
        let r2 = get(&c);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(c.active_streams(), 2);
        peer.respond(id1, "200", true).await;
        let (_, id2, _) = peer.expect(HEADERS).await;
        assert_eq!(id2, id1 + 2);
        peer.respond(id2, "204", true).await;
        assert_eq!(r1.await.unwrap().unwrap().0.status, 200);
        assert_eq!(r2.await.unwrap().unwrap().0.status, 204);
    }

    #[tokio::test]
    async fn refused_and_goaway_are_retryable() {
        let (c, mut peer) = pair(&[]).await;
        let r1 = get(&c);
        let (_, id1, _) = peer.expect(HEADERS).await;
        peer.send(RST_STREAM, 0, id1, &REFUSED_STREAM.to_be_bytes()).await;
        assert!(matches!(r1.await.unwrap(), Err(Error::Refused(_))));

        let r2 = get(&c);
        let (_, id2, _) = peer.expect(HEADERS).await;
        let r3 = get(&c);
        let (_, id3, _) = peer.expect(HEADERS).await;
        let mut ga = id2.to_be_bytes().to_vec();
        ga.extend_from_slice(&0u32.to_be_bytes());
        peer.send(GOAWAY, 0, 0, &ga).await;
        assert!(matches!(r3.await.unwrap(), Err(Error::Refused(_))));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(c.is_closed());
        peer.respond(id2, "200", true).await;
        assert_eq!(r2.await.unwrap().unwrap().0.status, 200);
        let _ = id3;
    }

    #[tokio::test]
    async fn window_updates_follow_consumption_and_cancel_on_drop() {
        let (c, mut peer) = pair(&[(0x4, 1 << 20)]).await;
        let r = get(&c);
        let (_, id, _) = peer.expect(HEADERS).await;
        peer.respond(id, "200", false).await;
        let (_, mut body) = r.await.unwrap().unwrap();
        // 4 MB, more than half of Chrome's 6 MB stream window.
        let chunk = vec![7u8; 16_384];
        for _ in 0..256 {
            peer.send(DATA, 0, id, &chunk).await;
        }
        // Nothing consumed yet: only connection-level updates may have been sent.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut got = 0;
        while got < 16_384 * 200 {
            got += body.chunk().await.unwrap().unwrap().len();
        }
        loop {
            let (_, sid, p) = peer.expect(WINDOW_UPDATE).await;
            if sid == id {
                assert!(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) >= 3_145_728);
                break;
            }
        }
        drop(body);
        let (_, sid, p) = peer.expect(RST_STREAM).await;
        assert_eq!((sid, u32::from_be_bytes([p[0], p[1], p[2], p[3]])), (id, CANCEL));
    }

    #[tokio::test]
    async fn header_table_size_update_is_emitted() {
        let (c, mut peer) = pair(&[(0x1, 0)]).await;
        let r = get(&c);
        let (_, id, p) = {
            // read raw: the decoder must see the size update first
            loop {
                let (t, fl, id, mut p) = peer.frame().await;
                if t == HEADERS {
                    if fl & PRIORITY_FLAG != 0 {
                        p.drain(..5);
                    }
                    break (fl, id, p);
                }
            }
        };
        assert_eq!(p[0], 0x20); // dynamic table size update to 0
        peer.dec.decode(&p).unwrap();
        peer.respond(id, "200", true).await;
        r.await.unwrap().unwrap();
    }
}
