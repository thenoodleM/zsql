//! zsql — lossless, column-aware compressor for mysqldump files.
//!
//! Generic compressors see row-ordered SQL text where ids, timestamps, MACs and
//! reply strings are interleaved. zsql splits every extended INSERT into one
//! stream per column and models each column:
//!   * integers  -> zigzag varint, delta-from-previous-row OR plain (best kept)
//!   * datetimes -> integer seconds/µs, delta from previous row OR from an
//!                  earlier time column in the same row (e.g. stop - start)
//!   * strings   -> per-column dictionary index + literal stream
//!   * NULL/type -> a tiny per-column kind stream
//! Everything else passes through verbatim. Each stream is compressed with
//! zstd -19 --long and xz -9e (in parallel), keeping the smaller.
//!
//! Decoding is byte-identical; the sha256 of the original is stored and checked.
//! Any INSERT line the parser is not certain about is passed through verbatim,
//! so odd data costs size, never correctness.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

const MAGIC: &[u8] = b"ZSQL2\n";
const DICT_CAP: usize = 1 << 18;
const SPILL: usize = 1 << 20;
/// after this many strings, a column whose dictionary hit rate is < 25% stops
/// using (and frees) its dictionary. Mirrored exactly by the decoder.
const FREEZE_AT: u32 = 65536;
const BIG_STREAM: u64 = 64 << 20;
const MEM_STREAM: u64 = 16 << 20; // decoder: streams up to this size are fully inflated
const K_NULL: u8 = 0;
const K_INT: u8 = 1;
const K_T: u8 = 2;
const K_T6: u8 = 3;
const K_STR: u8 = 4;
const K_RAW: u8 = 5;
const K_DEC: u8 = 6; // unquoted decimal 12.50 -> mantissa 1250, scale 2
const K_QINT: u8 = 7; // quoted canonical integer '1201908' -> int streams
const K_HEX: u8 = 8; // quoted hex string in a dictionary-frozen column -> raw bytes

type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

// ---------------- fast hasher for dictionaries ----------------
#[derive(Default)]
struct Fx(u64);
impl Hasher for Fx {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, b: &[u8]) {
        let mut h = self.0;
        for c in b.chunks(8) {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            h = (h.rotate_left(5) ^ u64::from_le_bytes(w)).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
        }
        self.0 = h;
    }
}
type FxMap = HashMap<Box<[u8]>, u32, BuildHasherDefault<Fx>>;

// ---------------- varints ----------------
#[inline]
fn putu(o: &mut Vec<u8>, mut u: u64) {
    while u > 0x7f {
        o.push((u as u8 & 0x7f) | 0x80);
        u >>= 7;
    }
    o.push(u as u8);
}
#[inline]
fn zz(n: i64) -> u64 {
    ((n << 1) ^ (n >> 63)) as u64
}
#[inline]
fn unzz(u: u64) -> i64 {
    ((u >> 1) as i64) ^ -((u & 1) as i64)
}

// ---------------- value classification ----------------
fn parse_int(v: &[u8]) -> Option<i64> {
    let (neg, d) = if v.first() == Some(&b'-') { (true, &v[1..]) } else { (false, v) };
    if d.is_empty() || d.len() > 18 || !d.iter().all(u8::is_ascii_digit) {
        return None;
    }
    if d[0] == b'0' && (d.len() > 1 || neg) {
        return None;
    }
    let mut n: i64 = 0;
    for &c in d {
        n = n * 10 + (c - b'0') as i64;
    }
    Some(if neg { -n } else { n })
}

/// hex text -> (flags, bytes). flags bit0: "0x" prefix, bit1: uppercase.
/// Only unambiguous forms: even length >= 8, single letter case.
fn hex_enc(s: &[u8], out: &mut Vec<u8>) -> Option<u8> {
    let (pfx, h) = if s.starts_with(b"0x") { (1u8, &s[2..]) } else { (0, s) };
    if h.len() < 8 || h.len() % 2 != 0 || h.len() > 4096 {
        return None;
    }
    let (mut lo, mut up) = (false, false);
    for &c in h {
        match c {
            b'0'..=b'9' => {}
            b'a'..=b'f' => lo = true,
            b'A'..=b'F' => up = true,
            _ => return None,
        }
    }
    if lo && up {
        return None;
    }
    let v = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => c - b'A' + 10,
    };
    for p in h.chunks(2) {
        out.push(v(p[0]) << 4 | v(p[1]));
    }
    Some(pfx | if up { 2 } else { 0 })
}
fn hex_dec(flags: u8, b: &[u8], o: &mut Vec<u8>) {
    if flags & 1 != 0 {
        o.extend_from_slice(b"0x");
    }
    let d: &[u8; 16] = if flags & 2 != 0 { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    for &x in b {
        o.push(d[(x >> 4) as usize]);
        o.push(d[(x & 15) as usize]);
    }
}

/// canonical decimal: -?(0|[1-9]d*).d+ , <= 18 digits, no "-0.00"
fn parse_dec(v: &[u8]) -> Option<(i64, u8)> {
    let (neg, d) = if v.first() == Some(&b'-') { (true, &v[1..]) } else { (false, v) };
    let dot = d.iter().position(|&c| c == b'.')?;
    let (ip, fp) = (&d[..dot], &d[dot + 1..]);
    if ip.is_empty() || fp.is_empty() || ip.len() + fp.len() > 18 {
        return None;
    }
    if !ip.iter().chain(fp).all(u8::is_ascii_digit) || (ip[0] == b'0' && ip.len() > 1) {
        return None;
    }
    let mut m: i64 = 0;
    for &c in ip.iter().chain(fp) {
        m = m * 10 + (c - b'0') as i64;
    }
    if neg && m == 0 {
        return None;
    }
    Some((if neg { -m } else { m }, fp.len() as u8))
}
fn dec_fmt(m: i64, sc: u8, o: &mut Vec<u8>) {
    if m < 0 {
        o.push(b'-');
    }
    let digits = format!("{:0w$}", m.unsigned_abs(), w = sc as usize + 1);
    let cut = digits.len() - sc as usize;
    o.extend_from_slice(&digits.as_bytes()[..cut]);
    o.push(b'.');
    o.extend_from_slice(&digits.as_bytes()[cut..]);
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + (m <= 2) as i64, m, d)
}
fn dim(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        _ => 28,
    }
}
fn num(s: &[u8]) -> Option<i64> {
    let mut n = 0i64;
    for &c in s {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (c - b'0') as i64;
    }
    Some(n)
}
/// 'YYYY-MM-DD HH:MM:SS[.ffffff]' (without quotes) -> (kind, value)
fn tenc(v: &[u8]) -> Option<(u8, i64)> {
    if !(v.len() == 19 || v.len() == 26) {
        return None;
    }
    if v[4] != b'-' || v[7] != b'-' || v[10] != b' ' || v[13] != b':' || v[16] != b':' {
        return None;
    }
    let (y, mo, d) = (num(&v[0..4])?, num(&v[5..7])?, num(&v[8..10])?);
    let (h, mi, s) = (num(&v[11..13])?, num(&v[14..16])?, num(&v[17..19])?);
    if y < 1 || !(1..=12).contains(&mo) || d < 1 || d > dim(y, mo) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    let secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + s;
    if v.len() == 26 {
        if v[19] != b'.' {
            return None;
        }
        Some((K_T6, secs * 1_000_000 + num(&v[20..26])?))
    } else {
        Some((K_T, secs))
    }
}
fn tdec(kind: u8, n: i64, o: &mut Vec<u8>) {
    let (mut s, mut us) = (n, 0);
    if kind == K_T6 {
        s = n.div_euclid(1_000_000);
        us = n.rem_euclid(1_000_000);
    }
    let (days, r) = (s.div_euclid(86400), s.rem_euclid(86400));
    let (y, m, d) = civil_from_days(days);
    let _ = write!(o, "{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, r / 3600, r % 3600 / 60, r % 60);
    if kind == K_T6 {
        let _ = write!(o, ".{:06}", us);
    }
}

// ---------------- INSERT line parser ----------------
/// Splits the bytes between `VALUES (` and `);\n` into fields; `ends[i]` marks
/// the field index where row i ends. Returns false if not 100% certain.
fn parse_rows<'a>(inner: &'a [u8], fields: &mut Vec<&'a [u8]>, ends: &mut Vec<usize>) -> bool {
    fields.clear();
    ends.clear();
    let n = inner.len();
    let mut p = 0;
    loop {
        let st = p;
        if p < n && inner[p] == b'\'' {
            p += 1;
            loop {
                match inner[p..].iter().position(|&c| c == b'\'' || c == b'\\') {
                    None => return false,
                    Some(k) => {
                        p += k;
                        if inner[p] == b'\\' {
                            p += 2;
                        } else {
                            p += 1;
                            break;
                        }
                    }
                }
                if p > n {
                    return false;
                }
            }
        } else {
            while p < n && !matches!(inner[p], b',' | b')' | b'(' | b'\'') {
                p += 1;
            }
            if p < n && matches!(inner[p], b'(' | b'\'') {
                return false;
            }
        }
        if p == st || p > n {
            return false;
        }
        let v = &inner[st..p];
        if v.contains(&0) {
            return false;
        }
        fields.push(v);
        if p == n {
            ends.push(fields.len());
            return true;
        }
        match inner[p] {
            b',' => p += 1,
            b')' if inner[p..].starts_with(b"),(") => {
                ends.push(fields.len());
                p += 3;
            }
            _ => return false,
        }
    }
}

// ---------------- stream store (spills to disk, bounded RAM) ----------------
struct Streams {
    dir: PathBuf,
    names: Vec<String>,
    bufs: Vec<Vec<u8>>,
    spilled: Vec<bool>,
    index: HashMap<String, usize>,
}
impl Streams {
    fn id(&mut self, name: String) -> usize {
        if let Some(&i) = self.index.get(&name) {
            return i;
        }
        let i = self.names.len();
        self.index.insert(name.clone(), i);
        self.names.push(name);
        self.bufs.push(Vec::new());
        self.spilled.push(false);
        i
    }
    fn path(&self, i: usize) -> PathBuf {
        self.dir.join(format!("s{}", i))
    }
    fn spill(&mut self, i: usize) -> io::Result<()> {
        if self.bufs[i].is_empty() {
            return Ok(());
        }
        let mut f = OpenOptions::new().create(true).append(true).open(self.path(i))?;
        f.write_all(&self.bufs[i])?;
        self.bufs[i].clear();
        self.spilled[i] = true;
        Ok(())
    }
    fn maybe_spill(&mut self, i: usize) -> io::Result<()> {
        if self.bufs[i].len() >= SPILL {
            self.spill(i)?;
        }
        Ok(())
    }
}

// ---------------- column encoder ----------------
const NS: usize = 11;
const SUB: [&str; NS] = ["kind", "ip", "id", "tp", "tr", "idx", "lit", "dm", "dsc", "hxh", "hxb"];
struct Col {
    s: [Vec<u8>; NS],
    prev_i: i64,
    prev_t: [i64; 2],
    dict: FxMap,
    hits: u32,
    seen: u32,
    frozen: bool,
}
impl Col {
    fn new() -> Self {
        Col { s: Default::default(), prev_i: 0, prev_t: [0; 2], dict: FxMap::default(), hits: 0, seen: 0, frozen: false }
    }
    #[inline]
    fn add(&mut self, v: &[u8], rowref: &mut [Option<i64>; 2]) {
        if v == b"NULL" {
            self.s[0].push(K_NULL);
        } else if v[0] == b'\'' {
            let s = &v[1..v.len() - 1];
            if let Some((k, n)) = tenc(s) {
                let t = (k - K_T) as usize;
                self.s[0].push(k);
                putu(&mut self.s[3], zz(n.wrapping_sub(self.prev_t[t])));
                let r = rowref[t].unwrap_or(self.prev_t[t]);
                putu(&mut self.s[4], zz(n.wrapping_sub(r)));
                self.prev_t[t] = n;
                rowref[t] = Some(n);
            } else if let Some(n) = parse_int(s) {
                self.s[0].push(K_QINT);
                putu(&mut self.s[1], zz(n));
                putu(&mut self.s[2], zz(n.wrapping_sub(self.prev_i)));
                self.prev_i = n;
            } else if self.frozen && {
                let l = self.s[10].len();
                match hex_enc(s, &mut self.s[10]) {
                    Some(f) => {
                        let n = (self.s[10].len() - l) as u64;
                        self.s[9].push(f);
                        putu(&mut self.s[9], n);
                        true
                    }
                    None => {
                        self.s[10].truncate(l);
                        false
                    }
                }
            } {
                self.s[0].push(K_HEX);
            } else {
                self.s[0].push(K_STR);
                let hit = if self.frozen { None } else { self.dict.get(s).copied() };
                if let Some(i) = hit {
                    putu(&mut self.s[5], i as u64 + 1);
                    self.hits += 1;
                } else {
                    self.s[5].push(0);
                    self.s[6].extend_from_slice(s);
                    self.s[6].push(0);
                    if !self.frozen && self.dict.len() < DICT_CAP {
                        let l = self.dict.len() as u32;
                        self.dict.insert(s.into(), l);
                    }
                }
                self.seen += 1;
                if !self.frozen && self.seen == FREEZE_AT && self.hits * 4 < self.seen {
                    self.frozen = true;
                    self.dict = FxMap::default();
                }
            }
        } else if let Some(n) = parse_int(v) {
            self.s[0].push(K_INT);
            putu(&mut self.s[1], zz(n));
            putu(&mut self.s[2], zz(n.wrapping_sub(self.prev_i)));
            self.prev_i = n;
        } else if let Some((m, sc)) = parse_dec(v) {
            self.s[0].push(K_DEC);
            putu(&mut self.s[7], zz(m));
            self.s[8].push(sc);
        } else {
            self.s[0].push(K_RAW);
            self.s[6].extend_from_slice(v);
            self.s[6].push(0);
        }
    }
}

struct Table {
    name: String,
    ncols: usize,
    cols: Vec<Col>,
    sid: Vec<[usize; NS]>,
}

// ---------------- compression of finished streams ----------------
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Max,
    Fast,
}

fn zstd_compress(data: &[u8], level: i32) -> Res<Vec<u8>> {
    let wlog = (64 - (data.len().max(1024) as u64 - 1).leading_zeros()).min(27);
    let mut c = zstd::bulk::Compressor::new(level)?;
    c.set_parameter(zstd::zstd_safe::CParameter::WindowLog(wlog))?;
    c.set_parameter(zstd::zstd_safe::CParameter::EnableLongDistanceMatching(data.len() > (8 << 20)))?;
    c.include_contentsize(true)?;
    Ok(c.compress(data)?)
}
fn xz_compress(data: &[u8]) -> Res<Vec<u8>> {
    let mut opt = xz2::stream::LzmaOptions::new_preset(9 | 0x8000_0000)?;
    let dict = (data.len().max(4096) as u32).next_power_of_two().min(64 << 20);
    opt.dict_size(dict);
    let mut f = xz2::stream::Filters::new();
    f.lzma2(&opt);
    let s = xz2::stream::Stream::new_stream_encoder(&f, xz2::stream::Check::None)?;
    let mut out = Vec::with_capacity(data.len() / 4 + 64);
    let mut e = xz2::write::XzEncoder::new_stream(&mut out, s);
    e.write_all(data)?;
    e.finish()?;
    Ok(out)
}
/// returns (codec, bytes)  codec: 'z' zstd, 'x' xz, 'r' raw
fn best(data: &[u8], mode: Mode, level: i32) -> Res<(u8, Vec<u8>)> {
    let mut b = (b'r', data.to_vec());
    let z = zstd_compress(data, level)?;
    if z.len() < b.1.len() {
        b = (b'z', z);
    }
    if mode == Mode::Max {
        let x = xz_compress(data)?;
        if x.len() < b.1.len() {
            b = (b'x', x);
        }
    }
    Ok(b)
}

/// Compress stream i into dir/c{i}; big streams are streamed from disk.
fn compress_one(st: &Streams, i: usize, mode: Mode, level: i32) -> Res<(u8, u64, PathBuf)> {
    let out = st.dir.join(format!("c{}", i));
    let rawlen = if st.spilled[i] { fs::metadata(st.path(i))?.len() } else { 0 } + st.bufs[i].len() as u64;
    let big = std::env::var("ZSQL_BIG_STREAM").ok().and_then(|v| v.parse().ok()).unwrap_or(BIG_STREAM);
    if rawlen <= big || !st.spilled[i] || !st.bufs[i].is_empty() {
        let data = read_stream(st, i)?;
        let (codec, bytes) = best(&data, mode, level)?;
        fs::write(&out, &bytes)?;
        return Ok((codec, rawlen, out));
    }
    let pz = st.dir.join(format!("c{}.z", i));
    {
        let mut e = zstd::stream::write::Encoder::new(BufWriter::new(File::create(&pz)?), level)?;
        e.set_pledged_src_size(Some(rawlen))?;
        e.include_contentsize(true)?;
        e.window_log(27)?;
        e.long_distance_matching(true)?;
        io::copy(&mut BufReader::with_capacity(1 << 20, File::open(st.path(i))?), &mut e)?;
        e.finish()?.flush()?;
    }
    let mut best_p = (b'z', pz);
    if mode == Mode::Max {
        let px = st.dir.join(format!("c{}.x", i));
        {
            let mut opt = xz2::stream::LzmaOptions::new_preset(9 | 0x8000_0000)?;
            opt.dict_size(64 << 20);
            let mut f = xz2::stream::Filters::new();
            f.lzma2(&opt);
            let s = xz2::stream::Stream::new_stream_encoder(&f, xz2::stream::Check::None)?;
            let mut e = xz2::write::XzEncoder::new_stream(BufWriter::new(File::create(&px)?), s);
            io::copy(&mut BufReader::with_capacity(1 << 20, File::open(st.path(i))?), &mut e)?;
            e.finish()?.flush()?;
        }
        if fs::metadata(&px)?.len() < fs::metadata(&best_p.1)?.len() {
            fs::remove_file(&best_p.1)?;
            best_p = (b'x', px);
        } else {
            fs::remove_file(&px)?;
        }
    }
    fs::rename(&best_p.1, &out)?;
    Ok((best_p.0, rawlen, out))
}

fn read_stream(st: &Streams, i: usize) -> io::Result<Vec<u8>> {
    let mut v = if st.spilled[i] { fs::read(st.path(i))? } else { Vec::new() };
    v.extend_from_slice(&st.bufs[i]);
    Ok(v)
}

struct Opts {
    mode: Mode,
    level: i32,
    jobs: usize,
    only: Option<Vec<String>>,
    tmp: Option<PathBuf>,
}

fn compress(input: &str, output: &str, o: &Opts) -> Res<()> {
    let t0 = Instant::now();
    let outp = Path::new(output);
    let base = o.tmp.clone().unwrap_or_else(|| {
        outp.parent().filter(|p| !p.as_os_str().is_empty()).map(Path::to_path_buf).unwrap_or_else(|| ".".into())
    });
    let dir = base.join(format!(".zsql.{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    let mut st = Streams { dir: dir.clone(), names: vec![], bufs: vec![], spilled: vec![], index: HashMap::new() };
    let ops_id = st.id("ops".into());
    let pass_id = st.id("pass".into());

    let reader: Box<dyn Read> = if input == "-" { Box::new(io::stdin().lock()) } else { Box::new(File::open(input)?) };
    let mut r = BufReader::with_capacity(8 << 20, reader);
    let mut h = blake3::Hasher::new();
    let mut total: u64 = 0;
    let mut t_hash = std::time::Duration::ZERO;
    let mut t_cols = std::time::Duration::ZERO;
    let mut line = Vec::with_capacity(4 << 20);
    let mut tables: Vec<Table> = vec![];
    let mut tix: HashMap<Vec<u8>, usize> = HashMap::new();
    let (mut fcap, mut ecap) = (0usize, 0usize);
    let mut npass: u64 = 0;
    let mut rows_col: u64 = 0;
    const PFX: &[u8] = b"INSERT INTO `";
    const PFX_R: &[u8] = b"REPLACE INTO `";
    const MID: &[u8] = b"` VALUES (";

    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        let th = Instant::now();
        h.update(&line);
        t_hash += th.elapsed();
        let mut fields: Vec<&[u8]> = Vec::with_capacity(fcap);
        let mut ends: Vec<usize> = Vec::with_capacity(ecap);
        total += line.len() as u64;
        let mut handled = false;
        let (verb, plen) = if line.starts_with(PFX) {
            ("INSERT", PFX.len())
        } else if line.starts_with(PFX_R) {
            ("REPLACE", PFX_R.len())
        } else {
            ("", 0)
        };
        if plen > 0 && line.ends_with(b");\n") {
            if let Some(q) = line[plen..].iter().position(|&c| c == b'`') {
                let name = &line[plen..plen + q];
                let body = plen + q;
                let key: Vec<u8> = [verb.as_bytes(), b" ", name].concat();
                let wanted = o.only.as_ref().map_or(true, |w| w.iter().any(|t| t.as_bytes() == name));
                if wanted && line[body..].starts_with(MID) {
                    let inner = &line[body + MID.len()..line.len() - 3];
                    if parse_rows(inner, &mut fields, &mut ends) {
                        fcap = fcap.max(fields.len());
                        ecap = ecap.max(ends.len());
                        let rowlen = ends[0];
                        let uniform = ends.iter().enumerate().all(|(i, &e)| e == (i + 1) * rowlen);
                        let ti = match tix.get(&key) {
                            Some(&t) => Some(t),
                            None if uniform => {
                                let t = tables.len();
                                let nm = String::from_utf8_lossy(&key).into_owned();
                                let sid = (0..rowlen)
                                    .map(|c| std::array::from_fn(|k| st.id(format!("t{}.c{}.{}", t, c, SUB[k]))))
                                    .collect();
                                tables.push(Table { name: nm, ncols: rowlen, cols: (0..rowlen).map(|_| Col::new()).collect(), sid });
                                tix.insert(key.clone(), t);
                                Some(t)
                            }
                            None => None,
                        };
                        if let Some(ti) = ti {
                            let tb = &mut tables[ti];
                            if uniform && rowlen == tb.ncols {
                                let ops = &mut st.bufs[ops_id];
                                putu(ops, npass);
                                putu(ops, ti as u64 + 1);
                                putu(ops, ends.len() as u64);
                                npass = 0;
                                let tc = Instant::now();
                                for row in fields.chunks(rowlen) {
                                    let mut rowref = [None; 2];
                                    for (c, v) in tb.cols.iter_mut().zip(row) {
                                        c.add(v, &mut rowref);
                                    }
                                }
                                t_cols += tc.elapsed();
                                rows_col += ends.len() as u64;
                                for (c, ids) in tb.cols.iter_mut().zip(&tb.sid) {
                                    for k in 0..NS {
                                        if !c.s[k].is_empty() {
                                            st.bufs[ids[k]].append(&mut c.s[k]);
                                            st.maybe_spill(ids[k])?;
                                        }
                                    }
                                }
                                handled = true;
                            }
                        }
                    }
                }
            }
        }
        if !handled {
            st.bufs[pass_id].extend_from_slice(&line);
            st.maybe_spill(pass_id)?;
            npass += 1;
        }
    }
    putu(&mut st.bufs[ops_id], npass);
    putu(&mut st.bufs[ops_id], 0);
    let digest = h.finalize();
    let digest = digest.as_bytes();
    let t_parse = t0.elapsed();

    // ---- choose variants (ip/id, tp/tr) and compress all streams in parallel ----
    // jobs: (stream ids that are alternatives, output name per alt)
    let mut groups: Vec<Vec<usize>> = vec![vec![ops_id], vec![pass_id]];
    for tb in &tables {
        for ids in &tb.sid {
            groups.push(vec![ids[0]]);
            groups.push(vec![ids[1], ids[2]]);
            groups.push(vec![ids[3], ids[4]]);
            groups.push(vec![ids[5]]);
            groups.push(vec![ids[7]]);
            groups.push(vec![ids[8]]);
            groups.push(vec![ids[9]]);
            groups.push(vec![ids[10]]);
            groups.push(vec![ids[6]]);
        }
    }
    for i in 0..st.names.len() {
        if st.spilled[i] {
            st.spill(i)?; // make on-disk copy complete so it can be streamed
        }
    }
    let empty = |i: usize| !st.spilled[i] && st.bufs[i].is_empty();
    groups.retain(|g| !g.iter().all(|&i| empty(i)));
    // biggest first for better parallel packing
    let size = |i: usize| -> u64 {
        (if st.spilled[i] { fs::metadata(st.path(i)).map(|m| m.len()).unwrap_or(0) } else { 0 }) + st.bufs[i].len() as u64
    };
    groups.sort_by_key(|g| std::cmp::Reverse(g.iter().map(|&i| size(i)).sum::<u64>()));

    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<(usize, u8, u64, PathBuf)>> = Mutex::new(vec![]);
    let err: Mutex<Option<String>> = Mutex::new(None);
    std::thread::scope(|sc| {
        for _ in 0..o.jobs.max(1) {
            sc.spawn(|| loop {
                let g = next.fetch_add(1, Ordering::SeqCst);
                if g >= groups.len() || err.lock().unwrap().is_some() {
                    break;
                }
                let run = || -> Res<(usize, u8, u64, PathBuf)> {
                    let mut win: Option<(usize, u8, u64, PathBuf, u64)> = None;
                    for &i in &groups[g] {
                        let (codec, rawlen, p) = compress_one(&st, i, o.mode, o.level)?;
                        let cl = fs::metadata(&p)?.len();
                        if win.as_ref().map_or(true, |w| cl < w.4) {
                            if let Some(w) = win.take() {
                                fs::remove_file(&w.3)?;
                            }
                            win = Some((i, codec, rawlen, p, cl));
                        } else {
                            fs::remove_file(&p)?;
                        }
                    }
                    let (i, codec, rawlen, p, _) = win.unwrap();
                    Ok((i, codec, rawlen, p))
                };
                match run() {
                    Ok(r) => results.lock().unwrap().push(r),
                    Err(e) => *err.lock().unwrap() = Some(e.to_string()),
                }
            });
        }
    });
    if let Some(e) = err.into_inner().unwrap() {
        let _ = fs::remove_dir_all(&dir);
        return Err(e.into());
    }
    let mut res = results.into_inner().unwrap();
    res.sort_by_key(|r| r.0);

    // ---- container: header (text) + blobs ----
    let mut hdr = String::new();
    hdr += &format!("size {}\nblake3 {}\n", total, digest.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    for (i, tb) in tables.iter().enumerate() {
        hdr += &format!("table {} {} {}\n", i, tb.ncols, tb.name);
    }
    let mut off = 0u64;
    for (i, codec, rawlen, p) in &res {
        let cl = fs::metadata(p)?.len();
        hdr += &format!("stream {} {} {} {} {}\n", st.names[*i], *codec as char, rawlen, off, cl);
        off += cl;
    }
    hdr += "end\n";
    let tmpout = format!("{}.part", output);
    {
        let mut w = BufWriter::with_capacity(8 << 20, File::create(&tmpout)?);
        w.write_all(MAGIC)?;
        w.write_all(&(hdr.len() as u64).to_le_bytes())?;
        w.write_all(hdr.as_bytes())?;
        for (_, _, _, p) in &res {
            io::copy(&mut File::open(p)?, &mut w)?;
        }
        w.flush()?;
        w.get_ref().sync_all()?;
    }
    fs::rename(&tmpout, output)?;
    fs::remove_dir_all(&dir)?;
    let outsz = fs::metadata(output)?.len();
    eprintln!(
        "zsql: {} -> {} bytes ({:.2}x) | {} tables, {} rows columnar | parse {:.1}s, total {:.1}s",
        total,
        outsz,
        total as f64 / outsz.max(1) as f64,
        tables.len(),
        rows_col,
        t_parse.as_secs_f64(),
        t0.elapsed().as_secs_f64()
    );
    if std::env::var_os("ZSQL_PROF").is_some() {
        eprintln!("zsql: prof hash {:.2}s, column-encode {:.2}s", t_hash.as_secs_f64(), t_cols.as_secs_f64());
    }
    Ok(())
}

// ---------------- decoder ----------------
struct In {
    buf: Vec<u8>,
    pos: usize,
    src: Option<Box<dyn Read>>,
}
impl In {
    fn empty() -> Self {
        In { buf: vec![], pos: 0, src: None }
    }
    fn fill(&mut self) -> io::Result<bool> {
        let Some(s) = self.src.as_mut() else { return Ok(false) };
        self.buf.drain(..self.pos);
        self.pos = 0;
        let l = self.buf.len();
        self.buf.resize(l + (1 << 20), 0);
        let n = s.read(&mut self.buf[l..])?;
        self.buf.truncate(l + n);
        Ok(n > 0)
    }
    #[inline]
    fn byte(&mut self) -> io::Result<u8> {
        while self.pos >= self.buf.len() {
            if !self.fill()? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream truncated"));
            }
        }
        self.pos += 1;
        Ok(self.buf[self.pos - 1])
    }
    #[inline]
    fn u(&mut self) -> io::Result<u64> {
        let (mut sh, mut r) = (0u32, 0u64);
        loop {
            let b = self.byte()?;
            r |= ((b & 0x7f) as u64) << sh;
            if b < 0x80 {
                return Ok(r);
            }
            sh += 7;
        }
    }
    /// up to (excluding) `delim`; with eof_ok returns the tail at EOF
    fn until(&mut self, delim: u8, keep: bool, out: &mut Vec<u8>) -> io::Result<()> {
        loop {
            if let Some(k) = self.buf[self.pos..].iter().position(|&c| c == delim) {
                let e = self.pos + k;
                out.extend_from_slice(&self.buf[self.pos..if keep { e + 1 } else { e }]);
                self.pos = e + 1;
                return Ok(());
            }
            if !self.fill()? {
                if keep && self.pos < self.buf.len() {
                    out.extend_from_slice(&self.buf[self.pos..]);
                    self.pos = self.buf.len();
                    return Ok(());
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "stream truncated"));
            }
        }
    }
}

struct Ent {
    codec: u8,
    raw: u64,
    off: u64,
    len: u64,
}

fn open_stream(path: &str, base: u64, e: &Ent) -> Res<In> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(base + e.off))?;
    let sec = BufReader::with_capacity(1 << 20, f.take(e.len));
    let rd: Box<dyn Read> = match e.codec {
        b'z' => {
            let mut d = zstd::stream::read::Decoder::with_buffer(sec)?;
            d.window_log_max(31)?;
            Box::new(d)
        }
        b'x' => Box::new(xz2::bufread::XzDecoder::new(sec)),
        _ => Box::new(sec),
    };
    if e.raw <= MEM_STREAM {
        let mut buf = Vec::with_capacity(e.raw as usize);
        let mut rd = rd;
        rd.read_to_end(&mut buf)?;
        Ok(In { buf, pos: 0, src: None })
    } else {
        Ok(In { buf: vec![], pos: 0, src: Some(rd) })
    }
}

struct DCol {
    s: [In; NS],
    int_delta: bool,
    t_row: bool,
    prev_i: i64,
    prev_t: [i64; 2],
    dict: Vec<Box<[u8]>>,
    hits: u32,
    seen: u32,
    frozen: bool,
}

fn decompress(input: &str, output: &str) -> Res<()> {
    let t0 = Instant::now();
    let mut f = File::open(input)?;
    let mut m = [0u8; 6];
    f.read_exact(&mut m)?;
    if m != MAGIC {
        return Err("not a zsql file".into());
    }
    let mut l = [0u8; 8];
    f.read_exact(&mut l)?;
    let hl = u64::from_le_bytes(l);
    let mut hb = vec![0u8; hl as usize];
    f.read_exact(&mut hb)?;
    let base = 6 + 8 + hl;
    let hdr = String::from_utf8(hb)?;
    let (mut sha, mut size) = (String::new(), 0u64);
    let mut tabs: Vec<(usize, String)> = vec![];
    let mut ents: HashMap<String, Ent> = HashMap::new();
    for ln in hdr.lines() {
        let p: Vec<&str> = ln.splitn(6, ' ').collect();
        match p[0] {
            "size" => size = p[1].parse()?,
            "blake3" => sha = p[1].into(),
            "table" => tabs.push((p[2].parse()?, ln.splitn(4, ' ').nth(3).ok_or("bad header")?.into())),
            "stream" => {
                ents.insert(
                    p[1].into(),
                    Ent { codec: p[2].as_bytes()[0], raw: p[3].parse()?, off: p[4].parse()?, len: p[5].parse()? },
                );
            }
            _ => {}
        }
    }
    let get = |n: &str| -> Res<In> { ents.get(n).map_or(Ok(In::empty()), |e| open_stream(input, base, e)) };
    let mut ops = get("ops")?;
    let mut pas = get("pass")?;
    let mut tables: Vec<Vec<DCol>> = vec![];
    let mut prefixes = vec![];
    for (ti, (n, name)) in tabs.iter().enumerate() {
        let (verb, tname) = name.split_once(' ').ok_or("bad table entry")?;
        prefixes.push(format!("{} INTO `{}` VALUES ", verb, tname).into_bytes());
        let mut cols = vec![];
        for c in 0..*n {
            let nm = |k: &str| format!("t{}.c{}.{}", ti, c, k);
            let int_delta = ents.contains_key(&nm("id"));
            let t_row = ents.contains_key(&nm("tr"));
            cols.push(DCol {
                s: [
                    get(&nm("kind"))?,
                    get(&nm(if int_delta { "id" } else { "ip" }))?,
                    In::empty(),
                    get(&nm(if t_row { "tr" } else { "tp" }))?,
                    In::empty(),
                    get(&nm("idx"))?,
                    get(&nm("lit"))?,
                    get(&nm("dm"))?,
                    get(&nm("dsc"))?,
                    get(&nm("hxh"))?,
                    get(&nm("hxb"))?,
                ],
                int_delta,
                t_row,
                prev_i: 0,
                prev_t: [0; 2],
                dict: vec![],
                hits: 0,
                seen: 0,
                frozen: false,
            });
        }
        tables.push(cols);
    }
    let to_stdout = output == "-";
    let tmpout = format!("{}.part", output);
    let sink: Box<dyn Write> = if to_stdout { Box::new(io::stdout().lock()) } else { Box::new(File::create(&tmpout)?) };
    let mut w = BufWriter::with_capacity(8 << 20, sink);
    let mut h = blake3::Hasher::new();
    let mut total = 0u64;
    let mut buf: Vec<u8> = Vec::with_capacity(8 << 20);
    let mut flush = |buf: &mut Vec<u8>, w: &mut BufWriter<Box<dyn Write>>| -> io::Result<()> {
        h.update(&buf[..]);
        total += buf.len() as u64;
        w.write_all(buf)?;
        buf.clear();
        Ok(())
    };
    loop {
        for _ in 0..ops.u()? {
            pas.until(b'\n', true, &mut buf)?;
        }
        let ti = ops.u()?;
        if ti == 0 {
            break;
        }
        let ti = ti as usize - 1;
        let nrows = ops.u()?;
        buf.extend_from_slice(&prefixes[ti]);
        let cols = &mut tables[ti];
        for r in 0..nrows {
            buf.extend_from_slice(if r == 0 { b"(" } else { b",(" });
            let mut rowref: [Option<i64>; 2] = [None; 2];
            for (ci, c) in cols.iter_mut().enumerate() {
                if ci > 0 {
                    buf.push(b',');
                }
                match c.s[0].byte()? {
                    K_NULL => buf.extend_from_slice(b"NULL"),
                    K_INT => {
                        let d = unzz(c.s[1].u()?);
                        let n = if c.int_delta { c.prev_i.wrapping_add(d) } else { d };
                        c.prev_i = n;
                        let _ = write!(buf, "{}", n);
                    }
                    k @ (K_T | K_T6) => {
                        let t = (k - K_T) as usize;
                        let d = unzz(c.s[3].u()?);
                        let r = if c.t_row { rowref[t].unwrap_or(c.prev_t[t]) } else { c.prev_t[t] };
                        let n = r.wrapping_add(d);
                        c.prev_t[t] = n;
                        rowref[t] = Some(n);
                        buf.push(b'\'');
                        tdec(k, n, &mut buf);
                        buf.push(b'\'');
                    }
                    K_STR => {
                        buf.push(b'\'');
                        let i = c.s[5].u()?;
                        if i > 0 {
                            let e = c.dict.get(i as usize - 1).ok_or("corrupt dictionary index")?;
                            buf.extend_from_slice(e);
                            c.hits += 1;
                        } else {
                            let st = buf.len();
                            c.s[6].until(0, false, &mut buf)?;
                            if !c.frozen && c.dict.len() < DICT_CAP {
                                c.dict.push(buf[st..].into());
                            }
                        }
                        c.seen += 1;
                        if !c.frozen && c.seen == FREEZE_AT && c.hits * 4 < c.seen {
                            c.frozen = true;
                            c.dict = vec![];
                        }
                        buf.push(b'\'');
                    }
                    K_RAW => c.s[6].until(0, false, &mut buf)?,
                    K_QINT => {
                        let d = unzz(c.s[1].u()?);
                        let n = if c.int_delta { c.prev_i.wrapping_add(d) } else { d };
                        c.prev_i = n;
                        let _ = write!(buf, "'{}'", n);
                    }
                    K_HEX => {
                        let f = c.s[9].byte()?;
                        let n = c.s[9].u()? as usize;
                        if n > 2048 {
                            return Err("corrupt hex length".into());
                        }
                        let mut tmp = Vec::with_capacity(n);
                        for _ in 0..n {
                            tmp.push(c.s[10].byte()?);
                        }
                        buf.push(b'\'');
                        hex_dec(f, &tmp, &mut buf);
                        buf.push(b'\'');
                    }
                    K_DEC => {
                        let m = unzz(c.s[7].u()?);
                        let sc = c.s[8].byte()?;
                        if sc > 18 {
                            return Err("corrupt decimal scale".into());
                        }
                        dec_fmt(m, sc, &mut buf);
                    }
                    k => return Err(format!("corrupt kind {}", k).into()),
                }
            }
            buf.push(b')');
        }
        buf.extend_from_slice(b";\n");
        if buf.len() > (4 << 20) {
            flush(&mut buf, &mut w)?;
        }
    }
    flush(&mut buf, &mut w)?;
    w.flush()?;
    drop(w);
    let got: String = h.finalize().as_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    if got != sha || total != size {
        if !to_stdout {
            let _ = fs::remove_file(&tmpout);
        }
        return Err(format!("CHECKSUM MISMATCH: output is NOT identical (got {} bytes)", total).into());
    }
    if !to_stdout {
        fs::rename(&tmpout, output)?;
    }
    eprintln!("zsql: restored {} bytes, blake3 OK, {:.1}s", total, t0.elapsed().as_secs_f64());
    Ok(())
}

fn usage() -> ! {
    eprintln!(
        "zsql — lossless column-aware compressor for mysqldump output

  zsql c [opts] IN.sql|- OUT.zsql     compress (IN '-' = stdin, e.g. mysqldump | zsql c - x.zsql)
      --fast          zstd only (no xz), much quicker
      -l N            zstd level (default 19)
      -j N            threads for stream compression (default 2)
      -t a,b          only columnarize these tables (default: all)
      --tmp DIR       scratch dir (default: next to OUT)
  zsql d IN.zsql OUT.sql|-            decompress + verify sha256 (OUT '-' = stdout)"
    );
    std::process::exit(2)
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.is_empty() {
        usage();
    }
    let r = match a[0].as_str() {
        "c" => {
            let mut o = Opts { mode: Mode::Max, level: 19, jobs: 2, only: None, tmp: None };
            let mut pos = vec![];
            let mut i = 1;
            while i < a.len() {
                match a[i].as_str() {
                    "--fast" => o.mode = Mode::Fast,
                    "-l" => {
                        i += 1;
                        o.level = a.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())
                    }
                    "-j" => {
                        i += 1;
                        o.jobs = a.get(i).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage())
                    }
                    "-t" => {
                        i += 1;
                        o.only = Some(a.get(i).unwrap_or_else(|| usage()).split(',').map(String::from).collect())
                    }
                    "--tmp" => {
                        i += 1;
                        o.tmp = Some(a.get(i).unwrap_or_else(|| usage()).into())
                    }
                    _ => pos.push(a[i].clone()),
                }
                i += 1;
            }
            if pos.len() != 2 {
                usage();
            }
            compress(&pos[0], &pos[1], &o)
        }
        "d" if a.len() == 3 => decompress(&a[1], &a[2]),
        _ => usage(),
    };
    if let Err(e) = r {
        eprintln!("zsql: error: {}", e);
        std::process::exit(1);
    }
}
