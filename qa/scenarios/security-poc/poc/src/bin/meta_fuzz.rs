//! Short mutation fuzzing of foca-meta (extract + text) on the tests/corpus corpus.
//! Each input runs on its own thread with a deadline (a hang is a finding); a panic is a finding (catch_unwind
//! inside extract should catch it); peak RSS is tracked. Deterministic PRNG (the seed is printed).
//! usage: meta_fuzz <corpus_dir> <seconds> [seed]; crashing inputs are written to qa/scenarios/security-poc/fuzz-crashes/
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if !matches!(p.extension().and_then(|x| x.to_str()), Some("json" | "md" | "py")) {
                out.push(p);
            }
        }
    }
}

fn rss_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0)))
        .unwrap_or(0)
}

const MAGIC: &[&[u8]] = &[b"obj", b"endobj", b"stream", b"endstream", b"/Length 999999999", b"/ObjStm", b"/Prev 0", b"xref", b"trailer", b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", b"<!DOCTYPE x [<!ENTITY a \"aaaa\">]>", b"&a;", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"\xfe\xff\xff\xff", b"\xff\xd8\xff\xe1", b"Exif\x00\x00", b"II*\x00", b"MM\x00*"];

fn mutate(r: &mut Rng, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    let n = 1 + r.below(8);
    for _ in 0..n {
        if v.is_empty() { v.push(0); }
        match r.below(7) {
            0 => { let i = r.below(v.len()); v[i] = r.next() as u8; }
            1 => { let i = r.below(v.len()); v[i] ^= 1 << r.below(8); }
            2 => { let i = r.below(v.len()); let m = MAGIC[r.below(MAGIC.len())]; v.splice(i..i, m.iter().copied()); }
            3 => { let i = r.below(v.len()); let len = r.below(64).min(v.len() - i); v.drain(i..i + len); }
            4 => { let i = r.below(v.len()); let j = r.below(v.len()); let len = r.below(256).min(v.len() - j); let chunk = v[j..j + len].to_vec(); v.splice(i..i, chunk); }
            5 => { let i = r.below(v.len().saturating_sub(4).max(1)); let val: u32 = [0, 0xffff_ffff, 0x7fff_ffff, 0x8000_0000, 1, 0xffff][r.below(6)]; for (k, b) in val.to_le_bytes().iter().enumerate() { if i + k < v.len() { v[i + k] = *b; } } }
            _ => { let i = r.below(v.len()); v.truncate(i.max(1)); }
        }
    }
    v
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let corpus = PathBuf::from(&a[1]);
    let secs: u64 = a.get(2).and_then(|s| s.parse().ok()).unwrap_or(300);
    let seed: u64 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(0x5eed_f0ca);
    let out = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../fuzz-crashes"));
    let mut files = Vec::new();
    walk(&corpus, &mut files);
    files.sort();
    let seeds: Vec<(String, Vec<u8>)> = files.iter().filter_map(|p| Some((p.file_name()?.to_string_lossy().into_owned(), std::fs::read(p).ok()?))).filter(|(_, b)| b.len() < 4 << 20).collect();
    println!("seed={seed:#x} corpus={} files, budget {secs}s", seeds.len());
    let mut r = Rng(seed);
    let t0 = Instant::now();
    let (mut n, mut errs, mut oks, mut hangs, mut panics) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut slowest = (Duration::ZERO, String::new());
    std::panic::set_hook(Box::new(|_| {}));
    while t0.elapsed() < Duration::from_secs(secs) {
        let (name, src) = &seeds[r.below(seeds.len())];
        let input = mutate(&mut r, src);
        let (tx, rx) = mpsc::channel();
        let data = input.clone();
        let nm = name.clone();
        let t = Instant::now();
        std::thread::spawn(move || {
            let lim = foca_meta::Limits::default();
            let res = std::panic::catch_unwind(|| {
                let e = foca_meta::extract(&data, Some(&nm), &lim).is_ok();
                let _ = foca_meta::text(&data, &lim);
                e
            });
            let _ = tx.send(res);
        });
        match rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(true)) => oks += 1,
            Ok(Ok(false)) => errs += 1,
            Ok(Err(_)) => {
                panics += 1;
                std::fs::create_dir_all(&out).ok();
                let p = out.join(format!("panic-{n}-{name}"));
                std::fs::write(&p, &input).ok();
                println!("PANIC escaped catch_unwind: {} (seed file {name})", p.display());
            }
            Err(_) => {
                hangs += 1;
                std::fs::create_dir_all(&out).ok();
                let p = out.join(format!("hang-{n}-{name}"));
                std::fs::write(&p, &input).ok();
                println!("HANG >10s: {} (seed file {name})", p.display());
            }
        }
        let el = t.elapsed();
        if el > slowest.0 { slowest = (el, name.clone()); }
        n += 1;
        if n % 2000 == 0 {
            println!("{n} execs, {:.0}s, ok={oks} err={errs} hang={hangs} panic={panics} peakRSS={} MB slowest={:?} ({})", t0.elapsed().as_secs_f64(), rss_kb() / 1024, slowest.0, slowest.1);
        }
        if hangs > 5 { break; }
    }
    println!("DONE {n} execs in {:.0}s: ok={oks} err={errs} hang={hangs} panic={panics} peakRSS={} MB slowest={:?} ({})", t0.elapsed().as_secs_f64(), rss_kb() / 1024, slowest.0, slowest.1);
}
