//! 学习模式:按 ID 统计周期(中位数 + MAD 稳健抖动)、秒级峰值速率、
//! DLC 范围和数据场逐字节取值范围,保存为文本模型文件。

use crate::candump::{Frame, MAX_DATA};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

pub struct IdModel {
    pub id: u32,
    pub count: u64,
    pub duration_us: i64,
    pub median_iat_us: f64, // 帧间隔中位数(周期)
    pub sigma_us: f64,      // 稳健标准差 = 1.4826 * MAD
    pub min_iat_us: u32,    // 学习期间最小帧间隔
    pub max_per_sec: u32,   // 学习期间任意 1 秒窗口内的最大帧数
    pub dlc_min: u8,
    pub dlc_max: u8,
    pub byte_min: [u8; MAX_DATA],
    pub byte_max: [u8; MAX_DATA],
}

impl IdModel {
    fn blank(id: u32) -> Self {
        IdModel {
            id,
            count: 0,
            duration_us: 0,
            median_iat_us: 0.0,
            sigma_us: 0.0,
            min_iat_us: 0,
            max_per_sec: 0,
            dlc_min: 0,
            dlc_max: 0,
            byte_min: [0; MAX_DATA],
            byte_max: [0; MAX_DATA],
        }
    }
}

pub struct Model {
    pub ids: BTreeMap<u32, IdModel>,
}

struct IdStats {
    count: u64,
    first_ts: i64,
    last_ts: i64,
    iats: Vec<u32>,
    byte_min: [u8; MAX_DATA],
    byte_max: [u8; MAX_DATA],
    dlc_min: u8,
    dlc_max: u8,
    sec_bucket: i64,
    sec_count: u32,
    max_per_sec: u32,
}

impl IdStats {
    fn new(ts: i64) -> Self {
        IdStats {
            count: 0,
            first_ts: ts,
            last_ts: ts,
            iats: Vec::new(),
            byte_min: [0xFF; MAX_DATA],
            byte_max: [0; MAX_DATA],
            dlc_min: 255,
            dlc_max: 0,
            sec_bucket: -1,
            sec_count: 0,
            max_per_sec: 0,
        }
    }

    fn add(&mut self, f: &Frame) {
        self.count += 1;
        if self.count > 1 {
            let d = f.ts_us - self.last_ts;
            if d >= 0 {
                self.iats.push(d as u32);
            }
        }
        self.last_ts = f.ts_us;

        let sec = f.ts_us / 1_000_000;
        if sec != self.sec_bucket {
            self.sec_bucket = sec;
            self.sec_count = 0;
        }
        self.sec_count += 1;
        if self.sec_count > self.max_per_sec {
            self.max_per_sec = self.sec_count;
        }

        if f.dlc < self.dlc_min {
            self.dlc_min = f.dlc;
        }
        if f.dlc > self.dlc_max {
            self.dlc_max = f.dlc;
        }
        for i in 0..(f.dlc as usize).min(MAX_DATA) {
            let v = f.data[i];
            if v < self.byte_min[i] {
                self.byte_min[i] = v;
            }
            if v > self.byte_max[i] {
                self.byte_max[i] = v;
            }
        }
    }
}

pub struct Learner {
    stats: HashMap<u32, IdStats>,
}

impl Learner {
    pub fn new() -> Self {
        Learner { stats: HashMap::new() }
    }

    pub fn add(&mut self, f: &Frame) {
        self.stats
            .entry(f.id)
            .or_insert_with(|| IdStats::new(f.ts_us))
            .add(f);
    }

    pub fn finish(self) -> Model {
        let mut ids = BTreeMap::new();
        for (id, st) in self.stats {
            let mut iats = st.iats;
            iats.sort_unstable();
            let (median, sigma, min_iat) = if iats.is_empty() {
                (0.0, 0.0, 0)
            } else {
                let med = percentile(&iats, 0.5);
                let mut dev: Vec<u32> =
                    iats.iter().map(|&x| (x as f64 - med).abs() as u32).collect();
                dev.sort_unstable();
                (med, 1.4826 * percentile(&dev, 0.5), iats[0])
            };
            ids.insert(
                id,
                IdModel {
                    id,
                    count: st.count,
                    duration_us: st.last_ts - st.first_ts,
                    median_iat_us: median,
                    sigma_us: sigma,
                    min_iat_us: min_iat,
                    max_per_sec: st.max_per_sec,
                    dlc_min: st.dlc_min,
                    dlc_max: st.dlc_max,
                    byte_min: st.byte_min,
                    byte_max: st.byte_max,
                },
            );
        }
        Model { ids }
    }
}

fn percentile(sorted: &[u32], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = p * (sorted.len() - 1) as f64;
    let lo = idx.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = idx - lo as f64;
    sorted[lo] as f64 * (1.0 - frac) + sorted[hi] as f64 * frac
}

impl Model {
    pub fn save(&self, path: &str) {
        let f = File::create(path).unwrap_or_else(|e| {
            eprintln!("无法写入模型文件 {path}: {e}");
            std::process::exit(1);
        });
        let mut w = BufWriter::new(f);
        writeln!(w, "CANIDS1").unwrap();
        for m in self.ids.values() {
            writeln!(w, "ID {:X}", m.id).unwrap();
            writeln!(w, "count {}", m.count).unwrap();
            writeln!(w, "duration_us {}", m.duration_us).unwrap();
            writeln!(w, "median_iat_us {:.1}", m.median_iat_us).unwrap();
            writeln!(w, "sigma_us {:.1}", m.sigma_us).unwrap();
            writeln!(w, "min_iat_us {}", m.min_iat_us).unwrap();
            writeln!(w, "max_per_sec {}", m.max_per_sec).unwrap();
            writeln!(w, "dlc_min {}", m.dlc_min).unwrap();
            writeln!(w, "dlc_max {}", m.dlc_max).unwrap();
            write!(w, "byte_min ").unwrap();
            for b in m.byte_min {
                write!(w, "{b:02X}").unwrap();
            }
            writeln!(w).unwrap();
            write!(w, "byte_max ").unwrap();
            for b in m.byte_max {
                write!(w, "{b:02X}").unwrap();
            }
            writeln!(w).unwrap();
            writeln!(w, "END").unwrap();
        }
    }

    pub fn load(path: &str) -> Model {
        let f = File::open(path).unwrap_or_else(|e| {
            eprintln!("无法打开模型文件 {path}: {e}");
            std::process::exit(1);
        });
        let mut r = BufReader::new(f);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        if line.trim() != "CANIDS1" {
            eprintln!("{path}: 不是有效的 can-ids 模型文件");
            std::process::exit(1);
        }
        let mut ids = BTreeMap::new();
        loop {
            line.clear();
            if r.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let t = line.trim();
            if let Some(hex) = t.strip_prefix("ID ") {
                let id = u32::from_str_radix(hex, 16).expect("模型文件 ID 损坏");
                let mut m = IdModel::blank(id);
                loop {
                    line.clear();
                    if r.read_line(&mut line).unwrap() == 0 {
                        break;
                    }
                    let t = line.trim();
                    if t == "END" {
                        break;
                    }
                    let (k, v) = t.split_once(' ').unwrap_or((t, ""));
                    match k {
                        "count" => m.count = v.parse().unwrap(),
                        "duration_us" => m.duration_us = v.parse().unwrap(),
                        "median_iat_us" => m.median_iat_us = v.parse().unwrap(),
                        "sigma_us" => m.sigma_us = v.parse().unwrap(),
                        "min_iat_us" => m.min_iat_us = v.parse().unwrap(),
                        "max_per_sec" => m.max_per_sec = v.parse().unwrap(),
                        "dlc_min" => m.dlc_min = v.parse().unwrap(),
                        "dlc_max" => m.dlc_max = v.parse().unwrap(),
                        "byte_min" => parse_hex64(v, &mut m.byte_min),
                        "byte_max" => parse_hex64(v, &mut m.byte_max),
                        _ => {}
                    }
                }
                ids.insert(id, m);
            }
        }
        Model { ids }
    }
}

fn parse_hex64(s: &str, out: &mut [u8; MAX_DATA]) {
    let b = s.as_bytes();
    for i in 0..MAX_DATA {
        let hi = b.get(2 * i).and_then(|&c| (c as char).to_digit(16));
        let lo = b.get(2 * i + 1).and_then(|&c| (c as char).to_digit(16));
        if let (Some(h), Some(l)) = (hi, lo) {
            out[i] = ((h << 4) | l) as u8;
        }
    }
}
