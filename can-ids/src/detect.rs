//! 检测模式:加载模型,逐帧检查六类异常。
//!
//! 告警类型:
//!   UNKNOWN_ID    模型中从未见过的 ID
//!   FREQ_BURST    同一 ID 秒级速率超过学习峰值的 2 倍
//!   PERIOD_EARLY  帧间隔显著小于周期(提前到达 —— 负载波动只会延迟报文,
//!                 不可能让报文提前,所以这是强注入信号)
//!   PERIOD_GAP    帧间隔显著大于周期(疑似丢帧/ECU 被抑制);
//!                 若同一时刻大量 ID 一起延迟则判定为总线负载波动,不报
//!   DATA_RANGE    数据场字节超出学习到的取值范围(含小容差)
//!   DLC_ANOMALY   数据长度超出学习范围

use crate::candump::Frame;
use crate::model::Model;
use std::collections::{HashMap, HashSet};
use std::io::Write;

pub struct Alert {
    pub ts_us: i64,
    pub rel_us: i64,
    pub kind: &'static str,
    pub id: u32,
    pub detail: String,
}

struct IdState {
    last_ts: i64,
    sec_bucket: i64,
    sec_count: u32,
}

pub struct Detector<'m> {
    model: &'m Model,
    state: HashMap<u32, IdState>,
    alerts: Vec<Alert>,
    // (ts, id, iat, rel) —— 延迟类候选,留到 finish() 做全局负载相关性判定
    late_candidates: Vec<(i64, u32, f64, i64)>,
    pub frames: u64,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
}

impl<'m> Detector<'m> {
    pub fn new(model: &'m Model) -> Self {
        Detector {
            model,
            state: HashMap::new(),
            alerts: Vec::new(),
            late_candidates: Vec::new(),
            frames: 0,
            first_ts: None,
            last_ts: None,
        }
    }

    pub fn process(&mut self, f: &Frame) {
        self.frames += 1;
        let first = *self.first_ts.get_or_insert(f.ts_us);
        self.last_ts = Some(f.ts_us);
        let rel = f.ts_us - first;
        let id = f.id;

        let Some(m) = self.model.ids.get(&id) else {
            self.alerts.push(Alert {
                ts_us: f.ts_us,
                rel_us: rel,
                kind: "UNKNOWN_ID",
                id,
                detail: "模型中不存在该 ID".to_string(),
            });
            return;
        };

        if f.dlc < m.dlc_min || f.dlc > m.dlc_max {
            self.alerts.push(Alert {
                ts_us: f.ts_us,
                rel_us: rel,
                kind: "DLC_ANOMALY",
                id,
                detail: format!("dlc={} 学习范围={}..{}", f.dlc, m.dlc_min, m.dlc_max),
            });
        }

        // 数据场逐字节范围(只检查学习时覆盖到的字节,容差 = max(2, 量程/8))
        let n = (f.dlc as usize).min(m.dlc_max as usize);
        for i in 0..n {
            let v = f.data[i];
            let lo = m.byte_min[i];
            let hi = m.byte_max[i];
            let tol = ((hi - lo) / 8).max(2);
            if v < lo.saturating_sub(tol) || v > hi.saturating_add(tol) {
                self.alerts.push(Alert {
                    ts_us: f.ts_us,
                    rel_us: rel,
                    kind: "DATA_RANGE",
                    id,
                    detail: format!(
                        "byte[{}]=0x{:02X} 学习范围=0x{:02X}..0x{:02X} 容差={}",
                        i, v, lo, hi, tol
                    ),
                });
                break; // 一帧报一个就够了
            }
        }

        // 秒级频率
        let st = self
            .state
            .entry(id)
            .or_insert(IdState { last_ts: -1, sec_bucket: -1, sec_count: 0 });
        let sec = f.ts_us / 1_000_000;
        if sec != st.sec_bucket {
            st.sec_bucket = sec;
            st.sec_count = 0;
        }
        st.sec_count += 1;
        let freq_th = (m.max_per_sec * 2).max(m.max_per_sec + 8);
        if st.sec_count == freq_th + 1 {
            self.alerts.push(Alert {
                ts_us: f.ts_us,
                rel_us: rel,
                kind: "FREQ_BURST",
                id,
                detail: format!("秒级速率超过 {}/s(学习峰值 {}/s)", freq_th, m.max_per_sec),
            });
        }

        // 周期/抖动(样本太少的 ID 不做时序判定)
        if m.count >= 100 && m.median_iat_us > 0.0 && st.last_ts >= 0 {
            let iat = (f.ts_us - st.last_ts) as f64;
            if iat >= 0.0 {
                let early_th =
                    m.median_iat_us - (4.0 * m.sigma_us).max(0.2 * m.median_iat_us);
                let late_th = m.median_iat_us + (8.0 * m.sigma_us).max(m.median_iat_us);
                if iat < early_th {
                    self.alerts.push(Alert {
                        ts_us: f.ts_us,
                        rel_us: rel,
                        kind: "PERIOD_EARLY",
                        id,
                        detail: format!(
                            "间隔={:.0}us 远小于周期={:.0}us(阈值 {:.0}us)",
                            iat, m.median_iat_us, early_th
                        ),
                    });
                } else if iat > late_th {
                    self.late_candidates.push((f.ts_us, id, iat, rel));
                }
            }
        }
        st.last_ts = f.ts_us;
    }

    /// 收尾:对延迟候选做全局负载相关性判定。
    /// 若某候选前后 2 秒内 ≥25% 的已知 ID 都出现延迟,判定为总线负载波动,抑制;
    /// 否则是单个 ID 的异常(丢帧/ECU 被抑制),报 PERIOD_GAP。
    /// 返回 (全部告警, 被负载波动抑制的数量)。
    pub fn finish(mut self) -> (Vec<Alert>, u64) {
        // 每个 (ID, 秒) 只保留最早一个候选,控制规模
        let mut dedup: HashMap<(u32, i64), (i64, f64, i64)> = HashMap::new();
        for &(ts, id, iat, rel) in &self.late_candidates {
            let key = (id, ts / 1_000_000);
            dedup
                .entry(key)
                .and_modify(|e| {
                    if ts < e.0 {
                        *e = (ts, iat, rel);
                    }
                })
                .or_insert((ts, iat, rel));
        }
        let mut cands: Vec<(i64, u32, f64, i64)> = dedup
            .into_iter()
            .map(|((id, _), (ts, iat, rel))| (ts, id, iat, rel))
            .collect();
        cands.sort_by_key(|c| c.0);

        // 滑动窗口(±2s)统计同时延迟的不同 ID 数。
        // 窗口要宽于 1s:慢周期 ID(如 1s 周期)在负载窗口末尾才显现延迟,
        // 此时其他 ID 的延迟事件已过去近 1s,±1s 窗口会漏掉相关性。
        let total_ids = self.model.ids.len().max(1);
        let mut counts: HashMap<u32, u32> = HashMap::new();
        let mut l = 0usize;
        let mut r = 0usize;
        let mut suppressed = 0u64;
        for i in 0..cands.len() {
            let ts = cands[i].0;
            while r < cands.len() && cands[r].0 <= ts + 2_000_000 {
                *counts.entry(cands[r].1).or_insert(0) += 1;
                r += 1;
            }
            while l < i && cands[l].0 < ts - 2_000_000 {
                if let Some(c) = counts.get_mut(&cands[l].1) {
                    *c -= 1;
                    if *c == 0 {
                        counts.remove(&cands[l].1);
                    }
                }
                l += 1;
            }
            let distinct = counts.len();
            if distinct >= 3 && distinct as f64 >= 0.25 * total_ids as f64 {
                suppressed += 1;
            } else {
                let m = &self.model.ids[&cands[i].1];
                self.alerts.push(Alert {
                    ts_us: cands[i].0,
                    rel_us: cands[i].3,
                    kind: "PERIOD_GAP",
                    id: cands[i].1,
                    detail: format!(
                        "间隔={:.0}us 远大于周期={:.0}us(疑似丢帧/ECU被抑制)",
                        cands[i].2, m.median_iat_us
                    ),
                });
            }
        }
        (self.alerts, suppressed)
    }
}

/// 报告输出:文本或 JSONL,带同类告警 1 秒去重(UNKNOWN_ID 5 秒)。
pub struct Reporter<W: Write> {
    out: W,
    json: bool,
    // (id, kind) -> (上次输出时间, 已抑制数, 最近一次时间, 最近一次相对时间)
    last: HashMap<(u32, &'static str), (i64, u32, i64, i64)>,
    pub total: u64,
    pub by_kind: HashMap<&'static str, u64>,
}

impl<W: Write> Reporter<W> {
    pub fn new(out: W, json: bool) -> Self {
        Reporter {
            out,
            json,
            last: HashMap::new(),
            total: 0,
            by_kind: HashMap::new(),
        }
    }

    pub fn emit(&mut self, a: Alert) {
        self.total += 1;
        *self.by_kind.entry(a.kind).or_insert(0) += 1;
        let window: i64 = if a.kind == "UNKNOWN_ID" { 5_000_000 } else { 1_000_000 };
        let key = (a.id, a.kind);
        let mut pending_note: Option<(u32, i64, i64)> = None;
        match self.last.get_mut(&key) {
            Some(e) if a.ts_us - e.0 < window => {
                e.1 += 1;
                e.2 = a.ts_us;
                e.3 = a.rel_us;
                return;
            }
            Some(e) => {
                if e.1 > 0 {
                    pending_note = Some((e.1, e.2, e.3));
                }
                *e = (a.ts_us, 0, a.ts_us, a.rel_us);
            }
            None => {
                self.last.insert(key, (a.ts_us, 0, a.ts_us, a.rel_us));
            }
        }
        if let Some((c, ts, rel)) = pending_note {
            self.note(a.kind, a.id, c, ts, rel);
        }
        self.write_alert(&a);
    }

    pub fn flush(&mut self) {
        let keys: Vec<(u32, &'static str)> = self.last.keys().copied().collect();
        for k in keys {
            let (c, ts, rel) = {
                let e = &self.last[&k];
                (e.1, e.2, e.3)
            };
            if c > 0 {
                self.note(k.1, k.0, c, ts, rel);
            }
        }
    }

    fn note(&mut self, kind: &'static str, id: u32, count: u32, ts: i64, rel: i64) {
        if self.json {
            writeln!(
                self.out,
                "{{\"ts\":{:.6},\"rel_s\":{:.6},\"kind\":\"NOTE\",\"id\":\"0x{:03X}\",\"detail\":\"{} 重复 {} 次已抑制\"}}",
                ts as f64 / 1e6,
                rel as f64 / 1e6,
                id,
                kind,
                count
            )
            .unwrap();
        } else {
            writeln!(
                self.out,
                "[+{:12.6}s] {:<13} id=0x{:03X}  同类告警在窗口内重复 {} 次,已抑制",
                rel as f64 / 1e6,
                "NOTE",
                id,
                count
            )
            .unwrap();
        }
    }

    fn write_alert(&mut self, a: &Alert) {
        if self.json {
            writeln!(
                self.out,
                "{{\"ts\":{:.6},\"rel_s\":{:.6},\"kind\":\"{}\",\"id\":\"0x{:03X}\",\"detail\":\"{}\"}}",
                a.ts_us as f64 / 1e6,
                a.rel_us as f64 / 1e6,
                a.kind,
                a.id,
                json_escape(&a.detail)
            )
            .unwrap();
        } else {
            writeln!(
                self.out,
                "[+{:12.6}s] {:<13} id=0x{:03X}  {}",
                a.rel_us as f64 / 1e6,
                a.kind,
                a.id,
                a.detail
            )
            .unwrap();
        }
    }

    pub fn summary(
        &mut self,
        frames: u64,
        bad: u64,
        elapsed: f64,
        first_ts: Option<i64>,
        last_ts: Option<i64>,
        congestion_suppressed: u64,
    ) {
        writeln!(self.out).unwrap();
        writeln!(self.out, "==== 检测汇总 ====").unwrap();
        writeln!(self.out, "报文总数: {} (解析失败 {})", frames, bad).unwrap();
        if let (Some(a), Some(b)) = (first_ts, last_ts) {
            writeln!(self.out, "日志时间跨度: {:.3} 秒", (b - a) as f64 / 1e6).unwrap();
        }
        writeln!(
            self.out,
            "检测耗时: {:.2} 秒 ({:.0} 帧/秒)",
            elapsed,
            frames as f64 / elapsed.max(1e-9)
        )
        .unwrap();
        writeln!(self.out, "告警总数: {}", self.total).unwrap();
        let mut kinds: Vec<_> = self.by_kind.iter().collect();
        kinds.sort_by_key(|(k, _)| *k);
        for (k, c) in kinds {
            writeln!(self.out, "  {:<13} {}", k, c).unwrap();
        }
        writeln!(
            self.out,
            "因总线负载波动抑制的周期告警: {}",
            congestion_suppressed
        )
        .unwrap();
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// 供评分脚本等外部工具复用的常量
#[allow(dead_code)]
pub const KINDS: [&str; 6] = [
    "UNKNOWN_ID",
    "FREQ_BURST",
    "PERIOD_EARLY",
    "PERIOD_GAP",
    "DATA_RANGE",
    "DLC_ANOMALY",
];

#[allow(dead_code)]
fn _assert_kinds_unique() {
    let s: HashSet<_> = KINDS.iter().collect();
    assert_eq!(s.len(), KINDS.len());
}
