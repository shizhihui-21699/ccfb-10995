//! can-ids —— CAN 总线离线入侵检测引擎
//!
//!   can-ids learn  -i <candump.log> -m <model.out>
//!   can-ids detect -i <candump.log> -m <model.in> [-r <report.out>] [--json]

mod candump;
mod detect;
mod model;

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::time::Instant;

fn usage() -> ! {
    eprintln!("can-ids —— CAN 总线离线入侵检测引擎");
    eprintln!();
    eprintln!("用法:");
    eprintln!("  can-ids learn  -i <candump.log> -m <model.out>");
    eprintln!("  can-ids detect -i <candump.log> -m <model.in> [-r <report.out>] [--json]");
    eprintln!();
    eprintln!("  -i  输入日志,'-' 表示 stdin");
    eprintln!("  -r  报告输出文件,缺省 stdout");
    eprintln!("  --json  告警以 JSONL 输出");
    std::process::exit(2);
}

fn get_opt(args: &[String], name: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

fn open_input(path: &str) -> Box<dyn BufRead> {
    if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::with_capacity(
            1 << 20,
            File::open(path).unwrap_or_else(|e| {
                eprintln!("无法打开输入 {path}: {e}");
                std::process::exit(1);
            }),
        ))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("learn") => cmd_learn(&args[1..]),
        Some("detect") => cmd_detect(&args[1..]),
        _ => usage(),
    }
}

fn cmd_learn(args: &[String]) {
    let input = get_opt(args, "-i").unwrap_or_else(|| usage());
    let model_path = get_opt(args, "-m").unwrap_or_else(|| usage());
    let t0 = Instant::now();
    let mut learner = model::Learner::new();
    let mut reader = open_input(&input);
    let mut line = String::with_capacity(256);
    let mut frames = 0u64;
    let mut bad = 0u64;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        match candump::parse_line(line.trim_end()) {
            Some(f) => {
                learner.add(&f);
                frames += 1;
            }
            None => bad += 1,
        }
    }
    let m = learner.finish();
    m.save(&model_path);
    let el = t0.elapsed().as_secs_f64();
    eprintln!(
        "[learn] 帧数={} 解析失败={} ID数={} 耗时={:.2}s ({:.0} 帧/秒)",
        frames,
        bad,
        m.ids.len(),
        el,
        frames as f64 / el.max(1e-9)
    );
    eprintln!("[learn] 模型已写入 {model_path}");
}

fn cmd_detect(args: &[String]) {
    let input = get_opt(args, "-i").unwrap_or_else(|| usage());
    let model_path = get_opt(args, "-m").unwrap_or_else(|| usage());
    let report = get_opt(args, "-r");
    let json = args.iter().any(|a| a == "--json");

    let m = model::Model::load(&model_path);
    eprintln!("[detect] 模型加载: {} 个 ID", m.ids.len());

    let t0 = Instant::now();
    let mut det = detect::Detector::new(&m);
    let mut reader = open_input(&input);
    let mut line = String::with_capacity(256);
    let mut bad = 0u64;
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
            break;
        }
        match candump::parse_line(line.trim_end()) {
            Some(f) => det.process(&f),
            None => bad += 1,
        }
    }
    let frames = det.frames;
    let first_ts = det.first_ts;
    let last_ts = det.last_ts;
    let (mut alerts, congestion_suppressed) = det.finish();
    alerts.sort_by_key(|a| a.ts_us);
    let el = t0.elapsed().as_secs_f64();

    let out: Box<dyn Write> = match &report {
        Some(p) => Box::new(BufWriter::new(File::create(p).unwrap())),
        None => Box::new(BufWriter::new(std::io::stdout())),
    };
    let mut reporter = detect::Reporter::new(out, json);
    for a in alerts {
        reporter.emit(a);
    }
    reporter.flush();
    reporter.summary(frames, bad, el, first_ts, last_ts, congestion_suppressed);
    eprintln!("[detect] {} 帧,耗时 {:.2}s", frames, el);
}
