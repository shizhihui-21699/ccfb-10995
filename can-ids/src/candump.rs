//! candump 日志行解析(零依赖,手写解析保证速度)。
//! 支持格式:
//!   (1700000000.123456) can0 123#DEADBEEF           标准 candump -l 紧凑格式
//!   (1700000000.123456) can0 123##1DEADBEEF         CAN FD(## 后跟 flags 半字节)
//!   (1700000000.123456) can0 123#R                  远程帧
//!   (1700000000.123456) can0 123 [8] DE AD BE EF    candump 经典表格格式
//! 解析失败的行返回 None,由调用方计数。

pub const MAX_DATA: usize = 64; // CAN FD 最大 64 字节

#[derive(Clone)]
pub struct Frame {
    pub ts_us: i64, // 时间戳,微秒(candump 绝对时间)
    pub id: u32,    // 11/29 位 ID 均按数值存放
    pub dlc: u8,
    pub data: [u8; MAX_DATA],
}

#[inline]
fn hex_val(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some((c - b'0') as u32),
        b'a'..=b'f' => Some((c - b'a' + 10) as u32),
        b'A'..=b'F' => Some((c - b'A' + 10) as u32),
        _ => None,
    }
}

pub fn parse_line(line: &str) -> Option<Frame> {
    let b = line.as_bytes();
    let mut i = 0usize;

    // ---- 时间戳 "(sec.usec)" ----
    if b.first() != Some(&b'(') {
        return None;
    }
    i += 1;
    let mut sec: i64 = 0;
    let mut got = false;
    while let Some(&c) = b.get(i) {
        if c.is_ascii_digit() {
            sec = sec * 10 + (c - b'0') as i64;
            got = true;
            i += 1;
        } else {
            break;
        }
    }
    if !got || b.get(i) != Some(&b'.') {
        return None;
    }
    i += 1;
    let mut frac: i64 = 0;
    let mut nd = 0;
    while let Some(&c) = b.get(i) {
        if c.is_ascii_digit() {
            if nd < 6 {
                frac = frac * 10 + (c - b'0') as i64;
                nd += 1;
            }
            i += 1;
        } else {
            break;
        }
    }
    while nd < 6 {
        frac *= 10;
        nd += 1;
    }
    if b.get(i) != Some(&b')') {
        return None;
    }
    i += 1;
    let ts_us = sec * 1_000_000 + frac;

    // ---- 接口名(can0 等),跳过 ----
    while b.get(i) == Some(&b' ') {
        i += 1;
    }
    while let Some(&c) = b.get(i) {
        if c == b' ' {
            break;
        }
        i += 1;
    }
    while b.get(i) == Some(&b' ') {
        i += 1;
    }

    // ---- ID(十六进制,最多 8 位)----
    let mut id: u32 = 0;
    let mut nid = 0;
    while let Some(&c) = b.get(i) {
        match hex_val(c) {
            Some(v) => {
                id = (id << 4) | v;
                nid += 1;
                if nid > 8 {
                    return None;
                }
                i += 1;
            }
            None => break,
        }
    }
    if nid == 0 {
        return None;
    }

    let mut data = [0u8; MAX_DATA];
    let mut dlc: u8 = 0;

    match b.get(i) {
        Some(&b'#') => {
            // 紧凑格式 ID#DATA
            i += 1;
            if b.get(i) == Some(&b'#') {
                // CAN FD: ID##<flags><data>
                i += 1;
                i += 1; // 跳过 flags 半字节
            }
            if b.get(i) == Some(&b'R') {
                // 远程帧,无数据
                return Some(Frame { ts_us, id, dlc: 0, data });
            }
            let mut nibble: Option<u8> = None;
            while let Some(&c) = b.get(i) {
                match hex_val(c) {
                    Some(v) => {
                        match nibble {
                            None => nibble = Some(v as u8),
                            Some(hi) => {
                                if (dlc as usize) < MAX_DATA {
                                    data[dlc as usize] = (hi << 4) | v as u8;
                                    dlc += 1;
                                }
                                nibble = None;
                            }
                        }
                        i += 1;
                    }
                    None => break,
                }
            }
        }
        Some(&b' ') => {
            // 经典格式 ID [n] b0 b1 ...
            while b.get(i) == Some(&b' ') {
                i += 1;
            }
            if b.get(i) != Some(&b'[') {
                return None;
            }
            i += 1;
            let mut n: usize = 0;
            while let Some(&c) = b.get(i) {
                if c.is_ascii_digit() {
                    n = n * 10 + (c - b'0') as usize;
                    i += 1;
                } else {
                    break;
                }
            }
            if b.get(i) != Some(&b']') {
                return None;
            }
            i += 1;
            for k in 0..n.min(MAX_DATA) {
                while b.get(i) == Some(&b' ') {
                    i += 1;
                }
                let hi = hex_val(*b.get(i)?)?;
                let lo = hex_val(*b.get(i + 1)?)?;
                data[k] = ((hi << 4) | lo) as u8;
                dlc += 1;
                i += 2;
            }
        }
        _ => return None,
    }

    Some(Frame { ts_us, id, dlc, data })
}
