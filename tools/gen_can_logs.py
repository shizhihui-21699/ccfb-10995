#!/usr/bin/env python3
"""合成 candump 格式 CAN 总线日志。

learn  模式: 纯正常流量(含若干总线负载波动窗口,用于让模型学到合理抖动)。
attack 模式: 正常流量 + 注入 5 段典型攻击,并输出 ground truth(<out>.attacks.jsonl)。

用法:
  python3 gen_can_logs.py --mode learn  --seconds 3600 --out learn.log
  python3 gen_can_logs.py --mode attack --seconds 360  --out attack.log
"""
import argparse
import heapq
import json
import math
import random
import sys

IDS = [
    0x0C0, 0x0F1, 0x121, 0x153, 0x1A4, 0x1F0,
    0x2A1, 0x2C4, 0x35A, 0x3B2, 0x400, 0x4A0,
]
PERIOD_MS = {
    0x0C0: 5, 0x0F1: 10, 0x121: 10, 0x153: 20, 0x1A4: 20, 0x1F0: 50,
    0x2A1: 100, 0x2C4: 100, 0x35A: 200, 0x3B2: 500, 0x400: 1000, 0x4A0: 1000,
}
BASE_TS = 1_700_000_000.0

# 攻击窗口(相对秒)
W_FUZZ = (60, 70)        # 模糊测试:随机 ID + 随机数据
W_INJECT = (120, 130)    # 注入:合法 ID 高频重放
W_SPOOF = (180, 190)     # 伪造:合法 ID、正常周期、数据越界
W_SUPPRESS = (240, 250)  # 抑制:某 ID 彻底消失
W_DOS = (300, 310)       # DoS:0x000 最高优先级泛洪


class Profile:
    """每个 ID 的数据场模型:7 个有界正弦信号字节 + 1 个滚动计数器。"""

    def __init__(self, rng):
        self.base = [rng.randint(20, 150) for _ in range(7)]
        self.amp = [rng.randint(0, 30) for _ in range(7)]
        self.freq = [rng.uniform(0.05, 0.5) for _ in range(7)]
        self.phase = [rng.uniform(0, 6.28) for _ in range(7)]

    def data(self, t, ctr):
        b = [int(self.base[i] + self.amp[i] * math.sin(self.freq[i] * t + self.phase[i])) & 0xFF
             for i in range(7)]
        b.append(ctr & 0xFF)
        return bytes(b)


def in_windows(t, windows):
    return any(s <= t < e for s, e in windows)


def gen_normal(can_id, t0, t1, profile, rng, load_windows, suppress_windows):
    """正常周期报文。负载窗口内所有 ID 一起被额外延迟(模拟总线拥塞)。"""
    period = PERIOD_MS[can_id] / 1000.0
    t = t0 + rng.uniform(0, period)
    ctr = 0
    while t < t1:
        rel = t - t0
        if not in_windows(rel, suppress_windows):
            yield t, can_id, profile.data(rel, ctr)
        ctr += 1
        jitter = rng.uniform(-0.02, 0.02)
        # 负载波动:额外 0~1.5 倍周期的延迟,所有 ID 在同一窗口内同时发生
        extra = rng.uniform(0.0, 1.5) if in_windows(rel, load_windows) else 0.0
        t += period * (1.0 + jitter + extra)


def gen_fuzz(rng, t0, t1, rate=200.0):
    t = t0
    while t < t1:
        yield t, rng.randint(0x100, 0x7EF), bytes(rng.getrandbits(8) for _ in range(8))
        t += rng.uniform(0.5, 1.5) / rate


def gen_inject(rng, t0, t1, can_id, profile, rate=500.0):
    t = t0
    while t < t1:
        yield t, can_id, profile.data(t - BASE_TS, rng.getrandbits(8))
        t += rng.uniform(0.5, 1.5) / rate


def gen_spoof(rng, t0, t1, can_id, period):
    t = t0
    while t < t1:
        yield t, can_id, b"\xff" * 7 + bytes([rng.getrandbits(8)])
        t += period * rng.uniform(0.95, 1.05)


def gen_dos(rng, t0, t1, rate=3000.0):
    t = t0
    while t < t1:
        yield t, 0x000, b"\x00" * 8
        t += 1.0 / rate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["learn", "attack"], required=True)
    ap.add_argument("--seconds", type=float, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    profiles = {i: Profile(random.Random(args.seed * 1000 + i)) for i in IDS}
    t0, t1 = BASE_TS, BASE_TS + args.seconds

    if args.mode == "learn":
        load_windows = [(900, 930), (2000, 2030), (3200, 3230)]
    else:
        load_windows = [(150, 160), (330, 340)]  # 与攻击窗口错开

    gens = []
    for i in IDS:
        sw = [W_SUPPRESS] if (args.mode == "attack" and i == 0x1F0) else []
        gens.append(gen_normal(i, t0, t1, profiles[i], rng, load_windows, sw))

    truth = []
    if args.mode == "attack":
        def A(w):
            return t0 + w[0], t0 + w[1]

        gens.append(gen_fuzz(rng, *A(W_FUZZ)))
        gens.append(gen_inject(rng, *A(W_INJECT), 0x0C0, profiles[0x0C0]))
        gens.append(gen_spoof(rng, *A(W_SPOOF), 0x153, PERIOD_MS[0x153] / 1000.0))
        gens.append(gen_dos(rng, *A(W_DOS)))
        truth = [
            {"start": W_FUZZ[0], "end": W_FUZZ[1], "attack": "fuzz",
             "expect": ["UNKNOWN_ID"]},
            {"start": W_INJECT[0], "end": W_INJECT[1], "attack": "inject", "id": "0x0C0",
             "expect": ["FREQ_BURST", "PERIOD_EARLY"]},
            {"start": W_SPOOF[0], "end": W_SPOOF[1], "attack": "spoof", "id": "0x153",
             "expect": ["DATA_RANGE"]},
            {"start": W_SUPPRESS[0], "end": W_SUPPRESS[1], "attack": "suppress", "id": "0x1F0",
             "expect": ["PERIOD_GAP"]},
            {"start": W_DOS[0], "end": W_DOS[1], "attack": "dos", "id": "0x000",
             "expect": ["UNKNOWN_ID"]},
        ]

    n = 0
    with open(args.out, "w") as f:
        for ts, cid, data in heapq.merge(*gens, key=lambda x: x[0]):
            f.write(f"({ts:.6f}) can0 {cid:03X}#{data.hex().upper()}\n")
            n += 1
    if truth:
        with open(args.out + ".attacks.jsonl", "w") as f:
            for t in truth:
                f.write(json.dumps(t) + "\n")
        print(f"ground truth -> {args.out}.attacks.jsonl", file=sys.stderr)
    print(f"写入 {args.out}: {n} 帧", file=sys.stderr)


if __name__ == "__main__":
    main()
