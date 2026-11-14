#!/usr/bin/env python3
"""对照 ground truth 评分检测报告。

用法: python3 score.py <report.txt> <attack.log.attacks.jsonl>
"""
import json
import re
import sys

ALERT_RE = re.compile(r"\[\+\s*([\d.]+)s\] (\w+)\s+id=(0x[0-9A-Fa-f]+)")


def main():
    report_path, truth_path = sys.argv[1], sys.argv[2]
    alerts = []
    for line in open(report_path):
        m = ALERT_RE.match(line)
        if m and m.group(2) != "NOTE":
            alerts.append((float(m.group(1)), m.group(2), m.group(3).upper()))

    truth = [json.loads(l) for l in open(truth_path)]
    windows = [(t["start"], t["end"]) for t in truth]

    print(f"告警总数(不含 NOTE): {len(alerts)}")
    print()
    all_pass = True
    for t in truth:
        # 窗口后留 5s 余量(抑制类攻击要等报文恢复才能发现缺口)
        lo, hi = t["start"] - 1.0, t["end"] + 5.0
        got = set()
        for ts, kind, cid in alerts:
            if lo <= ts <= hi:
                if "id" in t and cid != t["id"].upper():
                    continue
                got.add(kind)
        missing = [k for k in t["expect"] if k not in got]
        ok = not missing
        all_pass &= ok
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {t['attack']:<9} {t['start']:>4}-{t['end']:<4}s "
              f"期望 {t['expect']} 实际命中 {sorted(got)}"
              + (f" 缺失 {missing}" if missing else ""))

    # 窗口外告警 = 误报(负载波动窗口不应产生任何告警)
    fp = [a for a in alerts
          if not any(s - 1.0 <= a[0] <= e + 5.0 for s, e in windows)]
    print()
    print(f"窗口外告警(误报): {len(fp)}")
    for ts, kind, cid in fp[:20]:
        print(f"  +{ts:.3f}s {kind} {cid}")
    print()
    print("总体:", "PASS" if all_pass and not fp else "CHECK")


if __name__ == "__main__":
    main()
