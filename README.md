# can-ids — CAN 总线离线入侵检测引擎

读取 candump 格式日志,先学习正常流量基线,再离线检测异常。零依赖 Rust 实现,
一小时日志(约 200 万帧)一秒内跑完。

## 构建

```sh
cd can-ids && cargo build --release
```

## 使用

```sh
# 学习:从干净日志建立模型
can-ids learn  -i learn.log  -m model.txt

# 检测:输出带时间点的告警报告
can-ids detect -i attack.log -m model.txt -r report.txt
can-ids detect -i attack.log -m model.txt --json   # JSONL 输出
```

支持 candump 常见格式:`(ts) can0 123#DEADBEEF`、`ID##flags...`(CAN FD)、
`ID#R`(远程帧)、`(ts) can0 123 [8] DE AD ...`(经典表格格式)。

## 检测的六类异常

| 类型 | 含义 |
|---|---|
| `UNKNOWN_ID` | 模型中从未见过的 ID |
| `FREQ_BURST` | 同一 ID 秒级速率超过学习峰值 2 倍 |
| `PERIOD_EARLY` | 帧间隔显著小于周期(提前到达) |
| `PERIOD_GAP` | 帧间隔显著大于周期(丢帧 / ECU 被抑制) |
| `DATA_RANGE` | 数据场字节超出学习到的取值范围 |
| `DLC_ANOMALY` | 数据长度超出学习范围 |

## 算法要点

**学习(learn)**:按 ID 统计帧间隔中位数(周期)、MAD 稳健抖动(σ = 1.4826·MAD,
对离群值不敏感)、秒级峰值速率、DLC 范围、数据场逐字节 min/max。模型存为文本文件。

**检测(detect)**:逐帧流式检查,关键设计是如何区分攻击与总线负载波动——

- **提前到达是强信号**:负载波动只会让报文延迟,不可能让报文提前。所以
  `间隔 < 周期 − max(4σ, 20%·周期)` 直接报警,不做任何豁免。
- **延迟是弱信号**:延迟候选先缓存,收尾时做全局相关性判定——若该时刻前后 2 秒内
  ≥25% 的已知 ID 都在延迟,判定为总线拥塞,抑制;只有孤立延迟的 ID 才报
  `PERIOD_GAP`。(代价:攻击恰好发生在拥塞窗口内的单 ID 抑制会被一起抑制。)
- **数据范围**:逐字节比对学习区间,容差 max(2, 量程/8),避免边界抖动误报。
- **频率**:1 秒桶计数,超过 `max(2×峰值, 峰值+8)` 报警,每秒每 ID 最多一条。
- 同类告警 1 秒去重(UNKNOWN_ID 5 秒),被抑制的次数以 NOTE 行汇总,防止报告爆炸。

## 测试

```sh
# 合成日志:1 小时干净流量(含负载波动窗口)+ 6 分钟攻击流量
python3 tools/gen_can_logs.py --mode learn  --seconds 3600 --out data/learn.log
python3 tools/gen_can_logs.py --mode attack --seconds 360  --out data/attack.log

# 学习 + 检测 + 对照 ground truth 评分
can-ids learn  -i data/learn.log  -m data/model.txt
can-ids detect -i data/attack.log -m data/model.txt -r data/report.txt
python3 tools/score.py data/report.txt data/attack.log.attacks.jsonl
```

合成日志注入 5 段典型攻击(ground truth 在 `*.attacks.jsonl`):

| 窗口 | 攻击 | 预期命中 |
|---|---|---|
| 60–70s | 模糊测试(随机 ID + 随机数据) | UNKNOWN_ID |
| 120–130s | 注入(合法 ID 高频重放) | FREQ_BURST, PERIOD_EARLY |
| 180–190s | 伪造(合法 ID、数据越界) | DATA_RANGE |
| 240–250s | 抑制(某 ID 彻底消失) | PERIOD_GAP |
| 300–310s | DoS(0x000 泛洪) | UNKNOWN_ID |

当前结果:5 段攻击全部 PASS,干净日志和负载波动窗口零误报;
195 万帧学习 0.16s、检测 0.15s(M 系列 Mac)。
