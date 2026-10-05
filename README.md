# telemetry-gateway

低轨卫星地面站遥测网关。同一信道的二进制帧可经多条 TCP 连接并发送达，网关在任意
拆包、粘包、乱序与重传下重组出一致的连续载荷摘要，并通过 HTTP API 暴露每信道状态。

## 帧格式

| 字段 | 长度（字节） | 说明 |
| --- | --- | --- |
| 同步字 | 4 | 固定 `1A CF FC 1D` |
| 信道号 | 1 | 0–255 |
| 序号 | 4 | 大端 uint32，每信道从 0 开始 |
| 载荷长度 | 2 | 大端 uint16，合法范围 1–1024 |
| 载荷 | 1–1024 | 原始字节 |
| CRC32 | 4 | 大端 CRC-32（IEEE 多项式，同 zlib/PNG），覆盖信道号至载荷 |

解析语义：

- 任意拆包（含逐字节）、粘包、帧前垃圾字节均可处理；
- 长度非法（0 或 >1024）或 CRC 错误的候选帧被丢弃，并从其后一字节继续扫描同步字，
  因此与坏帧粘连的好帧仍能恢复。

## 重组语义

- 每信道 `nextSequence` 从 0 开始；可暂存领先 `nextSequence` 不超过 31 的帧
  （窗口 `[next, next+31]`）；
- 同序号同载荷的重传（无论已消费还是暂存中）一律忽略；
- 同序号载荷冲突，或序号越出窗口（`seq - next > 31`），该信道**永久**标记为
  `failed` 并记录明确原因，后续帧全部忽略，状态与原因保持稳定；
- 连续载荷（从 0 起无空洞的部分）滚动计算 SHA-256 与字节数。

## 检查点计划

`POST /api/channels/{id}/checkpoint-plan` 为信道登记一份可信检查点计划，用于发现
单帧 CRC 无法识别的整体串换（每一段的累计字节数/SHA-256 均由任务侧独立给出）：

```json
{
  "checkpoints": [
    {"sequence": 9,  "contiguousBytes": 1500, "sha256": "…小写 hex…"},
    {"sequence": 19, "contiguousBytes": 3100, "sha256": "…小写 hex…"}
  ]
}
```

- 含 1–4 项检查点，各项 `sequence`（末帧序号）严格递增，`sha256` 为 64 位小写 hex；
- 仅**已存在**（至少收到过一帧）且未 failed 的信道可登记：未知信道 `404`，
  非法 id/正文 `400`；
- 首项 `sequence` 不得早于登记时的 `nextSequence`：若入流已消费过该末帧
  （`nextSequence > sequence`），整份拒绝（`409`）且不保存任何内容；
- 每信道只接受一份计划。同内容重试幂等返回各项当前状态（`replayed: true`）；
  异内容返回 `409`，原计划不受影响；
- 登记与 TCP 入流在同一把锁内原子裁决。组装跨过边界（消费完序号 `sequence` 的帧）
  时，**只**核对截至该序号的累计字节数与 SHA-256；已暂存的更高序号帧不会混入；
- 任一检查点不符，信道**永久** `failed`，后续帧不得改变状态。查询稳定给出失败的
  检查点序号及期望/实际结果（见下）；此前已 `verified` 与之后仍 `pending` 的
  检查点状态同样保持稳定。

响应示例：

```json
{
  "replayed": false,
  "checkpoints": [
    {"sequence": 9,  "contiguousBytes": 1500, "sha256": "…", "state": "verified"},
    {"sequence": 19, "contiguousBytes": 3100, "sha256": "…", "state": "pending"}
  ]
}
```

`state` 为 `pending` / `verified` / `failed`；`failed` 项额外带
`actualContiguousBytes` 与 `actualSha256`。

## HTTP API

`GET /api/channels/{id}`（`id` 为 0–255 的整数）：

```json
{
  "channel": 7,
  "status": "ok",            // 或 "failed"
  "nextSequence": 48,
  "seenSequences": [0, 1, 2],
  "contiguousBytes": 7156,
  "sha256": "…hex…",
  "failReason": "…",         // 仅 failed 时存在
  "checkpoints": [ … ]       // 仅登记过检查点计划时存在
}
```

- 未知信道：`404`；非法 id：`400`；
- 未登记计划时响应字段与旧版完全一致（无 `checkpoints` 字段）；
- `GET /healthz`：健康检查，恒 `200`。

## 配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `HTTP_PORT` / `TCP_PORT` | `8080` / `9000` | 容器内监听端口 |
| `HTTP_HOST_PORT` / `TCP_HOST_PORT` | `8080` / `9000` | 宿主机映射端口（compose） |

## 运行

```sh
# 构建并启动网关（宿主机端口可用环境变量覆盖）
HTTP_HOST_PORT=18080 TCP_HOST_PORT=19000 docker compose up -d --build app

# 一次性验证：app 健康检查通过后自动运行 verify 服务，
# 其退出码覆盖：单元测试、镜像内项目构建、真实 TCP 写入与查询冒烟
docker compose up --build --exit-code-from verify verify
echo $?   # 0 表示全部通过

docker compose down
```

`verify` 的冒烟场景（每轮从当前空闲信道中随机选取测试信道 + 1 个 404 探测信道，
因此对同一网关实例可重复运行）：

1. 48 帧经三条并发连接送达——逐字节写入、与垃圾/坏 CRC/非法长度帧粘连、乱序、
   同载荷重传——最终摘要必须与本地独立计算的 SHA-256 完全一致；
2. 同序号不同载荷的冲突帧使信道永久 `failed`，且多次查询原因稳定；
3. 越窗序号使信道永久 `failed`；
4. 四项检查点的计划在乱序跨越多个检查点（含提前暂存于窗口边缘的帧）时逐项
   `verified`，并覆盖 404、幂等重试与异内容 409；
5. 检查点不符使信道永久 `failed`，失败检查点的序号与期望/实际结果稳定，
   后续帧不改变状态；
6. 首项边界已被入流越过的计划整份拒绝（409），边界恰为当前 `nextSequence`
   时仍可登记并在末帧到达后核对；
7. 未知信道返回 404。

## 本地开发

```sh
go test ./...                 # 单元测试
go run ./cmd/gateway          # 本地启动（TCP :9000, HTTP :8080）
APP_TCP_ADDR=localhost:9000 APP_HTTP_ADDR=http://localhost:8080 go run ./cmd/verify
```

## 结构

```
cmd/gateway/      网关入口（TCP + HTTP）
cmd/verify/       冒烟客户端（真实 TCP 写入 + HTTP 断言）
internal/gateway/ 解析器（parser）、信道重组（channel）、服务与 API（server）
scripts/verify.sh verify 服务入口：go test → go build → 冒烟
Dockerfile        多阶段：build / app / verify
docker-compose.yaml
```
