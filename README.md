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
  "failReason": "…"          // 仅 failed 时存在
}
```

- 未知信道：`404`；非法 id：`400`；
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

`verify` 的冒烟场景（每轮从当前空闲信道中随机选取 3 个测试信道 + 1 个 404 探测信道，
因此对同一网关实例可重复运行）：

1. 48 帧经三条并发连接送达——逐字节写入、与垃圾/坏 CRC/非法长度帧粘连、乱序、
   同载荷重传——最终摘要必须与本地独立计算的 SHA-256 完全一致；
2. 同序号不同载荷的冲突帧使信道永久 `failed`，且多次查询原因稳定；
3. 越窗序号使信道永久 `failed`；
4. 未知信道返回 404。

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
