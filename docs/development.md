# 开发指南

本文面向当前原生 Go 实现，协议目标为 Qoder CLI **1.1.74 的认证、模型缓存与 legacy HTTP/SSE 推理路径**。
使用与部署见 [README](../README.md)，提交约定见 [CONTRIBUTING](../CONTRIBUTING.md)，漏洞报告见 [SECURITY](../SECURITY.md)。

<a id="architecture"></a>
## 架构与模块边界

| 边界 | 主要文件 | 职责 |
|---|---|---|
| 应用装配 | `app.go`、`region.go`、`main.go` | flags/env、区域/端点、服务生命周期、模型目录 |
| 认证与存储 | `auth.go`、`auth_store.go`、`auth_lock.go` | 登录、刷新、凭据事务、活动 protocol context 的唯一所有权 |
| 原生协议 | `protocol*.go`、`native_*.go` | credential/runtime/model-cache codec、不可变 context、COSY 请求准备 |
| 公共 API | `proxy.go`、`convert.go`、`openai.go`、`responses.go` | 三类客户端格式转换、模型解析、重试与 SSE |
| 确定性测试 | `*_test.go`、`testdata/protocol/` | 合成输入、可注入时钟/熵、冻结向量和并发生命周期 |
| 可选 oracle | `tools/wasm_oracle/`、`tools/wasm_harness.py` | 独立模块中的授权外置 WASM 比对，不参与生产路径 |

server 依赖认证语义接口，catalog loader 依赖 model-cache decryptor；认证层负责替换、关闭活动 context。
应用停止接收请求并等待在途任务结束后，再关闭认证 context 和 protocol services。记录/回放 host transcript 仅用于测试。
核心 prepared request 和最终发送层须分别验证：1.1.74 的外层请求头规则不能反向改写历史核心向量。

根模块要求 **Go 1.25+**，仅使用标准库；提交的空 `go.sum` 是正常状态，**必须保留**。
`tools/wasm_oracle` 是独立 Go 模块，有自己的依赖与 `go.sum`，不会随根目录的 `go test ./...` 自动测试。
生产二进制始终为 native-only；外置 oracle 不提供运行时替代路径。

<a id="offline-checks"></a>
## 默认检查与可选离线模式

从仓库根目录运行，先安装本机 Go 1.25+。默认允许按 Go 配置下载标准模块依赖，适用于尚无依赖缓存的新 clone。
嵌套 oracle 模块可先通过 `go -C tools/wasm_oracle mod download` 获取依赖；该步骤访问模块代理/校验服务，不访问 Qoder 账号，也不下载认证 WASM。
以下测试不需要真实凭据、官方 CLI 或外置 WASM。合成 HTTP 测试可能使用本机 loopback 服务，但不访问 Qoder 账号。

```bash
export GOTOOLCHAIN=local GOWORK=off

go -C tools/wasm_oracle mod download
go test ./...
go test -race ./...
go vet ./...
QODER2API_E2E=0 QODER2API_E2E_REFRESH=0 go test -tags=e2e ./...
go -C tools/wasm_oracle test ./...
python3 -B tools/wasm_harness.py --self-test
```

`-race` 需要当前平台支持的 race 工具链。Python 自检仅依赖标准库，不安装 wasmtime。
默认检查不强制关闭 Go 模块下载；若要**严格离线运行**，先在允许联网的环境中完成上述 `mod download`，准备好本机工具链及依赖缓存，然后再设置：

```bash
export GOPROXY=off
```

随后重跑测试命令即可。缺依赖时离线模式会失败，这是缓存前置条件，不是账号或 WASM 要求。
不要为让检查通过而提供真实账号或开启 E2E gate；若环境里设有外置 oracle 的 opt-in 变量，应先移除它们。

需要构建时，使用明确的输出路径，避免覆盖根目录已有文件：

```bash
mkdir -p bin
go build -o ./bin/qodercli2api .
```

<a id="verification-scope"></a>
## 验证证据的范围

- `testdata/protocol/1.1.34/` 保留历史冻结基线，不因生产版本升级而重新标注或生成。
- `testdata/protocol/1.1.74/` 来自新模块的独立合成 capture/replay，另含 33 项兼容性 corpus；七项既有 strict-native 拒绝行为有明确记录。
- 静态样本、token-bound runtime 输入、CN 端点与最终发送层差异见 [1.1.74 分析](qodercli-1.1.74-analysis.md)。
- **1.1.74 尚未进行真实 global/CN 账号登录、刷新或推理验收**。历史 1.1.34 在线结果只说明当时的版本和账号，不能作为当前服务可用性证明。

报告验证结果时请注明版本/提交、命令、环境以及离线或真实调用的性质；不要用测试跳过代替在线通过。
模型的自述名称、单次文本输出和内置目录条目都不是模型身份或账号授权的可靠证据。

<a id="authorized-e2e"></a>
## 真实 E2E：仅在账号持有人明确授权后运行

**这些命令会向上游发送真实请求，可能消耗额度或产生费用；refresh 用例还会轮换并写入原始凭据。**
普通测试不要求真实账号。不要在公开 CI、fork PR 或不可信环境中配置这些 gate，也不要上传账号资料、抓包或 dump。
先确认区域、授权范围和凭据目录，安排没有其他进程竞争刷新令牌的测试时段。

E2E 使用独立配置：

| 环境变量 | 作用 |
|---|---|
| `QODER2API_E2E` | 仅值为 `1` 时允许真实账号测试 |
| `QODER2API_E2E_REFRESH` | refresh 用例还要求此值为 `1` |
| `QODER2API_E2E_REGION` | `global`（默认）或 `cn`，不继承普通服务的 region/PAT 选择 |
| `QODER2API_E2E_AUTH_DIR` | 完整源凭据目录；未指定时使用 E2E 所选区域的配置根下 `.auth` |
| `QODER2API_E2E_INFER_ENDPOINT` | E2E 推理端点覆盖 |
| `QODER2API_E2E_OPENAPI_ENDPOINT` | E2E OpenAPI 端点覆盖 |
| `QODER2API_E2E_WEB_ENDPOINT` | E2E 授权站点覆盖 |

区域对应的 `QODER_CONFIG_DIR` / `QODERCN_CONFIG_DIR` 仍影响默认配置根；普通服务的 `QODER2API_AUTH_DIR` 和端点变量不替代上述 E2E 变量。
环境 PAT 不能代替 E2E 所需的可用加密本地凭据；非 refresh 用例要求 token 足够新鲜，不会自动调用认证接口续期。

**非 refresh 模式**只把源目录中的 `user`、`machine_id` 和可选区域绑定复制到私有临时目录（0700/0600），构造、加载与关闭只作用于副本。
不复制锁或事务标记，不向源凭据目录写入；模型缓存仍从**原配置根只读加载**。测试结束清理副本。
只有构造入口同时确认两项 gate 为 `1`，refresh 模式才使用并持久化原凭据。
这类临时测试副本不是部署多个独立会话的方法；长期隔离必须在新 auth-dir 中重新登录。

```bash
# 仅使用你已明确授权的目录；国内账号将下面的 E2E_REGION 改为 cn
export QODER2API_E2E_AUTH_DIR=/authorized/path/to/.auth

# 默认 smoke 与三路由 stream/nonstream 矩阵：源凭据只读，推理仍可能计费
QODER2API_E2E=1 QODER2API_E2E_REFRESH=0 QODER2API_E2E_REGION=global \
  go test -tags=e2e . -run '^TestProtocolE2E(DefaultNative|Native)$' -count=1 -v

# 单独授权的刷新与 context rebuild：会轮换、写入原凭据
QODER2API_E2E=1 QODER2API_E2E_REFRESH=1 QODER2API_E2E_REGION=global \
  go test -tags=e2e . -run '^TestProtocolE2ERefresh$' -count=1 -v
```

harness 强制关闭 dump-dir，输出只保留安全状态与形状信息；分享结果前仍需人工检查脱敏。
测试被跳过、`/health` 返回成功或本地目录加载成功，都不等于真实上游验收通过。

<a id="optional-oracles"></a>
## 可选外置 oracle 与历史性能

只有需要验证互操作性时才使用 [工具说明](../tools/README.md) 中的独立 oracle。
验证器接受固定身份的 **1.1.34 / 1.1.74** 模块与对应冻结目录；操作者须自行提供有权持有和执行的外部模块。
所有输入必须为仓库的合成向量，不导入真实凭据、请求或响应。模块不得提交、嵌入或变成根模块依赖。

[BENCHMARK.md](../BENCHMARK.md) 保留 **2026-09-01、提交 `c79c82001aa6` 的 dirty-tree、1.1.34 pin** 历史快照，不是当前 1.1.74 性能结论。
`tools/benchmark.py` 仍只接受历史 1.1.34 pin；重跑时应指定仓库外的新输出文件，不覆盖或重新解释该历史报告。
性能数据不设任意 pass/fail 阈值，微基准也不代表网络延迟或完整应用启动速度。
