# qodercli2api

将 **qodercli 的模型推理能力**中转为标准 API 的本地代理服务。

通过对 `qodercli-1.1.5` 二进制逆向（还原其 OAuth 认证与推理协议，见[逆向工程](#6-逆向工程)），
用 Golang 实现并内嵌官方加密 WASM，对外提供三种兼容端点：

| 端点 | 协议 | 适用客户端 |
|---|---|---|
| `POST /v1/messages` | Anthropic Messages（SSE/非流式） | Claude Code |
| `POST /v1/chat/completions` | OpenAI Chat（SSE/非流式） | 任意 OpenAI 客户端 |
| `POST /v1/responses` | OpenAI Responses（SSE/非流式） | Codex CLI |

特性：sk 鉴权 · 15 个上游模型可切换（含 1M 上下文）· thinking/effort 映射 ·
工具调用双向转换 · token 自动刷新 · 内嵌设备流登录。

> 仅供学习研究用途；调用的是你自己账号的额度。

## 目录

1. [快速开始](#1-快速开始)
2. [客户端接入](#2-客户端接入)
3. [配置参考](#3-配置参考)
4. [模型与上下文窗口](#4-模型与上下文窗口)
5. [架构与协议转换](#5-架构与协议转换)
6. [逆向工程](#6-逆向工程)
7. [验证记录](#7-验证记录)
8. [项目结构](#8-项目结构)
9. [安全与注意事项](#9-安全与注意事项)

---

## 1. 快速开始

```bash
# 构建（官方加密 WASM 已 go:embed，单文件分发）
cd qodercli2api && go build -o qodercli2api .

# 登录（三选一）
# ① 本机已登录过 qodercli —— 无需任何操作，自动复用 ~/.qoder/.auth
# ② 设备流登录（浏览器授权）
./qodercli2api -login
# ③ Personal Access Token
./qodercli2api -login-pat "<PAT>"

# 启动
QODER2API_SK=sk-your-secret ./qodercli2api -addr :8377
```

验证：

```bash
curl http://127.0.0.1:8377/health        # {"ok":true,"authenticated":true}
curl -X POST http://127.0.0.1:8377/v1/chat/completions \
  -H "content-type: application/json" -H "Authorization: Bearer sk-your-secret" \
  -d '{"model":"auto","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}'
```

---

## 2. 客户端接入

### 2.1 Claude Code（Anthropic 端点）

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8377
export ANTHROPIC_AUTH_TOKEN=sk-your-secret
export ANTHROPIC_MODEL=auto        # 或 kmodel_latest / ultimate / ...
claude -p "hello"
```

- `~/.claude/settings.json` 里的 `env` 可能覆盖 shell 变量，可用
  `claude --settings <独立文件>` 隔离（参考 `re/q2a-settings.json`）
- `/model` 可切任意 qoder 模型 key；`/effort` 经 `thinking.budget_tokens` 映射为上游 `reasoning_effort`

### 2.2 Codex CLI（Responses 端点）

> codex-cli ≥0.145 仅支持 `wire_api = "responses"`（chat 已移除）。

```toml
# ~/.codex/config.toml
model = "auto"
model_provider = "q2a"

[model_providers.q2a]
name = "qoder2api"
base_url = "http://127.0.0.1:8377/v1"
wire_api = "responses"
env_key = "Q2A_API_KEY"
```

```bash
Q2A_API_KEY=sk-your-secret codex exec "say hi"
codex exec -m kmodel_latest "..."     # 切换模型
```

**项目级配置**（已实测）：codex 读取 `<项目根>/.codex/config.toml`，但有**信任门槛**——
未信任项目的配置被静默忽略。需在**用户配置**中声明信任（项目配置里写 `trust_level` 无效）：

```toml
# ~/.codex/config.toml
[projects."/abs/path/to/project"]
trust_level = "trusted"
```

```toml
# <项目根>/.codex/config.toml —— 本项目专用设置
model = "kmodel_latest"
model_provider = "q2a"
[model_providers.q2a]
name = "qoder2api"
base_url = "http://127.0.0.1:8377/v1"
wire_api = "responses"
env_key = "Q2A_API_KEY"
```

层级：`session(-c) > project（cwd 到 repo root 可有多层，深优先） > user > system`。

### 2.3 任意客户端（curl 参考）

```bash
# Anthropic 流式
curl -N -X POST http://127.0.0.1:8377/v1/messages \
  -H "content-type: application/json" -H "x-api-key: sk-your-secret" \
  -d '{"model":"auto","max_tokens":256,"stream":true,"messages":[{"role":"user","content":"hi"}]}'

# Anthropic thinking/effort
... -d '{"model":"auto","max_tokens":2048,"thinking":{"type":"enabled","budget_tokens":8192},"messages":[...]}'

# OpenAI Chat 流式（上游 chunk 直通 + [DONE]）
curl -N -X POST http://127.0.0.1:8377/v1/chat/completions \
  -H "content-type: application/json" -H "Authorization: Bearer sk-your-secret" \
  -d '{"model":"auto","stream":true,"messages":[{"role":"user","content":"hi"}]}'

# OpenAI Responses 流式
curl -N -X POST http://127.0.0.1:8377/v1/responses \
  -H "content-type: application/json" -H "Authorization: Bearer sk-your-secret" \
  -d '{"model":"auto","stream":true,"input":"hi","reasoning":{"effort":"medium"}}'
```

鉴权：客户端需带 `x-api-key: <sk>` 或 `Authorization: Bearer <sk>`，缺失/错误返回 401。

---

## 3. 配置参考

### 3.1 启动参数（flag / 环境变量）

| flag | 环境变量 | 默认 | 说明 |
|---|---|---|---|
| `-addr` | `QODER2API_ADDR` | `:8377` | 监听地址 |
| `-sk` | `QODER2API_SK` | 空 | **客户端 sk 密钥**；为空关闭鉴权（打印警告） |
| `-auth-dir` | `QODER2API_AUTH_DIR` | `~/.qoder/.auth` | 凭证目录 |
| `-endpoint` | `QODER2API_INFER_ENDPOINT` | `https://api2.qoder.sh` | 推理端点 |
| `-openapi-endpoint` | `QODER2API_OPENAPI_ENDPOINT` | `https://openapi.qoder.sh` | OpenAPI 端点 |
| `-web-endpoint` | `QODER2API_WEB_ENDPOINT` | `https://qoder.com` | 设备流授权页端点 |
| `-model-map` | `QODER2API_MODEL_MAP` | 空 | JSON 映射 `{"claude-sonnet-4-5":"auto","*":"auto"}` |
| `-default-model` | `QODER2API_DEFAULT_MODEL` | `auto` | 兜底模型 key |
| `-model-1m` | `QODER2API_MODEL_1M` | `ultimate` | `[1m]` 后缀请求的 1M 模型 key |
| `-catalog` | `QODER2API_CATALOG` | 自动 | 模型目录 JSON（默认自动解密 CLI 缓存） |
| `-login` | — | — | 设备流登录后退出 |
| `-login-pat` | — | — | PAT 登录后退出 |
| `-v` | `QODER2API_LOG=debug` | off | 详细日志 |

### 3.2 端点

| 端点 | 说明 |
|---|---|
| `POST /v1/messages` | Anthropic Messages（SSE/非流式） |
| `POST /v1/messages/count_tokens` | 粗估 token（Claude Code 压缩上下文用） |
| `POST /v1/chat/completions` | OpenAI Chat（SSE/非流式/工具调用/`reasoning_effort`） |
| `POST /v1/responses` | OpenAI Responses（SSE/非流式，Codex 适用） |
| `GET /v1/models` | 模型列表 |
| `GET /health` | 健康检查 |

### 3.3 systemd 部署（本机已有）

本机存在 `qodercli2api.service`（`~/.config/systemd/user/`，`Restart=always`），
环境文件 `qodercli2api.env`，重新构建二进制后 `systemctl --user restart qodercli2api` 即可生效。

---

## 4. 模型与上下文窗口

### 4.1 可选模型

| key | 名称 | 推理 | 视觉 | 上下文 |
|---|---|---|---|---|
| `auto` | Auto（默认） | - | ✓ | 180k |
| `ultimate` | Ultimate | ✓ | ✓ | **1M** |
| `performance` | Performance | - | ✓ | **1M** |
| `efficient` | Efficient | - | ✓ | 180k |
| `lite` | Lite | - | ✗ | 180k |
| `cmodel` | Cantus | ✓ | ✓ | **1M** |
| `qmodel_38max` | Qwen3.8-Max | ✓ | ✓ | **1M** |
| `qmodel_latest` | Qwen3.7-Max | - | ✓ | **1M** |
| `qmodel` | Qwen3.7-Plus | - | ✓ | **1M** |
| `kmodel_latest` | Kimi-K3 | - | ✓ | **1M** |
| `kmodel` | Kimi-K2.7-Code | - | ✓ | 256k |
| `gm51model` | GLM-5.2 | ✓ | ✓ | **1M** |
| `dmodel` | DeepSeek-V4-Pro | ✓ | ✓ | **1M** |
| `dfmodel` | DeepSeek-V4-Flash | ✓ | ✓ | **1M** |
| `mmodel` | MiniMax-M3 | - | ✓ | **1M** |

模型选择优先级：`-model-map` 精确匹配 > 客户端 model 即 qoder key > `[1m]` 后缀处理 > `-default-model` 兜底。

### 4.2 effort / thinking

| 客户端参数 | 上游 |
|---|---|
| Anthropic `thinking.budget_tokens` | 按官方 CHL 映射为 `reasoning_effort`：`≤0→none, ≤1024→low, ≤8192→medium, ≤24576→high, ≤49152→xhigh, >49152→max` |
| OpenAI `reasoning_effort` | 直接透传（`minimal→low`） |
| Responses `reasoning.effort` | 直接透传 |

上游的思考增量（`reasoning_content`）→ Anthropic `thinking` block / Responses `reasoning` item /
Chat 非流式按 deepseek 风格 `reasoning_content` 字段返回。

### 4.3 使用 1M 上下文

需要**客户端与代理两侧配合**：

**代理侧（已实现）**
- 模型名带 `[1m]` 后缀（如 `auto[1m]`）→ 自动路由到 1M 模型（默认 `ultimate`，`-model-1m` 可换）；
  已选 1M 模型（如 `ultimate[1m]`）则原样使用
- 自动将所选模型的 `max_input_tokens` 作为 `parameters.context_length` 告知上游

**Claude Code 侧**：`ANTHROPIC_MODEL=auto[1m]`（`[1m]` 后缀即其 1M 窗口约定）

**Codex 侧**（config.toml，已实测）：

```toml
model = "ultimate"
model_context_window = 1000000
model_auto_compact_token_limit = 900000   # 可选，自动压缩阈值
```

---

## 5. 架构与协议转换

```
Claude Code / Codex / 任意客户端
        │  Anthropic / OpenAI Chat / OpenAI Responses
        ▼
   qodercli2api
        ├── sk 鉴权中间件
        ├── 客户端请求 → RemoteChatAsk 转换
        ├── wazero 内嵌官方 WASM：prepareInferRequest（URL / 22 个签名头 / 加密 body）
        ├── token 自动刷新（提前 1h + 401 重试 + 30min 定时）
        └── 上游 SSE 信封解析 → 客户端协议事件序列
        ▼
   https://api2.qoder.sh（生产推理端点）
```

### 5.1 请求转换

| 客户端 | 上游（RemoteChatAsk） |
|---|---|
| `model` | `model_config.key`（映射/[1m]/兜底，见 §4.1） |
| `system` / `instructions` | 顶层 `system` 字符串 |
| 文本/图片消息 | OpenAI 消息（image→`image_url` data:URL） |
| `tool_use` / `function_call` | `tool_calls[{id,type:function,function:{name,arguments}}]` |
| `tool_result` / `function_call_output` | `role:"tool"` + `tool_call_id` |
| `tools` | OpenAI function 格式（`input_schema`→`parameters`） |
| thinking / effort | `parameters.reasoning_effort`（见 §4.2） |
| `tool_choice` | `parameters.tool_choice`（auto/any→required/none/tool） |
| `max_tokens` 等 | `parameters.{max_tokens,context_length,temperature,top_p,stop}` |

### 5.2 响应转换

| 上游 chunk | Anthropic | OpenAI Chat | OpenAI Responses |
|---|---|---|---|
| `delta.reasoning_content` | `thinking` block | （直通） | `reasoning` item + summary delta |
| `delta.content` | `text` block + `text_delta` | （直通） | `message` item + `output_text.delta` |
| `delta.tool_calls` | `tool_use` block | （直通） | `function_call` item + args delta |
| `finish_reason`+`usage` | `message_delta`+`message_stop` | 末帧+`[DONE]` | `response.completed`（含 usage） |
| 信封 statusCodeValue≠200 | `error` 事件 | error data+`[DONE]` | `response.failed` |

stop 映射：`stop→end_turn, tool_calls→tool_use, length→max_tokens, content_filter→refusal`。

### 5.3 设计决策

1. **必须内嵌 WASM**：请求体加密与 COSY 签名无法离线重写，wazero 复用官方逻辑，行为与官方天然一致
2. **凭证复用**：直接读写 `~/.qoder/.auth/user`（与 qodercli 兼容的加密格式），也支持独立设备流登录
3. **request_id 每次新 UUID**（服务器防重放，重复返回 103）
4. **单 WASM 上下文 + 互斥锁**：wasm-bindgen 模块非线程安全；打包仅数毫秒，无瓶颈
5. **usage 捕获**：部分模型的 usage 帧在 finish_reason 之后才到，延迟到 `event:finish` 再发最终事件

---

## 6. 逆向工程

> 完整细节：`docs/oauth.md`、`docs/inference-protocol.md`。此处为摘要。

### 6.1 总体结论

| 问题 | 答案 |
|---|---|
| OAuth 机制 | **自定义设备授权流**：浏览器开 `qoder.com/device/selectAccounts`（PKCE 风格 challenge），每秒轮询 `openapi.qoder.sh/api/v1/deviceToken/poll` 换 device token；凭证 WASM 加密存于 `~/.qoder/.auth/user` |
| 推理调用 | `POST api2.qoder.sh/algo/api/v2/service/pro/sse/agent_chat_generation`，22 个 `Cosy-*` 头 + `Bearer COSY.<base64>.<签名>`，请求体 WASM 加密；响应明文 SSE（信封包裹 OpenAI chunk） |
| 加密/签名 | 内嵌 Rust→WASM 模块 `qoder_auth_wasm_bg.wasm`（297KB），不可绕过，本项目用 wazero 复用 |

### 6.2 二进制分析

`qodercli-1.1.5`（133MB ELF，未 strip）不是 Go 程序，而是 **Bun 1.3.14 打包的 Node.js 单文件可执行程序**
（`napi_*` 符号 + bun/node_modules 字符串）。完整 JS bundle（16.9MB minified）以明文内嵌，
可直接 carve（产物 `re/extracted/bundle.js`）；bundle 内 base64 解码出 4 个模块：

| 文件 | 大小 | 内容 |
|---|---|---|
| `re/extracted/wasm_0.wasm` | 297KB | **qoder_auth_wasm（认证/加密核心）** |
| （ELF） | 652KB | 原生 addon |
| `re/extracted/wasm_2.wasm` | 205KB | tree-sitter |
| `re/extracted/wasm_3.wasm` | 1.38MB | tree-sitter-bash |

### 6.3 OAuth 要点

- **设备流**：`verifier(43~128随机字符)` + `challenge=base64url(sha256(verifier))` + `nonce=uuid`；
  授权页带 `client_id=e883ade2-...`（prod）/ `e93fe488-...`（非 prod）；轮询 404 继续、5 分钟超时
- **PAT**：`POST /api/v1/jobToken/exchange {"personal_token":...}`
- **刷新**：`expire_time-3600<now` 即刷新；`POST /api/v1/deviceToken/refresh {"refresh_token":...}`；
  refresh token 有效期约 4 个月
- **存储**：`~/.qoder/.auth/user`（0600），WASM `credential_storage_encrypt`，key = `machine_id` 前 16 字符
- **端点**：prod 推理 `api2.qoder.sh`（us→api1、jp→api3），`QODER_ENV={env}[-{region}]` 控制

### 6.4 推理协议要点

- **认证头**：`Authorization: Bearer COSY.{base64({version,requestId,info,cosyVersion,ideVersion})}.{签名}`，
  其中 `info` 即 `encrypt_user_info`；**设备 token 不上链**，服务器靠 `info`+`Cosy-Key` 认证
- **请求体**（RemoteChatAsk）：`request_id`（唯一，重复 403）、`session_id`、`model_config`、
  `system`、`messages`、`tools`、`parameters{max_tokens,reasoning_effort,...}`，整体 WASM 加密
- **响应**：SSE 信封 `{"headers","body","statusCodeValue"}`，`body` 为字符串化 OpenAI chunk
  （`content`/`reasoning_content`/流式 `tool_calls`/`finish_reason`/`usage`），
  `event:finish`（含首 token/总时长）收尾，**无 `[DONE]`**；错误帧 statusCodeValue≠200

### 6.5 qoder_auth_wasm 与分析方法

WASM 导出（wasm-bindgen ABI）：`qodercontext_new` / `qodercontext_prepareInferRequest`（推理打包）/
`prepareRequest`（通用打包）/ `credential_storage_encrypt|decrypt`（凭证）/
`generate_runtime_auth_fields`（运行时签名字段）/ `model_cache_decrypt`（目录）/ `decrypt_server_response`。

**分析方法（本项目原创）**：Python + wasmtime 手写完整 wasm-bindgen host glue
（堆从 index 1028 起、free-list、`IEA(ptr,len)` 内存视图、`getRandomValues` 直写内存等），
直接驱动真实 WASM——解密本机凭证、观察 22 个请求头与加密 body、
并用生成的 headers/body 对生产端点 curl 验证成功。代码见 `re/wasm_harness.py`；
Go 侧在 `wasm.go` 用 wazero 实现同等 glue。

---

## 7. 验证记录

| 测试 | 结果 |
|---|---|
| WASM harness 解密 `~/.qoder/.auth/user` | ✅ 拿到完整 UserInfo |
| WASM 生成请求 + curl 直打生产推理端点 | ✅ SSE 流（text/reasoning/tool_calls/usage/event:finish） |
| 相同 request_id 重放 | ✅ 403 `{"code":"103","message":"Duplicate request"}` |
| Anthropic 非流式 / 流式事件序列 | ✅ thinking+text blocks、message_start→…→message_stop、usage 正确 |
| 无 sk / 错 sk | ✅ 401 authentication_error |
| 工具调用（非流式+流式+多轮回传） | ✅ tool_use blocks、stop_reason=tool_use |
| thinking budget → reasoning_effort | ✅ 上游返回 reasoning_content 并转为 thinking block |
| Claude Code 对话 / Bash 工具回合 / 模型切换 | ✅ `PROXY_OK` / 正确执行 / 自述 Kimi |
| Chat 非流式/流式/工具调用 | ✅ OpenAI 格式 + usage + [DONE] |
| Responses 流式事件序列 | ✅ created→item.added→delta→done→completed 完整 |
| Codex exec 对话 / shell 工具回合 / 模型切换 | ✅ `CODEX_RESP_OK` / 正确执行 / 自述 Kimi |
| `[1m]` 后缀路由（auto[1m]、ultimate[1m]） | ✅ 正常返回 |
| Codex 1M 配置（model_context_window=1000000） | ✅ `CTX1M_OK` |
| Codex 项目级配置 + 信任门槛 | ✅ 未信任被忽略；用户配置声明信任后生效 |

---

## 8. 项目结构

```
qodercli2api/
├── qodercli-1.1.5              # 逆向目标二进制（Bun 单文件）
├── main.go                     # 入口/flags/启动/目录加载/PAT登录
├── wasm.go                     # wazero host glue + QoderContext API（★核心）
├── auth.go                     # 凭证读写/刷新/设备流登录
├── convert.go                  # Anthropic ↔ RemoteChatAsk 类型转换
├── proxy.go                    # Anthropic handlers + SSE 解析 + 模型解析
├── openai.go                   # /v1/chat/completions（OpenAI 直通转换）
├── responses.go                # /v1/responses（Responses API 转换）
├── go.mod / go.sum             # 依赖：仅 wazero + x/sys
├── assets/
│   └── qoder_auth_wasm_bg.wasm # qoder_auth_wasm（go:embed 进二进制）
├── docs/
│   ├── oauth.md                # OAuth 机制完整逆向文档
│   └── inference-protocol.md   # 推理协议完整逆向文档
├── re/
│   ├── extracted/              # carve 产物（bundle.js / wasm，gitignore 可再生）
│   ├── wasm_harness.py         # Python+wasmtime 分析 harness（可独立复用）
│   ├── q2a-settings.json       # Claude Code 隔离 settings 示例
│   ├── codex-home/config.toml  # Codex 配置示例
│   └── secrets/                # 本地凭证/抓包（gitignore，勿提交）
└── README.md                   # 本文件
```

---

## 9. 安全与注意事项

1. **凭证安全**：`re/secrets/` 含真实 token，已 gitignore；token/sk 不入日志、不进仓库
2. **SSRF 面**：`-endpoint` 等覆盖项属运维配置，勿暴露给不可信输入；建议仅监听本地
3. **sk 强度**：生产使用设置高强度 `QODER2API_SK`；无 sk 时服务对所有可访问者开放
4. **request_id 唯一性**：服务器拒绝重复（103），代理已保证每次新 UUID
5. **token 生命周期**：device token 约 1 天过期、refresh token 约 4 个月；代理自动刷新并回写
   `~/.qoder/.auth/user`（与 qodercli 共享，互不影响）
6. **合规**：仅供学习研究；调用用户自己账号的额度，请遵守 Qoder 服务条款
