# qodercli2api

将 Qoder CLI 的模型推理能力接入 Claude Code、Codex 和其他 API 客户端的本地代理。
提供 Anthropic Messages、OpenAI Chat Completions、OpenAI Responses 三类兼容接口，支持流式与非流式响应、工具调用转换和 thinking/effort 映射。

**非官方项目 · AGPL-3.0 · 原生 Go · 当前协议目标 Qoder CLI 1.1.74**

当前适配范围是认证、模型缓存及保留的 **legacy HTTP/SSE 推理路径**，不是官方 CLI 的完整实现。
不包含其 gRPC/HTTP3、新工具执行、service-account 或设备遥测系统，也不承诺完整实现三类接口规范的所有字段和功能。
当前源码树与生产构建不包含或分发认证 WASM；根模块只依赖 Go 标准库。外置分析工具及历史资产边界见 [NOTICE](NOTICE)。

> 本项目与 Qoder、Alibaba 无隶属、背书或赞助关系。仅使用你有权使用的账号与订阅，并遵守适用服务条款和法律。
> 1.1.74 的兼容依据是静态分析和合成离线向量；**尚未进行该版本的真实 global/CN 账号登录、刷新或推理验收**。1.1.34 的历史在线记录不代表当前版本已通过。

## 导航

- [快速开始](#快速开始)
- [区域与认证](#区域与认证)
- [客户端接入](#客户端接入)
- [配置参考](#配置参考)
- [接口与模型](#接口与模型)
- [安全与限制](#安全与限制)
- [开发与协议资料](#开发与协议资料)
- [许可证](#许可证)

## 快速开始

需要 **Go 1.25+**，以及可用的 Qoder 账号。生产构建不需要 Python、WASM runtime 或官方 CLI 二进制。
以下命令在仓库根目录运行，将产物写入 `bin/`，不覆盖根目录下可能已有的可执行文件。

```bash
mkdir -p bin
go build -o ./bin/qodercli2api .

# 海外站设备登录：复制程序打印的链接，在浏览器完成授权
./bin/qodercli2api -login -region global
```

若已通过官方 CLI 登录，且区域和凭据目录正确，可以跳过登录步骤。服务会复用并可能刷新、回写该目录中的凭据；
希望隔离官方 CLI 会话时，请用独立 `-auth-dir` **重新登录**，不要复制同一份轮换 token 并发运行。

```bash
# 生成客户端密钥；此示例需要 OpenSSL，也可用密码管理器生成至少 32 个随机字节
QODER2API_SK="$(openssl rand -hex 32)" && export QODER2API_SK

# 显式限制为本机 HTTP；密钥为空时拒绝执行这条示例命令
QODER2API_SK="${QODER2API_SK:?请先设置强随机客户端密钥}" \
  ./bin/qodercli2api -region global -addr 127.0.0.1:8377
```

`QODER2API_SK` 是你为**下游客户端**设置的共享访问密钥，**不是上游 Qoder PAT**。
请将同一密钥安全地提供给客户端进程，不要把它写入版本控制或公开日志。下文客户端命令假定其终端已设置这个值。

```bash
# 无鉴权的本地状态检查，不访问上游
curl http://127.0.0.1:8377/health

# 实际推理：会访问上游，可能消耗账号额度
curl http://127.0.0.1:8377/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${QODER2API_SK:?请设置与服务端相同的密钥}" \
  -d '{"model":"auto","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}'
```

`/health` 的 `authenticated: true` 仅表示进程内已加载认证状态，**不证明 token 仍有效、订阅可用或上游健康**。

## 区域与认证

### global 与 cn

国内站登录和启动都要选择 `cn`：

```bash
./bin/qodercli2api -login -region cn
QODER2API_SK="${QODER2API_SK:?请先设置强随机客户端密钥}" \
  ./bin/qodercli2api -region cn -addr 127.0.0.1:8377
```

区域优先级为 **`-region` > `QODER2API_REGION` > `QODER_REGION` > `global`**。
也可在登录和服务进程中统一设置 `QODER2API_REGION=cn`；一次 `-login -region cn` 不会改变后续进程的默认区域。
`QODER_REGION` 是本项目的兼容别名，不是官方 CLI 的国内站切换参数。

| 配置 | global | cn |
|---|---|---|
| 授权网站 | `https://qoder.com` | `https://qoder.cn` |
| OpenAPI | `https://openapi.qoder.sh` | `https://openapi.qoder.com.cn` |
| 推理网关 | `https://api2.qoder.sh` | `https://gateway.qoder.com.cn` |
| 默认凭据目录 | `~/.qoder/.auth` | `~/.qoder-cn/.auth` |
| 官方配置根变量 | `QODER_CONFIG_DIR` | `QODERCN_CONFIG_DIR` |
| 官方 PAT 变量 | `QODER_PERSONAL_ACCESS_TOKEN` | `QODERCN_PERSONAL_ACCESS_TOKEN` |

两站使用相同的生产设备登录 client UUID，但授权、OpenAPI、推理和目录必须成套选择；**只改浏览器网址不等于切换区域**。

### 凭据目录与持久化

`-auth-dir` / `QODER2API_AUTH_DIR` 指包含 `user` 和 `machine_id` 的**完整凭据目录**，优先于区域默认目录。
`QODER_CONFIG_DIR` / `QODERCN_CONFIG_DIR` 指**配置根**，默认在其下使用 `.auth`；自动模型缓存路径由最终 auth-dir 的父目录推导到 `.models`。
程序不会跨区域寻找、复制或迁移凭据。旧国内安装若使用 `~/.qoder/.auth`，只有确认账号归属后才能显式指定该目录。

只有 `machine_id` 不代表已登录；不要删除或重建已有 ID，应对相同区域与目录执行 `-login`。
持久化模式可能创建事务标记、区域绑定，并自动刷新和保存 `user`。加载旧格式时仅在内存中更新 runtime fields，不会仅因此重写 `user`。
发现区域、机器身份或凭据 revision 冲突时会拒绝操作，而不是覆盖其他进程的登录状态。

### 环境 PAT：凭据存储零写入模式

通过私密环境注入**所选区域**的官方 PAT 变量后，直接启动服务，无需 `-login-pat`：

```bash
# 假定已安全设置 QODERCN_PERSONAL_ACCESS_TOKEN；不要在命令中写入真实 PAT
QODER2API_SK="${QODER2API_SK:?请先设置强随机客户端密钥}" \
  ./bin/qodercli2api -region cn -addr 127.0.0.1:8377
```

- 仅读取所选区域前缀的 PAT，另一站点的变量不会被采用；环境 PAT 优先于服务模式下的本地凭据恢复。
- 身份与 token 只驻留内存；不读取已存 `user` / `machine_id`，也不创建或改写凭据、机器身份、事务标记或区域绑定。仍可读取目录/绑定元数据和模型缓存。
- 显式 `-login` 忽略环境 PAT，执行浏览器登录并持久化；`-login-pat <PAT>` 也是**持久化登录**，成功后退出。
- `-login` 与 `-login-pat` 互斥。命令行 PAT 可能暴露于历史记录和进程列表，优先使用设备登录或环境 PAT 服务模式。

## 客户端接入

以下只是连接示例；客户端版本、账号权限及所选模型会影响功能。客户端实际请求可能计费。

### Claude Code

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8377
export ANTHROPIC_AUTH_TOKEN="${QODER2API_SK:?请设置与服务端相同的密钥}"
export ANTHROPIC_MODEL=auto
claude
```

也可使用 [Claude settings 示例](examples/claude-settings.json)，把占位密钥替换为服务端密钥后，通过 `claude --settings <文件>` 加载。
已有用户或项目配置可能影响最终连接参数；示例只包含连接和模型设置，不替你关闭更新或改变其他客户端策略。

### Codex CLI

在客户端配置中使用 Responses 接口：

```toml
model = "auto"
model_provider = "q2a"

[model_providers.q2a]
name = "qodercli2api"
base_url = "http://127.0.0.1:8377/v1"
wire_api = "responses"
env_key = "Q2A_API_KEY"
```

```bash
Q2A_API_KEY="${QODER2API_SK:?请设置与服务端相同的密钥}" codex
```

[Codex 配置示例](examples/codex-config.toml) 另含 1M 上下文设置；它是客户端配置示例，不是账号已获 1M 权限的证明。

## 配置参考

同一配置项通常按 **命令行 > 对应环境变量 > 默认值** 解析；区域和凭据目录规则见上文。

| 参数 | 环境变量 | 默认值 / 作用 |
|---|---|---|
| `-addr` | `QODER2API_ADDR` | `:8377`，默认监听所有接口；本机请显式用 `127.0.0.1:8377` |
| `-sk` | `QODER2API_SK` | 空；为空会关闭客户端鉴权，日志提示 `api key auth=disabled` |
| `-region` | `QODER2API_REGION`，其次 `QODER_REGION` | `global`；支持 `global` / `cn` |
| `-auth-dir` | `QODER2API_AUTH_DIR` | 所选区域配置根下的 `.auth`；完整凭据目录 |
| `-endpoint` | `QODER2API_INFER_ENDPOINT` | 所选区域推理网关 |
| `-openapi-endpoint` | `QODER2API_OPENAPI_ENDPOINT` | 所选区域 OpenAPI |
| `-web-endpoint` | `QODER2API_WEB_ENDPOINT` | 所选区域授权网站 |
| `-model-map` | `QODER2API_MODEL_MAP` | 空；模型名到上游模型 key 的 JSON 映射 |
| `-default-model` | `QODER2API_DEFAULT_MODEL` | `auto`；未匹配模型的兜底 |
| `-model-1m` | `QODER2API_MODEL_1M` | `ultimate`；`[1m]` 请求的升级目标 |
| `-catalog` | `QODER2API_CATALOG` | 空；自动读取 CLI 缓存，可指定明文目录 JSON |
| `-login` | — | 设备流登录并持久化，随后退出 |
| `-login-pat <PAT>` | — | PAT 交换并持久化，随后退出；不等于环境 PAT 模式 |
| `-dump-dir` | `QODER2API_DUMP_DIR` | 空；启用后写失败请求明文，仅供受控调试 |
| `-v` | `QODER2API_LOG=debug` | 关闭；详细日志可能包含上游错误详情 |

端点覆盖必须是无 userinfo、query、fragment 的 HTTP(S) base URL。只允许可信运维配置它们，认证请求拒绝跨 origin 重定向。
**警告：默认的所有接口监听与空密钥不适合安全部署。** 服务监听使用明文 HTTP；跨主机访问应在反向代理、VPN 等边界上提供 TLS 与访问控制。

## 接口与模型

### 路由与鉴权

| 路由 | 说明 |
|---|---|
| `POST /v1/messages` | Anthropic Messages 兼容子集，SSE / 非流式 |
| `POST /v1/chat/completions` | OpenAI Chat Completions 兼容子集，SSE / 非流式 |
| `POST /v1/responses` | OpenAI Responses 兼容子集，SSE / 非流式 |
| `POST /v1/messages/count_tokens` | 按请求体字节数粗估，不是官方 tokenizer，也不用于准确计费 |
| `GET /v1/models` | 本地合并后的模型目录，不是实时账号授权查询 |
| `GET /health` | **无鉴权**；仅返回进程状态与内存中的认证状态 |

设置非空 SK 后，除 `/health` 外，上述路由需提供 `Authorization: Bearer <SK>` 或 `x-api-key: <SK>`，缺失或错误返回 401。
支持的主要内容包括文本、图片消息转换、函数工具调用/结果、流式增量和 reasoning 转换；不支持的字段不保证保留或具有官方语义。
工具由客户端执行，代理不提供官方 CLI 的工具执行环境。具体字段和协议边界见 [推理协议](docs/inference-protocol.md)。

### 查询模型与兜底行为

```bash
curl http://127.0.0.1:8377/v1/models \
  -H "Authorization: Bearer ${QODER2API_SK:?请设置与服务端相同的密钥}"
```

目录以 **16 个内置条目**为兼容基础/兜底，再由显式 `-catalog` 或本地 CLI 缓存覆盖、补充；它不是向上游实时请求的可用模型清单。
自动读取优先 `catalog-v7`，仅在它不存在时尝试 `catalog-v6`；v7 损坏不会通过旧缓存静默掩盖，代理不改写官方模型缓存。
即使 `/v1/models` 列出了模型，**也不证明当前账号、区域、视觉能力或上下文额度可用**。

返回的友好 `id` 可直接用于三个推理 API，`qoder_key` 保留内部 key。显示名为空、重名、与 key 冲突或带保留后缀时，公开 ID 安全回退为 key。
示例使用 `auto`、`ultimate` 等内部 key，减少显示名变化带来的影响。

模型选择先移除 `[1m]` 后缀，再按精确 `model-map` > `model-map["*"]` > 已知 key / 唯一友好名 > `default-model` 解析。
例如 `QODER2API_MODEL_MAP='{"my-model":"auto","*":"auto"}'` 会把未单独匹配的模型请求统一送往 `auto`。
若请求 `auto[1m]` 且基础模型窗口不足，会尝试升级到 `-model-1m`（默认 `ultimate`）；客户端也须配置相应窗口，不能据此扩大账号权限。

### thinking / effort

- Messages：`thinking.type=enabled` 时，`budget_tokens` 按 `≤0 / ≤1024 / ≤8192 / ≤24576 / ≤49152 / 更高` 映射为 `none / low / medium / high / xhigh / max`；`disabled` 映射为 `none`。
- Chat 的 `reasoning_effort` 与 Responses 的 `reasoning.effort` 接受上述等级，`minimal` 归一为 `low`；其他值不下发。
- 这些参数表达请求意图，不保证所选上游模型支持对应推理等级或返回 thinking 内容。

## 安全与限制

- 这是**单账号代理**，不是多租户平台；没有按客户端隔离的账号、配额或计费系统。持有 SK 的客户端共享上游账号能力。
- 仅绑定 loopback 并使用强随机 SK；跨主机时另设 TLS 和访问控制，也要限制无需鉴权的 `/health`。
- `user` 的加密是 CLI 格式兼容，不防御同时持有 `user` 和 `machine_id` 的人。保护整个凭据目录及备份，不能只保护 PAT。
- 持久化模式可能自动刷新/写盘；共享存储使用协作式租约，不是内核级 fencing，陈旧锁恢复仍有 TOCTOU 窗口。强隔离需独立 auth-dir 重新登录。
- 详细日志、明文 dump、真实请求/响应、模型缓存和客户端配置可能含敏感数据；不要放进公开 issue、PR 或仓库。
- 上游服务、订阅、模型与客户端行为会变化。离线协议兼容不等于在线可用性保证，也不提供绕过授权或转售额度的许可。

漏洞请走 [安全政策](SECURITY.md) 中的私密报告渠道，不要公开提交凭据或可复用认证材料。

## 开发与协议资料

- [开发指南](docs/development.md)：架构、离线检查、明确授权的真实 E2E 与可选 oracle。
- [贡献指南](CONTRIBUTING.md)：小范围 PR、合成测试数据、冻结历史向量和模块边界。
- [OAuth 与本地认证](docs/oauth.md)、[推理协议](docs/inference-protocol.md)：字段、存储和 wire format。
- [1.1.74 国内/海外兼容性分析](docs/qodercli-1.1.74-analysis.md)：版本锁定的静态证据与未验证边界。
- [分析工具](tools/README.md)：独立外置 oracle；普通构建与测试不需要它。
- [历史性能快照](BENCHMARK.md)：1.1.34、2026-09-01 的 dirty-tree 数据，不代表 1.1.74 当前性能。

## 许可证

项目采用 [GNU Affero General Public License v3.0](LICENSE)。通过网络向用户提供修改版服务时，须按许可证向这些用户提供对应源码。
商标、历史资产和外置 oracle 的独立授权边界见 [NOTICE](NOTICE)；项目许可证不授予 Qoder 服务或外部二进制的使用权。
