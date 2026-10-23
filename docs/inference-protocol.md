# qodercli v1.1.74 模型推理协议

> 生产保持 pure Go native-only。`testdata/protocol/1.1.74/` 独立固定当前核心协议，`1.1.34/` 保留历史向量。两版外置 oracle 的固定身份与验证命令见 [工具说明](../tools/README.md)，样本与静态证据见 [1.1.74 分析](qodercli-1.1.74-analysis.md)。本文区分核心 prepared request 与官方 JS 外层的最终发送规则；原始 22/18-header 向量不是最终网络请求头的完整清单。

## 1. URL

```text
POST {inference_endpoint}/algo/api/v2/service/pro/sse/agent_chat_generation
    ?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1
```

global 默认 endpoint 为 `https://api2.qoder.sh`，cn 为 `https://gateway.qoder.com.cn`，可由可信运维配置覆盖。`AgentId=agent_common` 是 URL 构造的固定常量，**不读取 body 的 `agent_id`**；修改、删除或重排 body 字段不会改变该 query 值。

COSY 签名使用的 path 固定为：

```text
/api/v2/service/pro/sse/agent_chat_generation
```

它不包含 endpoint 的 `/algo` 前缀，也不包含 query string。

## 2. 核心输出：最多 22 个请求头及条件 presence

normal-user 完整输入（非空 organization ID、至少一个 organization tag、非空 model key）的**原始 prepared header map** 精确包含 22 项。1.1.34/1.1.74 pinned WASM 的核心 presence 一致，native 实现逐项匹配。1.1.74 官方 JS 随后会改写机器 token/type 头，不能把下表直接当作最终发送头；外层差异的静态证据见 [分析记录 §4](qodercli-1.1.74-analysis.md#4-原生核心与最终发送请求必须分层验证)。

| Header | 值/条件 |
|---|---|
| `Accept` | `text/event-stream` |
| `Authorization` | `Bearer COSY.{payloadB64}.{signatureHex}`，见 §3 |
| `Cache-Control` | `no-cache` |
| `Connection` | `keep-alive` |
| `Content-Type` | `application/json` |
| `Cosy-Business-Product` | scene 的 `business_product`，默认 `cli` |
| `Cosy-Business-Type` | scene 的 `business_type`，默认 `agent` |
| `Cosy-ClientType` | scene 的 `client_type`，默认 `5`；HTTP map 展示时大小写可能被规范化为 `Cosy-Clienttype` |
| `Cosy-Data-Policy` | `data_policy_agreed=true` 时 `agree`，否则 `disagree` |
| `Cosy-Date` | 当前 Unix **秒**的十进制字符串；host clock 以毫秒提供后截为秒 |
| `Cosy-Key` | runtime fields 的 RSA ciphertext Base64 |
| `Cosy-MachineId` | 36 字符 machine UUID |
| `Cosy-MachineToken` | 与 MachineId 相同 |
| `Cosy-MachineType` | `5` |
| `Cosy-Organization-Id` | organization ID；仅当 ID 非空时存在 |
| `Cosy-Organization-Tags` | tags 按原顺序以逗号连接；仅当 slice 长度大于零时存在 |
| `Cosy-Scene` | scene，默认 `assistant` |
| `Cosy-User` | uid |
| `Cosy-Version` | context version，当前生产为 `1.1.74`；历史向量仍为 `1.1.34` |
| `Login-Version` | `v2` |
| `X-Model-Key` | `PrepareInferRequest` 的 model key；仅当 model key 非空时存在 |
| `X-Model-Source` | model source，通常 `system` 或 `custom`；与 `X-Model-Key` 同门控，key 非空时即使 source 为空也保留空值 header |

presence matrix 已由独立 WASM characterization 和 native/WASM differential 固化：

| 输入形状 | header 数 | 省略项 |
|---|---:|---|
| organization ID 非空、tags 非空、model key 非空 | 22 | 无 |
| organization ID 空、tags 空、model key 非空 | 20 | `Cosy-Organization-Id`、`Cosy-Organization-Tags` |
| organization ID 非空、tags 空、model key 非空 | 21 | `Cosy-Organization-Tags` |
| organization ID 空、tags 非空、model key 非空 | 21 | `Cosy-Organization-Id` |
| model key 空（无论 model source 是否为空） | 再减 2 | `X-Model-Key`、`X-Model-Source` |
| model key 非空、model source 空 | 不减少 | `X-Model-Source` 存在，值为空 |

`organization_tags=null` 与空 slice 在低层 context API 中不等价：pinned WASM 在 context New 阶段、任何 host entropy/clock 调用之前拒绝 nil tags；native factory 同样 fail closed。auth semantic boundary 会把登录/userinfo/load 得到的 nil tags 克隆为非 nil 空 slice，再生成 runtime fields 与 context config；它不放宽直接调用 factory 时的精确校验。非 nil 空 slice 是有效输入，并触发上表的 tags header omission。

### 2.1 代理的最终发送层

代理在克隆核心 prepared header map 后，按 1.1.74 的无 UMID 分支，不区分大小写移除所有 `Cosy-MachineToken` / `Cosy-MachineType` 键，保留 `Cosy-MachineId`。随后仅在键缺失时补充 `Cosy-Version`、`Cosy-ClientType`、`Cosy-MachineOS`；已有值（包括显式空值、多值和非规范大小写）不被覆盖。body、URL、Authorization/signature 和原始 prepared map 不被改写。

同一公共标识默认值也用于 OpenAPI 认证请求，但机器 token/type 清理仅用于推理。Linux/amd64 的 MachineOS 是已与样本核对的 `x86_64_linux`；其他平台使用标准架构/OS 名称映射，不声称已经逐个平台比对官方发行样本。本项目不主动采集 hostname、UMID 或硬件标识，也不注入遥测 trace 字段。

## 3. COSY Authorization

### 3.0 context New 与 Prepare 的 host transcript 分界

外部 v1.1.34 oracle characterization 固定了 context 生命周期的 host 调用分界，production native implementation 与 frozen fixtures 保持该语义：

- `nativeContextFactory.New` 的 redraw-free 基础形状为 `[16,109]`，不读取时钟：16 bytes 用于 runtime UUID，109 bytes 用于 RSA PKCS#1 v1.5 PS。PS 中每遇到一个 zero byte，就按从左到右顺序追加一次或多次 1-byte 重抽，直到该位置非零；因此含 zero 的有效形状可以是 `[16,109,1,...]`。使用与生成结果明确不同的 synthetic caller fields 对 pinned WASM 做 full-org 与 no-org 探针后，两者都证明 New **保留调用方传入的 `encrypt_user_info` 与 `key`**，Prepare 的 payload `info` 与 `Cosy-Key` 直接读取 caller fields。New 内部 runtime-field 生成的结果不进入签名状态；native 仍执行该生成并传播其 entropy/error/cancellation 行为，作为 oracle-observed constructor side effect。
- 随后的每次 `PrepareInferRequest` 精确读取一次时钟和一段 16-byte 安全熵，global host-call order 为 **clock → entropy**。该 16-byte tape 用于本节下方的 COSY request UUID；时钟用于 `Cosy-Date` 与签名。
- 测试分别 replay New 与 Prepare 并检查 transcript exhaustion；另有含 zero 的 New tape 固化 1-byte redraw 顺序。`infer-user.json` 保留完整 22-header 历史向量；`infer-user-no-org.json` 使用不同 caller fields 固化 caller ownership、no-org/empty-tags 与 empty-model-key 的 18-header 行为。两份 fixture 都保存 redraw-free 组合形状 `[16,109,16]` 加一次时钟。

### 3.1 request UUID

每次 prepare 读取安全随机 bytes `R[16]`，逐字节反转为 `U[i] = R[15-i]`，再设置 `U[6] = (U[6] & 0x0f) | 0x40`、`U[8] = (U[8] & 0x3f) | 0x80`。将完整 masked `U` 按 lowercase `8-4-4-4-12` 格式化为 COSY UUID；不再反转字段内部字节。该 UUID 是 Authorization payload 的 `requestId`，每次 prepare 都重新生成且不得复用。它与 handler 创建、位于 RemoteChatAsk raw JSON 中的 `request_id` 是不同层次的字段。

### 3.2 payload

payload 是以下 **固定字段顺序**的 raw JSON：

```json
{"version":"v1","requestId":"<uuid>","info":"<encrypt_user_info>","cosyVersion":"<context version>","ideVersion":""}
```

每个版本的 fixture 使用自身固定的 context version：历史目录仍包含 `"cosyVersion":"1.1.34"`，新目录及当前生产使用 `1.1.74`。version perturbation characterization 证明该字段读取 context version，而不是另一个独立常量；`Cosy-Version` header 与 payload 同步变化并影响签名。升级生产常量不会重写历史向量。

对这串 raw UTF-8 bytes 使用 **standard padded Base64**；保留标准 `+/` 字母表和 `=` padding，不使用 base64url。

### 3.3 canonical MD5 签名

令：

- `payloadB64`：上一节的标准 padded Base64
- `key`：runtime fields 的 `Cosy-Key` 字符串
- `unixSeconds`：与 `Cosy-Date` 完全相同
- `encodedBody`：§4 最终 POST body 字符串
- `signedPath`：`/api/v2/service/pro/sse/agent_chat_generation`

canonical bytes 精确为：

```text
payloadB64 LF key LF unixSeconds LF encodedBody LF signedPath
```

即五段、四个 `\n`，**末尾没有 LF**。签名是这些 UTF-8 bytes 的 MD5，输出 32 字符 lowercase hex：

```text
signatureHex = lowerhex(MD5(payloadB64 + "\n" + key + "\n" + unixSeconds + "\n" + encodedBody + "\n" + signedPath))
Authorization = "Bearer COSY." + payloadB64 + "." + signatureHex
```

签名 path 不含 `/algo`、不含 query，也不含尾随换行。它是 canonical MD5，不是“由 machine context 派生的未知签名算法”。

## 4. 请求 body codec

输入是调用方提供的 **raw UTF-8 JSON bytes**。codec 不 parse JSON、不规范化字段、不压缩空白，因此字段顺序、空格、转义形式甚至 JSON 语义等价但字节不同的输入都会得到不同 body；算法本身不依赖 user、model、clock 或 randomness，是 context-free deterministic transform。

1. 对 raw bytes 做 standard padded Base64。
2. 将标准 Base64 的 64 个字符按位置映射到以下 64 字符 alphabet：

```text
_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!
```

3. 将标准 Base64 padding `=` 映射为 `$`。
4. 对映射后的字符串做 outer-third swap：令 `k=floor(len/3)`，`A=s[:k]`、`B=s[k:len-k]`、`C=s[len-k:]`，输出 `C || B || A`。中段吸收不能整除 3 的余数。

逆变换为同样交换外侧 thirds，再把 `$` 和 custom alphabet 映回标准 Base64 后严格解码。该 body 是可逆的确定性编码，**不是加密**，也不需要每次调用 WASM 才能计算。native 与两版 pinned oracle 在有效编码域上保持 byte-exact 兼容；native 有意拒绝六种 oracle 容忍的非规范 padding/换行输入。具名差异及 33-case corpus 见 [版本分析](qodercli-1.1.74-analysis.md#4-原生核心与最终发送请求必须分层验证)，不放宽生产校验。

## 5. RemoteChatAsk raw JSON

当前 proxy 使用 `map[string]any` 构造 RemoteChatAsk，并由 Go `encoding/json` 序列化。`encoding/json` 会按 lexical order 输出 string map keys；这里不存在可依赖的 struct declaration order。当前 proxy 产生的紧凑 top-level key 顺序精确为：

```text
agent_id, aliyun_user_type, business, chat_context, chat_record_id, chat_task, custom_model, is_reply, is_retry, messages, model_config, parameters, request_id, request_set_id, session_id, session_type, source, stream, system, task_id, tools, version
```

其中 `business` 是必需对象，当前包含 `begin_at`、`id`、`name`、`product`、`stage`、`type`、`version`；它自己的 map keys 同样按 lexical order 输出。`messages`、`model_config`、`tools`、`parameters` 及其他嵌套 struct/map 分别遵循其自身 Go `encoding/json` 规则：struct 使用声明字段顺序，string-keyed map 使用 lexical key order，`omitempty` 仍可能影响字段存在性。

这描述的是**当前 proxy 生成的 raw bytes**，不声称它必然等同于 official CLI 的字段顺序。raw JSON 随后直接进入 §4 codec 并参与签名，所以 top-level 或 nested serialization 的任何字段、顺序、空值或转义变化都属于 signature-sensitive drift。characterization fixture 使用真实 `remoteChatAskBody` builder 的固定合成输入锁定这些 bytes。

`request_id` 必须全局唯一；服务端对重复值返回 code 103。虽然 body 仍含 `agent_id`，URL 的 AgentId 固定常量不从这里读取。

## 6. model cache：QMC v1

1.1.74 使用所选配置根下的 `.models/{uid}/catalog-v7`（global 默认 `~/.qoder`，CN 默认 `~/.qoder-cn`）。旧 `catalog-v6` 仅作为 v7 不存在时的兼容来源。缓存文件代数变化不等于加密 envelope 变化，两者仍使用 QMC v1：

1. HKDF-SHA256 的 IKM 为 raw `UTF8(uid)`；salt 为 ASCII `qoder-model-cache-enc`（21 bytes）；info 为 ASCII `model-cache-v1`（14 bytes）；输出精确为 32 bytes，作为 AES-256 key。
2. 使用随机 nonce 12 bytes、authentication tag 16 bytes、**empty AAD** 的 AES-256-GCM 加密 catalog plaintext。
3. 二进制 envelope 精确为 `QMC\x01 || nonce(12) || ciphertext || tag(16)`。
4. 整个 envelope 使用 standard padded Base64 保存。

解密必须校验 magic、version、最小长度和 GCM tag，任何失败均 fail closed。显式 `-catalog` 明文文件优先；自动加载只有在 v7 文件不存在时才读 v6。v7 读取、解密或结构错误会输出内容静默诊断并保留内置兜底，不借旧 v6 掩盖，也不删除或改写官方缓存。

仅解析 `chat`、`byok_enterprise`、`byok_teams` 三个已支持组；不会把 embedding、service-account 等未知场景混入 Chat API 清单。`key`/`model_key`、`display_name`/`name` 使用缺失或 null 才回退的规则，显式空字符串不触发别名。`enable` 缺失/null 默认启用，false 或数值 0 保留为禁用；禁用条目仍在内部解析清单中，避免被合成为启用条目，但不出现在 `/v1/models`。

至少要有一个真实的受支持数组才是合法目录结构；`[]` 有效，`null` 组不算数组。坏邻居组/条目不会丢弃其他有效条目。chat 同组后出现的键优先，非 chat 组不覆盖已有受支持组条目；模型映射、friendly ID 和 `[1m]` 机制保持原有语义。内置项仍是无可用缓存时的兼容兜底，不是实时账号授权列表。

## 7. response：明文 SSE

响应不使用 §4 codec，也不需要 WASM 解密。Content-Type 为 `text/event-stream`，数据帧是明文 JSON 外层信封：

```text
data:{"headers":{"Content-Type":["application/json"]},"body":"<inner JSON string>","statusCodeValue":200,"statusCode":"OK"}
```

`body` 通常再解析一次得到 OpenAI `chat.completion.chunk`，可含 `content`、`reasoning_content`、流式 `tool_calls`、`finish_reason` 和 `usage`。历史 1.1.34 授权 E2E 曾确认（1.1.74 尚未进行线上验收）：一个有效的 `statusCodeValue:200` 外层信封可在 `body` 字符串中携带精确的 `[DONE]` 标记；该标记本身不是上游终止依据。之后仍由独立的权威终止事件收尾：

```text
event:finish
data:{"firstTokenDuration":...,"totalDuration":...,"serverDuration":...}
```

因此，上游的 `[DONE]` 位于外层信封的 `body` 内，不是裸 `data:[DONE]` 帧；代理忽略这个精确标记，协议以 `event:finish` 为权威终止信号。需要区分协议与实现：当前生产 `readSSE` 也允许 EOF 结束读取，并未新增“缺少 finish 一律拒绝”的严格检查；测试观察器的终止形状验证更严格。面向不同下游客户端时，代理按目标协议生成终止帧。`statusCodeValue != 200` 是错误信封，会转换为各客户端协议的错误事件。

## 8. 当前 proxy retry 算法

一次 handler 调用最多执行 **4 attempts**。handler 创建并序列化一次 RemoteChatAsk raw JSON；其 body bytes 和内部 `request_id` 在所有 attempts 间保持不变。每个 attempt 都重新调用 `doUpstream` → `PrepareInferRequest`，因此重新生成 COSY UUID、读取当前 Unix seconds，并重新形成 Authorization/header/body wrapper。native 本地 `httptest` integration 锁定这一点：每个网络 attempt 恰好一次 prepare，不同 attempt 使用不同的 request entropy/clock，Authorization 与 COSY request UUID/date 随之更新，而 encoded body 和解码后的内部 `request_id` 保持不变；另有三次 1ms queue 后第四次成功的测试覆盖完整 4-attempt 上限。

- **transport error**：前 3 次失败分别无 jitter 等待 1、2、3 秒；第 4 次直接返回 transport error。
- **401**：只有 **attempt 1 自身返回 401** 才调用 `forceRefresh`；刷新成功后立即进入 attempt 2，不额外 sleep。若 attempt 1 是 transport error、408/429/5xx 或 queue 等其他结果，经过 retry 后 attempt 2/3/4 才返回 401，则直接返回该 response，绝不补做 refresh；attempt 1 的 refresh 失败也直接返回原 401。
- **普通 retryable status**：408、429、500–599 可重试。默认 exponential waits 为 attempt 1 后 1 秒、attempt 2 后 2 秒、attempt 3 后 4 秒。若 `Retry-After` 非空，只按 `time.ParseDuration(value + "s")` 解释为 numeric seconds；解析成功则覆盖默认值，HTTP-date 不支持。等待上限 30 秒，无 jitter。
- **queue response**：JSON `queue.isQueued=true` 时依次选 `queue.waitTime` → 顶层 `retryAfterMs` → 2000ms；顶层 `code="10605"` 时选 `retryAfterMs` → 2000ms。queue wait 同样 cap 30 秒；queue 分支不使用普通 exponential wait 或 `Retry-After` header。
- **取消**：所有等待通过 context-aware sleep；context cancel 立即返回 `ctx.Err()`。
- **response ownership**：非 200 response body 最多读取 8192 bytes 后关闭。需返回给 caller 时以已读取 bytes 构造新的 body；达到第 4 attempt 时返回最后 response，不再等待。200 response 保持开放交给 SSE caller。
- **其他状态**：非 queue 且不属于上述 retryable status 的 response 立即返回。

code 103 duplicate 的准确含义：当前 proxy retry 会保留同一 RemoteChatAsk `request_id`，所以不能把 code 103 当作可安全自动 retry 的状态；它不在 retryable status 集合中，会立即返回。若要形成协议意义上的新请求，必须由 handler/调用方重新创建 RemoteChatAsk 和新的 `request_id`，而不仅是重新 prepare COSY wrapper。

本地 clock/entropy/backend/context 失败发生在 prepare 阶段并 fail closed，不发送半准备请求；它作为 attempt transport-side error 进入上述 1/2/3 秒调度，最终仍失败返回。

## 9. Native-only production 与验证边界

Production 只有一个 native service constructor；没有 backend mode flag、环境变量、WASM adapter、shadow wrapper 或 fallback runtime。root module 和 production binary 不包含 WASM bytes，也不依赖 wazero。验证状态和授权运行命令见 [开发指南](development.md#authorized-e2e)。

native context 的当前语义如下：

- Factory 校验完整的 clock/entropy，以及 machine ID、版本、UID、非 nil organization tags 和四个非空 scene 字段；organization ID 与非 nil tags slice 可为空。配置和 tags 在 New 边界深拷贝。nil tags 按 frozen oracle 行为在任何 runtime/host work 前拒绝。
- New 使用调用 context 中的 host override（存在时优先于 factory host）执行 redraw-free `[16,109]`、零 clock 的 runtime-field 初始化；PS 中出现 zero 时追加 1-byte redraw。pinned WASM 的 full-org/no-org 非退化探针都确认生成结果不进入 context signing state：context 保留 caller fields，Prepare 的 payload `info` 与 `Cosy-Key` 也使用 caller fields。该生成调用保留的是 constructor side effect、失败与取消语义，不是字段替换。
- `PrepareInferRequest` 在本地构造完整 COSY request：literal endpoint concatenation、native body codec、反转/mask request UUID、固定顺序 payload、standard padded Base64、canonical MD5、条件 header presence，以及 fresh URL/header/body ownership。每次 prepare 按 **clock → 16-byte entropy** 顺序各调用一次；没有隐藏 counter 或 transcript state。
- context 本身不保存 transcript 或隐藏计数器。每次 Prepare 获得独立的不可变状态副本和 body 副本，返回的 header map、header value slices 与 body 也拥有独立 storage。生产 wall clock 与 secure entropy 实现可并发使用；record/replay machinery 仅存在于测试文件。
- Close 幂等并等待在途 Prepare；关闭开始后不再接纳新 Prepare。该本地 context 边界不执行 auth refresh 或网络请求。

普通 root 测试使用版本化 frozen fixtures 和 native deterministic replay，不需要 Python、外部 WASM 或网络。两版分别核验 `infer-user.json` 的原始 22-header、`infer-user-no-org.json` 的 caller ownership 与原始 18-header，以及 credential/runtime/model-cache；历史 signature/presence/transcript 测试继续保留。1.1.74 另有 33-case compatibility corpus，七项 strict-native 拒绝被精确列出。external oracle 验证与独立 capture 命令见 [工具说明](../tools/README.md)。

历史 1.1.34 的 race/fuzz/stress、跨平台构建与真实账号 E2E 结果不能作为 1.1.74 的线上验收。1.1.74 的证据来自静态分析和合成离线验证，尚未执行真实 global/CN 账号登录、刷新或推理验收。当前检查命令和证据范围见 [开发指南](development.md#verification-scope)，历史性能数据仍保留在 [BENCHMARK.md](../BENCHMARK.md)，不重新标注为当前性能。

可选 external oracle 位于 `tools/wasm_oracle` 独立子模块中，保留其自己的 wazero 依赖。它只接受运维方显式提供且身份匹配的授权 WASM，并以内容静默方式复核 synthetic frozen fixtures；它不属于 production dependency graph。
