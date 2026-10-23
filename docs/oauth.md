# qodercli v1.1.74 OAuth 与本地认证协议

> 当前协议版本为 1.1.74；`testdata/protocol/1.1.74/` 的合成向量来自独立 capture/replay，历史 `1.1.34/` 向量保持不变。两版外置 oracle 的尺寸/哈希和验证方法见 [tools/README.md](../tools/README.md)。1.1.74 国内/海外的设备 client_id 与核心 WASM 相同，端点、配置根及外围逻辑存在差异，见 [版本分析](qodercli-1.1.74-analysis.md)。
> 最初的登录流程与二进制结构结论来自对用户自行合法安装的 v1.1.5 的历史分析；当前生产算法是纯 Go native implementation。当前源码树与生产构建不包含或分发认证 WASM，也不分发 Qoder CLI、完整 JS bundle、真实凭据或抓包；历史资产边界见 [NOTICE](../NOTICE)。1.1.74 的真实 global/CN 账号登录、刷新及推理尚未验收，静态/合成验证不等于线上可用性证明。

qodercli 的“OAuth”是自定义设备授权流（Device Authorization Grant 变体 + PKCE 风格 challenge/verifier），不是标准 OAuth 授权码流程。下文明确区分 **历史 Qoder CLI 行为**与仓库中 **当前代理实现**；两者共享端点和基础 wire format，但错误处理与登录后 enrichment 并不完全相同。

## 1. 登录方式

**历史 Qoder CLI v1.1.5 分析**观察到浏览器设备流、PAT、宿主注入的 job token/access token，以及本地存储恢复等入口；环境变量 `QODER_PERSONAL_ACCESS_TOKEN` 可向历史 CLI 提供 PAT。

**当前代理**公开实现 `-login` 浏览器设备流、`-login-pat` 持久化 PAT 交换、已有本地 credential 恢复，以及所选区域官方 PAT 环境变量的临时服务模式。`-region global|cn` 贯穿授权、轮询、userinfo、刷新、推理与目录选择；优先级为 flag > `QODER2API_REGION` > `QODER_REGION` > global。

global 使用 `QODER_PERSONAL_ACCESS_TOKEN` / `QODER_CONFIG_DIR`，CN 使用 `QODERCN_PERSONAL_ACCESS_TOKEN` / `QODERCN_CONFIG_DIR`；只读取所选区域前缀的环境 PAT。环境 PAT 模式不读取已存 user/machine_id，也不创建或修改凭据、机器身份、事务标记或区域 sidecar；身份与 token 仅驻留内存，仍可读取既有目录/区域绑定元数据。显式 `-login` 忽略环境 PAT；两个显式登录参数不能同时使用。本文不把官方 SDK/job-token/service-account 入口声称为当前代理功能。

`-auth-dir` / `QODER2API_AUTH_DIR` 指完整凭据目录，优先于所选区域的默认存储位置；`*_CONFIG_DIR` 指配置根，默认在其下使用 `.auth`。登录和服务进程须选择相同区域与目录；一次显式登录不会改变后续进程的默认区域。`QODER2API_SK` 只用于下游客户端访问，与上游 PAT 无关。

## 2. 设备授权流

### 2.1 PKCE 风格参数

```text
verifier  = 43..128 个随机字符，字符集 A-Z a-z 0-9 -._~
challenge = base64url_nopad(SHA256(verifier))
nonce     = random UUID
machineId = 所选区域 .auth/machine_id 的已有身份（通常为 36 字符 UUID）
```

浏览器打开：

```text
GET https://qoder.com/device/selectAccounts
    ?challenge={challenge}
    &challenge_method=S256
    &nonce={nonce}
    &machine_id={machineId}
    &client_id=e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb
```

上述为 global 示例。CN 使用 `https://qoder.cn/device/selectAccounts`，生产设备 client_id 同为 `e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb`；poll、userinfo、refresh 和 PAT exchange 则使用 `https://openapi.qoder.com.cn`。只替换浏览器域名不足以切换区域。

没有 scope、redirect URI 或本地回调。客户端轮询：

```text
GET https://openapi.qoder.sh/api/v1/deviceToken/poll
    ?nonce={nonce}&verifier={verifier}&challenge_method=S256
Accept: application/json
```

**历史 Qoder CLI 行为**：未授权时 404 每 1 秒重试，总超时 300 秒；分析曾观察到指向网络代理的 ECONNREFUSED/ECONNRESET 连续 3 次后形成硬错误。token 成功后，CLI 会拉取 user info、organization tags 和 data policy，再保存 credential，并启动每 30 分钟一次的刷新检查。

**当前代理行为**：同样把 404 作为 pending 并每 1 秒重试、最多 5 分钟；但任意 transport error 都按 1 秒间隔继续到 deadline 或 context cancellation，**没有“三次代理错误即硬失败”计数器**。非 200/404 状态立即返回错误；200 JSON 缺 token 也立即失败。取得 token 后，代理先创建 runtime context 并保存 credential，再 best-effort 请求 `/api/v1/userinfo` 补充 profile；该 enrichment 失败不使登录失败。当前代理登录路径不调用历史 CLI 的 data-policy endpoint，也不应被描述为已经复制该 hard-error/data-policy 行为。

## 3. PAT 与 token 刷新

PAT 交换：

```http
POST /api/v1/jobToken/exchange
Content-Type: application/json

{"personal_token":"<PAT>","machine_id":"<已有或内存中的机器 ID>"}
```

PAT 过期/强制续期重新调用该 exchange，并校验返回账号 UID；不把 PAT 派生 token 交给浏览器的 device-token refresh 入口。环境 PAT 全程不落盘；显式 `-login-pat` 则使用持久化流程。缺少可用根 PAT 的 token 登录不能伪装成浏览器登录续期。

浏览器设备 token 刷新：

```http
POST /api/v1/deviceToken/refresh
Content-Type: application/json

{"refresh_token":"...","machine_id":"<已有机器 ID>"}
```

可用 machine_id 会随 refresh/exchange 发送。没有真实 UMID 时省略 machine_token，不用 machine_id 冒充它。

`expire_time - 3600 < now` 时提前刷新；每次用 token 前检查，后台每 30 分钟检查一次。当前 inference retry 只有在 **attempt 1 本身返回 401** 时才调用 `forceRefresh`，刷新成功后立即 retry 一次；如果先前已经发生 transport/status retry，后续 attempt 才返回 401，则直接返回该 401，不触发 refresh。刷新响应中的 token rotation 会先保留在内存中，再原子保存。

首次 browser/PAT login 的 credential publish 是 fail-closed，必须成功后才提交登录状态。已接受的新 token 与 replacement context 则以内存可用性为优先：后续普通 credential 保存失败时保留 `credentialDirty`，记录不含 credential 内容的原因，并在 30 秒 retry deadline 后重试，不为保存重试再次请求上游刷新。`Close` 忽略 retry deadline，最后尝试 flush 并返回失败。

1.1.74 的 runtime fields 绑定当前 token 与 profile。生成/构建失败或 post-build 检查遇到普通临时 I/O 错误时，不接受“新 token + 旧 fields”状态；保留旧活动 UI/context，并保全已由上游轮换的新 refresh token/expiry，待 I/O 恢复后按原 baseline 持久化。真正的账号、目录、lease 或 revision 冲突仍 fail closed，不会为了重试而覆盖其他进程的凭据。

## 4. credential 文件格式

| 项 | 精确格式 |
|---|---|
| 路径 | global `~/.qoder/.auth/user`；CN `~/.qoder-cn/.auth/user`；可显式覆盖 auth-dir。官方 CLI 的非生产 `user.<environment>` 不等于本项目自动选择的 profile |
| 明文 | UserInfo 的 UTF-8 JSON |
| key | `machine_id` 前 16 个字符，作为 **raw 16-byte UTF-8 key**，不是 hex/base64 解码值 |
| cipher | AES-128-CBC |
| IV | 与 key 完全相同的 16 bytes |
| padding | PKCS#7，严格校验 |
| envelope | strict standard padded Base64（标准字母表，必须有正确 `=` padding；不接受 URL-safe/缺 padding/尾随垃圾） |

该加密仅用于 CLI 格式兼容，不防御同时持有 `user` 和 `machine_id` 的人；完整目录、备份与运行账号权限都属于安全边界，见 [安全政策](../SECURITY.md)。

项目加载时保留兼容行为：若去除文件外围空白后内容以 `{` 开头，则按明文 JSON 解析；否则严格按上述格式解密。保存始终写加密格式，不写明文 fallback。未知 user JSON 字段以原始 JSON 值保留并深拷贝，避免刷新时丢失新版本元数据或大整数精度。

已有 machine_id 必须保留。缺失 ID 但已有 user、读取错误、空内容或非普通文件时拒绝操作，不自动生成替代身份；只有真正的新空存储才初始化 ID。加载旧凭据时会在内存中重新生成 token-bound runtime fields，但不会仅因加载而标记 dirty、改写 user 或创建区域绑定。后续真实持久化会保存当前字段；持久化构造/load 仍可能创建事务标记文件。

保存继续使用唯一 temp-file 路径：在目标目录创建 `.user-*` 临时文件，chmod `0600`，完整写入、`fsync`、关闭后 `rename`；失败时删除 temp。这样不会把两个 ciphertext 的字节交叉写入，但单文件原子替换本身不是跨进程事务。

持久化模式采用官方兼容的 `.credential-transaction` 标记和空目录 `.credential-transaction.lock` 租约（10 秒心跳、120 秒陈旧阈值），结合 machine ID、区域绑定和最后成功持久化 revision 检查。刷新期间持有 lease，浏览器等待和每次 poll 的网络请求期间不持有；每次 poll 前重新检查状态。检测到其他写入或身份变化就拒绝，不静默重绑定或覆盖另一登录。新目录为 0700，凭据/标记为 0600。

该租约是协作式机制，存在检查后路径替换、并发陈旧锁回收等固有 TOCTOU 窗口，不提供内核级 fencing。避免多个进程同时清理/恢复共享锁；需要强隔离时在独立 auth-dir 重新登录，不要复制同一份轮换凭据并发运行。详细限制见 [版本分析](qodercli-1.1.74-analysis.md#共享存储的并发规则)。

## 5. runtime auth fields

`generate_runtime_auth_fields(raw)` 对调用方提供的 **raw UTF-8 字符串原样处理，不先 parse/re-marshal JSON**；因此字段顺序、空白和转义都会进入 AES 明文。

1.1.74 官方 auth 语义层按 `uid`、`security_oauth_token`、`organization_id`、`organization_tags`、`data_policy_agreed` 顺序序列化。其中 token 字段是相对旧版四字段输入的重要变化；它只进入加密的 `encrypt_user_info`，不应写入日志或推理 body 的裸字段。历史无 token 的向量仍用于验证低层 raw-byte 算法，不能替代带合成 token 的调用层回归。

1. 读取 RNG bytes `R[16]`，逐字节反转为 `U[i] = R[15-i]`，然后设置 UUID mask：`U[6] = (U[6] & 0x0f) | 0x40`、`U[8] = (U[8] & 0x3f) | 0x80`。
2. runtime AES key `K` 精确为 lowercase `hex(U)[:16]` 的 **16 个 ASCII bytes**，等价于 masked/reversed `U` 的前 8 bytes 写成 16 个小写 hex 字符；不包含 UUID 连字符，也绝不能再做 hex decode。
3. 使用 `K` 执行 AES-128-CBC；IV=`K`，PKCS#7；对 raw input 加密并输出 strict standard padded Base64，作为 `encrypt_user_info`。
4. 用下列 pinned **runtime RSA-1024 SPKI public key**和 PKCS#1 v1.5 加密 `K`。其 modulus 为 1024 bits，public exponent 为 65537；SPKI DER 长 162 bytes，SHA-256 为 `a6a4aa468d90c618966e38122abfb06e566c18c9b21090d61f3e9b796b33e569`：

```pem
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----
```

该 key 直接从 pinned v1.1.34 WASM 提取，是用于互操作复现的非秘密公钥；不要与同一 WASM 中另一个 **2048-bit profile RSA public key**混淆。

5. PKCS#1 v1.5 编码块为 `00 02 || PS || 00 || M`：模长 128 bytes，`M=K` 为 16 bytes，所以 PS 精确为 **109 bytes**；PS 每字节必须非零，RNG 产生 0 时逐字节重试。RSA ciphertext 用 standard padded Base64 表示，作为 `key`。
6. 返回 JSON 的字段顺序固定为：

```json
{"encrypt_user_info":"<base64 AES ciphertext>","key":"<base64 RSA ciphertext>"}
```

该算法由 production pure-Go implementation 提供，并由 frozen fixtures 固定 byte-exact 兼容性。可选外部 oracle 仅用于经授权的离线复核，不进入生产构建或普通测试。当前验证证据见 [开发指南](development.md#verification-scope)。

## 6. runtime context 与凭证携带

代理认证层是 active protocol context 的唯一 owner。加载或刷新凭证后，它补齐 runtime fields、创建新的 native context，再原子替换并关闭旧 context；server 和 catalog 只依赖语义接口。

- OpenAPI：`Authorization: Bearer {security_oauth_token ?? access_token}`，`User-Agent: qoder/1.1.74`
- 推理：设备 token 不以明文独立字段发送；1.1.74 的 auth 输入把它纳入加密 `encrypt_user_info`，native context 使用该字段、RSA `key`、machine/org/scene 准备 COSY 请求，详见 [inference-protocol.md](inference-protocol.md)
- 认证语义边界：设备登录、PAT userinfo 与 credential reload 若得到 nil `organization_tags`，会在 runtime/context typed input 边界克隆为非 nil 空 slice；持久化 JSON 不必因此改写。直接调用低层 native context factory 仍按 frozen oracle 行为拒绝 nil tags
- credential codec 只返回 ciphertext；实际落盘仍由 §4 的单一原子保存路径执行
- production services 仅构造 native capabilities；clock/entropy 可注入，deterministic transcript record/replay 只用于测试与外置 oracle；`testdata/protocol/1.1.34/` 和 `1.1.74/` 分别保存固定身份的合成 fixtures

生产路径没有 backend mode、WASM rollback 或 fallback。验证与可选外部 oracle 命令见 [开发指南](development.md#optional-oracles)。

## 7. 生产端点与错误

| 用途 | global 默认 | cn 默认 |
|---|---|---|
| inference | `https://api2.qoder.sh` | `https://gateway.qoder.com.cn` |
| openapi | `https://openapi.qoder.sh` | `https://openapi.qoder.com.cn` |
| browser authorization | `https://qoder.com` | `https://qoder.cn` |

代理允许运维方通过启动参数覆盖端点。当前代理的轮询超时、credential 格式/PKCS#7/Base64 错误均 fail closed；轮询 transport error 的当前处理见 §2。**历史 Qoder CLI SDK 行为**中，`storagePolicy=readOnly` 模式不刷新、不落盘；当前代理不实现 SDK mode，不能把该约束描述为当前代理策略。当前验证状态和授权运行要求统一见 [开发指南](development.md#verification-scope)。
