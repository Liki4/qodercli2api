# Qoder CLI 1.1.74 兼容性分析

分析日期：2026-10-20。范围为 CLI 的认证、凭据、模型缓存和本项目使用的 legacy HTTP/SSE 推理协议，不是对官方 CLI 全部功能的复制。

下文区分静态源码证据、原生算法的离线验证，以及需要实际账号才能确认的服务端行为。该分析没有运行官方 CLI、安装脚本或访问真实账号凭据；**1.1.74 的真实 global/CN 账号登录、刷新及推理尚未验收**。历史 1.1.34 在线记录不能作为 1.1.74 验收结果，验证边界和授权命令见 [开发指南](development.md#verification-scope)。

## 1. 样本与版本身份

| 样本 | 长度（字节） | SHA-256 |
|---|---:|---|
| 本地 global `qodercli-1.1.74` | 181827040 | `fb8b9ea383bf6a701332fb1f4db48233a4e451e9cda01d0cda53660fcf3e35e7` |
| 官方 CN 1.1.74 Linux x64 压缩包 | 77775447 | `a8d3bffd23a179a51b325474bb04b9ff0ffaa24b759910c88f137adce358cf69` |
| 上述包中的 `qoderclicn` | 181827040 | `33794b7b2f98b27f8ad5a7ad8a27cc7162dec34b60c18bb16f8fcb885abb990e` |
| 两种 1.1.74 包内相同的 auth WASM | 298606 | `6419471effa631519def7797d76d7ede38b9fcfa9a83c2148c8ef5d43355b43d` |
| 历史 1.1.34 oracle 的固定 WASM | 297238 | `b3ddd7c9235cea51a965582506fa6281bb298ddab782ff3edb3f9015da2468d4` |

CN 压缩包从[官方固定版本 manifest](https://static.qoder.com.cn/qoder-cli-cn/channels/1.1.74/manifest.json)取得，先验证压缩包 SHA-256，再在内存中读取归档；未执行归档内程序。历史 oracle 的相同字节也存在于本地 1.1.12 样本中；这证明模块内容一致，不等于把该 CLI 本身重新标注为 1.1.34。

两个 1.1.74 样本都是 Bun 封装的 ELF，不是 Go 应用。global 样本包含 Bun 1.4.2、应用版本 `1.1.74` 和 revision `28a9573`。应用源码由 ASCII 与 UTF-16LE 的嵌入 JS 模块组成，仅扫描 ASCII strings 会漏掉大量认证代码。

本文给出的十六进制位置均为对应发行二进制的**文件偏移**，不是内存地址；不同平台或重打包构建不能直接复用这些位置。

## 2. 国内版不是海外版的浏览器域名别名

已核对两个构建的中心配置模块与实际设备授权函数：

| 属性 | global | CN |
|---|---|---|
| 配置目录默认名 | `.qoder` | `.qoder-cn` |
| 原生环境变量前缀 | `QODER_` | `QODERCN_` |
| 授权站点 | `https://qoder.com` | `https://qoder.cn` |
| OpenAPI | `https://openapi.qoder.sh` | `https://openapi.qoder.com.cn` |
| 默认推理入口 | `https://api2.qoder.sh` | `https://gateway.qoder.com.cn` |
| 产品 OAuth 标签 | `qoder-cli-oauth` | `qoder-cli-cn-oauth` |
| **生产设备登录 client_id** | `e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb` | **相同 UUID** |

非生产设备 client_id 也是两个构建共用的 `e93fe488-5778-4c35-a6fc-0f54ed7b3139`。产品 OAuth 标签和设备 client_id 是不同概念，不能混用。

关键位置：

- global 配置模块起始 `0x7f69ed5`，默认端点约 `0x7f6b039`。
- CN 配置常量起始 `0x7f69ee7`；其中构建标识为 CN，推理域名为 `gateway.qoder.com.cn`。
- global 设备授权模块起始 `0x8f35d55`，生产 UUID 在 `0x8f35f17`；CN 对应 UUID 在 `0x8f35fda`，设备查询构建在 `0x8f360c0`。

海外构建的 `QODER_ENV` 可以表达环境与 `us`、`sg`、`jp` 分区；这不是 CN 站点切换。也不能因为共享模块或安装器字符串中出现 `qoderclicn`，就认定海外构建支持运行时切换国内账号。

本项目的 `-region` / `QODER2API_REGION` / `QODER_REGION` 是适配器自己的配置，不应文档化为官方 CLI 已支持的参数。

## 3. 认证端点与凭据布局

### 设备登录

1.1.74 保留自定义 PKCE 式设备流程：本地生成 verifier、S256 challenge 和 nonce，构造授权网址，然后轮询结果。不是先调用标准 OAuth `device_authorization` 接口取得 `device_code`。

- 授权页：`/device/selectAccounts`
- 轮询：`GET /api/v1/deviceToken/poll`
- 刷新：`POST /api/v1/deviceToken/refresh`
- PAT 交换：`POST /api/v1/jobToken/exchange`
- 用户信息：`GET /api/v1/userinfo`

授权查询还可携带可选的 `machine_token`。1.1.74 的 `getMachineIdentityRequestFields`（global `0x8504d1e`）为 refresh/PAT exchange 添加有效的 `machine_id` 及可用的真实 UMID `machine_token`；无 UMID 时只保留有效 machine_id，不生成 machine_type，也不能用 machine_id 冒充 machine_token。

持久化登录方式标记为 `browser` 或 `token`。PAT 路径过期后会使用根 PAT **重新调用 jobToken/exchange**（`_doRefresh` 的 `pat` 分支，global `0x8508944`），不是把 PAT 派生 token 当作浏览器凭据送到 deviceToken/refresh。另有宿主 job-token 刷新入口，但不属于本项目的 1.1.74 适配范围。

授权网站、poll/userinfo/refresh 的 OpenAPI 以及推理入口分别承担不同职责。只改变浏览器网址不会同步改变后续请求区域。

### 磁盘格式

global 默认使用 `~/.qoder/.auth/`，CN 默认使用 `~/.qoder-cn/.auth/`。`.auth` 是目录：

- `machine_id`：机器身份；
- `user`：生产环境凭据；
- `user.<environment>`：官方 CLI 的非生产环境凭据；
- `.credential-transaction`：事务锁的标记文件。

只有 `machine_id` 的目录没有完整登录凭据，不能据此判定凭据格式改变。历史国内安装使用 `~/.qoder` 时，应显式指定其真实 auth-dir，不应让 CN 模式自动尝试海外默认目录。

加密对象仍为 JSON，credential codec 的输入密钥取 `machineId.slice(0,16)`。应成对保留 user 和 machine_id；读失败、解密失败或发现 ID 被替换，不是生成新机器身份的理由。

global UTF-16LE auth 模块起始 `0x80f403c`；目录构造位于 `0x84cb54e`，生产文件选择位于 `0x84cc3e4`，codec 调用约 `0x84d2bbc`。

### 共享存储的并发规则

官方 1.1.74 使用基于目录的租约锁，而非 `flock`：

- 原子创建空目录 `.credential-transaction.lock`；
- mtime 心跳间隔 10 秒，陈旧阈值 120 秒；
- 检查锁的 mtime，失去锁时标记 compromised；
- 通过删除空目录释放锁；不能在目录内另放 owner 文件而破坏该协议。

官方凭据写入使用独占创建的唯一同目录临时文件、0600 权限、同步后 rename。目录权限为 0700。机器 ID 首次发布还处理并发创建、采用已存在身份和写前身份一致性检查。

相关位置：事务获取 `0x84ccf82`、原子写 `0x84cd5ba`；锁库 mkdir/mtime/rmdir 路径约 `0x7ff4801`，心跳一致性检查约 `0x7ff4b67`。

**隔离边界：这是官方兼容的 advisory lease，不是内核级 fencing。** 最后的 inode/mtime 检查与按路径 rmdir/rename 之间不是原子操作。两个进程同时恢复一个陈旧锁时，即使没有额外长暂停，也可能发生检查后路径已被另一获取者替换的竞态；检测到失去所有权会停止后续发布，但无法撤回已发出的刷新请求。不能通过再加一次 stat 就声称消除此类窗口。需要更强隔离时，应在独立 auth-dir 中重新登录建立独立会话，而不是复制同一份可轮换 refresh token 后并发使用。

## 4. 原生核心与最终发送请求必须分层验证

### 核心 WASM 的变化

1.1.74 与历史模块具有相同的 31 个函数导入和 34 个导出，包含一致的导出索引/签名。与 297238 字节历史模块相比，data、import、export、memory、global、table、element 段逐字节相同。

新代码包含三个 typed-select helper。静态内联这些 helper 后，`prepareInferRequest`、`prepareRequest`、`generate_runtime_auth_fields` 的导出函数体与历史模块一致；其他函数还存在局部变量变动。这个结果支持复用原生实现，**但不代替所有 codec/context 的动态差分验证**。

global auth WASM 的 Base64 在 `0x8faddf9`，长度 398144 字符；CN 对应位置为 `0x8fadeb9`。两者解码后哈希相同。

生产保持纯 Go；WASM 仅作为外部 oracle。`testdata/protocol/1.1.34/` 的六个冻结文件保持不变；`testdata/protocol/1.1.74/` 的七个文件使用新模块、合成输入与确定性 host transcript 独立 capture，并经 fresh-instance replay 核验。重复 capture 的七个文件逐字节一致。

新增 33 个 body/异常输入对照用例，两版 WASM 对这组输入的结果一致。原生实现保留七项既有的严格拒绝策略：六种不规范 body 编码（`ab`、`_$__`、`kwm`、包含 CR 或 LF 的 `$kwm`、`$d$_`）以及非 QMC 的模型缓存输入 `!!!!`。它们有各自具名测试，不是通用忽略差异；有效输入仍须 exact 匹配。不应将“有效输入兼容”扩大为“所有损坏输入的容错行为相同”。

### JS 的 runtime 输入新增了设备 token

另一个不能只通过核心算法比较发现的变化位于 `regenerateRuntimeFields`：

- 旧 1.1.12（ASCII `0x60edb7a`）依次序列化 `uid`、`organization_id`、`organization_tags`、`data_policy_agreed`。
- 1.1.74（UTF-16LE `0x8501d46`）在 `uid` 后新增 **`security_oauth_token`**，然后才是上述组织和 policy 字段。

新增字段是 runtime AES 的明文输入，最终封装在 `encrypt_user_info` 内，而不是推理 body/普通认证头中的裸设备 token。`getUserInfoForAuth`（global `0x84fe896`）和 `createWasmContext`（`0x8500fbc`）已进一步确认：传给 context 的对象仍只含 uid、encrypt_user_info、key、组织及 policy 字段，不额外传裸 token。

算法本身仍是对 raw UTF-8 JSON 加密；兼容修复应在 auth 语义输入层传入当前 token，不能为了保留旧的四字段输入而遗漏它。加载旧凭据时也不能仅因旧 `encrypt_user_info/key` 非空就永远复用；官方在加载本地凭据后会重新生成 runtime fields。本项目在内存中再生，加载本身不因这一升级而重写 user。

历史无 token 的核心向量仍是有效的低层算法测试，但不能单独证明应用层已经采用 1.1.74 的完整输入。另有 `auth_runtime_token_test.go` 中独立的合成 token-bearing exact vector：结果来自实际 1.1.74 WASM，经 fresh Python/wasmtime capture/replay、Go/wazero oracle 双 fresh instance，以及 native typed-input 精确对照验证；不改写历史向量或七文件冻结目录。fixtures 和测试日志不使用真实 token。

### JS 外层确实改变了请求头

普通用户的 legacy 推理路径调用外层 wrapper（global `0x85ac9e0`）：

1. 取得核心算法生成的请求；
2. 不区分大小写删除 `Cosy-MachineToken` 和 `Cosy-MachineType`；
3. 若 UMID 管理器返回真实 machineToken，则覆盖机器 token/type；否则不补回。

`za()`（`0x8588852`）在 machineToken 不可用时返回空对象，发送调用点在 `0x85bd442`。因此，无 UMID 分支中两头都缺失；它不会回退到 machine_id 和固定类型 `5`。其他原始头，包括 `Cosy-MachineId`，保留。

随后公共请求层（约 `0x851b9e2`）补充缺失的 `Cosy-Version`、`Cosy-ClientType`、`Cosy-MachineOS`，推理请求还可以携带安全规范化的 `Cosy-MachineHostname`。1.1.74 Linux x64 样本的 OS 标识为 `x86_64_linux`。遥测 trace 注入不是原生签名算法本身。

这解释了为什么“原生输出等于新 WASM 输出”仍不足以证明最终 HTTP 请求与 1.1.74 一致。应分别测试 raw-core 和发送层，不能为了新 wrapper 改写历史核心向量。

无 UMID 路径存在并能执行到发送，不等于已经验证所有地区服务端都接受该路径。

## 5. 模型缓存 v7

官方缓存路径变为 `.models/<identity>/catalog-v7`；共享缓存仍调用 `model_cache_decrypt`，模块中仍包含 QMC v1 标识。**文件名升级为 v7 不代表加密 envelope 同时升级为 v7。**

远程模型接口仍可见 `/api/v2/model/list?Encode=1`。本项目读取本地缓存与显式目录文件，不应把内置兜底列表描述为实时账号授权模型列表。

global 目录代码约 `0x85acf94`。官方条目规范化代码明确支持：

- `key` 或 `model_key`；
- `display_name` 或 `name`；
- `source` 缺失时为 `system`，`format` 缺失时为 `openai`；
- `enable` 缺失默认启用，显式 `false` 或数值 `0` 表示禁用；
- `context_config`、`thinking_config`、上下文窗口、价格和 feature-switch 元数据；
- 按 scene 解析，并合入适用的 `byok_enterprise` 项。

legacy 请求构造器 `wkt`（global `0x8767105`）不是把 `server_model` 原样转发：它选择 key、display_name、format、vision/reasoning、source、max_input_tokens 等生成 `model_config`，另外处理 custom model 与默认输出上限。因此，目录里出现新的 UI/计价字段，不代表必须把所有未知字段直接放进推理请求。完整 direct-provider/BYOK 执行不属于本项目的 1.1.74 适配范围。

适配器应优先读 v7，仅在 v7 不存在时尝试旧 v6；v7 损坏不能被无提示的旧缓存回退掩盖。现有 BYOK 分组兼容与 friendly ID/model map 行为应通过回归测试保留。

## 6. 1.1.74 兼容范围与验收边界

1.1.74 还有 HTTP/gRPC 等新 transport 选择器。`model_server_transport` 的内置 gate 默认关闭；关闭时仍保留本项目使用的 legacy HTTP/SSE 路径。本项目的 1.1.74 适配不实现整个官方 CLI 的传输选择、设备采集、遥测、工具执行或新 provider 系统。

验证分为三层：

1. **静态证据**：本文的样本、端点、client_id、目录、锁、wrapper 和缓存行为。
2. **离线验证**：合成凭据/时间/熵 transcript、原生与两版外置 oracle、fake HTTP/临时目录和公共 API 回归。
3. **真实服务验证**：需要明确授权的设备登录、token 刷新及可能计费的推理；未执行时不得宣称已通过。

## 公开参考

- [国内 CLI 认证](https://docs.qoder.cn/cli/authentication)
- [海外 CLI 认证](https://docs.qoder.com/cli/authentication)
- [国内 CLI 发布记录](https://docs.qoder.cn/product-overview/qoder-cn-cli)：1.1.74 发布于 2026-10-19。
- [CN 1.1.74 固定版本 manifest](https://static.qoder.com.cn/qoder-cli-cn/channels/1.1.74/manifest.json)
- [CN Linux x64 发行包](https://static.qoder.com.cn/qoder-cli-cn/releases/1.1.74/qoderclicn-linux-x64.tar.gz)

当前网页文档并非版本锁定资料；涉及 1.1.74 的结论以对应样本的静态调用链和离线验证为准。
