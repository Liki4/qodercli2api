# qodercli v1.1.5 OAuth 机制逆向分析

> 来源：`qodercli-1.1.5`（Bun 1.3.14 单文件可执行程序，内嵌 minified JS bundle，已提取至 `re/extracted/bundle.js`）。
> 关键结论：qodercli 的"OAuth"是**自定义设备授权流（Device Authorization Grant 变体 + PKCE 风格 challenge/verifier）**，不是标准 OAuth 授权码流程。

## 1. 登录方式总览

`AuthManager` 支持 5 种登录方式（`login_method` 字段）：

| 方式 | 入口函数 | refreshStrategy |
|---|---|---|
| 浏览器设备流（OAuth） | `loginWithDeviceFlow()` | `device-token` |
| Personal Access Token | `loginWithPAT()` | `pat` |
| Job Token（SDK/宿主注入） | `initAuth({jobToken})` | `job_token` / `host-job-token` |
| Access Token（SDK 注入） | `initFromAccessToken()` | `none` |
| 本地存储恢复 | `initAuth()` → `initAuth:local-storage` | 随原登录方式 |

环境变量 `QODER_PERSONAL_ACCESS_TOKEN` 可提供 PAT。

## 2. 设备授权流（核心）

入口：`startDeviceFlow(apiBase, webBase, isProd)`。

### 2.1 参数生成（PKCE 风格）

```js
verifier  = 43~128 个随机字符（字符集 A-Z a-z 0-9 -._~，randomBytes 逐字节 %66）
challenge = base64url_nopad( SHA256(verifier) )   // 与 RFC7636 S256 一致
nonce     = randomUUID()
machineId = await getMachineId()                  // 36 字符 UUID，见 §6
```

### 2.2 授权 URL（用户浏览器打开）

```
GET {webBase}/device/selectAccounts
    ?challenge={challenge}
    &challenge_method=S256
    &nonce={nonce}
    &machine_id={machineId}
    &client_id={clientId}
```

- `webBase`（prod）：`https://qoder.com`（`D0A.prod.base`，记作 AEA；test 环境为 `https://test.qoder.ai`）
- **client_id**：
  - prod：`e883ade2-e6e3-4d6d-adf7-f92ceff5fdcb`
  - 非 prod：`e93fe488-5778-4c35-a6fc-0f54ed7b3139`
- 无 scope、无 redirect_uri（轮询模式不需要回调）

### 2.3 轮询换 token

```
GET {apiBase}/api/v1/deviceToken/poll?nonce={nonce}&verifier={verifier}&challenge_method=S256
Accept: application/json
```

- `apiBase`（prod）：`https://openapi.qoder.sh`
- 用户未完成授权 → `404`，每 **1000ms** 重试，总超时 **300s（5 分钟）**
- 网络/代理错误（ECONNREFUSED/ECONNRESET 指向代理）连续 3 次 → 抛错
- 成功返回 JSON：

```json
{
  "token": "...",                    // 设备 token（后续一切的凭证）
  "refresh_token": "...",
  "expires_at": "ISO8601",           // 或 expires_in（秒）
  "refresh_token_expires_at": "...", // 或 refresh_token_expires_in
  "user_id": "...",
  "user_name": "..."
}
```

### 2.4 登录后处理

`buildUserInfoFromDeviceToken()` 映射为内部 UserInfo：

```js
{
  uid: user_id, name: user_name,
  security_oauth_token: token, access_token: token,
  refresh_token, expire_time: unix秒, refresh_token_expire_time: unix秒,
  login_method: "browser", login_timestamp, encrypt_user_info: "", key: ""
}
```

随后：
1. `fetchAuthStatus(uid)` → `GET /api/v1/userinfo`（Bearer 认证）补全邮箱/组织信息；`fetchOrganizationTags(orgId)` 补组织标签
2. `fetchAndApplyDataPolicy()` → `GET /api/v2/config/getDataPolicy?requestId=...&version=2`
3. `saveCredentialStore()` 落盘（见 §5）
4. `startRefreshTimer()` 后台每 **30 分钟**检查刷新

## 3. PAT 登录

```
POST {openapi}/api/v1/jobToken/exchange
Content-Type: application/json
{"personal_token": "<PAT>"}
```

响应取 `token`/`device_token`/`access_token`（按此优先级）+ `expires_at` + `refresh_token` 等，之后与设备流相同（拉 userinfo、落盘）。

## 4. Token 刷新

- **过期判断**：`expire_time - 3600 < now`（提前 1 小时视为过期）；`isTokenReallyExpired()` 为 `now > expire_time`
- **触发**：每次用 token 前 `refreshTokenIfNeeded()`；后台定时器每 30 分钟检查
- **device-token 刷新**：

```
POST {openapi}/api/v1/deviceToken/refresh
Content-Type: application/json
{"refresh_token": "..."}
```

响应 `{device_token, refresh_token, expires_at}` → 更新 `security_oauth_token=device_token` 并重新落盘。

- **jobToken 刷新**：`POST /api/v1/jobToken/refresh`（SDK 场景，本文从略）

## 5. 凭证本地存储

| 项 | 值 |
|---|---|
| 路径 | `~/.qoder/.auth/user`（mode 0600；多 profile 时为 `user.{name}`） |
| 明文 | UserInfo 的 JSON 序列化 |
| 加密 | WASM 导出函数 `credential_storage_encrypt(json, key)` |
| 密钥 | `getMachineId()` 的前 **16** 个字符 |
| machine_id | 存于 `~/.qoder/.auth/machine_id`（36 字符 UUID，无换行） |

其他相关文件：`~/.qoder/.auth/dynamic-texts.json`、`dynamic-error-codes.json`（远端下发的文案，非敏感）。

## 6. 端点解析（v0(name)）

环境由 `QODER_ENV`（旧名 `QODER_ENV_ALIAS`）控制，格式 `{env}[-{region}]`：

| env | inference | center | openapi | base |
|---|---|---|---|---|
| prod | `https://api2.qoder.sh`（sg 默认；us→`api1.qoder.sh`，jp→`api3.qoder.sh`） | `https://center.qoder.sh` | `https://openapi.qoder.sh` | `https://qoder.com` |
| test | `https://test-api2.qoder.sh` | `https://test-center.qoder.sh` | `https://test-openapi.qoder.sh` | `https://test.qoder.ai` |
| daily | （内网 IP 主机） | `https://daily-center.qoder.sh` | `https://daily-openapi.qoder.sh` | `https://daily.qoder.ai` |

覆盖机制：
- CN 区域可用环境变量（`ZVA`，名称待确认，疑似 `QODER_CN_SERVER_ENDPOINT`）强制指定单一端点
- VPC 模式（`QODER_VPC_INSTANCE` 类配置）走 `vpc` 路由
- 运行时还会通过 `GET /api/v3|v4/service/region/endpoints`（签名请求）做端点选举/故障转移，配合 HTTPDNS（WASM `get_httpdns_account_id`）

## 7. 凭证携带方式

- OpenAPI 请求：`Authorization: Bearer {security_oauth_token ?? access_token}`，`User-Agent: qoder/{version}`
- 模型推理（model-server）：先 `refreshTokenIfNeeded()`，再取同一 Bearer token；**请求还需经 WASM `prepareRequest(endpoint, path, method, "auth"|"sign", body, headers)` 处理**——它在 WASM 内部生成完整 URL 并注入签名/加密切头（详见 `docs/inference-protocol.md`）
- 遥测：同样带 `Authorization: Bearer ...`

## 8. 错误与失效

- 轮询 5 分钟超时、代理不可达（3 次）为硬错误
- 401 会触发一次 auth 重试（先刷新 token 再重放）；`isAuthInvalidationError()` 判定后清空凭证并要求重新 `qodercli login`
- SDK 只读模式（`storagePolicy=readOnly`）不刷新、不落盘

## 9. 对中转程序的含义

1. **最简接入**：复用用户已登录的 `~/.qoder/.auth/user`——需要实现 `credential_storage_encrypt/decrypt`（WASM 函数，需从二进制提取 WASM 模块分析算法）→ 见阶段二
2. **自实现设备流**：完全可行且无需逆向加密——按 §2 生成 verifier/challenge/nonce，引导用户开浏览器授权，轮询拿 `{token, refresh_token}`，自己以 JSON 存储即可
3. 推理调用除 Bearer 外可能还有 WASM 签名头，必须继续阶段二确认 `prepareRequest` 注入了什么
