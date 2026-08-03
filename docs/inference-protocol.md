# qodercli v1.1.5 模型推理协议逆向分析

> 来源：`qodercli-1.1.5` 内嵌 JS bundle + `qoder_auth_wasm_bg.wasm`（已提取：`re/extracted/wasm_0.wasm`）。
> 所有结论均通过 `re/wasm_harness.py`（wasmtime 驱动真实 WASM）+ **对生产服务器的真实请求验证**。

## 1. 端点

```
POST {inference_endpoint}/algo/api/v2/service/pro/sse/agent_chat_generation
    ?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1
```

- prod inference endpoint：`https://api2.qoder.sh`（us→`api1.qoder.sh`，jp→`api3.qoder.sh`，见 oauth.md §6）
- URL 由 WASM `qodercontext_prepareInferRequest` 生成，query 参数固定（AgentId 来自请求体 agent_id）

## 2. 请求构造（WASM prepareInferRequest）

签名：`prepareInferRequest(endpoint, bodyJson, modelKey, modelSource)` → `{url, headers(Map×22), body(加密)}`

### 2.1 请求头（22 个，实测值）

| Header | 值 | 说明 |
|---|---|---|
| `Accept` | `text/event-stream` | |
| `Authorization` | `Bearer COSY.<base64(json)>.<32hex签名>` | **非裸 token**，见 §2.2 |
| `Cache-Control` | `no-cache` | |
| `Connection` | `keep-alive` | |
| `Content-Type` | `application/json` | |
| `Cosy-Business-Product` | `cli` | |
| `Cosy-Business-Type` | `agent` | |
| `Cosy-ClientType` | `5` | |
| `Cosy-Data-Policy` | `agree`/`disagree` | 来自 userInfo.data_policy_agreed |
| `Cosy-Date` | unix 秒 | 每次请求生成 |
| `Cosy-Key` | userInfo.key | 运行时生成的密钥（登录时 `generate_runtime_auth_fields`） |
| `Cosy-MachineId` | machine_id（36 字符 UUID） | `~/.qoder/.auth/machine_id` |
| `Cosy-MachineToken` | 同 MachineId | |
| `Cosy-MachineType` | `5` | |
| `Cosy-Organization-Id` | org uuid | |
| `Cosy-Organization-Tags` | 逗号分隔 | |
| `Cosy-Scene` | `assistant` | |
| `Cosy-User` | uid | |
| `Cosy-Version` | `1.1.5`（客户端版本） | |
| `Login-Version` | `v2` | |
| `X-Model-Key` | 模型 key（如 `auto`） | prepareInferRequest 第 3 参 |
| `X-Model-Source` | `system`/`custom` | prepareInferRequest 第 4 参 |

### 2.2 Authorization COSY token

```
Bearer COSY.{base64(JSON)}.{32hex}
```

base64 内 JSON：
```json
{
  "version": "v1",
  "requestId": "<每次请求新 UUID>",
  "info": "<userInfo.encrypt_user_info>",
  "cosyVersion": "1.1.5",
  "ideVersion": ""
}
```
末尾 32hex 为 WASM 计算的签名（密钥派生自 userInfo.key + machine 上下文，算法在 WASM 内）。

**注意**：设备 token（`dt-...`）不直接出现在推理请求中；服务器通过 `info`+`Cosy-Key` 完成认证。

### 2.3 请求体（RemoteChatAsk → 加密）

明文 JSON（构造自 agent 层）：

```json
{
  "request_id": "<uuid>",            // 全局唯一！重复返回 403 code 103 "Duplicate request"
  "request_set_id": "<uuid>",
  "chat_record_id": "<uuid>",
  "session_id": "<会话 id>",
  "stream": true,
  "chat_task": "FREE_INPUT",
  "chat_context": {},
  "is_reply": true,
  "is_retry": false,
  "source": 1,
  "version": "3",
  "agent_id": "agent_common",
  "task_id": "common",
  "session_type": "qodercli",
  "aliyun_user_type": "",
  "model_config": { ...目录中的模型对象... },
  "custom_model": null,
  "system": "<system prompt>",
  "messages": [ ...OpenAI 格式消息... ],
  "tools": [ ...OpenAI 格式 function 工具... ],
  "parameters": {"max_tokens": 1024, "reasoning_effort": "high"?, "context_length"?, "tool_choice"?}
}
```

该 JSON 经 WASM 加密为自定义编码字符串（`Encode=1`），即最终 POST body。**必须在每次请求时调用 WASM 生成，无法离线预计算。**

## 3. 响应协议（SSE）

Content-Type: text/event-stream。两种帧：

### 3.1 数据帧（外层信封）

```
data:{"headers":{"Content-Type":["application/json"]},"body":"<内层JSON字符串>","statusCodeValue":200,"statusCode":"OK"}
```

- `body` 是**字符串化的 OpenAI `chat.completion.chunk` JSON**（需二次解析）
- 错误帧：body 为 `{"code":"103","message":"Duplicate request"}`，statusCodeValue 403

### 3.2 内层 chunk 格式（OpenAI 标准扩展）

```json
{
  "id": "<request_id>", "object": "chat.completion.chunk", "created": 1785002833,
  "model": "auto", "system_fingerprint": "fpv0_ab14226c",
  "choices": [{"index": 0, "delta": {...}, "finish_reason": null}],
  "usage": {...}   // 仅最后一帧
}
```

delta 字段：
- `{"role":"assistant"}` — 首帧
- `{"content":"..."}` — 文本增量
- `{"reasoning_content":"..."}` — 思考增量（即使 model_config.is_reasoning=false 也可能出现）
- `{"tool_calls":[{"id":"toolu_bdrk_...","index":0,"type":"function","function":{"name":"get_weather","arguments":""}}]}` — 首帧带 id+name，后续帧仅流式 `arguments` 片段

结束：
- 最后数据帧：`choices[0].finish_reason` ∈ `stop`/`tool_calls`/`length` + 完整 `usage`：
  ```json
  {"completion_tokens":66,"completion_tokens_details":{"reasoning_tokens":0},
   "prompt_tokens":578,"prompt_tokens_details":{"cacheable_tokens":0,"cached_tokens":0},
   "total_tokens":644}
  ```
- 随后 `event:finish` + `data:{"firstTokenDuration":1811,"totalDuration":2487,"serverDuration":52}`，连接结束
- **没有 `data:[DONE]`**

## 4. 模型目录（`~/.qoder/.models/{uid}/catalog-v6`，model_cache_decrypt(uid) 解密）

| key | 名称 | reasoning | 视觉 | max_input |
|---|---|---|---|---|
| auto | Auto（默认） | - | ✓ | 180k |
| ultimate | Ultimate | ✓ | ✓ | 1M |
| performance | Performance | - | ✓ | 1M |
| efficient | Efficient | - | ✓ | 180k |
| lite | Lite | - | ✗ | 180k |
| cmodel | Cantus | ✓ | ✓ | 180k |
| qmodel_38max | Qwen3.8-Max | ✓ | ✓ | 180k |
| qmodel_latest | Qwen3.7-Max | - | ✓ | 1M |
| qmodel | Qwen3.7-Plus | - | ✓ | 1M |
| kmodel_latest | Kimi-K3 | - | ✓ | 180k |
| kmodel | Kimi-K2.7-Code | - | ✓ | 256k |
| gm51model | GLM-5.2 | ✓ | ✓ | 1M |
| dmodel | DeepSeek-V4-Pro | ✓ | ✓ | 1M |
| dfmodel | DeepSeek-V4-Flash | ✓ | ✓ | 1M |
| mmodel | MiniMax-M3 | - | ✓ | 1M |

目录由 `GET /algo/api/v2/model/catalog`（或类似，WASM 签名请求）定期刷新；`format` 均为 `openai`。

## 5. 错误与约束

| 现象 | 说明 |
|---|---|
| 403 + `{"code":"103","message":"Duplicate request"}` | request_id 重复，必须每次新 UUID |
| 401 | token 过期 → 先走 deviceToken/refresh |
| 429 / 5xx | 客户端按 r5() 规则重试（408/429/5xx 可重试） |
| 排队 | 特定状态表示请求排队（VI 带 retryAfterMs） |

## 6. 对中转程序的设计含义

1. **必须嵌入 WASM**（wazero）：`prepareInferRequest` 的加密 body 与 COSY 签名无法绕开
2. 请求路径固定加密体；响应是**明文 SSE**（信封 + OpenAI chunk），解析无需 WASM
3. Anthropic ↔ 上游映射要点：
   - `model` → model_config.key（映射表可配置；拿整目录对象填 model_config）
   - `thinking/effort` → `parameters.reasoning_effort`；`reasoning_content` delta → Anthropic `thinking` block
   - `max_tokens` → `parameters.max_tokens`
   - `system` → 顶层 `system` 字段；`messages`/`tools` OpenAI 格式转换（tool_result → role:tool 消息）
   - usage：`prompt_tokens`→`input_tokens`，`completion_tokens`→`output_tokens`
   - 非流式：代理聚合 SSE 后合成完整 Anthropic response
