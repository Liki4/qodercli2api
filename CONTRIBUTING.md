# 贡献指南

欢迎提交文档修正、合成测试、兼容性修复和小范围功能改进。使用方式见 [README](README.md)，架构与协议验证见 [开发指南](docs/development.md)。
安全问题请使用 [私密漏洞报告渠道](SECURITY.md)，不要先开公开 issue。

## 本地准备

- 安装 **Go 1.25+**。根模块仅使用标准库，无需官方 CLI、账号或 WASM。
- 根目录的空 `go.sum` 必须保留；不要为清理文件而删除它。
- `tools/wasm_oracle` 是独立 Go 模块，依赖和测试与根模块分开；首次检查需要下载标准 Go 模块依赖，不需要 Qoder 账号或外置 WASM。
- 需要构建时使用 `go build -o ./bin/qodercli2api .`（先创建 `bin/`），不要覆盖根目录的现有可执行文件。

默认检查从仓库根目录运行，允许按本机 Go 配置下载模块依赖，但不访问 Qoder 账号：

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

`mod download` 会按 Go 配置访问模块代理/校验服务，它不是 Qoder 账号调用，也不下载认证 WASM。
如需**严格离线检查**，先在允许联网的环境中执行上述下载命令、准备好依赖缓存，再设置 `GOPROXY=off` 运行测试；缺缓存时离线模式会失败，不应通过开启真实 E2E 来解决。

race 检查需要受支持的平台/工具链。外置 oracle 的 opt-in 环境变量应保持未设置；Python 自检不需要第三方包。
真实 E2E 不是贡献前提；它需要账号持有人单独明确授权，并可能计费和改写凭据，详见 [授权 E2E](docs/development.md#authorized-e2e)。

## Issue 与 PR

1. 描述可观察的问题、预期行为、相关协议版本和最小复现；只使用合成输入或已人工脱敏的信息。
2. 一个 PR 聚焦一个问题，避免混入无关重构、生成产物或大规模格式变化；行为变化附回归测试，用户配置变化同步更新文档。
3. 提交前格式化修改的 Go 文件，并运行与改动有关的检查。PR 中说明执行了哪些命令、结果及未运行的项目，不将跳过的测试写成通过。
4. 保留历史冻结向量的字节、版本和 manifest 身份；升级协议时新增独立版本目录和来源证据，不能改写旧向量来“修复”测试。

## 数据与授权边界

- 测试和 fixture 仅使用**合成数据**；不要提交真实账号、token、PAT、API key、环境文件、私有模型缓存、请求/响应或抓包。
- 不提交 Qoder CLI、认证 WASM、完整 JS bundle、原生 addon 或其他专有二进制/提取物。
- 可选 oracle 只能读取操作者有权持有和执行的外部 pinned 模块；遵循 [工具说明](tools/README.md) 与 [NOTICE](NOTICE)，不要把它嵌入生产构建。
- 避免在 issue 中粘贴完整日志；错误、路径、工具参数和模型输出也可能泄露私有信息。

贡献将按仓库的 [AGPL-3.0 许可证](LICENSE) 发布。提交前请确认你有权贡献相关代码和材料。
