# Vela 贡献指南

## 提交信息（Conventional Commits）

```
<type>(<scope>): <subject>

<body 可选：说明为什么，而不是做了什么>
```

type 取值：

- `feat`：新能力（如 `feat(runtime): add fstat translation`）
- `fix`：缺陷修复
- `chore`：构建/工具链/杂项
- `docs`：仅文档
- `test`：仅测试
- `refactor`：不改变行为的重构

规则：

- subject 用英文祈使句、不加句号、≤72 字符
- 代码标识符全英文；正文可中可英
- 每个提交必须 `cargo test --workspace` 通过

## 代码规则

- **runtime 及以上禁止 `cfg(target_os)` 与宿主类型**——宿主差异一律走 `vela-sys::Host`
- 所有公开错误用手写 enum 或 `thiserror`，library 路径禁止 `unwrap`（CLI 可 `exit`）
- 每个 `unsafe` 块写一行 SAFETY 注释，说明不变量
- 客户地址用 `GuestAddr` 语义对待，不与宿主指针混用
- 零第三方依赖是 v0 的硬约束；新增依赖需先开 issue 讨论
- v0 全同步，禁止 tokio/async

## PR 流程

1. fork + 分支（`feat/xxx`、`fix/xxx`）
2. 确保 `cargo build` 与 `cargo test --workspace` 通过
3. 涉及 Windows 特有路径（VEH、内存保护）必须在 Windows 上验证
4. 无 Windows 环境也能贡献：vela-abi、ELF 解析器、单元测试
