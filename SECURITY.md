# Security Policy / 安全策略

## Supported versions / 支持版本

| Version | Supported |
|---|---|
| 0.0.x | ✅ |

## Reporting a vulnerability / 报告漏洞

**请勿通过公开 issue 报告安全漏洞。**

请使用 GitHub 的 [Private vulnerability reporting](https://github.com/spadaos/vela/security/advisories/new)
提交私密报告，或在 issue 中申请进一步联系方式。我们会在 72 小时内确认。

报告时请包含：受影响版本、复现步骤、影响评估、（如有）修复建议。

## Scope / 范围

Vela **明确不是安全沙箱**——客户代码与 `vela.exe` 同进程同权限。以下情况
**不属于**漏洞：

- 客户程序可以读写宿主进程内存、执行任意宿主代码
- 客户程序可以访问当前用户能访问的一切资源
- guest 加载了恶意 ELF 导致的任何后果

以下属于漏洞：

- Vela 在**未运行任何 guest** 时崩溃或越权访问
- `vela` CLI 的参数处理（加载前路径）导致的越权
- Host trait 实现将宿主资源意外暴露给预期的 guest 语义之外
