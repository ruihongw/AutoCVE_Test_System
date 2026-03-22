# CVE 补丁自动化验证系统

基于黑白盒结合的智能分流机制，对 AI 适配的 CVE 漏洞补丁进行自动化验证。

## 功能特性

- **智能分流调度**: 根据 PoC 可用性、攻击向量、触发复杂度和补丁规模自动选择验证路径
- **代码检视引擎**: 三阶段深度分析 — 结构化解析、逻辑合理性评估、衍生风险排查
- **动态测试引擎**: 在隔离沙箱中进行漏洞触发验证和基础功能回归
- **环境隔离管理**: Strategy 模式支持多种沙箱后端（容器/虚拟机/chroot）
- **综合报告生成**: Markdown 格式的详细验证报告

## 快速开始

```bash
# 基础用法
python -m cve_verifier.main --patch fix.diff --meta cve.json

# 完整用法
python -m cve_verifier.main \
    --patch fix.diff \
    --meta cve.json \
    --poc poc.sh \
    --package fixed_pkg.rpm \
    -o report.md \
    -v
```

## 输入规范

| 输入 | 格式 | 必需 |
|------|------|------|
| 补丁文件 | unified diff | ✅ |
| CVE 元数据 | JSON | ✅ |
| 修复后软件包 | RPM/DEB/源码包 | ❌ |
| PoC 脚本 | 可执行脚本 | ❌ |

### CVE 元数据 JSON 示例

```json
{
    "cve_id": "CVE-2024-50021",
    "description": "use-after-free in network driver",
    "severity": "high",
    "cvss_score": 7.8,
    "attack_vector": "local",
    "affected_component": "linux-kernel",
    "cwe_id": "CWE-416"
}
```

## 验证路径

系统根据 CVE 特征自动选择验证路径:

| 路径 | 触发条件 | 验证内容 |
|------|----------|----------|
| 🔬 仅动态测试 | PoC 可用 + 易触发 + 补丁简洁 | 沙箱漏洞触发 + 基础回归 |
| 📝 仅代码检视 | 无 PoC + 难触发 | 补丁逻辑分析 + 衍生风险排查 |
| 🔄 双路径结合 | 其他情况 | 动态 + 检视 |

## 运行测试

```bash
python -m pytest tests/ -v
```

## 项目结构

```
cve_verifier/
├── main.py                  # 流水线入口
├── models.py                # 数据模型
├── task_parser.py           # 输入解析
├── smart_router.py          # 智能分流调度器
├── code_review_engine.py    # 代码检视引擎
├── dynamic_test_engine.py   # 动态测试引擎
├── environment_manager.py   # 环境隔离管理
├── regression_runner.py     # 基础回归执行器
└── report_generator.py      # 报告生成器
```
