# CVE 补丁自动化验证系统

基于黑白盒结合的智能分流机制，对 AI 适配的 CVE 漏洞补丁进行自动化验证。

## 功能特性

- **智能分流调度**: 根据 PoC 可用性、攻击向量、触发复杂度和补丁规模自动选择验证路径
- **代码检视引擎**: 组合模式四阶段深度分析 — 关联性、修复模式、逻辑合理性、衍生风险
- **动态测试引擎**: 在隔离沙箱中进行漏洞触发验证和基础功能回归
- **环境隔离管理**: Strategy 模式支持多种沙箱后端（容器/虚拟机/chroot）
- **LLM 深度分析**: OpenAI-compatible API 增强分析（可选，优雅降级）
- **综合报告生成**: Markdown 格式的详细验证报告 + AI 占位符
- **验证历史追踪**: JSONL 结构化输出，供趋势分析

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
├── models.py                # 数据模型 (17 dataclass + 7 Enum)
├── task_parser.py           # 输入解析
├── smart_router.py          # 智能分流调度器
├── code_review/             # 代码检视引擎 (组合模式)
│   ├── engine.py            # 编排入口
│   ├── relevance.py         # 关联性分析
│   ├── fix_pattern.py       # 修复模式识别
│   ├── logic_checker.py     # 逻辑合理性评估
│   ├── risk_assessor.py     # 衍生风险检测
│   └── ai_reviewer.py       # LLM 深度分析 (可选)
├── dynamic_test_engine.py   # 动态测试引擎
├── environment_manager.py   # 环境隔离管理
├── regression_runner.py     # 基础回归执行器
├── llm_analyzer.py          # LLM API 交互
├── report_generator.py      # 报告生成器
└── exceptions.py            # 异常层次结构
tests/
├── conftest.py              # pytest 配置
├── test_code_review_engine.py
├── test_smart_router.py
├── test_task_parser.py
├── test_report_generator.py
├── test_dynamic_test_engine.py
└── test_regression_runner.py    # 78 个测试，0 warnings
```
