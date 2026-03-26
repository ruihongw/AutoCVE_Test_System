---
description: 启动多 Agent 团队对项目 skill 进行多轮循环迭代优化，直至无可优化项
---

# 多 Agent 协同 Skill 优化工作流

本工作流模拟一个由 5 名专家组成的虚拟 Agent 团队，对 `skill/cve-patch-verifier/` 及其在 `project/` 中的实现进行多轮深度审查与优化。每轮审查由全部角色依次执行，产出优化建议并落地实施，循环往复直到所有角色均判定"无进一步优化空间"。

---

## Agent 角色定义

在每轮迭代中你需要依次扮演以下 5 个角色，**严格按角色视角给出审查意见**：

### 🎯 项目经理 (PM)
**关注维度**：
- 整体项目目标与当前实现的差距
- SKILL.md / README.md / AGENTS.md 等文档的完整性、准确性和一致性
- 功能覆盖度：是否有承诺了但未实现的功能？
- 错误处理与边界情况的覆盖率
- 模块间接口契约是否清晰
- 配置管理和环境变量文档化

### 🏗️ 架构师 (Architect)
**关注维度**：
- 代码架构合理性：模块职责划分、耦合度、扩展点
- 设计模式使用是否恰当（Strategy、Pipeline 等）
- 数据模型设计：dataclass 字段命名、类型标注、可选 vs 必选
- 依赖关系清晰度、循环依赖检测
- 性能瓶颈与可伸缩性
- 代码复用与 DRY 原则
- 异常层次体系与错误传播策略
- Python 最佳实践 (typing, docstring, logging)

### 🧪 测试工程师 (Tester)
**关注维度**：
- 单元测试覆盖率：哪些模块/函数缺少测试？
- 测试质量：断言是否充分？是否覆盖了边界条件？
- 集成测试：端到端流水线是否可自动化测试？
- Mock 策略：外部依赖（LLM API、文件系统、沙箱）是否正确 mock？
- 测试数据管理：fixture 是否合理？
- 回归测试：已知 bug 是否有对应测试？
- 测试可维护性：测试代码是否易读、易扩展？

### 🎨 用户体验工程师 (UX Engineer)
**关注维度**：
- CLI 用户体验：参数命名、帮助文本、错误提示是否友好
- 报告输出质量：Markdown 格式、可读性、信息架构
- SKILL.md 的可用性：新用户能否快速上手？
- 日志信息的有用性和可读性
- 进度反馈：长时间操作是否有足够的状态指示？
- 输出 JSON 结构的易用性
- 文档中的示例是否可直接运行？

### 🔧 Harness 工程专家 (Harness Engineer)
**关注维度**（基于 [OpenAI Harness Engineering](https://openai.com/index/harness-engineering/) 方法论）：
- **导航 Map 质量**：`AGENTS.md` / `CLAUDE.md` 是否为轻量级导航而非臃肿手册？是否正确指向 `docs/` 下专题文档？
- **知识层完整性**：`docs/` 下的 `ARCHITECTURE.md`、`PRODUCT_SENSE.md`、`QUALITY_SCORE.md`、`RELIABILITY.md` 是否与代码保持同步？
- **Agent 可读性**：数据结构、日志、输出是否结构化（JSON/JSONL），便于 Agent 解析和趋势分析？
- **验证历史追踪**：`verification_history.jsonl` 的 schema 是否完备？`cve_verify.py` 是否正确输出结构化记录？
- **深度优先可验证性**：每个变更是否可被独立验证？是否有清晰的 Design → Code → Review → Test 分段？
- **知识漂移检测**：文档中的数据（测试数量、模块列表、版本号等）是否与代码实际状态一致？
- **向后兼容别名**：重命名操作是否保留了向后兼容别名？

---

## 执行流程

### 准备阶段

1. **阅读全部源码**：依次阅读以下核心文件，构建对项目的全局理解：
   - `skill/cve-patch-verifier/SKILL.md` — Skill 使用说明
   - `skill/cve-patch-verifier/README.md` — Skill 自述
   - `skill/cve-patch-verifier/AGENTS.md` — Agent 导航 Map
   - `skill/cve-patch-verifier/docs/` — Harness Engineering 知识层（ARCHITECTURE / PRODUCT_SENSE / QUALITY_SCORE / RELIABILITY / VERIFICATION_HISTORY_SCHEMA）
   - `project/README.md` — 项目自述
   - `project/cve_verifier/models.py` — 数据模型
   - `project/cve_verifier/main.py` — 流水线入口
   - `project/cve_verifier/smart_router.py` — 智能分流
   - `project/cve_verifier/code_review/` — 代码检视子模块
   - `project/cve_verifier/dynamic_test_engine.py` — 动态测试引擎
   - `project/cve_verifier/environment_manager.py` — 沙箱环境管理
   - `project/cve_verifier/regression_runner.py` — 回归测试执行器
   - `project/cve_verifier/report_generator.py` — 报告生成器
   - `project/cve_verifier/llm_analyzer.py` — LLM 分析器
   - `project/cve_verifier/task_parser.py` — 任务解析器
   - `project/cve_verifier/exceptions.py` — 异常定义
   - `skill/cve-patch-verifier/scripts/cve_verify.py` — CLI 入口脚本
   - `skill/cve-patch-verifier/cve_verifier/` — Skill 内源码（与 project 对齐）

2. **阅读全部测试**：
   - `project/tests/test_code_review_engine.py`
   - `project/tests/test_smart_router.py`
   - `project/tests/test_task_parser.py`
   - `project/tests/test_report_generator.py`
   - `project/tests/test_dynamic_test_engine.py`
   - `project/tests/test_regression_runner.py`
   - `skill/cve-patch-verifier/tests/` 下的所有测试

3. **运行现有测试**，记录基线结果：
// turbo
```bash
cd c:\Users\Wrh\Desktop\CVE_test\project && python -m pytest tests/ -v --tb=short 2>&1
```

4. **创建优化跟踪文件** `project/optimization_log.md`，记录每一轮的发现与改进。

---

### 迭代循环（核心）

每轮迭代包括以下步骤，**循环执行直到所有角色均报告"无优化建议"**：

#### Step 1: 五角色审查

依次以每个角色的身份进行审查，输出结构化建议：

**审查输出格式**（每个角色）：
```markdown
## 🎯/🏗️/🧪/🎨/🔧 [角色名] — 第 N 轮审查

### 发现的问题
1. [严重程度: 高/中/低] 问题描述
   - 影响范围: ...
   - 建议修复: ...

2. ...

### 优化建议
1. [优先级: P0/P1/P2] 建议描述
   - 预期收益: ...
   - 实施难度: 低/中/高

### 结论
- [ ] 仍有优化空间 / [x] 已无可优化项
```

#### Step 2: 汇总与优先级排序

将五个角色的所有建议合并，按以下规则排序：
1. **P0 - 必须修复**：功能缺陷、安全风险、文档与代码不一致
2. **P1 - 强烈建议**：架构改进、测试覆盖、用户体验提升
3. **P2 - 可选优化**：代码风格、命名优化、锦上添花

#### Step 3: 实施优化

按优先级依次实施优化。对每项改动：
1. 修改代码或文档
2. 如涉及代码变更，运行测试确保不破坏现有功能：
// turbo
```bash
cd c:\Users\Wrh\Desktop\CVE_test\project && python -m pytest tests/ -v --tb=short 2>&1
```
3. 将改动和验证结果记录到 `project/optimization_log.md`

#### Step 4: 循环判定

检查本轮所有角色的结论：
- **任一角色标记"仍有优化空间"** → 进入下一轮迭代（回到 Step 1）
- **全部角色标记"已无可优化项"** → 退出循环，进入总结阶段

---

### 总结阶段

循环结束后：

1. **生成优化总结报告** `project/optimization_summary.md`，包括：
   - 总迭代轮次
   - 每轮的关键改进摘要
   - 各角色的最终评估
   - 优化前后的对比（测试覆盖率、代码质量指标等）

2. **最终验证**：运行全部测试确保一切通过：
// turbo
```bash
cd c:\Users\Wrh\Desktop\CVE_test\project && python -m pytest tests/ -v --tb=short 2>&1
```

3. **同步 Skill 目录**：确保 `skill/cve-patch-verifier/` 中的代码与 `project/` 保持一致。对比两边的文件差异，将优化同步到 skill 目录。

4. **通知用户** 审查优化总结报告。

---

## 约束与注意事项

- **每轮迭代必须五个角色全部审查**，不可跳过
- **角色之间不可互相影响**：每个角色只按自己的维度审查
- **改动必须测试验证**：所有代码修改后必须运行测试
- **保持向后兼容**：不能破坏现有 CLI 接口和输入/输出格式
- **记录一切**：每一项改动都要在 `optimization_log.md` 中有据可查
- **最大迭代轮次**：硬性上限 5 轮。如果 5 轮后仍有建议，记录为"遗留项"
- **Skill 与 Project 同步**：所有改动必须同时反映在 `skill/` 和 `project/` 两个目录中
