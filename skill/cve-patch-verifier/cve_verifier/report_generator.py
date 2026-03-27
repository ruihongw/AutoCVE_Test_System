"""
报告生成器 (Report Generator)

汇聚所有验证模块的输出，生成结构化的 Markdown 综合评估报告。
报告包含:
  - 验证路径说明
  - 代码检视结论
  - 动态测试结果
  - 衍生风险评估
  - 综合结论与建议
"""

import logging
from datetime import datetime
from typing import Optional, Dict, List, Any

from .models import (
    VerificationReport, VerificationRoute, RoutingDecision,
    CodeReviewResult, DynamicTestResult, RiskLevel,
    TestOutcome, RegressionRisk,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    综合评估报告生成器。

    将验证流水线各阶段的结果整合为清晰、可读的 Markdown 报告。
    """

    # ----------------------------------------------------------------
    #  公开接口
    # ----------------------------------------------------------------

    def generate(self, report: VerificationReport) -> str:
        """
        根据 VerificationReport 生成 Markdown 格式的综合评估报告。

        Args:
            report: 填充完整的验证报告数据对象

        Returns:
            Markdown 格式的报告文本
        """
        sections = [
            self._render_header(report),
            self._render_overview(report),
            self._render_routing_section(report),
        ]

        # 判断是否有 AI 数据（外部 LLM 或需要 AI 会话补充）
        cr = report.code_review_result
        has_ai_review = cr and (cr.ai_patch_analyses or cr.ai_regression_assessment)
        has_ai_conclusion = report.ai_conclusion is not None
        self._has_any_ai = has_ai_review or has_ai_conclusion

        # 动态章节编号（避免跳号）
        self._section_num = 2  # §1=概览, §2=分流 已渲染

        # 代码检视 — 所有路径均渲染（DYNAMIC_ONLY 显示简短说明）
        sections.append(self._render_code_review_section(report))

        # 动态测试 — 仅 DYNAMIC_ONLY 和 HYBRID
        route = report.verification_route
        if route in (VerificationRoute.DYNAMIC_ONLY, VerificationRoute.HYBRID):
            sections.append(self._render_dynamic_test_section(report))

        # 衍生风险 — 所有路径均渲染
        sections.append(self._render_regression_risk_section(report))

        sections.append(self._render_conclusion(report))
        sections.append(self._render_footer(report))

        return "\n\n".join(sections)

    def generate_and_save(
        self, report: VerificationReport, output_path: str
    ) -> str:
        """生成报告并保存到文件。"""
        content = self.generate(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        logger.info("报告已保存至: %s", output_path)
        return content

    # ----------------------------------------------------------------
    #  报告标题
    # ----------------------------------------------------------------

    def _render_header(self, report: VerificationReport) -> str:
        return "\n".join([
            f"# CVE 补丁验证报告",
            "",
            f"| 项目 | 详情 |",
            f"|------|------|",
            f"| **CVE 编号** | `{report.cve_id}` |",
            f"| **任务 ID** | `{report.task_id}` |",
            f"| **验证路径** | {self._route_label(report.verification_route)} |",
            f"| **综合风险** | {self._risk_badge(report.overall_risk_level)} |",
            f"| **生成时间** | {report.generated_at} |",
        ])

    # ----------------------------------------------------------------
    #  概览
    # ----------------------------------------------------------------

    def _render_overview(self, report: VerificationReport) -> str:
        lines = ["## 1. 验证概览", ""]

        route = report.verification_route
        if route == VerificationRoute.DYNAMIC_ONLY:
            lines.append(
                "本次验证采用 **动态测试** 路径。在隔离沙箱环境中对修复后的"
                "软件包进行了漏洞触发验证和基础功能回归测试。"
            )
        elif route == VerificationRoute.CODE_REVIEW_ONLY:
            lines.append(
                "本次验证采用 **代码检视** 路径。由于该漏洞无法或极难通过"
                "动态方式构造触发，验证主要手段为深度补丁代码检视与衍生风险评估。"
            )
        else:
            lines.append(
                "本次验证采用 **双路径结合** (代码检视 + 动态测试) 策略，"
                "以获得最全面的验证覆盖。"
            )

        return "\n".join(lines)

    # ----------------------------------------------------------------
    #  分流决策
    # ----------------------------------------------------------------

    def _render_routing_section(self, report: VerificationReport) -> str:
        lines = ["## 2. 智能分流决策", ""]

        rd = report.routing_decision
        if not rd:
            lines.append("_未记录分流决策详情。_")
            return "\n".join(lines)

        lines.append(f"**决策路径**: {self._route_label(rd.route)}")
        lines.append(f"**决策理由**: {rd.rationale}")
        lines.append("")

        # 评分明细表
        lines.append("### 评分维度")
        lines.append("")
        lines.append("| 维度 | 评分 | 说明 |")
        lines.append("|------|------|------|")

        scores = rd.scores
        dimensions = [
            ("PoC 可用性", scores.poc_availability, "poc_availability"),
            ("攻击面可达性", scores.attack_surface_reachability, "attack_surface_reachability"),
            ("触发条件复杂度", scores.trigger_complexity, "trigger_complexity"),
            ("补丁复杂度", scores.patch_complexity, "patch_complexity"),
        ]
        for name, score, key in dimensions:
            reason = scores.reasoning.get(key, "")
            lines.append(f"| {name} | `{score:.2f}` | {reason} |")

        lines.append("")
        lines.append(
            f"**权重分配**: 动态测试 {rd.dynamic_weight:.0%} / "
            f"代码检视 {rd.review_weight:.0%}"
        )

        return "\n".join(lines)

    # ----------------------------------------------------------------
    #  代码检视
    # ----------------------------------------------------------------

    def _next_section(self) -> int:
        """返回下一个章节编号。"""
        self._section_num += 1
        return self._section_num

    def _render_code_review_section(self, report: VerificationReport) -> str:
        sn = self._next_section()
        lines = [f"## {sn}. 代码检视结论", ""]

        cr = report.code_review_result
        if not cr:
            lines.append("_未执行代码检视。_")
            return "\n".join(lines)

        lines.append(f"**简要摘要**: {cr.summary}")
        lines.append("")

        # 构建 AI 分析的文件路径索引（用于内联匹配）
        ai_by_file = {}
        if cr.ai_patch_analyses:
            for analysis in cr.ai_patch_analyses:
                fp = analysis.get("_file_path", "")
                if fp:
                    ai_by_file[fp] = analysis

        # 逐文件评估
        if cr.patch_assessments:
            lines.append("### 逐文件评估")
            lines.append("")
            for idx, pa in enumerate(cr.patch_assessments, 1):
                lines.append(f"#### {idx}. `{pa.file_path}`")
                lines.append("")
                lines.append(f"- **CVE 关联性**: {pa.relevance_to_cve}")
                lines.append(f"- **修复手段**: {pa.fix_approach}")
                lines.append(f"- **逻辑合理性**: {pa.logic_soundness}")
                lines.append(f"- **补丁完整性**: {pa.completeness}")
                if pa.concerns:
                    lines.append(f"- **关注要点**:")
                    for c in pa.concerns:
                        lines.append(f"  - ⚠ {c}")
                lines.append("")

                # 内联 AI 深度分析（已有外部 LLM 数据时）
                ai = ai_by_file.get(pa.file_path)
                if ai:
                    lines.append("**🤖 AI 深度分析:**")
                    lines.append("")
                    fix = ai.get("fix_correctness", {})
                    if fix:
                        correct = "✅ 正确" if fix.get("is_correct") else "❌ 待确认"
                        conf = fix.get("confidence", "")
                        lines.append(f"- **修复正确性**: {correct} (置信度: {conf})")
                        if fix.get("reasoning"):
                            lines.append(f"- **分析**: {fix['reasoning']}")
                    comp = ai.get("patch_completeness", {})
                    if comp:
                        complete = "✅ 完整" if comp.get("is_complete") else "⚠ 不完整"
                        lines.append(f"- **补丁完整性(AI)**: {complete}")
                        if comp.get("missing_aspects"):
                            for m in comp["missing_aspects"]:
                                lines.append(f"  - 缺失: {m}")
                    semantic = ai.get("semantic_analysis", "")
                    if semantic:
                        lines.append(f"- **语义分析**: {semantic}")
                    lines.append("")
                elif not self._has_any_ai:
                    # 无 AI 数据：插入占位符供 AI 会话填充
                    lines.append(f"<!-- AI:file_analysis:{pa.file_path} -->")
                    lines.append("")

        return "\n".join(lines)

    # ----------------------------------------------------------------
    #  动态测试
    # ----------------------------------------------------------------

    def _render_dynamic_test_section(self, report: VerificationReport) -> str:
        sn = self._next_section()
        lines = [f"## {sn}. 动态测试结果", ""]

        dt = report.dynamic_test_result
        if not dt:
            lines.append("_未执行动态测试。_")
            return "\n".join(lines)

        lines.append(f"**综合结果**: {self._outcome_badge(dt.overall_outcome)}")
        lines.append(f"**结果摘要**: {dt.summary}")
        lines.append("")

        # 漏洞触发测试
        if dt.vulnerability_test:
            vt = dt.vulnerability_test
            lines.append("### 漏洞触发验证")
            lines.append("")
            lines.append(f"- **结果**: {self._outcome_badge(vt.outcome)}")
            lines.append(f"- **耗时**: {vt.duration_seconds:.2f}s")
            lines.append(f"- **退出码**: `{vt.return_code}`")
            if vt.details:
                lines.append(f"- **详情**: {vt.details}")
            lines.append("")

        # 回归测试
        if dt.regression_tests:
            lines.append("### 基础功能回归")
            lines.append("")
            lines.append("| 测试项 | 结果 | 耗时 | 退出码 |")
            lines.append("|--------|------|------|--------|")
            for rt in dt.regression_tests:
                lines.append(
                    f"| {rt.test_name} "
                    f"| {self._outcome_badge(rt.outcome)} "
                    f"| {rt.duration_seconds:.2f}s "
                    f"| `{rt.return_code}` |"
                )
            lines.append("")

        return "\n".join(lines)

    # ----------------------------------------------------------------
    #  衍生风险评估
    # ----------------------------------------------------------------

    def _render_regression_risk_section(
        self, report: VerificationReport
    ) -> str:
        sn = self._next_section()
        lines = [f"## {sn}. 衍生风险评估（防劣化）", ""]

        cr = report.code_review_result
        rule_risks = cr.regression_risks if cr else []

        # 合并 AI 衍生风险（如有外部 LLM 数据）
        ai_ra = cr.ai_regression_assessment if cr else None
        ai_risks_data = ai_ra.get("regression_risks", []) if ai_ra else []

        if not rule_risks and not ai_risks_data and not ai_ra:
            if not self._has_any_ai:
                lines.append("_规则引擎未发现衍生风险。_")
                lines.append("")
                lines.append("<!-- AI:regression_risks -->")
            else:
                lines.append("_未发现衍生风险。_")
            return "\n".join(lines)

        # 规则引擎风险
        if rule_risks:
            lines.append(
                f"共检出 **{len(rule_risks)}** 条衍生风险 (规则引擎)，"
                f"综合风险等级: {self._risk_badge(cr.overall_risk_level)}"
            )
            lines.append("")

            sorted_risks = sorted(
                rule_risks,
                key=lambda r: {"high": 0, "medium": 1, "low": 2, "none": 3}.get(
                    r.risk_level.value, 4
                ),
            )

            lines.append("| # | 等级 | 分类 | 文件 | 描述 |")
            lines.append("|---|------|------|------|------|")
            for idx, risk in enumerate(sorted_risks, 1):
                lines.append(
                    f"| {idx} "
                    f"| {self._risk_badge(risk.risk_level)} "
                    f"| {risk.category} "
                    f"| `{risk.file_path}` "
                    f"| {risk.description} |"
                )
            lines.append("")

            high_risks = [
                r for r in sorted_risks if r.risk_level == RiskLevel.HIGH
            ]
            if high_risks:
                lines.append("### 高风险项详情")
                lines.append("")
                for r in high_risks:
                    lines.append(f"**[{r.category}] {r.file_path}**")
                    lines.append(f"- 描述: {r.description}")
                    lines.append(f"- 影响范围: {r.affected_scope}")
                    if r.evidence:
                        lines.append(f"- 证据:")
                        lines.append(f"  ```")
                        lines.append(f"  {r.evidence}")
                        lines.append(f"  ```")
                    lines.append("")
        else:
            lines.append("规则引擎未检出衍生风险。")
            lines.append("")

        # 内联 AI 衍生风险评估（已有外部 LLM 数据时）
        if ai_ra:
            lines.append("### 🤖 AI 衍生风险评估")
            lines.append("")
            if ai_ra.get("overall_risk_assessment"):
                lines.append(f"**综合评估**: {ai_ra['overall_risk_assessment']}")
                lines.append("")
            core = ai_ra.get("core_logic_impact", {})
            if core:
                changed = "是" if core.get("is_core_logic_changed") else "否"
                lines.append(f"**核心逻辑是否变更**: {changed}")
                if core.get("explanation"):
                    lines.append(f"- {core['explanation']}")
                lines.append("")
            if ai_risks_data:
                lines.append("| 等级 | 分类 | 描述 | 缓解建议 |")
                lines.append("|------|------|------|----------|")
                for r in ai_risks_data:
                    lines.append(
                        f"| {r.get('risk_level', '')} | {r.get('category', '')} "
                        f"| {r.get('description', '')} "
                        f"| {r.get('mitigation', '')} |"
                    )
                lines.append("")
        elif not self._has_any_ai:
            # 无 AI 数据：占位符
            lines.append("<!-- AI:regression_risks -->")
            lines.append("")

        return "\n".join(lines)

    # ----------------------------------------------------------------
    #  综合结论
    # ----------------------------------------------------------------

    def _render_conclusion(self, report: VerificationReport) -> str:
        sn = self._next_section()
        lines = [f"## {sn}. 综合结论", ""]

        lines.append(f"**结论**: {report.overall_conclusion}")
        lines.append(f"**综合风险等级**: {self._risk_badge(report.overall_risk_level)}")
        lines.append("")

        if report.recommendations:
            lines.append("### 建议")
            lines.append("")
            for idx, rec in enumerate(report.recommendations, 1):
                lines.append(f"{idx}. {rec}")
            lines.append("")

        # 内联 AI 综合结论（已有外部 LLM 数据时）
        ac = report.ai_conclusion
        if ac:
            lines.append("### 🤖 AI 综合结论")
            lines.append("")
            verdict = ac.get("overall_verdict", "")
            verdict_map = {
                "approve": "✅ 建议合入",
                "reject": "❌ 建议拒绝",
                "conditional_approve": "⚠ 有条件合入",
            }
            lines.append(f"- **判定**: {verdict_map.get(verdict, verdict)}")
            lines.append(f"- **置信度**: {ac.get('confidence', '')}")
            if ac.get("summary"):
                lines.append(f"- **摘要**: {ac['summary']}")
            if ac.get("key_findings"):
                lines.append("- **核心发现**:")
                for f in ac["key_findings"]:
                    lines.append(f"  - {f}")
            if ac.get("recommendations"):
                lines.append("- **AI 建议**:")
                for r in ac["recommendations"]:
                    lines.append(f"  - {r}")
            merge = ac.get("merge_readiness", "")
            if merge:
                lines.append(f"- **合入就绪度**: {merge}")
            lines.append("")
        elif not self._has_any_ai:
            # 无 AI 数据：占位符
            lines.append("<!-- AI:conclusion -->")
            lines.append("")

        return "\n".join(lines)

    # ----------------------------------------------------------------
    #  页脚
    # ----------------------------------------------------------------

    def _render_footer(self, report: VerificationReport) -> str:
        from cve_verifier import __version__
        return "\n".join([
            "---",
            "",
            f"*本报告由 CVE 补丁自动化验证系统 v{__version__} 自动生成*",
            f"*生成时间: {report.generated_at}*",
        ])

    # ----------------------------------------------------------------
    #  格式化工具
    # ----------------------------------------------------------------

    @staticmethod
    def _route_label(route: VerificationRoute) -> str:
        labels = {
            VerificationRoute.DYNAMIC_ONLY: "🔬 仅动态测试",
            VerificationRoute.CODE_REVIEW_ONLY: "📝 仅代码检视",
            VerificationRoute.HYBRID: "🔄 双路径结合 (动态测试 + 代码检视)",
        }
        return labels.get(route, str(route))

    @staticmethod
    def _risk_badge(level: RiskLevel) -> str:
        badges = {
            RiskLevel.HIGH: "🔴 高",
            RiskLevel.MEDIUM: "🟡 中",
            RiskLevel.LOW: "🟢 低",
            RiskLevel.NONE: "⚪ 无",
        }
        return badges.get(level, str(level))

    @staticmethod
    def _outcome_badge(outcome: TestOutcome) -> str:
        badges = {
            TestOutcome.PASS: "✅ 通过",
            TestOutcome.FAIL: "❌ 失败",
            TestOutcome.ERROR: "💥 异常",
            TestOutcome.SKIPPED: "⏭ 跳过",
            TestOutcome.INCONCLUSIVE: "❓ 无法确定",
        }
        return badges.get(outcome, str(outcome))
