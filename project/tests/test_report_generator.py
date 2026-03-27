"""
报告生成器单元测试

覆盖报告各章节的渲染、格式徽章和边界情况。
"""

import unittest

from cve_verifier.models import (
    VerificationReport, VerificationRoute, RoutingDecision, RoutingScore,
    CodeReviewResult, DynamicTestResult, PatchAssessment,
    RegressionRisk, RiskLevel, TestCaseResult, TestOutcome,
)
from cve_verifier.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """报告生成器测试套件"""

    def setUp(self):
        self.generator = ReportGenerator()

    def _make_report(self, **overrides) -> VerificationReport:
        """构造测试用验证报告。"""
        defaults = dict(
            task_id="TEST-RPT-001",
            cve_id="CVE-2024-0001",
            verification_route=VerificationRoute.CODE_REVIEW_ONLY,
            routing_decision=RoutingDecision(
                route=VerificationRoute.CODE_REVIEW_ONLY,
                scores=RoutingScore(
                    poc_availability=0.0,
                    attack_surface_reachability=0.4,
                    trigger_complexity=0.5,
                    patch_complexity=0.3,
                    reasoning={
                        "poc_availability": "无 PoC",
                        "attack_surface_reachability": "本地",
                        "trigger_complexity": "中等",
                        "patch_complexity": "简单",
                    },
                ),
                dynamic_weight=0.0,
                review_weight=1.0,
                rationale="测试用分流决策",
            ),
            code_review_result=CodeReviewResult(
                overall_assessment="测试整体评估",
                patch_assessments=[
                    PatchAssessment(
                        file_path="src/main.c",
                        relevance_to_cve="高度相关",
                        fix_approach="边界检查",
                        logic_soundness="合理",
                        completeness="完整",
                        concerns=[],
                    ),
                ],
                regression_risks=[
                    RegressionRisk(
                        risk_level=RiskLevel.LOW,
                        category="控制流变更",
                        file_path="src/main.c",
                        description="新增 return 语句",
                    ),
                ],
                overall_risk_level=RiskLevel.LOW,
                summary="共检视 1 个文件，发现 1 条衍生风险",
            ),
            overall_conclusion="验证通过",
            overall_risk_level=RiskLevel.LOW,
            recommendations=["按流程推进合入"],
            generated_at="2026-01-01T00:00:00",
        )
        defaults.update(overrides)
        return VerificationReport(**defaults)

    # ----------------------------------------------------------------
    #  基础渲染测试
    # ----------------------------------------------------------------

    def test_generate_returns_non_empty(self):
        """生成报告内容非空"""
        report = self._make_report()
        content = self.generator.generate(report)
        self.assertTrue(len(content) > 0)

    def test_report_contains_cve_id(self):
        """报告包含 CVE 编号"""
        report = self._make_report()
        content = self.generator.generate(report)
        self.assertIn("CVE-2024-0001", content)

    def test_report_contains_sections(self):
        """报告包含所有必需章节"""
        report = self._make_report()
        content = self.generator.generate(report)
        self.assertIn("验证概览", content)
        self.assertIn("智能分流决策", content)
        self.assertIn("代码检视结论", content)
        self.assertIn("衍生风险评估", content)
        self.assertIn("综合结论", content)

    def test_report_does_not_contain_dynamic_for_review_only(self):
        """仅代码检视路径不包含动态测试章节"""
        report = self._make_report()
        content = self.generator.generate(report)
        self.assertNotIn("动态测试结果", content)

    def test_dynamic_only_report(self):
        """仅动态测试路径包含正确章节"""
        report = self._make_report(
            verification_route=VerificationRoute.DYNAMIC_ONLY,
            code_review_result=None,
            dynamic_test_result=DynamicTestResult(
                overall_outcome=TestOutcome.PASS,
                summary="全部通过",
                vulnerability_test=TestCaseResult(
                    test_name="漏洞触发", outcome=TestOutcome.PASS,
                    duration_seconds=1.5, return_code=1,
                ),
            ),
        )
        content = self.generator.generate(report)
        self.assertIn("动态测试结果", content)
        self.assertIn("代码检视结论", content)  # 所有路径均渲染代码检视

    def test_hybrid_report_contains_both(self):
        """双路径报告包含代码检视和动态测试"""
        report = self._make_report(
            verification_route=VerificationRoute.HYBRID,
            dynamic_test_result=DynamicTestResult(
                overall_outcome=TestOutcome.PASS, summary="通过",
            ),
        )
        content = self.generator.generate(report)
        self.assertIn("代码检视结论", content)
        self.assertIn("动态测试结果", content)

    # ----------------------------------------------------------------
    #  格式徽章测试
    # ----------------------------------------------------------------

    def test_risk_badge_high(self):
        """高风险徽章"""
        badge = ReportGenerator._risk_badge(RiskLevel.HIGH)
        self.assertIn("🔴", badge)

    def test_risk_badge_none(self):
        """无风险徽章"""
        badge = ReportGenerator._risk_badge(RiskLevel.NONE)
        self.assertIn("⚪", badge)

    def test_outcome_badge_pass(self):
        """通过徽章"""
        badge = ReportGenerator._outcome_badge(TestOutcome.PASS)
        self.assertIn("✅", badge)

    def test_outcome_badge_fail(self):
        """失败徽章"""
        badge = ReportGenerator._outcome_badge(TestOutcome.FAIL)
        self.assertIn("❌", badge)

    def test_route_label(self):
        """路径标签"""
        labels = [
            ReportGenerator._route_label(VerificationRoute.DYNAMIC_ONLY),
            ReportGenerator._route_label(VerificationRoute.CODE_REVIEW_ONLY),
            ReportGenerator._route_label(VerificationRoute.HYBRID),
        ]
        self.assertTrue(all(len(l) > 0 for l in labels))

    # ----------------------------------------------------------------
    #  版本号测试
    # ----------------------------------------------------------------

    def test_footer_contains_version(self):
        """页脚包含正确的版本号"""
        from cve_verifier import __version__
        report = self._make_report()
        content = self.generator.generate(report)
        self.assertIn(f"v{__version__}", content)

    # ----------------------------------------------------------------
    #  AI 占位符测试
    # ----------------------------------------------------------------

    def test_no_ai_generates_placeholders(self):
        """无 AI 数据时生成占位符"""
        report = self._make_report()
        content = self.generator.generate(report)
        self.assertIn("<!-- AI:conclusion -->", content)

    def test_with_ai_conclusion_no_placeholder(self):
        """有 AI 结论时不生成占位符"""
        report = self._make_report(
            ai_conclusion={
                "overall_verdict": "approve",
                "confidence": "high",
                "summary": "建议合入",
            },
        )
        content = self.generator.generate(report)
        self.assertNotIn("<!-- AI:conclusion -->", content)
        self.assertIn("AI 综合结论", content)

    # ----------------------------------------------------------------
    #  文件保存测试
    # ----------------------------------------------------------------

    def test_generate_and_save(self):
        """保存报告到文件"""
        import tempfile
        import os
        report = self._make_report()
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            temp_path = f.name
        try:
            content = self.generator.generate_and_save(report, temp_path)
            self.assertTrue(os.path.exists(temp_path))
            with open(temp_path, "r", encoding="utf-8") as f:
                saved = f.read()
            self.assertEqual(content, saved)
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()
