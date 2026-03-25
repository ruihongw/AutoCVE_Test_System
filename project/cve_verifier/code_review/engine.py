"""
代码检视分析引擎 (Code Review Engine) — 重构版

三阶段深度代码检视流水线:
  阶段一: 结构化解析 — 将 diff 解析为语义化的修改描述
  阶段二: 补丁逻辑合理性评估 — 分析修复手段与 CVE 的匹配度
  阶段三: 衍生风险评估 — 排查补丁是否改变原有核心逻辑
  阶段四(可选): AI 深度检视 — LLM 语义分析增强
"""

import logging
from typing import Optional, TYPE_CHECKING

from ..models import (
    VerificationTask, CodeReviewResult, PatchAssessment,
    PatchedFile,
)

from .relevance import RelevanceAnalyzer
from .fix_pattern import FixPatternIdentifier
from .logic_checker import LogicChecker
from .risk_assessor import RiskAssessor
from .ai_reviewer import AIReviewer

if TYPE_CHECKING:
    from ..llm_analyzer import LLMAnalyzer

logger = logging.getLogger(__name__)


class CodeReviewEngine:
    """
    代码检视引擎

    对 AI 适配生成的补丁进行深度分析，覆盖逻辑合理性和
    衍生风险两个核心关注维度。支持可选的 LLM 深度语义增强。

    架构: 组合模式，将各阶段分析委托给专门的子模块:
    - RelevanceAnalyzer: 关联性分析
    - FixPatternIdentifier: 修复模式识别
    - LogicChecker: 逻辑合理性与完整性评估
    - RiskAssessor: 衍生风险评估与综合结论
    - AIReviewer: AI 深度检视
    """

    def __init__(self, llm_analyzer: Optional["LLMAnalyzer"] = None):
        """
        Args:
            llm_analyzer: 可选的 LLM 分析器实例。提供时启用 AI 深度检视。
        """
        self._relevance = RelevanceAnalyzer()
        self._fix_pattern = FixPatternIdentifier()
        self._logic = LogicChecker()
        self._risk = RiskAssessor()
        self._ai = AIReviewer(llm_analyzer)

    # ================================================================
    #  公开接口
    # ================================================================

    def review(self, task: VerificationTask) -> CodeReviewResult:
        """
        对验证任务执行完整的三阶段代码检视。

        Args:
            task: 已解析的验证任务上下文

        Returns:
            CodeReviewResult 包含逐文件评估、衍生风险列表及综合结论
        """
        logger.info("开始代码检视: %s (%d 文件变更)",
                     task.cve_meta.cve_id, task.patch_info.total_files_changed)

        # 阶段一 & 阶段二: 逐文件进行结构化解析 + 合理性评估
        assessments = []
        for pf in task.patch_info.patched_files:
            assessment = self._assess_patched_file(pf, task)
            assessments.append(assessment)

        # 阶段三: 衍生风险评估
        regression_risks = self._risk.assess_regression_risks(
            task.patch_info.patched_files, task
        )

        # 阶段四: AI 深度检视 (如果 LLM 可用)
        ai_patch_analyses = None
        ai_regression_assessment = None
        if self._ai.is_available:
            logger.info("执行阶段四: AI 深度检视...")
            ai_patch_analyses = self._ai.run_patch_analysis(task)
            ai_regression_assessment = self._ai.run_regression_assessment(task)

        # 综合结论
        overall_risk = self._risk.compute_overall_risk(regression_risks)

        # AI 风险可能提升整体风险等级
        if ai_regression_assessment:
            ai_risk = self._ai.extract_risk_level(ai_regression_assessment)
            if ai_risk and ai_risk.value > overall_risk.value:
                overall_risk = ai_risk

        overall_assessment = self._risk.generate_overall_assessment(
            assessments, regression_risks, overall_risk, task
        )
        summary = self._risk.generate_summary(
            assessments, regression_risks, overall_risk
        )

        result = CodeReviewResult(
            overall_assessment=overall_assessment,
            patch_assessments=assessments,
            regression_risks=regression_risks,
            overall_risk_level=overall_risk,
            summary=summary,
            ai_patch_analyses=ai_patch_analyses,
            ai_regression_assessment=ai_regression_assessment,
        )

        logger.info("代码检视完成: 整体风险等级 = %s", overall_risk.value)
        return result

    # ================================================================
    #  逐文件评估（编排子模块）
    # ================================================================

    def _assess_patched_file(
        self, pf: PatchedFile, task: VerificationTask
    ) -> PatchAssessment:
        """对单个被补丁修改的文件进行评估。"""
        return PatchAssessment(
            file_path=pf.target_path,
            relevance_to_cve=self._relevance.analyze(pf, task),
            fix_approach=self._fix_pattern.identify(pf),
            logic_soundness=self._logic.evaluate_logic_soundness(pf, task),
            completeness=self._logic.evaluate_completeness(pf, task),
            concerns=self._logic.identify_concerns(pf, task),
        )
