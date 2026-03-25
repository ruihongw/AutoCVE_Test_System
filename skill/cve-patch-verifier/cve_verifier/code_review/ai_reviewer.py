"""
AI 深度检视模块

调用 LLM 对补丁进行深度语义分析和衍生风险评估。
"""

from typing import List, Optional, TYPE_CHECKING

from ..models import VerificationTask, PatchedFile, RiskLevel

if TYPE_CHECKING:
    from ..llm_analyzer import LLMAnalyzer


class AIReviewer:
    """AI 深度检视器，基于 LLM 的补丁语义分析。"""

    def __init__(self, llm_analyzer: Optional["LLMAnalyzer"] = None):
        self._llm = llm_analyzer

    @property
    def is_available(self) -> bool:
        """LLM 是否可用。"""
        return bool(self._llm and self._llm.is_available)

    def run_patch_analysis(
        self, task: VerificationTask
    ) -> Optional[List[dict]]:
        """对每个补丁文件调用 LLM 进行深度语义分析。"""
        if not self.is_available:
            return None

        results = []
        cve = task.cve_meta

        for pf in task.patch_info.patched_files:
            diff_content = "\n".join(
                hunk.raw_content for hunk in pf.hunks if hunk.raw_content
            )
            if not diff_content:
                diff_content = self._reconstruct_diff(pf)

            analysis = self._llm.analyze_patch(
                cve_id=cve.cve_id,
                description=cve.description,
                cwe_id=cve.cwe_id,
                severity=cve.severity.value,
                cvss_score=cve.cvss_score,
                attack_vector=cve.attack_vector.value,
                affected_component=cve.affected_component,
                file_path=pf.target_path,
                diff_content=diff_content,
            )
            if analysis:
                analysis["_file_path"] = pf.target_path
                results.append(analysis)

        return results if results else None

    def run_regression_assessment(
        self, task: VerificationTask
    ) -> Optional[dict]:
        """调用 LLM 对完整补丁进行衍生风险评估。"""
        if not self.is_available:
            return None

        return self._llm.assess_regression_risk(
            cve_id=task.cve_meta.cve_id,
            description=task.cve_meta.description,
            affected_component=task.cve_meta.affected_component,
            full_diff=task.patch_info.raw_content[:8000],  # 防止过长
        )

    @staticmethod
    def extract_risk_level(ai_assessment: dict) -> Optional[RiskLevel]:
        """从 AI 衍生风险评估结果中提取风险等级。"""
        risks = ai_assessment.get("regression_risks", [])
        if not risks:
            return None
        level_map = {
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
        }
        max_level = RiskLevel.NONE
        for r in risks:
            level = level_map.get(r.get("risk_level", "").lower())
            if level and level.value > max_level.value:
                max_level = level
        return max_level if max_level != RiskLevel.NONE else None

    @staticmethod
    def _reconstruct_diff(pf: PatchedFile) -> str:
        """从 PatchedFile 重建可读 diff 片段。"""
        lines = []
        for hunk in pf.hunks:
            header = hunk.section_header or ""
            lines.append(f"@@ -{hunk.source_start},{hunk.source_length} "
                         f"+{hunk.target_start},{hunk.target_length} @@ {header}")
            for line in hunk.removed_lines:
                lines.append(f"-{line}")
            for line in hunk.added_lines:
                lines.append(f"+{line}")
        return "\n".join(lines)
