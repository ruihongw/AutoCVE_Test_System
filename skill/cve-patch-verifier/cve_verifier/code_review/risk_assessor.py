"""
衍生风险评估模块

全面排查补丁可能引入的衍生风险（防劣化），包括：
- 函数签名/接口变更
- 控制流改变
- 数据流约束变更
- 资源管理变更
- 错误处理路径变更
- 跨文件影响
"""

import re
from typing import List

from ..models import (
    PatchedFile, PatchAssessment, RegressionRisk,
    RiskLevel, VerificationTask,
)


class RiskAssessor:
    """衍生风险评估器。"""

    def assess_regression_risks(
        self, patched_files: List[PatchedFile], task: VerificationTask
    ) -> List[RegressionRisk]:
        """全面排查补丁可能引入的衍生风险。"""
        risks: List[RegressionRisk] = []

        for pf in patched_files:
            risks.extend(self._check_signature_changes(pf))
            risks.extend(self._check_control_flow_changes(pf))
            risks.extend(self._check_data_flow_changes(pf))
            risks.extend(self._check_resource_management_changes(pf))
            risks.extend(self._check_error_handling_changes(pf))

        risks.extend(self._check_cross_file_impact(patched_files))
        return risks

    def compute_overall_risk(
        self, risks: List[RegressionRisk]
    ) -> RiskLevel:
        """计算综合风险等级。"""
        if any(r.risk_level == RiskLevel.HIGH for r in risks):
            return RiskLevel.HIGH
        if any(r.risk_level == RiskLevel.MEDIUM for r in risks):
            return RiskLevel.MEDIUM
        if any(r.risk_level == RiskLevel.LOW for r in risks):
            return RiskLevel.LOW
        return RiskLevel.NONE

    def generate_overall_assessment(
        self,
        assessments: List[PatchAssessment],
        risks: List[RegressionRisk],
        overall_risk: RiskLevel,
        task: VerificationTask,
    ) -> str:
        """生成整体评估结论文本。"""
        lines = [
            f"## 代码检视结论 — {task.cve_meta.cve_id}",
            "",
            f"- **补丁涉及文件数**: {len(assessments)}",
            f"- **衍生风险条目数**: {len(risks)}",
            f"- **综合风险等级**: {overall_risk.value.upper()}",
            "",
        ]

        high_risks = [r for r in risks if r.risk_level == RiskLevel.HIGH]
        if high_risks:
            lines.append("### ⚠ 高风险项")
            for r in high_risks:
                lines.append(f"- [{r.category}] {r.description}")
            lines.append("")

        concerned_files = [a for a in assessments if a.concerns]
        if concerned_files:
            lines.append("### 关注要点")
            for a in concerned_files:
                for c in a.concerns:
                    lines.append(f"- `{a.file_path}`: {c}")

        return "\n".join(lines)

    def generate_summary(
        self,
        assessments: List[PatchAssessment],
        risks: List[RegressionRisk],
        overall_risk: RiskLevel,
    ) -> str:
        """生成简短摘要。"""
        risk_counts = {level: 0 for level in RiskLevel}
        for r in risks:
            risk_counts[r.risk_level] += 1

        parts = [
            f"共检视 {len(assessments)} 个文件",
            f"发现 {len(risks)} 条衍生风险",
            f"(高={risk_counts[RiskLevel.HIGH]}, "
            f"中={risk_counts[RiskLevel.MEDIUM]}, "
            f"低={risk_counts[RiskLevel.LOW]})",
            f"综合风险: {overall_risk.value.upper()}",
        ]
        return "，".join(parts)

    # ── 签名变更检测 ──

    def _check_signature_changes(self, pf: PatchedFile) -> List[RegressionRisk]:
        """检测函数签名或结构体定义变更。"""
        risks = []
        for hunk in pf.hunks:
            removed_funcs = self._extract_function_signatures(hunk.removed_lines)
            added_funcs = self._extract_function_signatures(hunk.added_lines)

            for old_sig in removed_funcs:
                old_name = self._extract_func_name(old_sig)
                matching_new = [
                    s for s in added_funcs
                    if self._extract_func_name(s) == old_name
                ]
                if matching_new:
                    for new_sig in matching_new:
                        if old_sig.strip() != new_sig.strip():
                            risks.append(RegressionRisk(
                                risk_level=RiskLevel.MEDIUM,
                                category="函数签名变更",
                                file_path=pf.target_path,
                                description=(
                                    f"函数 '{old_name}' 签名发生变更，"
                                    f"所有调用点需同步更新"
                                ),
                                affected_scope="所有调用该函数的模块",
                                evidence=f"旧: {old_sig.strip()}\n新: {new_sig.strip()}",
                            ))
                elif old_name:
                    risks.append(RegressionRisk(
                        risk_level=RiskLevel.HIGH,
                        category="函数移除",
                        file_path=pf.target_path,
                        description=f"函数 '{old_name}' 被移除，可能导致链接/调用失败",
                        affected_scope="所有依赖该函数的模块",
                        evidence=f"已移除: {old_sig.strip()}",
                    ))
        return risks

    # ── 控制流变更检测 ──

    def _check_control_flow_changes(self, pf: PatchedFile) -> List[RegressionRisk]:
        """检测控制流结构变更。"""
        risks = []

        for hunk in pf.hunks:
            added_text = "\n".join(hunk.added_lines)
            removed_text = "\n".join(hunk.removed_lines)

            added_returns = re.findall(r'return\s+[^;]+', added_text)
            removed_returns = re.findall(r'return\s+[^;]+', removed_text)

            if removed_returns and not added_returns:
                risks.append(RegressionRisk(
                    risk_level=RiskLevel.MEDIUM,
                    category="控制流变更",
                    file_path=pf.target_path,
                    description=(
                        f"在 '{hunk.section_header or '未知位置'}' 处移除了 return 语句，"
                        "可能改变函数退出行为"
                    ),
                    affected_scope=hunk.section_header or "未知",
                    evidence=f"已移除的 return: {removed_returns}",
                ))

            if added_returns and not removed_returns:
                risks.append(RegressionRisk(
                    risk_level=RiskLevel.LOW,
                    category="控制流变更",
                    file_path=pf.target_path,
                    description=(
                        f"在 '{hunk.section_header or '未知位置'}' 处新增了 return 语句，"
                        "可能引入提前退出路径"
                    ),
                    affected_scope=hunk.section_header or "未知",
                    evidence=f"新增的 return: {added_returns}",
                ))

            added_gotos = re.findall(r'goto\s+(\w+)', added_text)
            removed_gotos = re.findall(r'goto\s+(\w+)', removed_text)
            new_gotos = set(added_gotos) - set(removed_gotos)
            if new_gotos:
                risks.append(RegressionRisk(
                    risk_level=RiskLevel.LOW,
                    category="控制流变更",
                    file_path=pf.target_path,
                    description=(
                        f"新增 goto 跳转目标: {', '.join(new_gotos)}，"
                        "需确认跳转标签存在且清理逻辑正确"
                    ),
                    affected_scope=hunk.section_header or "未知",
                    evidence=f"新增 goto: {list(new_gotos)}",
                ))

        return risks

    # ── 数据流约束变更 ──

    def _check_data_flow_changes(self, pf: PatchedFile) -> List[RegressionRisk]:
        """检测数据流约束变更。"""
        risks = []

        for hunk in pf.hunks:
            added_text = "\n".join(hunk.added_lines)

            casts = re.findall(
                r'\(\s*(?:unsigned\s+)?(?:int|long|short|char|size_t|u\d+|s\d+)\s*\)',
                added_text,
            )
            if casts:
                risks.append(RegressionRisk(
                    risk_level=RiskLevel.LOW,
                    category="数据流变更",
                    file_path=pf.target_path,
                    description=(
                        f"新增了 {len(casts)} 处类型转换，"
                        "需确认不会引入截断或符号扩展问题"
                    ),
                    affected_scope=hunk.section_header or "未知",
                    evidence=f"类型转换: {casts[:5]}",
                ))

        return risks

    # ── 资源管理变更 ──

    def _check_resource_management_changes(
        self, pf: PatchedFile
    ) -> List[RegressionRisk]:
        """检测资源管理（内存/锁/文件描述符）变更。"""
        risks = []

        for hunk in pf.hunks:
            added_text = "\n".join(hunk.added_lines)
            removed_text = "\n".join(hunk.removed_lines)

            added_locks = len(re.findall(
                r'(?:mutex_lock|spin_lock|down|lock)\s*\(', added_text
            ))
            added_unlocks = len(re.findall(
                r'(?:mutex_unlock|spin_unlock|up|unlock)\s*\(', added_text
            ))
            removed_locks = len(re.findall(
                r'(?:mutex_lock|spin_lock|down|lock)\s*\(', removed_text
            ))
            removed_unlocks = len(re.findall(
                r'(?:mutex_unlock|spin_unlock|up|unlock)\s*\(', removed_text
            ))

            if (added_locks - removed_locks) != (added_unlocks - removed_unlocks):
                risks.append(RegressionRisk(
                    risk_level=RiskLevel.HIGH,
                    category="资源管理变更",
                    file_path=pf.target_path,
                    description=(
                        "锁的获取与释放操作不对称，可能导致死锁或竞态"
                    ),
                    affected_scope=hunk.section_header or "未知",
                    evidence=(
                        f"新增 lock/unlock: +{added_locks}/-{added_unlocks}, "
                        f"移除 lock/unlock: +{removed_locks}/-{removed_unlocks}"
                    ),
                ))

        return risks

    # ── 错误处理路径变更 ──

    def _check_error_handling_changes(
        self, pf: PatchedFile
    ) -> List[RegressionRisk]:
        """检测错误处理路径变更。"""
        risks = []

        for hunk in pf.hunks:
            removed_text = "\n".join(hunk.removed_lines)

            removed_error_handling = re.findall(
                r'(?:if\s*\(.*err|goto\s+\w*(?:err|out|fail|cleanup))',
                removed_text, re.IGNORECASE,
            )
            if removed_error_handling:
                added_text = "\n".join(hunk.added_lines)
                added_error_handling = re.findall(
                    r'(?:if\s*\(.*err|goto\s+\w*(?:err|out|fail|cleanup))',
                    added_text, re.IGNORECASE,
                )
                if len(added_error_handling) < len(removed_error_handling):
                    risks.append(RegressionRisk(
                        risk_level=RiskLevel.MEDIUM,
                        category="错误处理变更",
                        file_path=pf.target_path,
                        description=(
                            f"移除了 {len(removed_error_handling)} 处错误处理逻辑，"
                            f"仅新增 {len(added_error_handling)} 处，"
                            "可能遗漏错误路径"
                        ),
                        affected_scope=hunk.section_header or "未知",
                        evidence=f"移除: {removed_error_handling}",
                    ))

        return risks

    # ── 跨文件影响分析 ──

    def _check_cross_file_impact(
        self, patched_files: List[PatchedFile]
    ) -> List[RegressionRisk]:
        """分析跨文件影响。"""
        risks = []

        header_files = [
            pf for pf in patched_files
            if re.search(r'\.(h|hpp|hxx)$', pf.target_path)
        ]
        source_files = [
            pf for pf in patched_files
            if not re.search(r'\.(h|hpp|hxx)$', pf.target_path)
        ]

        if header_files and not source_files:
            risks.append(RegressionRisk(
                risk_level=RiskLevel.MEDIUM,
                category="跨文件影响",
                file_path=", ".join(h.target_path for h in header_files),
                description=(
                    "仅修改了头文件而未修改对应源文件，"
                    "需确认所有引用该头文件的编译单元不受影响"
                ),
                affected_scope="所有包含被修改头文件的源文件",
            ))

        if len(patched_files) > 5:
            risks.append(RegressionRisk(
                risk_level=RiskLevel.LOW,
                category="跨文件影响",
                file_path="(多文件)",
                description=(
                    f"补丁涉及 {len(patched_files)} 个文件，"
                    "变更范围较广，建议进行集成回归测试"
                ),
                affected_scope="多模块",
            ))

        return risks

    # ── 工具方法 ──

    @staticmethod
    def _extract_function_signatures(lines: List[str]) -> List[str]:
        """从代码行中提取函数签名。"""
        signatures = []
        pattern = re.compile(
            r'^[\w\s\*]+\s+(\w+)\s*\([^)]*\)',
        )
        for line in lines:
            match = pattern.match(line.strip())
            if match:
                signatures.append(line.strip())
        return signatures

    @staticmethod
    def _extract_func_name(signature: str) -> str:
        """从函数签名中提取函数名。"""
        match = re.search(r'(\w+)\s*\(', signature)
        return match.group(1) if match else ""
