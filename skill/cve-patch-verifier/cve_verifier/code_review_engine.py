"""
代码检视分析引擎 (Code Review Engine)

三阶段深度代码检视流水线:
  阶段一: 结构化解析 — 将 diff 解析为语义化的修改描述
  阶段二: 补丁逻辑合理性评估 — 分析修复手段与 CVE 的匹配度
  阶段三: 衍生风险评估 — 排查补丁是否改变原有核心逻辑，
          评估引入新问题的可能性
"""

import logging
import re
from typing import List, Tuple, Optional, TYPE_CHECKING

from .models import (
    VerificationTask, CodeReviewResult, PatchAssessment,
    RegressionRisk, RiskLevel, PatchedFile, DiffHunk,
)

if TYPE_CHECKING:
    from .llm_analyzer import LLMAnalyzer

logger = logging.getLogger(__name__)


class CodeReviewEngine:
    """
    代码检视引擎

    对 AI 适配生成的补丁进行深度分析，覆盖逻辑合理性和
    衍生风险两个核心关注维度。支持可选的 LLM 深度语义增强。
    """

    def __init__(self, llm_analyzer: Optional["LLMAnalyzer"] = None):
        """
        Args:
            llm_analyzer: 可选的 LLM 分析器实例。提供时启用 AI 深度检视。
        """
        self._llm = llm_analyzer

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
        regression_risks = self._assess_regression_risks(
            task.patch_info.patched_files, task
        )

        # 阶段四: AI 深度检视 (如果 LLM 可用)
        ai_patch_analyses = None
        ai_regression_assessment = None
        if self._llm and self._llm.is_available:
            logger.info("执行阶段四: AI 深度检视...")
            ai_patch_analyses = self._run_ai_patch_analysis(task)
            ai_regression_assessment = self._run_ai_regression_assessment(task)

        # 综合结论
        overall_risk = self._compute_overall_risk(regression_risks)

        # AI 风险可能提升整体风险等级
        if ai_regression_assessment:
            ai_risk = self._extract_ai_risk_level(ai_regression_assessment)
            if ai_risk and ai_risk.value > overall_risk.value:
                overall_risk = ai_risk

        overall_assessment = self._generate_overall_assessment(
            assessments, regression_risks, overall_risk, task
        )
        summary = self._generate_summary(assessments, regression_risks, overall_risk)

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
    #  阶段一 & 阶段二: 逐文件评估
    # ================================================================

    def _assess_patched_file(
        self, pf: PatchedFile, task: VerificationTask
    ) -> PatchAssessment:
        """对单个被补丁修改的文件进行评估。"""

        # 1. 关联性分析
        relevance = self._analyze_relevance(pf, task)

        # 2. 修复手段识别
        fix_approach = self._identify_fix_approach(pf)

        # 3. 逻辑合理性评估
        logic_soundness = self._evaluate_logic_soundness(pf, task)

        # 4. 补丁完整性评估
        completeness = self._evaluate_completeness(pf, task)

        # 5. 关注要点
        concerns = self._identify_concerns(pf, task)

        return PatchAssessment(
            file_path=pf.target_path,
            relevance_to_cve=relevance,
            fix_approach=fix_approach,
            logic_soundness=logic_soundness,
            completeness=completeness,
            concerns=concerns,
        )

    # ----------------------------------------------------------------
    #  关联性分析
    # ----------------------------------------------------------------

    def _analyze_relevance(
        self, pf: PatchedFile, task: VerificationTask
    ) -> str:
        """分析补丁文件与 CVE 的关联性。"""
        cve = task.cve_meta
        indicators = []

        # 检查文件路径是否与受影响组件相关
        component = cve.affected_component.lower()
        if component and component in pf.target_path.lower():
            indicators.append(f"文件路径包含受影响组件名称 '{cve.affected_component}'")

        # 检查修改内容是否包含 CVE ID 引用
        for hunk in pf.hunks:
            for line in hunk.added_lines:
                if cve.cve_id.lower() in line.lower():
                    indicators.append("新增代码中引用了该 CVE ID")
                    break

        # 检查函数名是否与漏洞描述相关
        desc_keywords = self._extract_keywords(cve.description)
        for hunk in pf.hunks:
            if hunk.section_header:
                header_lower = hunk.section_header.lower()
                matches = [kw for kw in desc_keywords if kw in header_lower]
                if matches:
                    indicators.append(
                        f"修改函数 '{hunk.section_header}' 与漏洞描述关键词匹配: "
                        f"{', '.join(matches)}"
                    )

        if indicators:
            return "高度相关 — " + "; ".join(indicators)
        if pf.is_new:
            return "新增文件，可能为修复所需的辅助代码"
        return "关联性需进一步人工确认"

    # ----------------------------------------------------------------
    #  修复手段识别
    # ----------------------------------------------------------------

    def _identify_fix_approach(self, pf: PatchedFile) -> str:
        """识别补丁使用的修复手段/模式。"""
        patterns_found = []

        all_added = []
        all_removed = []
        for hunk in pf.hunks:
            all_added.extend(hunk.added_lines)
            all_removed.extend(hunk.removed_lines)

        added_text = "\n".join(all_added)
        removed_text = "\n".join(all_removed)

        # 检测常见修复模式
        fix_patterns = self._get_fix_patterns()
        for pattern_name, indicators in fix_patterns.items():
            for indicator in indicators:
                if re.search(indicator, added_text, re.IGNORECASE):
                    patterns_found.append(pattern_name)
                    break

        if pf.is_new:
            patterns_found.append("新增辅助文件")
        if pf.is_deleted:
            patterns_found.append("移除废弃代码")

        if not patterns_found:
            # 尝试简单启发
            if len(all_added) > len(all_removed) * 2:
                patterns_found.append("大量新增代码（可能为防御性加固）")
            elif len(all_removed) > len(all_added) * 2:
                patterns_found.append("大量代码删减（可能为移除有害逻辑）")
            else:
                patterns_found.append("代码重构/替换")

        return "、".join(patterns_found)

    def _get_fix_patterns(self) -> dict:
        """返回常见修复模式及其代码特征标识。"""
        return {
            "输入验证/边界检查": [
                r'if\s*\(.*(?:len|size|count|length|bound)',
                r'(?:check|valid|verify|sanitiz)',
                r'(?:max|min|limit|clamp)\s*\(',
                r'>=?\s*0\s*&&|<=?\s*\w+_(?:MAX|SIZE|LEN)',
            ],
            "空指针/空值防护": [
                r'if\s*\(\s*!?\s*\w+\s*(?:==|!=)\s*(?:NULL|nullptr|None)',
                r'if\s*\(\s*\w+\s*\)',
                r'if\s+not\s+\w+',
            ],
            "权限/访问控制强化": [
                r'(?:permission|privilege|capabilit|access|auth)',
                r'(?:capable|ns_capable|may_\w+)',
                r'(?:check_perm|access_ok)',
            ],
            "内存安全加固": [
                r'(?:kfree|free)\s*\(', r'(?:kmalloc|malloc|calloc)',
                r'(?:memset|memcpy|memmove)',
                r'(?:size_t|ssize_t)',
                r'sizeof\s*\(',
            ],
            "整数溢出防护": [
                r'(?:overflow|underflow)',
                r'(?:check_add|check_mul|safe_)',
                r'INT_MAX|INT_MIN|UINT_MAX|SIZE_MAX',
            ],
            "锁/同步机制修改": [
                r'(?:mutex|spin_lock|rw_lock|semaphore)',
                r'(?:lock|unlock)\s*\(',
                r'(?:atomic_|rcu_)',
            ],
            "错误处理完善": [
                r'(?:goto\s+\w*err|goto\s+\w*out|goto\s+\w*fail)',
                r'(?:return\s+-\w+|return\s+err)',
                r'(?:IS_ERR|PTR_ERR|ERR_PTR)',
            ],
        }

    # ----------------------------------------------------------------
    #  逻辑合理性评估
    # ----------------------------------------------------------------

    def _evaluate_logic_soundness(
        self, pf: PatchedFile, task: VerificationTask
    ) -> str:
        """评估补丁逻辑的合理性。"""
        observations = []

        for hunk in pf.hunks:
            # 检查是否有对称的加/删操作
            if hunk.added_lines and hunk.removed_lines:
                observations.append(self._compare_added_removed(hunk))
            elif hunk.added_lines and not hunk.removed_lines:
                observations.append(
                    f"在 '{hunk.section_header or '未知位置'}' 纯增补代码 "
                    f"({len(hunk.added_lines)} 行)"
                )
            elif hunk.removed_lines and not hunk.added_lines:
                observations.append(
                    f"在 '{hunk.section_header or '未知位置'}' 纯删除代码 "
                    f"({len(hunk.removed_lines)} 行)"
                )

        # 检查补丁与 CVE CWE 类型的一致性
        cwe_check = self._check_cwe_consistency(pf, task)
        if cwe_check:
            observations.append(cwe_check)

        return "; ".join(observations) if observations else "需人工深入审查"

    def _compare_added_removed(self, hunk: DiffHunk) -> str:
        """比较 hunk 中新增与删除代码的差异模式。"""
        added_set = set(line.strip() for line in hunk.added_lines if line.strip())
        removed_set = set(line.strip() for line in hunk.removed_lines if line.strip())

        only_added = added_set - removed_set
        only_removed = removed_set - added_set

        location = hunk.section_header or f"L{hunk.source_start}"

        if not only_added and not only_removed:
            return f"'{location}' 处仅格式/空白变更"

        return (
            f"'{location}' 处替换了 {len(only_removed)} 行为 {len(only_added)} 行新代码"
        )

    def _check_cwe_consistency(
        self, pf: PatchedFile, task: VerificationTask
    ) -> str:
        """检查补丁手段是否与 CWE 分类一致。"""
        cwe = task.cve_meta.cwe_id.upper() if task.cve_meta.cwe_id else ""
        if not cwe:
            return ""

        # CWE → 期望的修复模式关键字映射
        cwe_fix_hints = {
            "CWE-120": ["bound", "size", "length", "overflow"],     # 缓冲区溢出
            "CWE-125": ["bound", "size", "index", "range"],         # 越界读
            "CWE-787": ["bound", "size", "overflow", "length"],     # 越界写
            "CWE-416": ["free", "null", "use_after", "rcu"],        # UAF
            "CWE-476": ["null", "nullptr", "check", "valid"],       # 空指针解引用
            "CWE-190": ["overflow", "max", "check", "safe_"],       # 整数溢出
            "CWE-362": ["lock", "mutex", "atomic", "synchroni"],    # 竞态条件
            "CWE-863": ["permission", "access", "auth", "capab"],   # 授权缺陷
        }

        expected_keywords = cwe_fix_hints.get(cwe, [])
        if not expected_keywords:
            return ""

        added_text = " ".join(
            line for hunk in pf.hunks for line in hunk.added_lines
        ).lower()

        found = [kw for kw in expected_keywords if kw in added_text]
        if found:
            return f"补丁包含与 {cwe} 对应的修复特征: {', '.join(found)}"
        return f"补丁中未明确检测到与 {cwe} 直接关联的修复特征，建议人工确认"

    # ----------------------------------------------------------------
    #  补丁完整性评估
    # ----------------------------------------------------------------

    def _evaluate_completeness(
        self, pf: PatchedFile, task: VerificationTask
    ) -> str:
        """评估补丁是否完整覆盖了修复范围。"""
        observations = []

        # 检查是否有 TODO / FIXME / HACK 遗留
        for hunk in pf.hunks:
            for line in hunk.added_lines:
                if re.search(r'\b(TODO|FIXME|HACK|XXX|WORKAROUND)\b',
                             line, re.IGNORECASE):
                    observations.append(
                        f"新增代码包含待办标记: '{line.strip()[:80]}'"
                    )

        # 检查错误路径覆盖
        error_path_check = self._check_error_path_coverage(pf)
        if error_path_check:
            observations.append(error_path_check)

        if not observations:
            return "未发现明显的完整性缺陷"
        return "; ".join(observations)

    def _check_error_path_coverage(self, pf: PatchedFile) -> str:
        """检查新增代码中的错误路径是否有适当处理。"""
        for hunk in pf.hunks:
            added_text = "\n".join(hunk.added_lines)

            # 检测资源分配但缺少对应释放
            alloc_patterns = [
                r'(?:malloc|calloc|kmalloc|kzalloc|alloc_\w+)\s*\(',
                r'(?:fopen|open)\s*\(',
            ]
            free_patterns = [
                r'(?:free|kfree|release|close|fclose)\s*\(',
            ]

            has_alloc = any(
                re.search(p, added_text) for p in alloc_patterns
            )
            has_free = any(
                re.search(p, added_text) for p in free_patterns
            )

            if has_alloc and not has_free:
                return "新增了资源分配操作，但未检测到对应的释放操作，需确认错误路径中的资源清理"

        return ""

    # ----------------------------------------------------------------
    #  关注要点
    # ----------------------------------------------------------------

    def _identify_concerns(
        self, pf: PatchedFile, task: VerificationTask
    ) -> List[str]:
        """识别需要额外关注的要点。"""
        concerns = []

        # 大规模变更
        total_changes = pf.total_additions + pf.total_deletions
        if total_changes > 100:
            concerns.append(
                f"单文件变更量较大 ({pf.total_additions}+/{pf.total_deletions}-), "
                f"建议仔细检视"
            )

        # 仅删除，不新增
        if pf.total_deletions > 0 and pf.total_additions == 0:
            concerns.append("仅删除代码，需确认删除内容不影响正常功能")

        # 涉及头文件/接口定义
        if re.search(r'\.(h|hpp|hxx)$', pf.target_path):
            concerns.append("修改了头文件/接口定义，可能影响其他编译单元")

        # 配置/构建文件
        if re.search(r'(Makefile|CMakeLists|Kconfig|\.conf)', pf.target_path):
            concerns.append("修改了构建/配置文件，可能影响编译与部署流程")

        return concerns

    # ================================================================
    #  阶段三: 衍生风险评估
    # ================================================================

    def _assess_regression_risks(
        self, patched_files: List[PatchedFile], task: VerificationTask
    ) -> List[RegressionRisk]:
        """
        全面排查补丁可能引入的衍生风险（防劣化）。

        分析维度:
          - 函数签名/接口变更
          - 控制流改变
          - 数据流约束变更
          - 资源管理变更
          - 错误处理路径变更
          - 跨文件影响
        """
        risks: List[RegressionRisk] = []

        for pf in patched_files:
            # 1. 函数签名变更检测
            risks.extend(self._check_signature_changes(pf))

            # 2. 控制流变更检测
            risks.extend(self._check_control_flow_changes(pf))

            # 3. 数据流约束变更
            risks.extend(self._check_data_flow_changes(pf))

            # 4. 资源管理变更
            risks.extend(self._check_resource_management_changes(pf))

            # 5. 错误处理路径变更
            risks.extend(self._check_error_handling_changes(pf))

        # 6. 跨文件影响分析
        risks.extend(self._check_cross_file_impact(patched_files))

        return risks

    def _check_signature_changes(self, pf: PatchedFile) -> List[RegressionRisk]:
        """检测函数签名或结构体定义变更。"""
        risks = []
        for hunk in pf.hunks:
            # 检查删除行中的函数声明
            removed_funcs = self._extract_function_signatures(hunk.removed_lines)
            added_funcs = self._extract_function_signatures(hunk.added_lines)

            for old_sig in removed_funcs:
                # 查找对应的新签名
                old_name = self._extract_func_name(old_sig)
                matching_new = [
                    s for s in added_funcs
                    if self._extract_func_name(s) == old_name
                ]
                if matching_new:
                    # 签名存在但有变更
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
                    # 函数被移除
                    risks.append(RegressionRisk(
                        risk_level=RiskLevel.HIGH,
                        category="函数移除",
                        file_path=pf.target_path,
                        description=f"函数 '{old_name}' 被移除，可能导致链接/调用失败",
                        affected_scope="所有依赖该函数的模块",
                        evidence=f"已移除: {old_sig.strip()}",
                    ))

        return risks

    def _check_control_flow_changes(self, pf: PatchedFile) -> List[RegressionRisk]:
        """检测控制流结构变更。"""
        risks = []

        for hunk in pf.hunks:
            added_text = "\n".join(hunk.added_lines)
            removed_text = "\n".join(hunk.removed_lines)

            # 检查 return 语句变更
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

            # 检查新增的提前返回
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

            # 检查 goto 语句变更
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

    def _check_data_flow_changes(self, pf: PatchedFile) -> List[RegressionRisk]:
        """检测数据流约束变更。"""
        risks = []

        for hunk in pf.hunks:
            added_text = "\n".join(hunk.added_lines)

            # 检查类型转换
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

    def _check_resource_management_changes(
        self, pf: PatchedFile
    ) -> List[RegressionRisk]:
        """检测资源管理（内存/锁/文件描述符）变更。"""
        risks = []

        for hunk in pf.hunks:
            added_text = "\n".join(hunk.added_lines)
            removed_text = "\n".join(hunk.removed_lines)

            # 锁操作变更
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

    def _check_error_handling_changes(
        self, pf: PatchedFile
    ) -> List[RegressionRisk]:
        """检测错误处理路径变更。"""
        risks = []

        for hunk in pf.hunks:
            removed_text = "\n".join(hunk.removed_lines)

            # 检查是否移除了错误处理代码
            removed_error_handling = re.findall(
                r'(?:if\s*\(.*err|goto\s+\w*(?:err|out|fail|cleanup))',
                removed_text, re.IGNORECASE,
            )
            if removed_error_handling:
                # 验证是否有对应的替代
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

    def _check_cross_file_impact(
        self, patched_files: List[PatchedFile]
    ) -> List[RegressionRisk]:
        """分析跨文件影响。"""
        risks = []

        # 检查是否修改了头文件
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

        # 检查是否修改了多个相互关联的文件
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

    # ================================================================
    #  综合结论生成
    # ================================================================

    def _compute_overall_risk(
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

    def _generate_overall_assessment(
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

        # 高风险项提示
        high_risks = [r for r in risks if r.risk_level == RiskLevel.HIGH]
        if high_risks:
            lines.append("### ⚠ 高风险项")
            for r in high_risks:
                lines.append(f"- [{r.category}] {r.description}")
            lines.append("")

        # 各文件关注要点
        concerned_files = [a for a in assessments if a.concerns]
        if concerned_files:
            lines.append("### 关注要点")
            for a in concerned_files:
                for c in a.concerns:
                    lines.append(f"- `{a.file_path}`: {c}")

        return "\n".join(lines)

    def _generate_summary(
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

    # ================================================================
    #  工具方法
    # ================================================================

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        """从文本中提取有意义的关键词（>= 4 字符）。"""
        words = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{3,}', text.lower())
        # 过滤常见停用词
        stopwords = {
            'that', 'this', 'with', 'from', 'have', 'been', 'could',
            'would', 'should', 'which', 'their', 'there', 'when',
            'where', 'what', 'will', 'more', 'also', 'than', 'into',
            'does', 'were', 'allows', 'before', 'after', 'other',
        }
        return [w for w in set(words) if w not in stopwords]

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

    # ================================================================
    #  阶段四: AI 深度检视
    # ================================================================

    def _run_ai_patch_analysis(
        self, task: VerificationTask
    ) -> Optional[List[dict]]:
        """对每个补丁文件调用 LLM 进行深度语义分析。"""
        results = []
        cve = task.cve_meta

        for pf in task.patch_info.patched_files:
            # 构造 diff 内容
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

    def _run_ai_regression_assessment(
        self, task: VerificationTask
    ) -> Optional[dict]:
        """调用 LLM 对完整补丁进行衍生风险评估。"""
        return self._llm.assess_regression_risk(
            cve_id=task.cve_meta.cve_id,
            description=task.cve_meta.description,
            affected_component=task.cve_meta.affected_component,
            full_diff=task.patch_info.raw_content[:8000],  # 防止过长
        )

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

    @staticmethod
    def _extract_ai_risk_level(ai_assessment: dict) -> Optional[RiskLevel]:
        """从 AI 衍生风险评估结果中提取风险等级。"""
        risks = ai_assessment.get("regression_risks", [])
        if not risks:
            return None
        level_map = {"high": RiskLevel.HIGH, "medium": RiskLevel.MEDIUM, "low": RiskLevel.LOW}
        max_level = RiskLevel.NONE
        for r in risks:
            level = level_map.get(r.get("risk_level", "").lower())
            if level and level.value > max_level.value:
                max_level = level
        return max_level if max_level != RiskLevel.NONE else None
