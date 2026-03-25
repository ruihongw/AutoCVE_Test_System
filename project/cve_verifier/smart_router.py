"""
智能分流调度器 (Smart Router)

核心决策引擎 — 根据 CVE 特征与验证资源进行多维评估，
决定采用动态测试、代码检视或双路径结合的验证策略。

决策矩阵维度:
  1. PoC 可用性       — 是否提供了可执行验证脚本
  2. 攻击面可达性     — CVE 攻击向量的外部可触发性
  3. 触发条件复杂度   — 是否需要特殊硬件/时序/竞态等条件
  4. 补丁复杂度       — 代码变更规模与结构复杂度
"""

import logging
import re
from typing import Dict, Optional, TYPE_CHECKING

from .models import (
    VerificationTask, RoutingDecision, RoutingScore,
    VerificationRoute, AttackVector,
)

if TYPE_CHECKING:
    from .llm_analyzer import LLMAnalyzer

logger = logging.getLogger(__name__)


class SmartRouter:
    """
    智能分流调度器

    评估验证任务的各项特征指标，通过加权评分矩阵计算
    动态测试可行性得分与代码检视必要性得分，输出最优验证路径。
    """

    # ----------------------------------------------------------------
    #  可配置阈值与权重（可通过外部配置覆盖）
    # ----------------------------------------------------------------

    # 各评估维度在「动态测试可行性」最终得分中的权重
    DIMENSION_WEIGHTS: Dict[str, float] = {
        "poc_availability":          0.40,   # PoC 可用性权重最高
        "attack_surface_reachability": 0.25,
        "trigger_complexity":        0.20,   # 注意: 此维度取反
        "patch_complexity":          0.15,
    }

    # 路径决策阈值
    DYNAMIC_THRESHOLD = 0.65       # 动态可行性 >= 此值 → 可执行动态测试
    CODE_REVIEW_THRESHOLD = 0.35   # 动态可行性 <  此值 → 仅代码检视

    # 补丁复杂度分级阈值
    PATCH_SIMPLE_MAX_FILES = 3
    PATCH_SIMPLE_MAX_LINES = 50
    PATCH_COMPLEX_MIN_FILES = 8
    PATCH_COMPLEX_MIN_LINES = 300

    def __init__(self, llm_analyzer: Optional["LLMAnalyzer"] = None):
        """
        Args:
            llm_analyzer: 可选的 LLM 分析器实例。提供时启用 AI 辅助触发可行性评估。
        """
        self._llm = llm_analyzer

    # ----------------------------------------------------------------
    #  公开接口
    # ----------------------------------------------------------------

    def route(self, task: VerificationTask) -> RoutingDecision:
        """
        对验证任务执行智能分流决策。

        Args:
            task: 已解析的验证任务上下文

        Returns:
            RoutingDecision，包含选定路径、评分明细及决策理由
        """
        scores = self._evaluate_dimensions(task)
        dynamic_feasibility = self._compute_dynamic_feasibility(scores)
        route, rationale = self._decide_route(dynamic_feasibility, scores)

        # 计算两条路径的权重分配
        dynamic_weight, review_weight = self._compute_weights(
            route, dynamic_feasibility
        )

        decision = RoutingDecision(
            route=route,
            scores=scores,
            dynamic_weight=dynamic_weight,
            review_weight=review_weight,
            rationale=rationale,
        )

        logger.info(
            "分流决策: %s (动态=%.2f, 检视=%.2f) | %s",
            route.value, dynamic_weight, review_weight, rationale,
        )
        return decision

    # ----------------------------------------------------------------
    #  维度评估
    # ----------------------------------------------------------------

    def _evaluate_dimensions(self, task: VerificationTask) -> RoutingScore:
        """逐维度评估并生成评分。"""
        reasoning: Dict[str, str] = {}

        # 维度一: PoC 可用性
        poc_score, poc_reason = self._score_poc_availability(task)
        reasoning["poc_availability"] = poc_reason

        # 维度二: 攻击面可达性
        attack_score, attack_reason = self._score_attack_surface(task)
        reasoning["attack_surface_reachability"] = attack_reason

        # 维度三: 触发条件复杂度
        trigger_score, trigger_reason = self._score_trigger_complexity(task)
        reasoning["trigger_complexity"] = trigger_reason

        # 维度四: 补丁复杂度
        patch_score, patch_reason = self._score_patch_complexity(task)
        reasoning["patch_complexity"] = patch_reason

        # AI 辅助触发可行性评估 (可选)
        ai_trigger = None
        if self._llm and self._llm.is_available:
            ai_trigger = self._run_ai_trigger_assessment(task)
            if ai_trigger:
                reasoning["ai_trigger"] = ai_trigger.get(
                    "trigger_feasibility", {}
                ).get("reasoning", "AI 评估已完成")

        return RoutingScore(
            poc_availability=poc_score,
            attack_surface_reachability=attack_score,
            trigger_complexity=trigger_score,
            patch_complexity=patch_score,
            reasoning=reasoning,
            ai_trigger_assessment=ai_trigger,
        )

    def _score_poc_availability(self, task: VerificationTask) -> tuple:
        """
        评估 PoC 可用性。

        - 提供了可执行 PoC 脚本 → 1.0
        - 提供了额外验证脚本但无明确 PoC → 0.5
        - 完全无脚本 → 0.0
        """
        if task.poc_available and task.poc_script_path:
            return 1.0, "提供了可执行的 PoC 验证脚本"
        if task.extra_scripts:
            return 0.5, f"提供了 {len(task.extra_scripts)} 个辅助验证脚本，但无明确 PoC"
        return 0.0, "未提供任何验证脚本"

    def _score_attack_surface(self, task: VerificationTask) -> tuple:
        """
        评估攻击面可达性。

        基于 CVE 攻击向量判断外部可触发的难易程度。
        """
        vector_scores = {
            AttackVector.NETWORK:  1.0,    # 网络可达，最易远程触发
            AttackVector.ADJACENT: 0.7,    # 邻接网络
            AttackVector.LOCAL:    0.4,    # 本地触发
            AttackVector.PHYSICAL: 0.1,    # 物理接触
            AttackVector.UNKNOWN:  0.3,    # 未知，偏保守
        }
        vector = task.cve_meta.attack_vector
        score = vector_scores.get(vector, 0.3)
        reason = f"攻击向量为 {vector.value}，可达性评分 {score:.1f}"
        return score, reason

    def _score_trigger_complexity(self, task: VerificationTask) -> tuple:
        """
        评估触发条件复杂度（得分越高表示触发越困难）。

        通过分析 CVE 描述中的关键词推断触发难度。
        """
        description = (task.cve_meta.description or "").lower()
        cwe = (task.cve_meta.cwe_id or "").lower()

        difficulty = 0.3  # 基准难度
        factors = []

        # 竞态条件 / 时序依赖
        race_patterns = [
            r'race\s+condition', r'toctou', r'time[- ]of[- ]check',
            r'concurren', r'竞态', r'竞争条件',
        ]
        if any(re.search(p, description) for p in race_patterns):
            difficulty += 0.25
            factors.append("涉及竞态/时序条件")

        # 特殊硬件 / 物理依赖
        hardware_patterns = [
            r'hardware', r'firmware', r'device\s+driver',
            r'physical', r'usb', r'pci', r'dma',
            r'硬件', r'固件',
        ]
        if any(re.search(p, description) for p in hardware_patterns):
            difficulty += 0.2
            factors.append("涉及特定硬件/物理设备")

        # 需要特权
        priv_patterns = [
            r'privilege', r'root', r'admin', r'kernel\s+space',
            r'ring\s*0', r'特权', r'内核态',
        ]
        if any(re.search(p, description) for p in priv_patterns):
            difficulty += 0.1
            factors.append("需要特权环境")

        # 内存破坏类（可能难以稳定复现）
        memory_patterns = [
            r'heap', r'buffer\s+overflow', r'use[- ]after[- ]free',
            r'double[- ]free', r'out[- ]of[- ]bound', r'堆', r'溢出',
        ]
        if any(re.search(p, description) for p in memory_patterns):
            difficulty += 0.1
            factors.append("内存破坏类漏洞，复现可能不稳定")

        difficulty = min(difficulty, 1.0)
        reason = "、".join(factors) if factors else "未检测到显著触发障碍"
        return difficulty, reason

    def _score_patch_complexity(self, task: VerificationTask) -> tuple:
        """
        评估补丁复杂度。

        基于文件数量与变更行数综合评估。
        补丁越复杂，代码检视的价值越高。
        """
        pi = task.patch_info
        total_changes = pi.total_additions + pi.total_deletions
        num_files = pi.total_files_changed

        if (num_files <= self.PATCH_SIMPLE_MAX_FILES
                and total_changes <= self.PATCH_SIMPLE_MAX_LINES):
            score = 0.2
            reason = f"补丁规模较小 ({num_files} 文件, {total_changes} 行变更)"
        elif (num_files >= self.PATCH_COMPLEX_MIN_FILES
              or total_changes >= self.PATCH_COMPLEX_MIN_LINES):
            score = 0.9
            reason = f"补丁规模较大 ({num_files} 文件, {total_changes} 行变更)，检视价值高"
        else:
            # 线性插值
            file_ratio = min(num_files / self.PATCH_COMPLEX_MIN_FILES, 1.0)
            line_ratio = min(total_changes / self.PATCH_COMPLEX_MIN_LINES, 1.0)
            score = 0.2 + 0.7 * max(file_ratio, line_ratio)
            reason = f"补丁规模中等 ({num_files} 文件, {total_changes} 行变更)"
        return score, reason

    # ----------------------------------------------------------------
    #  综合决策
    # ----------------------------------------------------------------

    def _compute_dynamic_feasibility(self, scores: RoutingScore) -> float:
        """
        计算动态测试可行性综合得分。

        注意: 触发复杂度维度需要取反（越难触发，动态可行性越低）。
        """
        w = self.DIMENSION_WEIGHTS
        feasibility = (
            w["poc_availability"] * scores.poc_availability
            + w["attack_surface_reachability"] * scores.attack_surface_reachability
            + w["trigger_complexity"] * (1.0 - scores.trigger_complexity)
            + w["patch_complexity"] * (1.0 - scores.patch_complexity)
        )
        return round(feasibility, 4)

    def _decide_route(
        self, feasibility: float, scores: RoutingScore
    ) -> tuple:
        """
        根据动态可行性得分决定验证路径。

        Returns:
            (VerificationRoute, rationale_string)
        """
        if feasibility >= self.DYNAMIC_THRESHOLD:
            # 动态可行性高 — 但如果补丁较复杂，仍启用双路径
            if scores.patch_complexity >= 0.6:
                route = VerificationRoute.HYBRID
                rationale = (
                    f"动态可行性较高 ({feasibility:.2f})，"
                    f"但补丁复杂度 ({scores.patch_complexity:.2f}) 较高，"
                    "启用双路径以确保检视覆盖"
                )
            else:
                route = VerificationRoute.DYNAMIC_ONLY
                rationale = (
                    f"动态可行性高 ({feasibility:.2f})，补丁简洁，"
                    "优先采用动态验证"
                )
        elif feasibility <= self.CODE_REVIEW_THRESHOLD:
            route = VerificationRoute.CODE_REVIEW_ONLY
            rationale = (
                f"动态可行性低 ({feasibility:.2f})，"
                "无法有效构造触发场景，切换为代码检视"
            )
        else:
            route = VerificationRoute.HYBRID
            rationale = (
                f"动态可行性中等 ({feasibility:.2f})，"
                "采用双路径结合以获得更全面的验证覆盖"
            )
        return route, rationale

    def _compute_weights(
        self, route: VerificationRoute, feasibility: float
    ) -> tuple:
        """
        为双路径模式计算各路径权重。

        Returns:
            (dynamic_weight, review_weight)
        """
        if route == VerificationRoute.DYNAMIC_ONLY:
            return 1.0, 0.0
        if route == VerificationRoute.CODE_REVIEW_ONLY:
            return 0.0, 1.0
        # HYBRID: 基于可行性得分动态分配
        dynamic_w = round(feasibility, 2)
        review_w = round(1.0 - dynamic_w, 2)
        return dynamic_w, review_w

    # ----------------------------------------------------------------
    #  AI 辅助评估
    # ----------------------------------------------------------------

    def _run_ai_trigger_assessment(
        self, task: VerificationTask
    ) -> Optional[dict]:
        """调用 LLM 评估漏洞动态触发可行性。"""
        file_paths = ", ".join(
            pf.target_path for pf in task.patch_info.patched_files
        )
        return self._llm.evaluate_trigger_feasibility(
            cve_id=task.cve_meta.cve_id,
            description=task.cve_meta.description,
            cwe_id=task.cve_meta.cwe_id,
            attack_vector=task.cve_meta.attack_vector.value,
            cvss_score=task.cve_meta.cvss_score,
            num_files=task.patch_info.total_files_changed,
            additions=task.patch_info.total_additions,
            deletions=task.patch_info.total_deletions,
            file_paths=file_paths,
        )
