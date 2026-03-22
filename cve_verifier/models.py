"""
数据模型定义

定义贯穿整个验证流水线的核心数据结构，保障模块间数据传递的类型安全与一致性。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime


# ============================================================
#  枚举类型
# ============================================================

class VerificationRoute(Enum):
    """验证路径枚举"""
    DYNAMIC_ONLY = "dynamic_only"          # 仅动态测试
    CODE_REVIEW_ONLY = "code_review_only"  # 仅代码检视
    HYBRID = "hybrid"                      # 双路径结合


class AttackVector(Enum):
    """攻击向量类型"""
    NETWORK = "network"
    ADJACENT = "adjacent"
    LOCAL = "local"
    PHYSICAL = "physical"
    UNKNOWN = "unknown"


class Severity(Enum):
    """漏洞严重等级"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """衍生风险等级"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class SandboxBackend(Enum):
    """沙箱隔离后端类型"""
    CONTAINER = "container"
    VIRTUAL_MACHINE = "virtual_machine"
    CHROOT = "chroot"
    NAMESPACE = "namespace"


class TestOutcome(Enum):
    """测试结果枚举"""
    PASS = "pass"               # 验证通过（漏洞已修复 / 功能正常）
    FAIL = "fail"               # 验证失败（漏洞未修复 / 功能受损）
    ERROR = "error"             # 执行错误
    SKIPPED = "skipped"         # 跳过
    INCONCLUSIVE = "inconclusive"  # 无法确定


# ============================================================
#  CVE 元数据
# ============================================================

@dataclass
class CVEMeta:
    """CVE 漏洞元数据"""
    cve_id: str                                    # CVE 编号, e.g. CVE-2024-1234
    description: str = ""                          # 漏洞描述
    severity: Severity = Severity.UNKNOWN          # 严重等级
    cvss_score: float = 0.0                        # CVSS 评分
    attack_vector: AttackVector = AttackVector.UNKNOWN  # 攻击向量
    affected_component: str = ""                   # 受影响组件/包名
    affected_versions: List[str] = field(default_factory=list)  # 受影响版本
    cwe_id: str = ""                               # CWE 分类
    references: List[str] = field(default_factory=list)  # 参考链接
    extra: Dict[str, Any] = field(default_factory=dict)  # 扩展字段


# ============================================================
#  补丁信息
# ============================================================

@dataclass
class DiffHunk:
    """单个 diff hunk（代码变更块）"""
    source_start: int = 0       # 原文件起始行
    source_length: int = 0      # 原文件行数
    target_start: int = 0       # 新文件起始行
    target_length: int = 0      # 新文件行数
    section_header: str = ""    # 节标题（函数名等）
    added_lines: List[str] = field(default_factory=list)    # 新增行
    removed_lines: List[str] = field(default_factory=list)  # 删除行
    context_lines: List[str] = field(default_factory=list)  # 上下文行
    raw_content: str = ""       # 原始 hunk 内容


@dataclass
class PatchedFile:
    """单个被补丁修改的文件"""
    source_path: str = ""       # 原路径 (a/...)
    target_path: str = ""       # 新路径 (b/...)
    is_new: bool = False        # 是否为新增文件
    is_deleted: bool = False    # 是否为删除文件
    is_renamed: bool = False    # 是否为重命名
    hunks: List[DiffHunk] = field(default_factory=list)
    total_additions: int = 0
    total_deletions: int = 0


@dataclass
class PatchInfo:
    """补丁完整信息"""
    patch_file_path: str = ""                     # 补丁文件路径
    raw_content: str = ""                         # 原始补丁内容
    patched_files: List[PatchedFile] = field(default_factory=list)
    total_files_changed: int = 0
    total_additions: int = 0
    total_deletions: int = 0


# ============================================================
#  验证任务
# ============================================================

@dataclass
class VerificationTask:
    """完整的验证任务上下文"""
    task_id: str = ""                              # 任务唯一标识
    cve_meta: CVEMeta = field(default_factory=lambda: CVEMeta(cve_id=""))
    patch_info: PatchInfo = field(default_factory=PatchInfo)
    package_path: str = ""                         # 修复后软件包路径
    poc_script_path: Optional[str] = None          # PoC 验证脚本路径
    poc_available: bool = False                    # 是否有可用 PoC
    extra_scripts: List[str] = field(default_factory=list)  # 额外验证脚本
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================
#  分流决策
# ============================================================

@dataclass
class RoutingScore:
    """分流评分维度明细"""
    poc_availability: float = 0.0          # PoC 可用性评分 [0, 1]
    attack_surface_reachability: float = 0.0  # 攻击面可达性评分 [0, 1]
    trigger_complexity: float = 0.0        # 触发难度评分 [0, 1] (越高越难触发)
    patch_complexity: float = 0.0          # 补丁复杂度评分 [0, 1]
    reasoning: Dict[str, str] = field(default_factory=dict)  # 各维度评判理由
    ai_trigger_assessment: Optional[Dict] = None  # LLM 触发可行性评估


@dataclass
class RoutingDecision:
    """分流决策结果"""
    route: VerificationRoute = VerificationRoute.HYBRID
    scores: RoutingScore = field(default_factory=RoutingScore)
    dynamic_weight: float = 0.5    # 动态测试权重
    review_weight: float = 0.5     # 代码检视权重
    rationale: str = ""            # 决策综合说明


# ============================================================
#  代码检视结果
# ============================================================

@dataclass
class RegressionRisk:
    """单条衍生风险条目"""
    risk_level: RiskLevel = RiskLevel.NONE
    category: str = ""              # 风险分类
    file_path: str = ""             # 涉及文件
    description: str = ""           # 风险描述
    affected_scope: str = ""        # 影响范围
    evidence: str = ""              # 证据/代码片段


@dataclass
class PatchAssessment:
    """单个补丁文件的评估"""
    file_path: str = ""
    relevance_to_cve: str = ""      # 与 CVE 的关联性说明
    fix_approach: str = ""          # 修复手段描述
    logic_soundness: str = ""       # 逻辑合理性评估
    completeness: str = ""          # 补丁完整性评估
    concerns: List[str] = field(default_factory=list)  # 关注要点


@dataclass
class CodeReviewResult:
    """代码检视完整结果"""
    overall_assessment: str = ""           # 整体评估结论
    patch_assessments: List[PatchAssessment] = field(default_factory=list)
    regression_risks: List[RegressionRisk] = field(default_factory=list)
    overall_risk_level: RiskLevel = RiskLevel.NONE
    summary: str = ""                      # 简要总结
    details: str = ""                      # 详细分析
    ai_patch_analyses: Optional[List[Dict]] = None  # LLM 逐文件深度分析
    ai_regression_assessment: Optional[Dict] = None  # LLM 衍生风险评估


# ============================================================
#  动态测试结果
# ============================================================

@dataclass
class TestCaseResult:
    """单个测试用例执行结果"""
    test_name: str = ""
    outcome: TestOutcome = TestOutcome.SKIPPED
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    details: str = ""


@dataclass
class DynamicTestResult:
    """动态测试完整结果"""
    vulnerability_test: Optional[TestCaseResult] = None   # 漏洞触发测试
    regression_tests: List[TestCaseResult] = field(default_factory=list)  # 回归测试
    environment_info: Dict[str, str] = field(default_factory=dict)
    sandbox_backend: str = ""
    overall_outcome: TestOutcome = TestOutcome.SKIPPED
    summary: str = ""


# ============================================================
#  综合验证报告
# ============================================================

@dataclass
class VerificationReport:
    """最终综合评估报告"""
    task_id: str = ""
    cve_id: str = ""
    verification_route: VerificationRoute = VerificationRoute.HYBRID
    routing_decision: Optional[RoutingDecision] = None
    code_review_result: Optional[CodeReviewResult] = None
    dynamic_test_result: Optional[DynamicTestResult] = None
    overall_conclusion: str = ""           # 综合结论
    overall_risk_level: RiskLevel = RiskLevel.NONE
    recommendations: List[str] = field(default_factory=list)  # 建议
    ai_conclusion: Optional[Dict] = None   # LLM 综合结论
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
