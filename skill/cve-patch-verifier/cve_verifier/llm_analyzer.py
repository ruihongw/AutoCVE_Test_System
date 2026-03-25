"""
LLM 分析器 (LLM Analyzer)

封装 OpenAI 兼容 API 调用，为 CVE 补丁验证提供深度 AI 推理能力。

功能:
  - 补丁逻辑深度分析  — 语义理解修复手段是否正确
  - 衍生风险 AI 评估   — 推理补丁对原有逻辑的影响
  - 触发可行性评估     — 基于漏洞原理判断动态触发难度
  - 综合结论生成       — 生成有深度的审查意见和建议

设计原则:
  - 优雅降级: API 不可用时返回空结果，不阻断流水线
  - 结构化输出: 要求 LLM 输出 JSON 并进行解析
  - Prompt 工程: 针对补丁审查场景精心设计多套 prompt
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)


# ============================================================
#  配置
# ============================================================

@dataclass
class LLMConfig:
    """LLM 连接配置"""
    api_key: str = ""                           # API 密钥
    base_url: str = "https://api.openai.com/v1" # API 基础 URL (兼容接口)
    model: str = "gpt-4o"                       # 模型名称
    temperature: float = 0.2                    # 温度 (低温度保证分析稳定性)
    max_tokens: int = 4096                      # 最大 token 数
    timeout: int = 300                          # 请求超时秒数
    max_retries: int = 2                        # 最大重试次数
    enabled: bool = True                        # 是否启用 LLM


# ============================================================
#  Prompt 模板
# ============================================================

SYSTEM_PROMPT = """你是一位资深的 Linux 内核与系统安全专家，精通 C/C++ 代码审查和 CVE 漏洞分析。
你的任务是对 AI 自动适配的安全补丁进行专业级代码检视。

分析要求:
1. 基于漏洞原理，判断补丁修复手段是否正确且充分
2. 识别补丁可能引入的衍生问题（功能退化、资源泄漏、逻辑错误等）
3. 评估补丁是否改变了原有模块的核心行为
4. 所有结论必须有代码证据支撑

你必须用中文回答，并按要求的 JSON 格式输出。"""


PATCH_ANALYSIS_PROMPT = """请分析以下 CVE 安全补丁:

## CVE 信息
- CVE ID: {cve_id}
- 描述: {description}
- CWE: {cwe_id}
- 严重等级: {severity}
- CVSS: {cvss_score}
- 攻击向量: {attack_vector}
- 受影响组件: {affected_component}

## 补丁内容 (文件: {file_path})

```diff
{diff_content}
```

请按以下 JSON 格式输出你的分析:

```json
{{
    "fix_correctness": {{
        "is_correct": true/false,
        "confidence": "high/medium/low",
        "reasoning": "修复逻辑是否正确的详细分析...",
        "fix_approach_summary": "简述修复手段..."
    }},
    "patch_completeness": {{
        "is_complete": true/false,
        "missing_aspects": ["遗漏的修复点1", "遗漏的修复点2"],
        "reasoning": "补丁是否完整覆盖了漏洞的所有触发路径..."
    }},
    "code_quality": {{
        "follows_conventions": true/false,
        "style_issues": ["风格问题1"],
        "improvement_suggestions": ["改进建议1"]
    }},
    "semantic_analysis": "对补丁代码的深度语义分析，解释每段变更的目的和效果..."
}}
```"""


REGRESSION_RISK_PROMPT = """请评估以下 CVE 安全补丁的衍生风险（防劣化分析）:

## CVE 信息
- CVE ID: {cve_id}
- 描述: {description}
- 受影响组件: {affected_component}

## 完整补丁内容

```diff
{full_diff}
```

请从以下维度进行衍生风险分析，并按 JSON 格式输出:

```json
{{
    "regression_risks": [
        {{
            "risk_level": "high/medium/low",
            "category": "风险分类（如: 功能退化/性能影响/内存安全/并发安全/接口兼容性）",
            "description": "风险描述...",
            "affected_scope": "影响范围...",
            "evidence": "代码证据...",
            "mitigation": "缓解建议..."
        }}
    ],
    "overall_risk_assessment": "综合风险评估叙述...",
    "core_logic_impact": {{
        "is_core_logic_changed": true/false,
        "explanation": "原有核心逻辑是否被改变的分析..."
    }},
    "recommendations": ["建议1", "建议2"]
}}
```"""


TRIGGER_FEASIBILITY_PROMPT = """请评估以下 CVE 漏洞的动态触发可行性:

## CVE 信息
- CVE ID: {cve_id}
- 描述: {description}
- CWE: {cwe_id}
- 攻击向量: {attack_vector}
- CVSS: {cvss_score}

## 补丁变更摘要
- 变更文件数: {num_files}
- 变更行数: +{additions}/-{deletions}
- 涉及路径: {file_paths}

请按 JSON 格式评估:

```json
{{
    "trigger_feasibility": {{
        "score": 0.0-1.0,
        "difficulty": "easy/medium/hard/very_hard",
        "reasoning": "可触发性的详细分析..."
    }},
    "environment_requirements": {{
        "needs_special_hardware": true/false,
        "needs_specific_kernel": true/false,
        "needs_network_access": true/false,
        "needs_root_privilege": true/false,
        "other_requirements": ["其他条件"]
    }},
    "poc_construction_hints": "如果要构造 PoC，关键步骤提示...",
    "recommended_verification_approach": "dynamic/code_review/hybrid",
    "reasoning": "推荐验证方式的理由..."
}}
```"""


CONCLUSION_PROMPT = """请基于以下验证结果，生成综合评估结论:

## CVE 信息
- CVE ID: {cve_id}
- 描述: {description}
- 严重等级: {severity}

## 代码检视结果
{code_review_summary}

## 衍生风险
{regression_risks_summary}

## 动态测试结果
{dynamic_test_summary}

请按 JSON 格式输出综合评估:

```json
{{
    "overall_verdict": "approve/reject/conditional_approve",
    "confidence": "high/medium/low",
    "summary": "一段话的综合结论...",
    "key_findings": ["核心发现1", "核心发现2"],
    "risks_to_watch": ["需持续关注的风险1"],
    "recommendations": ["改进建议1", "改进建议2"],
    "merge_readiness": "ready/needs_revision/block",
    "merge_readiness_reasoning": "合入就绪度分析..."
}}
```"""


# ============================================================
#  LLM 分析器
# ============================================================

class LLMAnalyzer:
    """
    LLM 分析器

    通过 OpenAI 兼容 API 调用大语言模型，为 CVE 补丁验证
    提供深度语义分析和智能推理能力。

    所有方法均采用优雅降级策略:
    API 调用失败时返回 None，不阻断主流水线。
    """

    def __init__(self, config: Optional[LLMConfig] = None):
        """
        Args:
            config: LLM 配置。未提供或未启用时所有方法直接返回 None。
        """
        self._config = config
        self._client = None

        if config and config.enabled and config.api_key:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=config.api_key,
                    base_url=config.base_url,
                    timeout=config.timeout,
                    max_retries=config.max_retries,
                )
                logger.info(
                    "LLM 分析器已初始化: model=%s, base_url=%s",
                    config.model, config.base_url,
                )
            except ImportError:
                logger.warning("openai 库未安装，LLM 分析功能不可用。请运行: pip install openai")
            except Exception as e:
                logger.warning("LLM 客户端初始化失败: %s", e)

    @property
    def is_available(self) -> bool:
        """LLM 是否可用。"""
        return self._client is not None

    # ----------------------------------------------------------------
    #  补丁逻辑深度分析
    # ----------------------------------------------------------------

    def analyze_patch(
        self,
        cve_id: str,
        description: str,
        cwe_id: str,
        severity: str,
        cvss_score: float,
        attack_vector: str,
        affected_component: str,
        file_path: str,
        diff_content: str,
    ) -> Optional[Dict[str, Any]]:
        """
        对单个文件的补丁进行深度语义分析。

        Args:
            cve_id, description, ...: CVE 元数据
            file_path: 被修改的文件路径
            diff_content: 该文件的 diff 内容

        Returns:
            解析后的分析结果字典，或 None（降级）
        """
        if not self.is_available:
            return None

        prompt = PATCH_ANALYSIS_PROMPT.format(
            cve_id=cve_id,
            description=description,
            cwe_id=cwe_id,
            severity=severity,
            cvss_score=cvss_score,
            attack_vector=attack_vector,
            affected_component=affected_component,
            file_path=file_path,
            diff_content=diff_content,
        )

        return self._call_llm(prompt, context="补丁分析")

    # ----------------------------------------------------------------
    #  衍生风险 AI 评估
    # ----------------------------------------------------------------

    def assess_regression_risk(
        self,
        cve_id: str,
        description: str,
        affected_component: str,
        full_diff: str,
    ) -> Optional[Dict[str, Any]]:
        """
        AI 驱动的衍生风险评估。

        对完整补丁进行语义级分析，推理补丁对原有核心逻辑的影响。
        """
        if not self.is_available:
            return None

        prompt = REGRESSION_RISK_PROMPT.format(
            cve_id=cve_id,
            description=description,
            affected_component=affected_component,
            full_diff=full_diff,
        )

        return self._call_llm(prompt, context="衍生风险评估")

    # ----------------------------------------------------------------
    #  触发可行性评估
    # ----------------------------------------------------------------

    def evaluate_trigger_feasibility(
        self,
        cve_id: str,
        description: str,
        cwe_id: str,
        attack_vector: str,
        cvss_score: float,
        num_files: int,
        additions: int,
        deletions: int,
        file_paths: str,
    ) -> Optional[Dict[str, Any]]:
        """
        基于漏洞原理评估动态触发可行性。
        """
        if not self.is_available:
            return None

        prompt = TRIGGER_FEASIBILITY_PROMPT.format(
            cve_id=cve_id,
            description=description,
            cwe_id=cwe_id,
            attack_vector=attack_vector,
            cvss_score=cvss_score,
            num_files=num_files,
            additions=additions,
            deletions=deletions,
            file_paths=file_paths,
        )

        return self._call_llm(prompt, context="触发可行性评估")

    # ----------------------------------------------------------------
    #  综合结论生成
    # ----------------------------------------------------------------

    def generate_conclusion(
        self,
        cve_id: str,
        description: str,
        severity: str,
        code_review_summary: str,
        regression_risks_summary: str,
        dynamic_test_summary: str,
    ) -> Optional[Dict[str, Any]]:
        """
        基于全部验证结果生成综合评估结论。
        """
        if not self.is_available:
            return None

        prompt = CONCLUSION_PROMPT.format(
            cve_id=cve_id,
            description=description,
            severity=severity,
            code_review_summary=code_review_summary,
            regression_risks_summary=regression_risks_summary,
            dynamic_test_summary=dynamic_test_summary,
        )

        return self._call_llm(prompt, context="综合结论生成")

    # ----------------------------------------------------------------
    #  底层调用
    # ----------------------------------------------------------------

    def _call_llm(
        self, user_prompt: str, context: str = ""
    ) -> Optional[Dict[str, Any]]:
        """
        调用 LLM API 并解析 JSON 响应。

        采用优雅降级: 任何异常仅记录日志并返回 None。
        """
        try:
            logger.info("[LLM] 发起请求: %s ...", context)

            response = self._client.chat.completions.create(
                model=self._config.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self._config.temperature,
                max_tokens=self._config.max_tokens,
            )

            content = response.choices[0].message.content
            logger.debug("[LLM] 原始响应:\n%s", content[:500])

            # 解析 JSON — 尝试从 markdown 代码块中提取
            parsed = self._extract_json(content)
            if parsed:
                logger.info("[LLM] %s 完成，结果已解析", context)
                return parsed
            else:
                logger.warning("[LLM] %s: JSON 解析失败，返回原始文本", context)
                return {"raw_response": content}

        except Exception as e:
            logger.warning("[LLM] %s 调用失败 (优雅降级): %s", context, e)
            return None

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict]:
        """
        从 LLM 响应文本中提取 JSON。

        支持:
          - 纯 JSON 文本
          - Markdown ```json ... ``` 代码块内嵌 JSON
          - 文本中内嵌的 JSON 片段
        """
        import re

        # 尝试 1: 直接解析
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            pass

        # 尝试 2: 提取 markdown json 代码块
        json_blocks = re.findall(r'```json\s*\n(.*?)\n```', text, re.DOTALL)
        for block in json_blocks:
            try:
                return json.loads(block)
            except json.JSONDecodeError:
                continue

        # 尝试 3: 查找最外层的 { ... }
        brace_match = re.search(r'\{.*\}', text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group())
            except json.JSONDecodeError:
                pass

        return None
