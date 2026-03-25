"""
CVE 补丁自动化验证系统 — 主入口

编排完整的验证流水线:
  输入解析 → 智能分流 → 代码检视/动态测试 → (AI 深度分析) → 报告生成
"""

import argparse
import logging
import os
import sys
from datetime import datetime

from .exceptions import CVEVerifierError

from .models import (
    VerificationReport, VerificationRoute, RiskLevel,
)
from .task_parser import TaskParser
from .smart_router import SmartRouter
from .code_review import CodeReviewEngine
from .dynamic_test_engine import DynamicTestEngine
from .report_generator import ReportGenerator
from .llm_analyzer import LLMAnalyzer, LLMConfig


def setup_logging(verbose: bool = False):
    """配置日志输出。"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _create_llm_analyzer(
    api_key: str = "",
    api_base: str = "",
    model: str = "",
) -> LLMAnalyzer:
    """
    创建 LLM 分析器实例。

    优先级: 命令行参数 > 环境变量 > 默认值
    """
    final_key = api_key or os.environ.get("CVE_VERIFIER_API_KEY", "")
    final_base = (
        api_base
        or os.environ.get("CVE_VERIFIER_API_BASE", "")
        or "https://api.openai.com/v1"
    )
    final_model = (
        model
        or os.environ.get("CVE_VERIFIER_MODEL", "")
        or "gpt-4o"
    )

    config = LLMConfig(
        api_key=final_key,
        base_url=final_base,
        model=final_model,
        enabled=bool(final_key),
    )

    analyzer = LLMAnalyzer(config)

    logger = logging.getLogger("pipeline")
    if analyzer.is_available:
        logger.info("LLM 已启用: model=%s, base=%s", final_model, final_base)
    else:
        if final_key:
            logger.warning("LLM 初始化失败，将以纯规则模式运行")
        else:
            logger.info("未配置 API Key，以纯规则模式运行 (可通过 --api-key 或环境变量 CVE_VERIFIER_API_KEY 启用)")

    return analyzer


def run_pipeline(
    patch_path: str,
    cve_meta_path: str,
    output_path: str = "verification_report.md",
    package_path: str = "",
    poc_script_path: str = "",
    api_key: str = "",
    api_base: str = "",
    model: str = "",
    verbose: bool = False,
) -> VerificationReport:
    """
    执行完整验证流水线。

    Args:
        patch_path:      补丁文件路径
        cve_meta_path:   CVE 元数据 JSON 路径
        output_path:     报告输出路径
        package_path:    修复后软件包路径
        poc_script_path: PoC 脚本路径
        api_key:         LLM API 密钥
        api_base:        LLM API 基础 URL
        model:           LLM 模型名称
        verbose:         是否开启详细日志

    Returns:
        VerificationReport 对象
    """
    setup_logging(verbose)
    logger = logging.getLogger("pipeline")

    logger.info("=" * 60)
    logger.info("CVE 补丁自动化验证系统 v2.0 (AI 增强)")
    logger.info("=" * 60)

    # ── 初始化 LLM ──
    llm_analyzer = _create_llm_analyzer(api_key, api_base, model)

    # ── Step 1: 任务解析 ──
    logger.info("[1/6] 解析输入...")
    parser = TaskParser()
    task = parser.parse(
        patch_path=patch_path,
        cve_meta_path=cve_meta_path,
        package_path=package_path,
        poc_script_path=poc_script_path if poc_script_path else None,
    )
    logger.info(
        "任务 %s: CVE=%s, 补丁文件=%d, PoC=%s",
        task.task_id, task.cve_meta.cve_id,
        task.patch_info.total_files_changed,
        "可用" if task.poc_available else "不可用",
    )

    # ── Step 2: 智能分流 ──
    logger.info("[2/6] 执行智能分流...")
    router = SmartRouter(llm_analyzer=llm_analyzer)
    routing_decision = router.route(task)
    logger.info("分流结果: %s", routing_decision.route.value)

    # ── Step 3: 代码检视 ──
    code_review_result = None
    if routing_decision.route in (
        VerificationRoute.CODE_REVIEW_ONLY,
        VerificationRoute.HYBRID,
    ):
        logger.info("[3/6] 执行代码检视 (含 AI 深度分析)...")
        review_engine = CodeReviewEngine(llm_analyzer=llm_analyzer)
        code_review_result = review_engine.review(task)
        logger.info("代码检视完成: %s", code_review_result.summary)
    else:
        logger.info("[3/6] 跳过代码检视（仅动态路径）")

    # ── Step 4: 动态测试 ──
    dynamic_test_result = None
    if routing_decision.route in (
        VerificationRoute.DYNAMIC_ONLY,
        VerificationRoute.HYBRID,
    ):
        logger.info("[4/6] 执行动态测试...")
        test_engine = DynamicTestEngine()
        dynamic_test_result = test_engine.run(task)
        logger.info("动态测试完成: %s", dynamic_test_result.summary)
    else:
        logger.info("[4/6] 跳过动态测试（仅检视路径）")

    # ── Step 5: AI 综合结论 ──
    ai_conclusion = None
    if llm_analyzer.is_available:
        logger.info("[5/6] 生成 AI 综合结论...")
        ai_conclusion = _generate_ai_conclusion(
            task, code_review_result, dynamic_test_result, llm_analyzer
        )
    else:
        logger.info("[5/6] 跳过 AI 结论（LLM 未启用）")

    # ── Step 6: 报告生成 ──
    logger.info("[6/6] 生成验证报告...")
    report = _build_report(
        task, routing_decision, code_review_result,
        dynamic_test_result, ai_conclusion,
    )

    generator = ReportGenerator()
    generator.generate_and_save(report, output_path)

    logger.info("=" * 60)
    logger.info("验证完成! 报告已保存至: %s", output_path)
    logger.info("综合结论: %s | 风险等级: %s",
                report.overall_conclusion, report.overall_risk_level.value)
    logger.info("=" * 60)

    return report


def _generate_ai_conclusion(task, code_review_result, dynamic_test_result, llm_analyzer):
    """调用 LLM 生成综合结论。"""
    cr_summary = "未执行代码检视"
    if code_review_result:
        cr_summary = code_review_result.summary or code_review_result.overall_assessment

    risk_summary = "未发现衍生风险"
    if code_review_result and code_review_result.regression_risks:
        risk_parts = []
        for r in code_review_result.regression_risks:
            risk_parts.append(f"[{r.risk_level.value}] {r.category}: {r.description}")
        risk_summary = "\n".join(risk_parts)

    dt_summary = "未执行动态测试"
    if dynamic_test_result:
        dt_summary = dynamic_test_result.summary

    return llm_analyzer.generate_conclusion(
        cve_id=task.cve_meta.cve_id,
        description=task.cve_meta.description,
        severity=task.cve_meta.severity.value,
        code_review_summary=cr_summary,
        regression_risks_summary=risk_summary,
        dynamic_test_summary=dt_summary,
    )


def _build_report(
    task, routing_decision, code_review_result,
    dynamic_test_result, ai_conclusion=None,
):
    """构建综合验证报告。"""
    # 确定综合风险等级
    overall_risk = RiskLevel.NONE
    if code_review_result:
        overall_risk = code_review_result.overall_risk_level

    # 构建综合结论
    conclusion_parts = []

    if code_review_result:
        conclusion_parts.append(
            f"代码检视显示补丁涉及 "
            f"{len(code_review_result.patch_assessments)} 个文件，"
            f"发现 {len(code_review_result.regression_risks)} 条衍生风险。"
        )

    if dynamic_test_result:
        conclusion_parts.append(f"动态测试结果: {dynamic_test_result.summary}。")

    # AI 结论融合
    if ai_conclusion and ai_conclusion.get("summary"):
        conclusion_parts.append(f"AI 分析: {ai_conclusion['summary']}")

    overall_conclusion = " ".join(conclusion_parts) if conclusion_parts else "验证已完成。"

    # 建议 (规则 + AI)
    recommendations = _generate_recommendations(
        routing_decision, code_review_result, dynamic_test_result
    )
    if ai_conclusion and ai_conclusion.get("recommendations"):
        for rec in ai_conclusion["recommendations"]:
            if rec not in recommendations:
                recommendations.append(f"[AI] {rec}")

    return VerificationReport(
        task_id=task.task_id,
        cve_id=task.cve_meta.cve_id,
        verification_route=routing_decision.route,
        routing_decision=routing_decision,
        code_review_result=code_review_result,
        dynamic_test_result=dynamic_test_result,
        overall_conclusion=overall_conclusion,
        overall_risk_level=overall_risk,
        recommendations=recommendations,
        ai_conclusion=ai_conclusion,
        generated_at=datetime.now().isoformat(),
    )


def _generate_recommendations(routing_decision, code_review_result, dynamic_test_result):
    """基于验证结果生成建议列表。"""
    recommendations = []

    if code_review_result:
        high_risks = [
            r for r in code_review_result.regression_risks
            if r.risk_level == RiskLevel.HIGH
        ]
        if high_risks:
            recommendations.append(
                "存在高风险衍生问题，建议在合入前进行专项审查和更充分的回归测试。"
            )

        medium_risks = [
            r for r in code_review_result.regression_risks
            if r.risk_level == RiskLevel.MEDIUM
        ]
        if medium_risks:
            recommendations.append(
                f"存在 {len(medium_risks)} 条中风险项，建议开发者逐一确认。"
            )

    if dynamic_test_result:
        from .models import TestOutcome
        if dynamic_test_result.overall_outcome == TestOutcome.FAIL:
            recommendations.append(
                "动态测试存在失败项，须排查后重新验证。"
            )
        elif dynamic_test_result.overall_outcome == TestOutcome.INCONCLUSIVE:
            recommendations.append(
                "部分测试结果不确定，建议人工复核或补充测试用例。"
            )

    if not recommendations:
        recommendations.append("验证未发现显著问题，建议按流程推进合入。")

    return recommendations


def main():
    """命令行入口。"""
    parser = argparse.ArgumentParser(
        description="CVE 补丁自动化验证系统 (AI 增强版)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 纯规则模式
  python -m cve_verifier.main --patch fix.diff --meta cve.json

  # AI 增强模式
  python -m cve_verifier.main --patch fix.diff --meta cve.json --api-key sk-xxx

  # 自定义 API (OpenAI 兼容接口)
  python -m cve_verifier.main --patch fix.diff --meta cve.json \\
      --api-key sk-xxx --api-base https://your-api.com/v1 --model gpt-4o

环境变量:
  CVE_VERIFIER_API_KEY   — LLM API 密钥
  CVE_VERIFIER_API_BASE  — LLM API 基础 URL
  CVE_VERIFIER_MODEL     — LLM 模型名称
        """,
    )
    parser.add_argument(
        "--patch", required=True,
        help="补丁文件路径 (unified diff 格式)",
    )
    parser.add_argument(
        "--meta", required=True,
        help="CVE 元数据 JSON 文件路径",
    )
    parser.add_argument(
        "--package", default="",
        help="修复后软件包路径 (可选)",
    )
    parser.add_argument(
        "--poc", default="",
        help="PoC 验证脚本路径 (可选)",
    )
    parser.add_argument(
        "-o", "--output", default="verification_report.md",
        help="报告输出路径 (默认: verification_report.md)",
    )
    # LLM 配置参数
    parser.add_argument(
        "--api-key", default="",
        help="LLM API 密钥 (或通过 CVE_VERIFIER_API_KEY 环境变量设置)",
    )
    parser.add_argument(
        "--api-base", default="",
        help="LLM API 基础 URL (默认: https://api.openai.com/v1)",
    )
    parser.add_argument(
        "--model", default="",
        help="LLM 模型名称 (默认: gpt-4o)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出详细日志",
    )

    args = parser.parse_args()

    try:
        run_pipeline(
            patch_path=args.patch,
            cve_meta_path=args.meta,
            output_path=args.output,
            package_path=args.package,
            poc_script_path=args.poc,
            api_key=args.api_key,
            api_base=args.api_base,
            model=args.model,
            verbose=args.verbose,
        )
    except FileNotFoundError as e:
        print(f"错误: 文件未找到 — {e}", file=sys.stderr)
        sys.exit(1)
    except CVEVerifierError as e:
        print(f"验证错误: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"未知错误: {e}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
