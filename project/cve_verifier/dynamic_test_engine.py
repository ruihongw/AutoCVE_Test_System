"""
动态测试引擎 (Dynamic Test Engine)

协调环境管理器与回归执行器，在隔离沙箱中完成:
  1. 漏洞触发测试 — 运行 PoC 验证漏洞是否已修复
  2. 基础功能回归 — 确保核心功能不因补丁受损
"""

import logging
import sys
from typing import Optional

from .models import (
    VerificationTask, DynamicTestResult, TestCaseResult,
    TestOutcome,
)
from .environment_manager import EnvironmentManager
from .regression_runner import RegressionRunner

logger = logging.getLogger(__name__)


class DynamicTestEngine:
    """
    动态测试引擎

    在完全隔离的环境中部署修复后的软件包，
    执行漏洞触发验证和基础功能回归。
    """

    def __init__(
        self,
        env_manager: Optional[EnvironmentManager] = None,
        regression_runner: Optional[RegressionRunner] = None,
    ):
        self._env_manager = env_manager or EnvironmentManager()
        self._regression_runner = regression_runner or RegressionRunner()

    # ----------------------------------------------------------------
    #  公开接口
    # ----------------------------------------------------------------

    def run(self, task: VerificationTask) -> DynamicTestResult:
        """
        执行完整的动态测试流程。

        流程:
          1. 创建隔离沙箱
          2. 部署修复后的软件包
          3. 执行漏洞触发测试（若有 PoC）
          4. 执行基础功能回归
          5. 收集结果
          6. 销毁沙箱（无论成败）

        Args:
            task: 验证任务上下文

        Returns:
            DynamicTestResult
        """
        sandbox_id = None
        result = DynamicTestResult()

        # ────────────────────────────────────────────────
        # 平台检测: 非 Linux 环境跳过所有动态测试
        # ────────────────────────────────────────────────
        if sys.platform != "linux":
            logger.warning(
                "当前为 %s 环境，所有动态测试跳过（需在 Linux 内核环境下执行）",
                sys.platform,
            )
            platform_notice = (
                f"当前为 {sys.platform} 环境，动态测试需在 Linux "
                "内核环境中执行，已全部跳过。请在 Linux 6.6+ 内核"
                "环境下重新运行以获取真实测试结果。"
            )
            if task.poc_available and task.poc_script_path:
                result.vulnerability_test = TestCaseResult(
                    test_name="漏洞触发验证",
                    outcome=TestOutcome.SKIPPED,
                    details=platform_notice,
                )
            result.overall_outcome = TestOutcome.SKIPPED
            result.summary = (
                f"动态测试已跳过 — {sys.platform} 环境不支持"
                "内核级 PoC 执行和功能回归测试"
            )
            result.environment_info["platform"] = sys.platform
            result.environment_info["skipped_reason"] = "non-linux"
            return result

        try:
            # 步骤 1: 创建沙箱
            logger.info("创建隔离沙箱...")
            sandbox_id = self._env_manager.create(
                self._build_sandbox_config(task)
            )
            result.environment_info["sandbox_id"] = sandbox_id

            # 步骤 2: 部署软件包
            if task.package_path:
                logger.info("部署软件包: %s", task.package_path)
                deploy_ok = self._env_manager.deploy(
                    sandbox_id, task.package_path
                )
                if not deploy_ok:
                    result.overall_outcome = TestOutcome.ERROR
                    result.summary = "软件包部署失败"
                    return result

            # 步骤 3: 漏洞触发测试
            if task.poc_available and task.poc_script_path:
                logger.info("执行漏洞触发测试...")
                result.vulnerability_test = self._run_vulnerability_test(
                    sandbox_id, task
                )

            # 步骤 4: 基础功能回归
            logger.info("执行基础功能回归...")
            result.regression_tests = self._run_regression_tests(
                sandbox_id, task
            )

            # 步骤 5: 汇总结果
            result.overall_outcome = self._determine_overall_outcome(result)
            result.summary = self._generate_summary(result)

        except Exception as e:
            logger.error("动态测试过程中发生错误: %s", e)
            result.overall_outcome = TestOutcome.ERROR
            result.summary = f"测试执行异常: {str(e)}"

        finally:
            # 步骤 6: 确保沙箱销毁
            if sandbox_id:
                logger.info("清理沙箱: %s", sandbox_id)
                try:
                    self._env_manager.destroy(sandbox_id)
                except Exception as cleanup_err:
                    logger.error("沙箱清理失败: %s", cleanup_err)
                    # 尝试强制清理
                    self._env_manager.cleanup_all()

        return result

    # ----------------------------------------------------------------
    #  漏洞触发测试
    # ----------------------------------------------------------------

    def _run_vulnerability_test(
        self, sandbox_id: str, task: VerificationTask
    ) -> TestCaseResult:
        """
        运行 PoC 脚本验证漏洞是否已被修复。

        判定逻辑:
          - PoC 运行后返回非零退出码（触发失败）→ 漏洞已修复 (PASS)
          - PoC 运行后返回零退出码（正常触发）→ 漏洞未修复 (FAIL)
          - 执行超时/异常 → INCONCLUSIVE
        """
        test_result = TestCaseResult(test_name="漏洞触发验证")

        try:
            # 部署 PoC 到沙箱
            poc_deploy_cmd = f"cp {task.poc_script_path} /tmp/poc_test"
            self._env_manager.execute(sandbox_id, poc_deploy_cmd)

            # 赋予执行权限
            self._env_manager.execute(sandbox_id, "chmod +x /tmp/poc_test")

            # 执行 PoC
            exec_result = self._env_manager.execute(
                sandbox_id,
                "/tmp/poc_test",
                timeout=120,
            )

            test_result.stdout = exec_result.get("stdout", "")
            test_result.stderr = exec_result.get("stderr", "")
            test_result.return_code = exec_result.get("return_code", -1)
            test_result.duration_seconds = exec_result.get("duration", 0)

            # 分析结果
            if test_result.return_code != 0:
                test_result.outcome = TestOutcome.PASS
                test_result.details = (
                    "PoC 执行返回非零退出码，漏洞触发失败，表明漏洞已被修复"
                )
            else:
                test_result.outcome = TestOutcome.FAIL
                test_result.details = (
                    "PoC 执行成功（返回 0），漏洞仍可触发，补丁可能未生效"
                )

        except Exception as e:
            test_result.outcome = TestOutcome.INCONCLUSIVE
            test_result.details = f"PoC 执行过程中发生错误: {str(e)}"

        return test_result

    # ----------------------------------------------------------------
    #  基础功能回归
    # ----------------------------------------------------------------

    def _run_regression_tests(
        self, sandbox_id: str, task: VerificationTask
    ) -> list:
        """
        执行基础功能回归测试。

        使用 RegressionRunner 获取该组件的回归测试命令并逐一执行。
        """
        test_commands = self._regression_runner.get_regression_commands(task)
        results = []

        for cmd_info in test_commands:
            test_result = TestCaseResult(
                test_name=cmd_info.get("name", "回归测试"),
            )
            try:
                exec_result = self._env_manager.execute(
                    sandbox_id,
                    cmd_info["command"],
                    timeout=cmd_info.get("timeout", 300),
                )

                test_result.stdout = exec_result.get("stdout", "")
                test_result.stderr = exec_result.get("stderr", "")
                test_result.return_code = exec_result.get("return_code", -1)
                test_result.duration_seconds = exec_result.get("duration", 0)

                test_result.outcome = (
                    TestOutcome.PASS if test_result.return_code == 0
                    else TestOutcome.FAIL
                )

            except Exception as e:
                test_result.outcome = TestOutcome.ERROR
                test_result.details = str(e)

            results.append(test_result)

        return results

    # ----------------------------------------------------------------
    #  结果汇总
    # ----------------------------------------------------------------

    def _determine_overall_outcome(
        self, result: DynamicTestResult
    ) -> TestOutcome:
        """多测试结果综合判定。"""
        outcomes = []

        if result.vulnerability_test:
            outcomes.append(result.vulnerability_test.outcome)
        for rt in result.regression_tests:
            outcomes.append(rt.outcome)

        if not outcomes:
            return TestOutcome.SKIPPED
        if any(o == TestOutcome.FAIL for o in outcomes):
            return TestOutcome.FAIL
        if any(o == TestOutcome.ERROR for o in outcomes):
            return TestOutcome.ERROR
        if any(o == TestOutcome.INCONCLUSIVE for o in outcomes):
            return TestOutcome.INCONCLUSIVE
        if all(o == TestOutcome.PASS for o in outcomes):
            return TestOutcome.PASS
        return TestOutcome.INCONCLUSIVE

    def _generate_summary(self, result: DynamicTestResult) -> str:
        """生成动态测试结果摘要。"""
        parts = []

        if result.vulnerability_test:
            vt = result.vulnerability_test
            parts.append(f"漏洞触发验证: {vt.outcome.value}")

        total_regression = len(result.regression_tests)
        passed = sum(
            1 for t in result.regression_tests if t.outcome == TestOutcome.PASS
        )
        parts.append(f"回归测试: {passed}/{total_regression} 通过")
        parts.append(f"综合结果: {result.overall_outcome.value}")

        return "，".join(parts)

    # ----------------------------------------------------------------
    #  工具方法
    # ----------------------------------------------------------------

    @staticmethod
    def _build_sandbox_config(task: VerificationTask) -> dict:
        """根据任务特征构建沙箱配置。"""
        config = {
            "memory_limit": "2G",
            "cpu_limit": 2,
            "network": "isolated",
            "disk_limit": "10G",
            "timeout": 600,
            "labels": {
                "task_id": task.task_id,
                "cve_id": task.cve_meta.cve_id,
            },
        }
        # 网络类漏洞可能需要受限网络
        from .models import AttackVector
        if task.cve_meta.attack_vector == AttackVector.NETWORK:
            config["network"] = "restricted"

        return config
