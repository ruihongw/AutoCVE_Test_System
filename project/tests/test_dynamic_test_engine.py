"""
动态测试引擎与环境管理器单元测试

覆盖沙箱生命周期管理、漏洞触发逻辑和结果汇总。
"""

import unittest

from cve_verifier.models import (
    VerificationTask, CVEMeta, PatchInfo, PatchedFile, DiffHunk,
    AttackVector, Severity, TestOutcome, DynamicTestResult, TestCaseResult,
)
from cve_verifier.environment_manager import (
    EnvironmentManager, DefaultSandboxDriver,
)
from cve_verifier.dynamic_test_engine import DynamicTestEngine


class TestDefaultSandboxDriver(unittest.TestCase):
    """默认沙箱驱动测试"""

    def setUp(self):
        self.driver = DefaultSandboxDriver()

    def test_create_sandbox(self):
        """创建沙箱返回有效 ID"""
        sid = self.driver.create_sandbox({"memory_limit": "1G"})
        self.assertTrue(sid.startswith("sandbox-"))
        self.assertTrue(self.driver.is_sandbox_alive(sid))

    def test_deploy_package(self):
        """部署包到沙箱成功"""
        sid = self.driver.create_sandbox({})
        result = self.driver.deploy_package(sid, "/tmp/pkg.rpm")
        self.assertTrue(result)

    def test_deploy_to_nonexistent(self):
        """部署到不存在的沙箱失败"""
        result = self.driver.deploy_package("fake-id", "/tmp/pkg.rpm")
        self.assertFalse(result)

    def test_execute_command(self):
        """在沙箱中执行命令"""
        sid = self.driver.create_sandbox({})
        result = self.driver.execute_command(sid, "echo test")
        self.assertEqual(result["return_code"], 0)
        self.assertIn("echo test", result["stdout"])

    def test_execute_in_nonexistent(self):
        """在不存在的沙箱中执行返回错误"""
        result = self.driver.execute_command("fake-id", "echo test")
        self.assertEqual(result["return_code"], -1)

    def test_destroy_sandbox(self):
        """销毁沙箱后不再存活"""
        sid = self.driver.create_sandbox({})
        self.assertTrue(self.driver.is_sandbox_alive(sid))
        self.driver.destroy_sandbox(sid)
        self.assertFalse(self.driver.is_sandbox_alive(sid))

    def test_destroy_idempotent(self):
        """多次销毁同一沙箱不报错"""
        sid = self.driver.create_sandbox({})
        self.driver.destroy_sandbox(sid)
        result = self.driver.destroy_sandbox(sid)
        self.assertTrue(result)

    def test_collect_artifacts(self):
        """收集产物返回映射"""
        sid = self.driver.create_sandbox({})
        result = self.driver.collect_artifacts(sid, ["/var/log/test.log"])
        self.assertIn("/var/log/test.log", result)


class TestEnvironmentManager(unittest.TestCase):
    """环境管理器测试"""

    def setUp(self):
        self.manager = EnvironmentManager()

    def test_create_and_destroy(self):
        """创建和销毁沙箱"""
        sid = self.manager.create()
        self.assertTrue(len(sid) > 0)
        self.assertTrue(self.manager.destroy(sid))

    def test_cleanup_all(self):
        """全量清理所有活跃沙箱"""
        self.manager.create()
        self.manager.create()
        self.manager.cleanup_all()
        self.assertEqual(len(self.manager._active_sandboxes), 0)

    def test_execute_in_sandbox(self):
        """在沙箱中执行命令"""
        sid = self.manager.create()
        result = self.manager.execute(sid, "ls /tmp")
        self.assertEqual(result["return_code"], 0)


class TestDynamicTestEngine(unittest.TestCase):
    """动态测试引擎测试"""

    def _make_task(self, poc_available=False, package_path="") -> VerificationTask:
        return VerificationTask(
            task_id="TEST-DYN-001",
            cve_meta=CVEMeta(
                cve_id="CVE-2024-0001",
                description="test vulnerability",
                severity=Severity.HIGH,
                attack_vector=AttackVector.LOCAL,
            ),
            patch_info=PatchInfo(
                patched_files=[PatchedFile(
                    target_path="src/main.c",
                    hunks=[DiffHunk(added_lines=["fix"])],
                    total_additions=1,
                )],
                total_files_changed=1,
                total_additions=1,
            ),
            poc_available=poc_available,
            poc_script_path="/tmp/poc.sh" if poc_available else None,
            package_path=package_path,
        )

    def test_run_without_poc(self):
        """无 PoC 时跳过漏洞触发测试"""
        engine = DynamicTestEngine()
        task = self._make_task(poc_available=False)
        result = engine.run(task)
        self.assertIsNone(result.vulnerability_test)

    def test_run_with_poc(self):
        """有 PoC 时执行漏洞触发测试"""
        engine = DynamicTestEngine()
        task = self._make_task(poc_available=True)
        result = engine.run(task)
        # 默认驱动模拟执行返回 0 → PoC 触发成功 → FAIL (漏洞未修复)
        self.assertIsNotNone(result.vulnerability_test)

    def test_run_with_package(self):
        """有软件包时执行部署"""
        engine = DynamicTestEngine()
        task = self._make_task(package_path="/tmp/pkg.rpm")
        result = engine.run(task)
        self.assertIn("sandbox_id", result.environment_info)

    def test_determine_overall_outcome_all_pass(self):
        """全部通过时综合结果为 PASS"""
        engine = DynamicTestEngine()
        result = DynamicTestResult(
            vulnerability_test=TestCaseResult(
                test_name="PoC", outcome=TestOutcome.PASS),
            regression_tests=[
                TestCaseResult(test_name="回归1", outcome=TestOutcome.PASS),
            ],
        )
        outcome = engine._determine_overall_outcome(result)
        self.assertEqual(outcome, TestOutcome.PASS)

    def test_determine_overall_outcome_has_fail(self):
        """存在失败时综合结果为 FAIL"""
        engine = DynamicTestEngine()
        result = DynamicTestResult(
            regression_tests=[
                TestCaseResult(test_name="回归1", outcome=TestOutcome.PASS),
                TestCaseResult(test_name="回归2", outcome=TestOutcome.FAIL),
            ],
        )
        outcome = engine._determine_overall_outcome(result)
        self.assertEqual(outcome, TestOutcome.FAIL)

    def test_determine_overall_outcome_empty(self):
        """无测试结果时为 SKIPPED"""
        engine = DynamicTestEngine()
        result = DynamicTestResult()
        outcome = engine._determine_overall_outcome(result)
        self.assertEqual(outcome, TestOutcome.SKIPPED)

    def test_sandbox_cleanup_on_success(self):
        """成功后沙箱被清理"""
        driver = DefaultSandboxDriver()
        manager = EnvironmentManager(driver=driver)
        engine = DynamicTestEngine(env_manager=manager)
        task = self._make_task()
        engine.run(task)
        # 沙箱应已被清理
        self.assertEqual(len(manager._active_sandboxes), 0)


if __name__ == "__main__":
    unittest.main()
