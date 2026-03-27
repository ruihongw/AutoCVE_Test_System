"""
Linux 沙箱驱动测试

- Linux 上: 真实创建/销毁沙箱、执行命令、验证 stdout 和 return_code
- Windows 上: 自动跳过所有 Linux 专属测试

同时测试 EnvironmentManager 的平台自动检测逻辑。
"""

import os
import sys
import tempfile
import unittest

from cve_verifier.environment_manager import (
    EnvironmentManager, DefaultSandboxDriver,
)


class TestPlatformDetection(unittest.TestCase):
    """平台自动检测测试（所有平台均可运行）"""

    def test_explicit_driver_takes_priority(self):
        """显式传入驱动时不触发自动检测"""
        mock_driver = DefaultSandboxDriver()
        mgr = EnvironmentManager(driver=mock_driver)
        self.assertIs(mgr.driver, mock_driver)
        self.assertFalse(mgr.is_real_sandbox)

    def test_auto_detection_selects_default_on_windows(self):
        """Windows 平台应选择默认模拟驱动"""
        if sys.platform == "linux":
            self.skipTest("仅在非 Linux 平台测试")
        mgr = EnvironmentManager()
        self.assertIsInstance(mgr.driver, DefaultSandboxDriver)
        self.assertFalse(mgr.is_real_sandbox)

    def test_auto_detection_selects_linux_on_linux(self):
        """Linux 平台应选择 LinuxSandboxDriver"""
        if sys.platform != "linux":
            self.skipTest("仅在 Linux 平台测试")
        from cve_verifier.linux_sandbox_driver import LinuxSandboxDriver
        mgr = EnvironmentManager()
        self.assertIsInstance(mgr.driver, LinuxSandboxDriver)
        self.assertTrue(mgr.is_real_sandbox)


@unittest.skipUnless(sys.platform == "linux", "Linux 沙箱测试仅在 Linux 上运行")
class TestLinuxSandboxDriver(unittest.TestCase):
    """Linux 真实沙箱驱动测试"""

    def setUp(self):
        from cve_verifier.linux_sandbox_driver import LinuxSandboxDriver
        self._test_base = tempfile.mkdtemp(prefix="test_sandbox_")
        self.driver = LinuxSandboxDriver(base_dir=self._test_base)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._test_base, ignore_errors=True)

    def test_create_sandbox(self):
        """创建沙箱返回有效 ID"""
        sid = self.driver.create_sandbox({"memory_limit": "1G"})
        self.assertTrue(sid.startswith("sandbox-"))
        self.assertTrue(self.driver.is_sandbox_alive(sid))

    def test_sandbox_directory_created(self):
        """创建沙箱后应存在对应目录"""
        sid = self.driver.create_sandbox({})
        sandbox_dir = os.path.join(self._test_base, sid)
        self.assertTrue(os.path.isdir(sandbox_dir))
        # 验证子目录
        for subdir in ("bin", "tmp", "logs", "packages"):
            self.assertTrue(
                os.path.isdir(os.path.join(sandbox_dir, subdir))
            )

    def test_execute_echo(self):
        """在沙箱中执行 echo 并验证 stdout"""
        sid = self.driver.create_sandbox({})
        result = self.driver.execute_command(sid, 'echo "hello sandbox"')
        self.assertEqual(result["return_code"], 0)
        self.assertIn("hello sandbox", result["stdout"])
        self.assertGreater(result["duration"], 0)

    def test_execute_captures_stderr(self):
        """捕获 stderr"""
        sid = self.driver.create_sandbox({})
        result = self.driver.execute_command(sid, 'echo "err" >&2')
        self.assertIn("err", result["stderr"])

    def test_execute_nonzero_exit(self):
        """非零退出码"""
        sid = self.driver.create_sandbox({})
        result = self.driver.execute_command(sid, "exit 42")
        self.assertEqual(result["return_code"], 42)

    def test_execute_timeout(self):
        """命令超时处理"""
        sid = self.driver.create_sandbox({})
        result = self.driver.execute_command(sid, "sleep 999", timeout=1)
        self.assertEqual(result["return_code"], -9)
        self.assertIn("超时", result["stderr"])

    def test_execute_nonexistent_sandbox(self):
        """不存在的沙箱返回错误"""
        result = self.driver.execute_command("nonexistent", "echo hi")
        self.assertEqual(result["return_code"], -1)

    def test_deploy_file(self):
        """部署文件到沙箱"""
        sid = self.driver.create_sandbox({})
        # 创建临时文件
        with tempfile.NamedTemporaryFile(
            suffix=".sh", delete=False, mode="w"
        ) as f:
            f.write("#!/bin/bash\necho test\n")
            tmp_file = f.name
        try:
            self.assertTrue(self.driver.deploy_package(sid, tmp_file))
        finally:
            os.unlink(tmp_file)

    def test_collect_artifacts(self):
        """收集沙箱内文件"""
        sid = self.driver.create_sandbox({})
        # 在沙箱内创建文件
        self.driver.execute_command(sid, "echo 'artifact content' > test.log")
        artifacts = self.driver.collect_artifacts(sid, ["test.log"])
        self.assertIn("test.log", artifacts)
        self.assertIn("artifact content", artifacts["test.log"])

    def test_collect_path_traversal_blocked(self):
        """路径穿越被阻止"""
        sid = self.driver.create_sandbox({})
        artifacts = self.driver.collect_artifacts(sid, ["../../etc/passwd"])
        # 不应返回真实 /etc/passwd 内容
        for v in artifacts.values():
            self.assertNotIn("root:", v)

    def test_destroy_idempotent(self):
        """销毁沙箱幂等"""
        sid = self.driver.create_sandbox({})
        self.assertTrue(self.driver.destroy_sandbox(sid))
        self.assertTrue(self.driver.destroy_sandbox(sid))  # 重复销毁不报错
        self.assertFalse(self.driver.is_sandbox_alive(sid))

    def test_destroy_removes_directory(self):
        """销毁沙箱后目录被删除"""
        sid = self.driver.create_sandbox({})
        sandbox_dir = os.path.join(self._test_base, sid)
        self.assertTrue(os.path.isdir(sandbox_dir))
        self.driver.destroy_sandbox(sid)
        self.assertFalse(os.path.isdir(sandbox_dir))

    def test_execute_in_sandbox_cwd(self):
        """命令在沙箱目录内执行"""
        sid = self.driver.create_sandbox({})
        result = self.driver.execute_command(sid, "pwd")
        sandbox_dir = os.path.join(self._test_base, sid)
        self.assertIn(sandbox_dir, result["stdout"])


if __name__ == "__main__":
    unittest.main()
