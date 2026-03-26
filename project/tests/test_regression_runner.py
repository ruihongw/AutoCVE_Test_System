"""
回归测试执行器单元测试

覆盖回归命令生成逻辑：包完整性、组件特定、补丁范围。
"""

import unittest

from cve_verifier.models import (
    VerificationTask, CVEMeta, PatchInfo, PatchedFile, DiffHunk,
    AttackVector, Severity,
)
from cve_verifier.regression_runner import RegressionRunner


class TestRegressionRunner(unittest.TestCase):
    """回归测试执行器测试"""

    def setUp(self):
        self.runner = RegressionRunner()

    def _make_task(
        self, component="libfoo", target_paths=None, package_path=""
    ) -> VerificationTask:
        if target_paths is None:
            target_paths = ["src/main.c"]
        patched_files = [
            PatchedFile(
                target_path=path,
                hunks=[DiffHunk(added_lines=["+ fix"])],
                total_additions=1,
            )
            for path in target_paths
        ]
        return VerificationTask(
            task_id="TEST-REG-001",
            cve_meta=CVEMeta(
                cve_id="CVE-2024-0001",
                affected_component=component,
                severity=Severity.HIGH,
                attack_vector=AttackVector.LOCAL,
            ),
            patch_info=PatchInfo(
                patched_files=patched_files,
                total_files_changed=len(patched_files),
                total_additions=len(patched_files),
            ),
            package_path=package_path,
        )

    # ----------------------------------------------------------------
    #  基础测试
    # ----------------------------------------------------------------

    def test_always_returns_commands(self):
        """总是返回至少一条命令"""
        task = self._make_task()
        commands = self.runner.get_regression_commands(task)
        self.assertGreater(len(commands), 0)

    def test_command_structure(self):
        """每条命令有 name/command/timeout"""
        task = self._make_task()
        commands = self.runner.get_regression_commands(task)
        for cmd in commands:
            self.assertIn("name", cmd)
            self.assertIn("command", cmd)
            self.assertIn("timeout", cmd)

    # ----------------------------------------------------------------
    #  包完整性检查
    # ----------------------------------------------------------------

    def test_rpm_package_checks(self):
        """RPM 包触发完整性校验"""
        task = self._make_task(package_path="/tmp/fix.rpm")
        commands = self.runner.get_regression_commands(task)
        rpm_cmds = [c for c in commands if "RPM" in c["name"]]
        self.assertGreater(len(rpm_cmds), 0)

    def test_deb_package_checks(self):
        """DEB 包触发完整性校验"""
        task = self._make_task(package_path="/tmp/fix.deb")
        commands = self.runner.get_regression_commands(task)
        deb_cmds = [c for c in commands if "DEB" in c["name"]]
        self.assertGreater(len(deb_cmds), 0)

    def test_tarball_package_checks(self):
        """源码包触发解压测试"""
        task = self._make_task(package_path="/tmp/src.tar.gz")
        commands = self.runner.get_regression_commands(task)
        tar_cmds = [c for c in commands if "源码包" in c["name"]]
        self.assertGreater(len(tar_cmds), 0)

    def test_no_package_no_integrity(self):
        """无包路径不生成包完整性检查"""
        task = self._make_task(package_path="")
        commands = self.runner.get_regression_commands(task)
        integrity_cmds = [
            c for c in commands
            if any(k in c["name"] for k in ["RPM", "DEB", "源码包"])
        ]
        self.assertEqual(len(integrity_cmds), 0)

    # ----------------------------------------------------------------
    #  组件识别测试
    # ----------------------------------------------------------------

    def test_library_component(self):
        """库组件触发 ldconfig 测试"""
        task = self._make_task(component="libxml2")
        commands = self.runner.get_regression_commands(task)
        lib_cmds = [c for c in commands if "共享库" in c["name"]]
        self.assertGreater(len(lib_cmds), 0)

    def test_kernel_component(self):
        """内核组件触发模块加载测试"""
        task = self._make_task(
            component="linux-kernel",
            target_paths=["drivers/net/ice/ice_main.c"],
        )
        commands = self.runner.get_regression_commands(task)
        kernel_cmds = [c for c in commands if "内核" in c["name"]]
        self.assertGreater(len(kernel_cmds), 0)

    def test_service_component(self):
        """服务组件触发 systemd 测试"""
        task = self._make_task(
            component="sshd",
            target_paths=["src/sshd.service"],
        )
        commands = self.runner.get_regression_commands(task)
        svc_cmds = [c for c in commands if "服务" in c["name"]]
        self.assertGreater(len(svc_cmds), 0)

    # ----------------------------------------------------------------
    #  补丁范围测试
    # ----------------------------------------------------------------

    def test_c_source_triggers_compile(self):
        """C 源文件触发编译验证"""
        task = self._make_task(target_paths=["src/parser.c"])
        commands = self.runner.get_regression_commands(task)
        compile_cmds = [c for c in commands if "编译" in c["name"]]
        self.assertGreater(len(compile_cmds), 0)

    def test_header_only_no_compile(self):
        """仅头文件不触发编译验证"""
        task = self._make_task(target_paths=["include/api.h"])
        commands = self.runner.get_regression_commands(task)
        compile_cmds = [c for c in commands if "编译" in c["name"]]
        self.assertEqual(len(compile_cmds), 0)


if __name__ == "__main__":
    unittest.main()
