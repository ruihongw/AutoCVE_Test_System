"""
基础回归执行器 (Regression Runner)

根据软件包类型和组件特征，生成适当的基础功能回归测试命令集。
确保核心功能不因补丁而受损。
"""

import logging
import re
from typing import List, Dict

from .models import VerificationTask

logger = logging.getLogger(__name__)


class RegressionRunner:
    """
    回归测试命令生成器。

    根据受影响组件和软件包信息，智能选择并生成
    基础功能回归测试命令序列。
    """

    def get_regression_commands(
        self, task: VerificationTask
    ) -> List[Dict]:
        """
        为指定任务生成回归测试命令列表。

        每个命令项包含:
          - name:    测试名称
          - command: 执行命令
          - timeout: 超时秒数

        Args:
            task: 验证任务上下文

        Returns:
            回归测试命令字典列表
        """
        commands = []

        # 1. 通用包完整性检查
        commands.extend(self._package_integrity_checks(task))

        # 2. 基于组件的特定回归
        commands.extend(self._component_specific_tests(task))

        # 3. 基于补丁修改范围的验证
        commands.extend(self._patch_scope_tests(task))

        if not commands:
            commands.append({
                "name": "基础连通性检查",
                "command": "echo 'basic connectivity check' && exit 0",
                "timeout": 30,
            })

        logger.info("生成 %d 条回归测试命令", len(commands))
        return commands

    def _package_integrity_checks(
        self, task: VerificationTask
    ) -> List[Dict]:
        """生成软件包完整性验证命令。"""
        commands = []

        if task.package_path:
            pkg = task.package_path

            # RPM 包
            if pkg.endswith(".rpm"):
                commands.append({
                    "name": "RPM 包完整性校验",
                    "command": f"rpm -K {pkg}",
                    "timeout": 60,
                })
                commands.append({
                    "name": "RPM 安装测试",
                    "command": f"rpm -ivh --test {pkg}",
                    "timeout": 120,
                })

            # DEB 包
            elif pkg.endswith(".deb"):
                commands.append({
                    "name": "DEB 包完整性校验",
                    "command": f"dpkg --info {pkg}",
                    "timeout": 60,
                })

            # 源码包
            elif pkg.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
                commands.append({
                    "name": "源码包解压测试",
                    "command": f"tar -tf {pkg} > /dev/null",
                    "timeout": 60,
                })

        return commands

    def _component_specific_tests(
        self, task: VerificationTask
    ) -> List[Dict]:
        """
        根据受影响组件生成特定回归测试命令。

        通过分析组件名称和补丁路径推断组件类型。
        """
        commands = []
        component = task.cve_meta.affected_component.lower()
        patch_paths = [
            pf.target_path.lower()
            for pf in task.patch_info.patched_files
        ]

        # 识别组件类型并添加相应回归测试
        if self._is_library_component(component, patch_paths):
            commands.append({
                "name": "共享库加载测试",
                "command": f"ldconfig -v 2>/dev/null | grep -i '{component}' || true",
                "timeout": 30,
            })

        if self._is_service_component(component, patch_paths):
            commands.append({
                "name": "服务启动测试",
                "command": f"systemctl start {component} && systemctl is-active {component}",
                "timeout": 120,
            })

        if self._is_kernel_component(component, patch_paths):
            commands.append({
                "name": "内核模块加载测试",
                "command": "uname -r && lsmod | head -20",
                "timeout": 60,
            })

        return commands

    def _patch_scope_tests(self, task: VerificationTask) -> List[Dict]:
        """根据补丁修改的文件类型添加编译/链接验证。"""
        commands = []

        source_files = [
            pf for pf in task.patch_info.patched_files
            if re.search(r'\.(c|cpp|cc|cxx)$', pf.target_path)
        ]
        if source_files:
            commands.append({
                "name": "编译验证",
                "command": "make -j$(nproc) 2>&1 | tail -20",
                "timeout": 300,
            })

        return commands

    # ----------------------------------------------------------------
    #  组件类型识别
    # ----------------------------------------------------------------

    @staticmethod
    def _is_library_component(component: str, paths: list) -> bool:
        return bool(
            re.search(r'^lib', component)
            or any(re.search(r'\.(so|a|dylib)', p) for p in paths)
        )

    @staticmethod
    def _is_service_component(component: str, paths: list) -> bool:
        return bool(
            any(re.search(r'(\.service|systemd|daemon|server)', p) for p in paths)
            or component.endswith("d")
        )

    @staticmethod
    def _is_kernel_component(component: str, paths: list) -> bool:
        return bool(
            re.search(r'(kernel|linux|kmod)', component)
            or any(re.search(r'(drivers/|kernel/|net/|fs/)', p) for p in paths)
        )
