"""
环境管理器 (Environment Manager)

提供统一的沙箱生命周期管理接口，支持多种隔离后端
（容器 / 虚拟机 / chroot / 命名空间）。

生命周期: create → deploy → execute → collect → destroy

设计原则:
  - 策略模式 (Strategy Pattern): 不绑定特定隔离技术
  - 失败安全: 异常时保证资源清理
  - 可扩展: 新后端仅需实现 SandboxBackendDriver 接口
"""

import logging
import time
import uuid
from abc import ABC, abstractmethod
from typing import Optional, Dict, List

from .models import SandboxBackend

logger = logging.getLogger(__name__)


# ============================================================
#  沙箱后端驱动接口 (Strategy Interface)
# ============================================================

class SandboxBackendDriver(ABC):
    """
    沙箱隔离后端的抽象驱动接口。

    每种隔离技术（Docker/QEMU/chroot/namespace 等）实现此接口，
    环境管理器通过该接口统一调度，不依赖具体实现。
    """

    @abstractmethod
    def create_sandbox(self, config: Dict) -> str:
        """
        创建隔离沙箱实例。

        Args:
            config: 沙箱配置（镜像、资源限制、网络策略等）

        Returns:
            沙箱实例唯一标识
        """

    @abstractmethod
    def deploy_package(self, sandbox_id: str, package_path: str) -> bool:
        """
        将待测软件包部署到沙箱中。

        Args:
            sandbox_id: 沙箱实例 ID
            package_path: 待部署的软件包路径

        Returns:
            部署是否成功
        """

    @abstractmethod
    def execute_command(
        self, sandbox_id: str, command: str, timeout: int = 300
    ) -> Dict:
        """
        在沙箱中执行命令。

        Args:
            sandbox_id: 沙箱实例 ID
            command:     要执行的命令
            timeout:     超时秒数

        Returns:
            执行结果字典 {"stdout", "stderr", "return_code", "duration"}
        """

    @abstractmethod
    def collect_artifacts(self, sandbox_id: str, artifact_paths: List[str]) -> Dict:
        """
        从沙箱中收集测试产物（日志、core dump 等）。

        Args:
            sandbox_id:    沙箱实例 ID
            artifact_paths: 沙箱内需收集的文件路径列表

        Returns:
            路径→内容 映射字典
        """

    @abstractmethod
    def destroy_sandbox(self, sandbox_id: str) -> bool:
        """
        销毁沙箱实例并清理所有资源。

        此方法必须保证幂等性:
          - 已销毁的沙箱再次调用不报错
          - 异常中断后可安全重入
        """

    @abstractmethod
    def is_sandbox_alive(self, sandbox_id: str) -> bool:
        """检查沙箱是否仍在运行。"""


# ============================================================
#  默认后端驱动（用于框架演示与测试）
# ============================================================

class DefaultSandboxDriver(SandboxBackendDriver):
    """
    默认沙箱驱动 — 模拟实现。

    用于框架跑通与单元测试。实际部署时应替换为
    容器/虚拟机后端驱动。
    """

    def __init__(self):
        self._sandboxes: Dict[str, Dict] = {}

    def create_sandbox(self, config: Dict) -> str:
        sandbox_id = f"sandbox-{uuid.uuid4().hex[:8]}"
        self._sandboxes[sandbox_id] = {
            "config": config,
            "status": "running",
            "deployed_packages": [],
            "execution_log": [],
        }
        logger.info("[DefaultDriver] 创建沙箱: %s", sandbox_id)
        return sandbox_id

    def deploy_package(self, sandbox_id: str, package_path: str) -> bool:
        if sandbox_id not in self._sandboxes:
            logger.error("沙箱 %s 不存在", sandbox_id)
            return False
        self._sandboxes[sandbox_id]["deployed_packages"].append(package_path)
        logger.info("[DefaultDriver] 部署包到 %s: %s", sandbox_id, package_path)
        return True

    def execute_command(
        self, sandbox_id: str, command: str, timeout: int = 300
    ) -> Dict:
        if sandbox_id not in self._sandboxes:
            return {"stdout": "", "stderr": "沙箱不存在", "return_code": -1, "duration": 0}

        start_time = time.time()
        logger.info("[DefaultDriver] 在 %s 中执行: %s", sandbox_id, command)

        result = {
            "stdout": f"[模拟执行] {command}",
            "stderr": "",
            "return_code": 0,
            "duration": round(time.time() - start_time, 3),
        }
        self._sandboxes[sandbox_id]["execution_log"].append({
            "command": command, "result": result,
        })
        return result

    def collect_artifacts(self, sandbox_id: str, artifact_paths: List[str]) -> Dict:
        logger.info("[DefaultDriver] 从 %s 收集产物: %s", sandbox_id, artifact_paths)
        return {path: f"[模拟内容] {path}" for path in artifact_paths}

    def destroy_sandbox(self, sandbox_id: str) -> bool:
        if sandbox_id in self._sandboxes:
            del self._sandboxes[sandbox_id]
            logger.info("[DefaultDriver] 销毁沙箱: %s", sandbox_id)
        return True

    def is_sandbox_alive(self, sandbox_id: str) -> bool:
        return sandbox_id in self._sandboxes


# ============================================================
#  环境管理器
# ============================================================

class EnvironmentManager:
    """
    沙箱环境生命周期管理器。

    统一管理沙箱的创建、部署、执行、收集与销毁，
    保障异常场景下的资源清理。
    """

    def __init__(self, driver: Optional[SandboxBackendDriver] = None):
        """
        Args:
            driver: 沙箱后端驱动。未提供时使用默认模拟驱动。
        """
        self._driver = driver or DefaultSandboxDriver()
        self._active_sandboxes: List[str] = []

    @property
    def driver(self) -> SandboxBackendDriver:
        return self._driver

    def create(self, config: Optional[Dict] = None) -> str:
        """创建新的隔离沙箱。"""
        config = config or self._default_config()
        sandbox_id = self._driver.create_sandbox(config)
        self._active_sandboxes.append(sandbox_id)
        return sandbox_id

    def deploy(self, sandbox_id: str, package_path: str) -> bool:
        """将软件包部署到沙箱。"""
        return self._driver.deploy_package(sandbox_id, package_path)

    def execute(
        self, sandbox_id: str, command: str, timeout: int = 300
    ) -> Dict:
        """在沙箱中执行命令。"""
        return self._driver.execute_command(sandbox_id, command, timeout)

    def collect(
        self, sandbox_id: str, artifact_paths: Optional[List[str]] = None
    ) -> Dict:
        """收集沙箱中的测试产物。"""
        paths = artifact_paths or ["/var/log/test.log"]
        return self._driver.collect_artifacts(sandbox_id, paths)

    def destroy(self, sandbox_id: str) -> bool:
        """销毁沙箱并清理资源。"""
        result = self._driver.destroy_sandbox(sandbox_id)
        if sandbox_id in self._active_sandboxes:
            self._active_sandboxes.remove(sandbox_id)
        return result

    def cleanup_all(self):
        """强制清理所有活跃沙箱（异常恢复用）。"""
        logger.warning("执行全量清理: %d 个活跃沙箱", len(self._active_sandboxes))
        for sid in list(self._active_sandboxes):
            try:
                self._driver.destroy_sandbox(sid)
            except Exception as e:
                logger.error("清理沙箱 %s 失败: %s", sid, e)
        self._active_sandboxes.clear()

    @staticmethod
    def _default_config() -> Dict:
        """返回默认沙箱配置。"""
        return {
            "memory_limit": "2G",
            "cpu_limit": 2,
            "network": "isolated",
            "disk_limit": "10G",
            "timeout": 600,
        }
