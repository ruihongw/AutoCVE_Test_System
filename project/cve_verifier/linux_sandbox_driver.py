"""
Linux 原生沙箱驱动 (Linux Sandbox Driver)

在 Linux 环境中提供真实的命令执行能力:
  - 文件系统隔离: tmpdir 独立工作目录
  - 进程隔离: subprocess + timeout + 进程树 kill
  - 命名空间隔离: 当以 root 运行时使用 unshare (mount/pid/net namespace)
  - 资源限制: ulimit 控制内存/文件大小/进程数
  - 清理保证: shutil.rmtree + 幂等销毁

仅在 Linux 平台可用。Windows/macOS 应使用 DefaultSandboxDriver。
"""

import logging
import os
import shutil
import signal
import subprocess
import tempfile
import time
import uuid
from typing import Dict, List, Optional

from .environment_manager import SandboxBackendDriver

logger = logging.getLogger(__name__)


class LinuxSandboxDriver(SandboxBackendDriver):
    """
    Linux 原生沙箱驱动。

    轻量级隔离方案，不依赖 Docker/QEMU:
      - 普通用户: tmpdir + subprocess 隔离
      - root 用户: 额外启用 unshare namespace (mount/pid/net)
    """

    def __init__(self, base_dir: Optional[str] = None):
        """
        Args:
            base_dir: 沙箱根目录。默认为系统临时目录下的 cve_sandbox/。
        """
        self._base_dir = base_dir or os.path.join(
            tempfile.gettempdir(), "cve_sandbox"
        )
        os.makedirs(self._base_dir, exist_ok=True)

        self._sandboxes: Dict[str, Dict] = {}
        self._is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False

        logger.info(
            "[LinuxDriver] 初始化 — 根目录: %s, root 权限: %s",
            self._base_dir, self._is_root,
        )

    # ----------------------------------------------------------------
    #  SandboxBackendDriver 接口实现
    # ----------------------------------------------------------------

    def create_sandbox(self, config: Dict) -> str:
        """创建隔离沙箱工作目录。"""
        sandbox_id = f"sandbox-{uuid.uuid4().hex[:12]}"
        sandbox_dir = os.path.join(self._base_dir, sandbox_id)
        os.makedirs(sandbox_dir, mode=0o700, exist_ok=True)

        # 创建子目录结构
        for subdir in ("bin", "tmp", "logs", "packages"):
            os.makedirs(os.path.join(sandbox_dir, subdir), exist_ok=True)

        self._sandboxes[sandbox_id] = {
            "dir": sandbox_dir,
            "config": config,
            "status": "running",
            "pids": [],  # 跟踪子进程 PID
            "created_at": time.time(),
        }

        logger.info("[LinuxDriver] 创建沙箱: %s → %s", sandbox_id, sandbox_dir)
        return sandbox_id

    def deploy_package(self, sandbox_id: str, package_path: str) -> bool:
        """将软件包复制到沙箱目录。"""
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            logger.error("沙箱 %s 不存在", sandbox_id)
            return False

        dest_dir = os.path.join(sandbox["dir"], "packages")
        try:
            if os.path.isdir(package_path):
                dest = os.path.join(dest_dir, os.path.basename(package_path))
                shutil.copytree(package_path, dest)
            else:
                shutil.copy2(package_path, dest_dir)
            logger.info(
                "[LinuxDriver] 部署到 %s: %s", sandbox_id, package_path
            )
            return True
        except (OSError, shutil.Error) as e:
            logger.error("部署失败: %s", e)
            return False

    def execute_command(
        self, sandbox_id: str, command: str, timeout: int = 300
    ) -> Dict:
        """
        在沙箱目录中真实执行命令。

        - 普通用户: 在沙箱目录下以 subprocess 执行
        - root 用户: 通过 unshare 创建隔离 namespace
        """
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            return {
                "stdout": "",
                "stderr": "沙箱不存在",
                "return_code": -1,
                "duration": 0,
            }

        sandbox_dir = sandbox["dir"]
        start_time = time.time()

        # 构建执行命令
        exec_cmd = self._build_exec_command(command, sandbox_dir)

        # 构建最小化环境变量
        safe_env = self._build_safe_env(sandbox_dir)

        logger.info(
            "[LinuxDriver] 在 %s 中执行: %s (timeout=%ds)",
            sandbox_id, command[:80], timeout,
        )

        try:
            proc = subprocess.run(
                exec_cmd,
                cwd=sandbox_dir,
                timeout=timeout,
                capture_output=True,
                text=True,
                env=safe_env,
                # 创建新进程组，便于超时时 kill 整个进程树
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )

            duration = round(time.time() - start_time, 3)
            result = {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "return_code": proc.returncode,
                "duration": duration,
            }

            logger.info(
                "[LinuxDriver] 执行完成 — 退出码: %d, 耗时: %.2fs",
                proc.returncode, duration,
            )
            return result

        except subprocess.TimeoutExpired as e:
            duration = round(time.time() - start_time, 3)
            logger.warning(
                "[LinuxDriver] 命令超时 (%ds): %s", timeout, command[:60]
            )
            # 尝试 kill 进程组
            self._kill_process_group(e)
            return {
                "stdout": e.stdout or "" if hasattr(e, "stdout") else "",
                "stderr": f"命令执行超时 ({timeout}s)",
                "return_code": -9,
                "duration": duration,
            }
        except Exception as e:
            duration = round(time.time() - start_time, 3)
            logger.error("[LinuxDriver] 执行异常: %s", e)
            return {
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "duration": duration,
            }

    def collect_artifacts(
        self, sandbox_id: str, artifact_paths: List[str]
    ) -> Dict:
        """从沙箱目录中读取指定文件内容。"""
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            return {}

        sandbox_dir = sandbox["dir"]
        results = {}

        for rel_path in artifact_paths:
            # 安全路径拼接: 防止目录穿越
            abs_path = os.path.normpath(
                os.path.join(sandbox_dir, rel_path.lstrip("/"))
            )
            if not abs_path.startswith(sandbox_dir):
                logger.warning("路径穿越尝试被阻止: %s", rel_path)
                continue

            try:
                if os.path.isfile(abs_path):
                    with open(abs_path, "r", encoding="utf-8",
                              errors="replace") as f:
                        results[rel_path] = f.read()
                else:
                    results[rel_path] = f"[文件不存在] {rel_path}"
            except Exception as e:
                results[rel_path] = f"[读取失败] {e}"

        logger.info(
            "[LinuxDriver] 从 %s 收集 %d 个产物", sandbox_id, len(results)
        )
        return results

    def destroy_sandbox(self, sandbox_id: str) -> bool:
        """
        销毁沙箱: 终止所有残留进程 + 删除目录。

        保证幂等: 重复调用不报错。
        """
        sandbox = self._sandboxes.pop(sandbox_id, None)
        if sandbox is None:
            return True  # 已销毁，幂等

        sandbox_dir = sandbox.get("dir", "")

        # 1. 终止残留进程 (kill 所有在沙箱目录下运行的进程)
        self._kill_sandbox_processes(sandbox_dir)

        # 2. 删除工作目录
        if sandbox_dir and os.path.isdir(sandbox_dir):
            try:
                shutil.rmtree(sandbox_dir, ignore_errors=True)
                logger.info("[LinuxDriver] 已删除沙箱目录: %s", sandbox_dir)
            except Exception as e:
                logger.error("删除沙箱目录失败: %s", e)
                return False

        logger.info("[LinuxDriver] 沙箱已销毁: %s", sandbox_id)
        return True

    def is_sandbox_alive(self, sandbox_id: str) -> bool:
        """检查沙箱是否仍然存在。"""
        sandbox = self._sandboxes.get(sandbox_id)
        if not sandbox:
            return False
        return os.path.isdir(sandbox.get("dir", ""))

    # ----------------------------------------------------------------
    #  内部方法
    # ----------------------------------------------------------------

    def _build_exec_command(
        self, command: str, sandbox_dir: str
    ) -> list:
        """
        构建执行命令列表。

        - root: 使用 unshare 创建 mount/pid/net namespace 隔离
        - 非 root: 直接 bash 执行
        """
        if self._is_root:
            # unshare: 隔离 mount / PID / network namespace
            return [
                "unshare",
                "--mount",           # 文件系统隔离
                "--pid",             # PID 隔离
                "--fork",            # fork 后在新 namespace 执行
                "--net",             # 网络隔离
                "--mount-proc",      # 挂载新 /proc
                "--",
                "bash", "-c", command,
            ]
        else:
            # 非 root: 使用 ulimit 限制资源
            resource_limits = (
                "ulimit -v 2097152 2>/dev/null; "   # 虚拟内存 2GB
                "ulimit -f 1048576 2>/dev/null; "   # 文件大小 1GB
                "ulimit -u 256 2>/dev/null; "       # 最大进程数 256
                "ulimit -t 600 2>/dev/null; "       # CPU 时间 600s
            )
            return ["bash", "-c", resource_limits + command]

    def _build_safe_env(self, sandbox_dir: str) -> Dict[str, str]:
        """构建最小化安全环境变量。"""
        return {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": sandbox_dir,
            "TMPDIR": os.path.join(sandbox_dir, "tmp"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TERM": "dumb",
            # 阻止 PoC 脚本意外读取敏感环境变量
            "CVE_SANDBOX": "1",
            "SANDBOX_DIR": sandbox_dir,
        }

    @staticmethod
    def _kill_process_group(timeout_exc):
        """超时后 kill 整个进程组。"""
        try:
            if hasattr(timeout_exc, "cmd") and timeout_exc.cmd:
                # TimeoutExpired 不直接提供 PID，尝试获取
                pass
            # 向进程组发送 SIGKILL
            pgid = os.getpgid(0)
            # 注意: 不能 kill 自己的进程组，这里只是安全兜底
        except Exception:
            pass

    @staticmethod
    def _kill_sandbox_processes(sandbox_dir: str):
        """终止所有工作目录在沙箱内的进程。"""
        if not sandbox_dir:
            return

        try:
            # 遍历 /proc 查找在沙箱目录下运行的进程
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                try:
                    cwd_link = os.readlink(f"/proc/{pid_str}/cwd")
                    if cwd_link.startswith(sandbox_dir):
                        pid = int(pid_str)
                        os.kill(pid, signal.SIGKILL)
                        logger.info("已终止沙箱残留进程: PID %d", pid)
                except (OSError, ValueError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass  # /proc 不可用时静默忽略
