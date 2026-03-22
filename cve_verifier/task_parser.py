"""
任务解析器 (Task Parser)

负责读取、解析各类输入（补丁文件、CVE元数据、PoC脚本、软件包），
构建统一的 VerificationTask 上下文对象，驱动后续验证流水线。
"""

import json
import os
import re
import uuid
from typing import Optional

from .models import (
    CVEMeta, PatchInfo, PatchedFile, DiffHunk,
    VerificationTask, AttackVector, Severity,
)


class TaskParser:
    """
    任务解析器

    解析补丁文件、CVE 元数据、可选的 PoC 脚本和软件包路径，
    输出结构化的 VerificationTask 对象。
    """

    # ----------------------------------------------------------------
    #  公开接口
    # ----------------------------------------------------------------

    def parse(
        self,
        patch_path: str,
        cve_meta_path: str,
        package_path: str = "",
        poc_script_path: Optional[str] = None,
        extra_scripts: Optional[list] = None,
    ) -> VerificationTask:
        """
        解析全部输入并构建验证任务。

        Args:
            patch_path:      补丁文件路径（unified diff 格式）
            cve_meta_path:   CVE 元数据 JSON 文件路径
            package_path:    修复后的软件包路径（可选）
            poc_script_path: PoC 验证脚本路径（可选）
            extra_scripts:   额外的验证脚本列表（可选）

        Returns:
            VerificationTask 对象
        """
        task = VerificationTask(
            task_id=self._generate_task_id(),
            patch_info=self.parse_patch(patch_path),
            cve_meta=self.parse_cve_meta(cve_meta_path),
            package_path=package_path,
            poc_script_path=poc_script_path,
            poc_available=self._check_poc_available(poc_script_path),
            extra_scripts=extra_scripts or [],
        )
        return task

    # ----------------------------------------------------------------
    #  补丁解析
    # ----------------------------------------------------------------

    def parse_patch(self, patch_path: str) -> PatchInfo:
        """
        解析 unified diff 格式的补丁文件。

        将补丁拆分为 PatchedFile → DiffHunk 的层级结构，
        统计新增/删除行数等指标。
        """
        raw_content = self._read_file(patch_path)
        patched_files = self._split_into_files(raw_content)

        total_additions = sum(f.total_additions for f in patched_files)
        total_deletions = sum(f.total_deletions for f in patched_files)

        return PatchInfo(
            patch_file_path=patch_path,
            raw_content=raw_content,
            patched_files=patched_files,
            total_files_changed=len(patched_files),
            total_additions=total_additions,
            total_deletions=total_deletions,
        )

    def _split_into_files(self, raw: str) -> list:
        """将完整 diff 内容按文件拆分为 PatchedFile 列表。"""
        file_pattern = re.compile(
            r'^diff\s+--git\s+a/(.+?)\s+b/(.+?)$', re.MULTILINE
        )
        splits = list(file_pattern.finditer(raw))
        patched_files = []

        for idx, match in enumerate(splits):
            start = match.start()
            end = splits[idx + 1].start() if idx + 1 < len(splits) else len(raw)
            segment = raw[start:end]

            source_path = match.group(1)
            target_path = match.group(2)

            pf = PatchedFile(
                source_path=source_path,
                target_path=target_path,
                is_new="new file mode" in segment,
                is_deleted="deleted file mode" in segment,
                is_renamed=source_path != target_path,
                hunks=self._parse_hunks(segment),
            )
            pf.total_additions = sum(len(h.added_lines) for h in pf.hunks)
            pf.total_deletions = sum(len(h.removed_lines) for h in pf.hunks)
            patched_files.append(pf)

        return patched_files

    def _parse_hunks(self, file_segment: str) -> list:
        """从单个文件段中解析所有 diff hunks。"""
        hunk_pattern = re.compile(
            r'^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@\s*(.*)',
            re.MULTILINE,
        )
        matches = list(hunk_pattern.finditer(file_segment))
        hunks = []

        for idx, match in enumerate(matches):
            start = match.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(file_segment)
            body = file_segment[start:end]

            added, removed, context = [], [], []
            for line in body.splitlines():
                if line.startswith('+'):
                    added.append(line[1:])
                elif line.startswith('-'):
                    removed.append(line[1:])
                elif line.startswith(' '):
                    context.append(line[1:])

            hunks.append(DiffHunk(
                source_start=int(match.group(1)),
                source_length=int(match.group(2) or 1),
                target_start=int(match.group(3)),
                target_length=int(match.group(4) or 1),
                section_header=match.group(5).strip(),
                added_lines=added,
                removed_lines=removed,
                context_lines=context,
                raw_content=match.group(0) + body,
            ))

        return hunks

    # ----------------------------------------------------------------
    #  CVE 元数据解析
    # ----------------------------------------------------------------

    def parse_cve_meta(self, meta_path: str) -> CVEMeta:
        """
        解析 CVE 元数据 JSON 文件。

        支持的字段与 CVEMeta 数据模型对齐。
        """
        raw = self._read_file(meta_path)
        data = json.loads(raw)

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        vector_map = {
            "network": AttackVector.NETWORK,
            "adjacent": AttackVector.ADJACENT,
            "local": AttackVector.LOCAL,
            "physical": AttackVector.PHYSICAL,
        }

        return CVEMeta(
            cve_id=data.get("cve_id", ""),
            description=data.get("description", ""),
            severity=severity_map.get(
                data.get("severity", "").lower(), Severity.UNKNOWN
            ),
            cvss_score=float(data.get("cvss_score", 0.0)),
            attack_vector=vector_map.get(
                data.get("attack_vector", "").lower(), AttackVector.UNKNOWN
            ),
            affected_component=data.get("affected_component", ""),
            affected_versions=data.get("affected_versions", []),
            cwe_id=data.get("cwe_id", ""),
            references=data.get("references", []),
            extra=data.get("extra", {}),
        )

    # ----------------------------------------------------------------
    #  PoC 检测
    # ----------------------------------------------------------------

    def _check_poc_available(self, poc_path: Optional[str]) -> bool:
        """检查 PoC 脚本是否存在且非空。"""
        if not poc_path:
            return False
        if not os.path.isfile(poc_path):
            return False
        return os.path.getsize(poc_path) > 0

    # ----------------------------------------------------------------
    #  工具方法
    # ----------------------------------------------------------------

    @staticmethod
    def _read_file(path: str) -> str:
        """读取文件内容，支持多种编码。"""
        for encoding in ("utf-8", "latin-1"):
            try:
                with open(path, "r", encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
        raise IOError(f"无法以支持的编码读取文件: {path}")

    @staticmethod
    def _generate_task_id() -> str:
        """生成唯一任务 ID。"""
        return f"TASK-{uuid.uuid4().hex[:12].upper()}"
