"""
逻辑合理性评估模块

评估补丁逻辑的合理性、完整性和与 CWE 的一致性。
"""

import re
from typing import List

from ..models import PatchedFile, DiffHunk, VerificationTask


class LogicChecker:
    """评估补丁逻辑的合理性与完整性。"""

    # CWE → 期望的修复模式关键字映射
    CWE_FIX_HINTS = {
        "CWE-120": ["bound", "size", "length", "overflow"],     # 缓冲区溢出
        "CWE-125": ["bound", "size", "index", "range"],         # 越界读
        "CWE-787": ["bound", "size", "overflow", "length"],     # 越界写
        "CWE-416": ["free", "null", "use_after", "rcu"],        # UAF
        "CWE-476": ["null", "nullptr", "check", "valid"],       # 空指针解引用
        "CWE-190": ["overflow", "max", "check", "safe_"],       # 整数溢出
        "CWE-362": ["lock", "mutex", "atomic", "synchroni"],    # 竞态条件
        "CWE-863": ["permission", "access", "auth", "capab"],   # 授权缺陷
    }

    def evaluate_logic_soundness(
        self, pf: PatchedFile, task: VerificationTask
    ) -> str:
        """评估补丁逻辑的合理性。"""
        observations = []

        for hunk in pf.hunks:
            if hunk.added_lines and hunk.removed_lines:
                observations.append(self._compare_added_removed(hunk))
            elif hunk.added_lines and not hunk.removed_lines:
                observations.append(
                    f"在 '{hunk.section_header or '未知位置'}' 纯增补代码 "
                    f"({len(hunk.added_lines)} 行)"
                )
            elif hunk.removed_lines and not hunk.added_lines:
                observations.append(
                    f"在 '{hunk.section_header or '未知位置'}' 纯删除代码 "
                    f"({len(hunk.removed_lines)} 行)"
                )

        cwe_check = self._check_cwe_consistency(pf, task)
        if cwe_check:
            observations.append(cwe_check)

        return "; ".join(observations) if observations else "需人工深入审查"

    def evaluate_completeness(
        self, pf: PatchedFile, task: VerificationTask
    ) -> str:
        """评估补丁是否完整覆盖了修复范围。"""
        observations = []

        # 检查是否有 TODO / FIXME / HACK 遗留
        for hunk in pf.hunks:
            for line in hunk.added_lines:
                if re.search(r'\b(TODO|FIXME|HACK|XXX|WORKAROUND)\b',
                             line, re.IGNORECASE):
                    observations.append(
                        f"新增代码包含待办标记: '{line.strip()[:80]}'"
                    )

        # 检查错误路径覆盖
        error_path_check = self._check_error_path_coverage(pf)
        if error_path_check:
            observations.append(error_path_check)

        if not observations:
            return "未发现明显的完整性缺陷"
        return "; ".join(observations)

    def identify_concerns(
        self, pf: PatchedFile, task: VerificationTask
    ) -> List[str]:
        """识别需要额外关注的要点。"""
        concerns = []

        total_changes = pf.total_additions + pf.total_deletions
        if total_changes > 100:
            concerns.append(
                f"单文件变更量较大 ({pf.total_additions}+/{pf.total_deletions}-), "
                f"建议仔细检视"
            )

        if pf.total_deletions > 0 and pf.total_additions == 0:
            concerns.append("仅删除代码，需确认删除内容不影响正常功能")

        if re.search(r'\.(h|hpp|hxx)$', pf.target_path):
            concerns.append("修改了头文件/接口定义，可能影响其他编译单元")

        if re.search(r'(Makefile|CMakeLists|Kconfig|\.conf)', pf.target_path):
            concerns.append("修改了构建/配置文件，可能影响编译与部署流程")

        return concerns

    # ── 内部方法 ──

    @staticmethod
    def _compare_added_removed(hunk: DiffHunk) -> str:
        """比较 hunk 中新增与删除代码的差异模式。"""
        added_set = set(line.strip() for line in hunk.added_lines if line.strip())
        removed_set = set(line.strip() for line in hunk.removed_lines if line.strip())

        only_added = added_set - removed_set
        only_removed = removed_set - added_set

        location = hunk.section_header or f"L{hunk.source_start}"

        if not only_added and not only_removed:
            return f"'{location}' 处仅格式/空白变更"

        return (
            f"'{location}' 处替换了 {len(only_removed)} 行为 {len(only_added)} 行新代码"
        )

    def _check_cwe_consistency(
        self, pf: PatchedFile, task: VerificationTask
    ) -> str:
        """检查补丁手段是否与 CWE 分类一致。"""
        cwe = task.cve_meta.cwe_id.upper() if task.cve_meta.cwe_id else ""
        if not cwe:
            return ""

        expected_keywords = self.CWE_FIX_HINTS.get(cwe, [])
        if not expected_keywords:
            return ""

        added_text = " ".join(
            line for hunk in pf.hunks for line in hunk.added_lines
        ).lower()

        found = [kw for kw in expected_keywords if kw in added_text]
        if found:
            return f"补丁包含与 {cwe} 对应的修复特征: {', '.join(found)}"
        return f"补丁中未明确检测到与 {cwe} 直接关联的修复特征，建议人工确认"

    @staticmethod
    def _check_error_path_coverage(pf: PatchedFile) -> str:
        """检查新增代码中的错误路径是否有适当处理。"""
        for hunk in pf.hunks:
            added_text = "\n".join(hunk.added_lines)

            alloc_patterns = [
                r'(?:malloc|calloc|kmalloc|kzalloc|alloc_\w+)\s*\(',
                r'(?:fopen|open)\s*\(',
            ]
            free_patterns = [
                r'(?:free|kfree|release|close|fclose)\s*\(',
            ]

            has_alloc = any(
                re.search(p, added_text) for p in alloc_patterns
            )
            has_free = any(
                re.search(p, added_text) for p in free_patterns
            )

            if has_alloc and not has_free:
                return "新增了资源分配操作，但未检测到对应的释放操作，需确认错误路径中的资源清理"

        return ""
