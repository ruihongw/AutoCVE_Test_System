"""
修复模式识别模块

识别补丁使用的修复手段和常见安全修复模式。
"""

import re
from typing import Dict, List

from ..models import PatchedFile


class FixPatternIdentifier:
    """识别补丁使用的修复手段/模式。"""

    # 常见修复模式及其代码特征标识
    FIX_PATTERNS: Dict[str, List[str]] = {
        "输入验证/边界检查": [
            r'if\s*\(.*(?:len|size|count|length|bound)',
            r'(?:check|valid|verify|sanitiz)',
            r'(?:max|min|limit|clamp)\s*\(',
            r'>=?\s*0\s*&&|<=?\s*\w+_(?:MAX|SIZE|LEN)',
        ],
        "空指针/空值防护": [
            r'if\s*\(\s*!?\s*\w+\s*(?:==|!=)\s*(?:NULL|nullptr|None)',
            r'if\s*\(\s*\w+\s*\)',
            r'if\s+not\s+\w+',
        ],
        "权限/访问控制强化": [
            r'(?:permission|privilege|capabilit|access|auth)',
            r'(?:capable|ns_capable|may_\w+)',
            r'(?:check_perm|access_ok)',
        ],
        "内存安全加固": [
            r'(?:kfree|free)\s*\(', r'(?:kmalloc|malloc|calloc)',
            r'(?:memset|memcpy|memmove)',
            r'(?:size_t|ssize_t)',
            r'sizeof\s*\(',
        ],
        "整数溢出防护": [
            r'(?:overflow|underflow)',
            r'(?:check_add|check_mul|safe_)',
            r'INT_MAX|INT_MIN|UINT_MAX|SIZE_MAX',
        ],
        "锁/同步机制修改": [
            r'(?:mutex|spin_lock|rw_lock|semaphore)',
            r'(?:lock|unlock)\s*\(',
            r'(?:atomic_|rcu_)',
        ],
        "错误处理完善": [
            r'(?:goto\s+\w*err|goto\s+\w*out|goto\s+\w*fail)',
            r'(?:return\s+-\w+|return\s+err)',
            r'(?:IS_ERR|PTR_ERR|ERR_PTR)',
        ],
    }

    def identify(self, pf: PatchedFile) -> str:
        """识别补丁使用的修复手段/模式。"""
        patterns_found = []

        all_added = []
        all_removed = []
        for hunk in pf.hunks:
            all_added.extend(hunk.added_lines)
            all_removed.extend(hunk.removed_lines)

        added_text = "\n".join(all_added)

        # 检测常见修复模式
        for pattern_name, indicators in self.FIX_PATTERNS.items():
            for indicator in indicators:
                if re.search(indicator, added_text, re.IGNORECASE):
                    patterns_found.append(pattern_name)
                    break

        if pf.is_new:
            patterns_found.append("新增辅助文件")
        if pf.is_deleted:
            patterns_found.append("移除废弃代码")

        if not patterns_found:
            if len(all_added) > len(all_removed) * 2:
                patterns_found.append("大量新增代码（可能为防御性加固）")
            elif len(all_removed) > len(all_added) * 2:
                patterns_found.append("大量代码删减（可能为移除有害逻辑）")
            else:
                patterns_found.append("代码重构/替换")

        return "、".join(patterns_found)
