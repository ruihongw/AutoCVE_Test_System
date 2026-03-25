"""
关联性分析模块

分析补丁文件与 CVE 漏洞的关联程度。
"""

import re
from typing import List

from ..models import PatchedFile, VerificationTask


class RelevanceAnalyzer:
    """分析补丁文件与 CVE 的关联性。"""

    def analyze(self, pf: PatchedFile, task: VerificationTask) -> str:
        """分析补丁文件与 CVE 的关联性。"""
        cve = task.cve_meta
        indicators = []

        # 检查文件路径是否与受影响组件相关
        component = cve.affected_component.lower()
        if component and component in pf.target_path.lower():
            indicators.append(f"文件路径包含受影响组件名称 '{cve.affected_component}'")

        # 检查修改内容是否包含 CVE ID 引用
        for hunk in pf.hunks:
            for line in hunk.added_lines:
                if cve.cve_id.lower() in line.lower():
                    indicators.append("新增代码中引用了该 CVE ID")
                    break

        # 检查函数名是否与漏洞描述相关
        desc_keywords = self._extract_keywords(cve.description)
        for hunk in pf.hunks:
            if hunk.section_header:
                header_lower = hunk.section_header.lower()
                matches = [kw for kw in desc_keywords if kw in header_lower]
                if matches:
                    indicators.append(
                        f"修改函数 '{hunk.section_header}' 与漏洞描述关键词匹配: "
                        f"{', '.join(matches)}"
                    )

        if indicators:
            return "高度相关 — " + "; ".join(indicators)
        if pf.is_new:
            return "新增文件，可能为修复所需的辅助代码"
        return "关联性需进一步人工确认"

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        """从文本中提取有意义的关键词（>= 4 字符）。"""
        words = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]{3,}', text.lower())
        stopwords = {
            'that', 'this', 'with', 'from', 'have', 'been', 'could',
            'would', 'should', 'which', 'their', 'there', 'when',
            'where', 'what', 'will', 'more', 'also', 'than', 'into',
            'does', 'were', 'allows', 'before', 'after', 'other',
        }
        return [w for w in set(words) if w not in stopwords]
