"""
任务解析器单元测试

覆盖补丁文件解析、CVE 元数据解析和 PoC 检测逻辑。
"""

import json
import os
import tempfile
import unittest

from cve_verifier.task_parser import TaskParser
from cve_verifier.models import AttackVector, Severity


class TestTaskParser(unittest.TestCase):
    """任务解析器测试套件"""

    def setUp(self):
        self.parser = TaskParser()
        self.temp_dir = tempfile.mkdtemp()

    def _write_temp_file(self, filename, content):
        path = os.path.join(self.temp_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    # ----------------------------------------------------------------
    #  补丁解析
    # ----------------------------------------------------------------

    def test_parse_simple_patch(self):
        """解析简单的单文件 diff"""
        patch_content = """diff --git a/src/main.c b/src/main.c
index 1234567..89abcde 100644
--- a/src/main.c
+++ b/src/main.c
@@ -10,3 +10,5 @@ int process(int x) {
     int result = 0;
+    if (x < 0)
+        return -EINVAL;
     result = compute(x);
-    return result;
+    return result > 0 ? result : 0;
"""
        patch_path = self._write_temp_file("test.diff", patch_content)
        patch_info = self.parser.parse_patch(patch_path)

        self.assertEqual(patch_info.total_files_changed, 1)
        self.assertEqual(len(patch_info.patched_files), 1)

        pf = patch_info.patched_files[0]
        self.assertEqual(pf.source_path, "src/main.c")
        self.assertEqual(pf.target_path, "src/main.c")
        self.assertGreater(len(pf.hunks), 0)

    def test_parse_multi_file_patch(self):
        """解析多文件 diff"""
        patch_content = """diff --git a/src/a.c b/src/a.c
index 111..222 100644
--- a/src/a.c
+++ b/src/a.c
@@ -1,3 +1,4 @@
 line1
+new_line
 line2
diff --git a/src/b.h b/src/b.h
index 333..444 100644
--- a/src/b.h
+++ b/src/b.h
@@ -5,2 +5,3 @@
 header
+new_decl
"""
        patch_path = self._write_temp_file("multi.diff", patch_content)
        patch_info = self.parser.parse_patch(patch_path)

        self.assertEqual(patch_info.total_files_changed, 2)

    def test_detect_new_file(self):
        """检测新增文件"""
        patch_content = """diff --git a/src/new.c b/src/new.c
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/src/new.c
@@ -0,0 +1,3 @@
+#include <stdio.h>
+void hello() {}
"""
        patch_path = self._write_temp_file("new.diff", patch_content)
        patch_info = self.parser.parse_patch(patch_path)

        self.assertTrue(patch_info.patched_files[0].is_new)

    # ----------------------------------------------------------------
    #  CVE 元数据解析
    # ----------------------------------------------------------------

    def test_parse_cve_meta(self):
        """解析标准 CVE 元数据 JSON"""
        meta = {
            "cve_id": "CVE-2024-1234",
            "description": "Buffer overflow in parser",
            "severity": "high",
            "cvss_score": 8.1,
            "attack_vector": "network",
            "affected_component": "libxml2",
            "cwe_id": "CWE-120",
        }
        meta_path = self._write_temp_file("meta.json", json.dumps(meta))
        cve = self.parser.parse_cve_meta(meta_path)

        self.assertEqual(cve.cve_id, "CVE-2024-1234")
        self.assertEqual(cve.severity, Severity.HIGH)
        self.assertEqual(cve.attack_vector, AttackVector.NETWORK)
        self.assertAlmostEqual(cve.cvss_score, 8.1)
        self.assertEqual(cve.cwe_id, "CWE-120")

    def test_parse_cve_meta_unknown_values(self):
        """未知枚举值回退为 UNKNOWN"""
        meta = {
            "cve_id": "CVE-2024-9999",
            "severity": "extreme",
            "attack_vector": "cosmic_rays",
        }
        meta_path = self._write_temp_file("unknown.json", json.dumps(meta))
        cve = self.parser.parse_cve_meta(meta_path)

        self.assertEqual(cve.severity, Severity.UNKNOWN)
        self.assertEqual(cve.attack_vector, AttackVector.UNKNOWN)

    # ----------------------------------------------------------------
    #  PoC 检测
    # ----------------------------------------------------------------

    def test_poc_available_with_file(self):
        """存在 PoC 文件时返回 True"""
        poc_path = self._write_temp_file("poc.sh", "#!/bin/bash\nexit 0")
        self.assertTrue(self.parser._check_poc_available(poc_path))

    def test_poc_unavailable_no_path(self):
        """无路径时返回 False"""
        self.assertFalse(self.parser._check_poc_available(None))
        self.assertFalse(self.parser._check_poc_available(""))

    def test_poc_unavailable_nonexistent(self):
        """路径不存在时返回 False"""
        self.assertFalse(self.parser._check_poc_available("/nonexistent/poc.sh"))

    # ----------------------------------------------------------------
    #  完整解析
    # ----------------------------------------------------------------

    def test_full_parse(self):
        """完整解析流程"""
        patch_content = """diff --git a/src/main.c b/src/main.c
--- a/src/main.c
+++ b/src/main.c
@@ -1,2 +1,3 @@
 existing
+added
"""
        meta = {"cve_id": "CVE-2024-5678", "severity": "medium", "attack_vector": "local"}

        patch_path = self._write_temp_file("full.diff", patch_content)
        meta_path = self._write_temp_file("full_meta.json", json.dumps(meta))

        task = self.parser.parse(patch_path, meta_path)

        self.assertTrue(task.task_id.startswith("TASK-"))
        self.assertEqual(task.cve_meta.cve_id, "CVE-2024-5678")
        self.assertFalse(task.poc_available)


if __name__ == "__main__":
    unittest.main()
