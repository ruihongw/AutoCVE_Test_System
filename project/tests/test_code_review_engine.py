"""
代码检视引擎单元测试

覆盖 diff 解析、修复模式识别、逻辑合理性评估和衍生风险检测。
"""

import unittest
import os

from cve_verifier.models import (
    VerificationTask, CVEMeta, PatchInfo, PatchedFile, DiffHunk,
    AttackVector, Severity, RiskLevel,
)
from cve_verifier.code_review import CodeReviewEngine


class TestCodeReviewEngine(unittest.TestCase):
    """代码检视引擎测试套件"""

    def setUp(self):
        self.engine = CodeReviewEngine()

    def _make_task(
        self,
        patched_files=None,
        cve_id="CVE-2024-0001",
        description="use-after-free in network driver",
        cwe_id="CWE-416",
        component="linux-kernel",
    ) -> VerificationTask:
        """构造测试用 VerificationTask。"""
        if patched_files is None:
            patched_files = [self._make_simple_patched_file()]

        return VerificationTask(
            task_id="TEST-CR-001",
            cve_meta=CVEMeta(
                cve_id=cve_id,
                description=description,
                cwe_id=cwe_id,
                affected_component=component,
                severity=Severity.HIGH,
                cvss_score=7.8,
                attack_vector=AttackVector.LOCAL,
            ),
            patch_info=PatchInfo(
                patched_files=patched_files,
                total_files_changed=len(patched_files),
                total_additions=sum(pf.total_additions for pf in patched_files),
                total_deletions=sum(pf.total_deletions for pf in patched_files),
            ),
        )

    def _make_simple_patched_file(self) -> PatchedFile:
        """构造简单的补丁文件。"""
        return PatchedFile(
            source_path="drivers/net/ice/ice_dpll.c",
            target_path="drivers/net/ice/ice_dpll.c",
            hunks=[DiffHunk(
                source_start=520,
                source_length=10,
                target_start=520,
                target_length=12,
                section_header="ice_dpll_init_rclk_pins",
                added_lines=[
                    "	while (i-- > 0) {",
                    "		ice_dpll_release_pin(&pins[i]);",
                    "	}",
                ],
                removed_lines=[
                    "	ice_dpll_release_pins(pins, i);",
                ],
                context_lines=[
                    "	struct ice_dpll *de = &pf->dplls;",
                    "	int ret = 0;",
                ],
            )],
            total_additions=3,
            total_deletions=1,
        )

    # ----------------------------------------------------------------
    #  基础功能测试
    # ----------------------------------------------------------------

    def test_review_returns_result(self):
        """检视引擎返回有效结果"""
        task = self._make_task()
        result = self.engine.review(task)
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.overall_assessment)
        self.assertEqual(len(result.patch_assessments), 1)

    def test_review_covers_all_files(self):
        """检视覆盖所有补丁文件"""
        files = [
            self._make_simple_patched_file(),
            PatchedFile(
                target_path="include/net/ice.h",
                hunks=[DiffHunk(
                    added_lines=["void ice_dpll_release_pin(struct ice_dpll_pin *pin);"],
                    section_header="",
                )],
                total_additions=1,
                total_deletions=0,
            ),
        ]
        task = self._make_task(patched_files=files)
        result = self.engine.review(task)
        self.assertEqual(len(result.patch_assessments), 2)

    # ----------------------------------------------------------------
    #  关联性分析测试
    # ----------------------------------------------------------------

    def test_relevance_detects_component_match(self):
        """文件路径包含组件名时标记为高度相关"""
        pf = PatchedFile(
            target_path="drivers/net/ice/ice_main.c",
            hunks=[DiffHunk(added_lines=["fix"], section_header="ice_probe")],
            total_additions=1,
        )
        task = self._make_task(patched_files=[pf], component="ice")
        result = self.engine.review(task)
        self.assertIn("高度相关", result.patch_assessments[0].relevance_to_cve)

    # ----------------------------------------------------------------
    #  修复手段识别测试
    # ----------------------------------------------------------------

    def test_identifies_null_check_pattern(self):
        """识别空指针防护修复模式"""
        pf = PatchedFile(
            target_path="src/main.c",
            hunks=[DiffHunk(
                added_lines=["if (ptr == NULL) return -EINVAL;"],
                removed_lines=[],
                section_header="process_data",
            )],
            total_additions=1,
        )
        task = self._make_task(patched_files=[pf])
        result = self.engine.review(task)
        self.assertTrue(len(result.patch_assessments[0].fix_approach) > 0)

    def test_identifies_bounds_check(self):
        """识别边界检查修复模式"""
        pf = PatchedFile(
            target_path="src/parser.c",
            hunks=[DiffHunk(
                added_lines=[
                    "if (len > MAX_SIZE) return -E2BIG;",
                    "if (check_bounds(offset, count)) {",
                ],
                removed_lines=[],
                section_header="parse_input",
            )],
            total_additions=2,
        )
        task = self._make_task(patched_files=[pf], cwe_id="CWE-120")
        result = self.engine.review(task)
        fix_approach = result.patch_assessments[0].fix_approach
        self.assertTrue(len(fix_approach) > 0)

    # ----------------------------------------------------------------
    #  衍生风险评估测试
    # ----------------------------------------------------------------

    def test_detects_function_removal_risk(self):
        """检测函数移除风险"""
        pf = PatchedFile(
            target_path="src/api.c",
            hunks=[DiffHunk(
                added_lines=[],
                removed_lines=[
                    "int legacy_handler(struct request *req) {",
                ],
                section_header="legacy_handler",
            )],
            total_additions=0,
            total_deletions=1,
        )
        task = self._make_task(patched_files=[pf])
        result = self.engine.review(task)
        high_risks = [
            r for r in result.regression_risks
            if r.risk_level == RiskLevel.HIGH
        ]
        self.assertGreater(len(high_risks), 0)

    def test_detects_lock_asymmetry(self):
        """检测锁操作不对称风险"""
        pf = PatchedFile(
            target_path="src/driver.c",
            hunks=[DiffHunk(
                added_lines=[
                    "	mutex_lock(&dev->lock);",
                    "	process_data(dev);",
                    # 缺少 mutex_unlock
                ],
                removed_lines=[],
                section_header="device_io",
            )],
            total_additions=2,
        )
        task = self._make_task(patched_files=[pf])
        result = self.engine.review(task)
        lock_risks = [
            r for r in result.regression_risks
            if r.category == "资源管理变更"
        ]
        self.assertGreater(len(lock_risks), 0)

    def test_detects_header_modification_risk(self):
        """检测头文件修改的跨文件影响"""
        header = PatchedFile(
            target_path="include/module.h",
            hunks=[DiffHunk(
                added_lines=["#define NEW_MACRO 1"],
                section_header="",
            )],
            total_additions=1,
        )
        task = self._make_task(patched_files=[header])
        result = self.engine.review(task)

        # 应检测到关注要点: 头文件修改
        has_header_concern = any(
            "头文件" in c
            for a in result.patch_assessments
            for c in a.concerns
        )
        self.assertTrue(has_header_concern)

    def test_detects_cross_file_header_only(self):
        """仅修改头文件时检测跨文件风险"""
        header = PatchedFile(
            target_path="include/api.h",
            hunks=[DiffHunk(added_lines=["int new_func();"])],
            total_additions=1,
        )
        task = self._make_task(patched_files=[header])
        result = self.engine.review(task)
        cross_risks = [
            r for r in result.regression_risks
            if r.category == "跨文件影响"
        ]
        self.assertGreater(len(cross_risks), 0)

    # ----------------------------------------------------------------
    #  CWE 一致性检查测试
    # ----------------------------------------------------------------

    def test_cwe_consistency_positive(self):
        """CWE-416 UAF 补丁包含 free/null 关键字时正面报告"""
        pf = PatchedFile(
            target_path="src/memory.c",
            hunks=[DiffHunk(
                added_lines=[
                    "kfree(obj);",
                    "obj = NULL;",
                ],
                section_header="cleanup_object",
            )],
            total_additions=2,
        )
        task = self._make_task(patched_files=[pf], cwe_id="CWE-416")
        result = self.engine.review(task)
        assessment = result.patch_assessments[0]
        self.assertIn("修复特征", assessment.logic_soundness)

    # ----------------------------------------------------------------
    #  综合评估测试
    # ----------------------------------------------------------------

    def test_overall_risk_level_reflects_highest(self):
        """综合风险等级反映最高单项风险"""
        pf = PatchedFile(
            target_path="src/api.c",
            hunks=[DiffHunk(
                added_lines=[],
                removed_lines=["int old_func(int a, int b) {"],
                section_header="old_func",
            )],
            total_additions=0,
            total_deletions=1,
        )
        task = self._make_task(patched_files=[pf])
        result = self.engine.review(task)
        # 函数移除应为 HIGH
        self.assertEqual(result.overall_risk_level, RiskLevel.HIGH)

    def test_no_risk_for_clean_patch(self):
        """干净的小补丁不产生高风险"""
        pf = PatchedFile(
            target_path="src/util.c",
            hunks=[DiffHunk(
                added_lines=["	return 0;"],
                removed_lines=["	return -1;"],
                section_header="helper_func",
            )],
            total_additions=1,
            total_deletions=1,
        )
        task = self._make_task(patched_files=[pf])
        result = self.engine.review(task)
        self.assertNotEqual(result.overall_risk_level, RiskLevel.HIGH)


class TestCodeReviewIntegration(unittest.TestCase):
    """集成测试: 使用示例补丁数据"""

    def test_review_with_sample_data(self):
        """使用示例数据执行完整代码检视"""
        examples_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "examples"
        )
        patch_path = os.path.join(examples_dir, "sample_patch.diff")
        meta_path = os.path.join(examples_dir, "sample_cve_meta.json")

        if not (os.path.exists(patch_path) and os.path.exists(meta_path)):
            self.skipTest("示例文件不存在")

        from cve_verifier.task_parser import TaskParser
        parser = TaskParser()
        task = parser.parse(patch_path, meta_path)

        engine = CodeReviewEngine()
        result = engine.review(task)

        self.assertIsNotNone(result)
        self.assertTrue(len(result.patch_assessments) > 0)
        self.assertTrue(len(result.summary) > 0)


if __name__ == "__main__":
    unittest.main()
