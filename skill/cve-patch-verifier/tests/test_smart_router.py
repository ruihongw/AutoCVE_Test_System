"""
智能分流调度器单元测试

覆盖各种 CVE 特征组合下的分流决策正确性验证。
"""

import unittest
import os
import json
import tempfile

from cve_verifier.models import (
    VerificationTask, CVEMeta, PatchInfo, PatchedFile, DiffHunk,
    AttackVector, Severity, VerificationRoute,
)
from cve_verifier.smart_router import SmartRouter


class TestSmartRouter(unittest.TestCase):
    """智能分流调度器测试套件"""

    def setUp(self):
        self.router = SmartRouter()

    def _make_task(
        self,
        poc_available=False,
        poc_script_path=None,
        attack_vector=AttackVector.LOCAL,
        description="",
        cwe_id="",
        num_files=1,
        total_additions=10,
        total_deletions=5,
        extra_scripts=None,
    ) -> VerificationTask:
        """构造测试用 VerificationTask。"""
        patched_files = [
            PatchedFile(
                target_path=f"src/file{i}.c",
                total_additions=total_additions // max(num_files, 1),
                total_deletions=total_deletions // max(num_files, 1),
                hunks=[DiffHunk(added_lines=["+ line"] * (total_additions // max(num_files, 1)))],
            )
            for i in range(num_files)
        ]

        return VerificationTask(
            task_id="TEST-001",
            cve_meta=CVEMeta(
                cve_id="CVE-2024-0001",
                description=description,
                attack_vector=attack_vector,
                cwe_id=cwe_id,
                severity=Severity.HIGH,
                cvss_score=7.5,
            ),
            patch_info=PatchInfo(
                patched_files=patched_files,
                total_files_changed=num_files,
                total_additions=total_additions,
                total_deletions=total_deletions,
            ),
            poc_available=poc_available,
            poc_script_path=poc_script_path,
            extra_scripts=extra_scripts or [],
        )

    # ----------------------------------------------------------------
    #  路径决策测试
    # ----------------------------------------------------------------

    def test_dynamic_only_with_poc_and_network_vector(self):
        """有 PoC + 网络攻击面 + 简单补丁 → DYNAMIC_ONLY"""
        task = self._make_task(
            poc_available=True,
            poc_script_path="/tmp/poc.sh",
            attack_vector=AttackVector.NETWORK,
            num_files=1,
            total_additions=5,
            total_deletions=3,
        )
        decision = self.router.route(task)
        self.assertEqual(decision.route, VerificationRoute.DYNAMIC_ONLY)
        self.assertGreater(decision.dynamic_weight, 0)

    def test_code_review_only_no_poc_physical_vector(self):
        """无 PoC + 物理攻击面 + 竞态条件 → CODE_REVIEW_ONLY"""
        task = self._make_task(
            poc_available=False,
            attack_vector=AttackVector.PHYSICAL,
            description="A race condition in hardware driver requires physical access",
            num_files=2,
            total_additions=40,
            total_deletions=20,
        )
        decision = self.router.route(task)
        self.assertEqual(decision.route, VerificationRoute.CODE_REVIEW_ONLY)
        self.assertEqual(decision.dynamic_weight, 0.0)
        self.assertEqual(decision.review_weight, 1.0)

    def test_hybrid_with_poc_and_complex_patch(self):
        """有 PoC + 简单攻击面 + 复杂补丁 → HYBRID"""
        task = self._make_task(
            poc_available=True,
            poc_script_path="/tmp/poc.sh",
            attack_vector=AttackVector.NETWORK,
            num_files=10,
            total_additions=200,
            total_deletions=150,
        )
        decision = self.router.route(task)
        self.assertEqual(decision.route, VerificationRoute.HYBRID)

    def test_hybrid_medium_feasibility(self):
        """中等可行性场景 → HYBRID"""
        task = self._make_task(
            poc_available=False,
            extra_scripts=["/tmp/helper.sh"],
            attack_vector=AttackVector.LOCAL,
            num_files=3,
            total_additions=30,
            total_deletions=20,
        )
        decision = self.router.route(task)
        # 中等动态可行性应产生 HYBRID 或 CODE_REVIEW_ONLY
        self.assertIn(decision.route, [
            VerificationRoute.HYBRID,
            VerificationRoute.CODE_REVIEW_ONLY,
        ])

    # ----------------------------------------------------------------
    #  评分维度测试
    # ----------------------------------------------------------------

    def test_poc_score_with_script(self):
        """有 PoC 脚本时评分为 1.0"""
        task = self._make_task(poc_available=True, poc_script_path="/tmp/poc.sh")
        decision = self.router.route(task)
        self.assertEqual(decision.scores.poc_availability, 1.0)

    def test_poc_score_without_script(self):
        """无任何脚本时评分为 0.0"""
        task = self._make_task(poc_available=False)
        decision = self.router.route(task)
        self.assertEqual(decision.scores.poc_availability, 0.0)

    def test_poc_score_with_extra_scripts(self):
        """有辅助脚本但无 PoC 时评分为 0.5"""
        task = self._make_task(
            poc_available=False,
            extra_scripts=["/tmp/test.sh"],
        )
        decision = self.router.route(task)
        self.assertEqual(decision.scores.poc_availability, 0.5)

    def test_trigger_complexity_race_condition(self):
        """竞态条件描述应增加触发难度"""
        task_normal = self._make_task(description="simple buffer overflow")
        task_race = self._make_task(description="race condition in driver")
        d_normal = self.router.route(task_normal)
        d_race = self.router.route(task_race)
        self.assertGreater(
            d_race.scores.trigger_complexity,
            d_normal.scores.trigger_complexity,
        )

    def test_patch_complexity_scaling(self):
        """补丁复杂度随规模增长"""
        task_small = self._make_task(num_files=1, total_additions=5, total_deletions=3)
        task_large = self._make_task(num_files=10, total_additions=400, total_deletions=200)
        d_small = self.router.route(task_small)
        d_large = self.router.route(task_large)
        self.assertGreater(
            d_large.scores.patch_complexity,
            d_small.scores.patch_complexity,
        )

    # ----------------------------------------------------------------
    #  权重分配测试
    # ----------------------------------------------------------------

    def test_weights_sum_to_one(self):
        """动态与检视权重之和为 1"""
        for poc in [True, False]:
            for vector in AttackVector:
                task = self._make_task(
                    poc_available=poc,
                    poc_script_path="/tmp/poc.sh" if poc else None,
                    attack_vector=vector,
                )
                decision = self.router.route(task)
                self.assertAlmostEqual(
                    decision.dynamic_weight + decision.review_weight,
                    1.0,
                    places=2,
                    msg=f"权重之和不为 1: poc={poc}, vector={vector}",
                )

    def test_decision_has_rationale(self):
        """所有决策都包含理由说明"""
        task = self._make_task()
        decision = self.router.route(task)
        self.assertTrue(len(decision.rationale) > 0)
        self.assertTrue(len(decision.scores.reasoning) > 0)


class TestSmartRouterIntegration(unittest.TestCase):
    """集成测试: 使用完整的 TaskParser 输出"""

    def test_full_pipeline_with_sample_data(self):
        """使用示例数据走通完整分流逻辑"""
        examples_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "examples"
        )
        patch_path = os.path.join(examples_dir, "sample_patch.diff")
        meta_path = os.path.join(examples_dir, "sample_cve_meta.json")

        if not os.path.exists(patch_path) or not os.path.exists(meta_path):
            self.skipTest("示例文件不存在")

        from cve_verifier.task_parser import TaskParser
        parser = TaskParser()
        task = parser.parse(patch_path, meta_path)

        router = SmartRouter()
        decision = router.route(task)

        # 验证基本结构完整性
        self.assertIsNotNone(decision.route)
        self.assertIsNotNone(decision.rationale)
        self.assertGreaterEqual(decision.dynamic_weight, 0)
        self.assertGreaterEqual(decision.review_weight, 0)


if __name__ == "__main__":
    unittest.main()
