#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reverse-Toolkit v5.1 核心单元测试
运行: python3 test_core.py
慢测试（需要真跑 Ghidra）: RUN_GHIDRA=1 python3 test_core.py
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import mcp_server as srv


def _first_evidence(kind=None):
    for rec in srv._STATE["evidence"]:
        if kind is None or rec["kind"] == kind:
            return rec
    return None


class TestV51Core(unittest.TestCase):

    def test_00_tool_count_is_five(self):
        """工具数量必须是 5（v5.1 做减法）"""
        src = open(os.path.join(os.path.dirname(__file__), "mcp_server.py"), encoding="utf-8").read()
        self.assertEqual(src.count("@mcp.tool()"), 5)
        for name in ("set_sample", "run_recon", "deep_dive",
                     "extract_threat_intel", "audit_and_report"):
            self.assertIn("def %s(" % name, src)
        # 旧工具名不应再暴露
        for old in ("def get_overview(", "def risk_check(", "def extract_iocs("):
            self.assertNotIn(old, src)

    def test_01_set_sample_valid(self):
        res = srv.set_sample("/bin/ls")
        self.assertIn("已锁定样本", res)
        self.assertIn("[Evidence: file+0x0]", res)
        self.assertEqual(srv._STATE["active_path"], "/bin/ls")
        self.assertEqual(len(srv._STATE["evidence"]), 1)

    def test_02_set_sample_invalid(self):
        res = srv.set_sample("/tmp/not_exist_99999")
        self.assertIn("[ERROR] 文件不存在", res)

    def test_03_run_recon_evidence(self):
        srv.set_sample("/bin/ls")
        res = srv.run_recon()
        self.assertIn("REA Recon", res)
        self.assertIn("风险评级", res)
        self.assertIn("[Evidence:", res)
        # 至少要有一条真实地址（ELF 字符串应能映射到 VA）
        self.assertRegex(res, r"\[Evidence: 0x[0-9a-f]+\]")
        # 台账同步
        self.assertGreater(len(srv._STATE["evidence"]), 3)
        self.assertIsNotNone(srv._STATE["metadata"]["risk_level"])

    def test_04_audit_fail_fake_address(self):
        srv.set_sample("/bin/ls")
        srv.run_recon()
        claims = json.dumps([
            {"id": "C1", "claim": "样本调用了 0xdeadbeef 处的后门函数", "evidence": ["0xdeadbeef"]}
        ])
        res = srv.audit_and_report(claims, write_file=False)
        self.assertIn("[AUDIT_RESULT: FAIL]", res)
        self.assertIn("AE-2", res)
        self.assertNotIn("# /bin/ls 逆向分析报告", res)

    def test_05_audit_fail_no_evidence(self):
        srv.set_sample("/bin/ls")
        srv.run_recon()
        claims = json.dumps([{"id": "C1", "claim": "样本具有反调试能力"}])
        res = srv.audit_and_report(claims, write_file=False)
        self.assertIn("[AUDIT_RESULT: FAIL]", res)
        self.assertIn("AE-1", res)

    def test_05b_audit_fail_fake_symbol(self):
        """编造的函数名（正文裸写，不带反引号）也必须被 AE-4 抓住"""
        srv.set_sample("/bin/ls")
        srv.run_recon()
        rec = _first_evidence("file")
        claims = json.dumps([
            {"id": "C1", "claim": "sub_401000 负责解密 C2 配置", "evidence": [rec["id"]]}
        ])
        res = srv.audit_and_report(claims, write_file=False)
        self.assertIn("[AUDIT_RESULT: FAIL]", res)
        self.assertIn("AE-4", res)
        self.assertIn("sub_401000", res)

    def test_06_audit_pass_with_real_evidence(self):
        srv.set_sample("/bin/ls")
        srv.run_recon()
        rec = _first_evidence("file")
        self.assertIsNotNone(rec)
        claims = json.dumps([
            {"id": "C1", "claim": "样本文件指纹已记录", "evidence": [rec["id"]], "confidence": "high"}
        ])
        res = srv.audit_and_report(claims, title="单测报告", write_file=False)
        self.assertIn("[AUDIT_RESULT: PASS]", res)
        self.assertIn("单测报告", res)

    def test_07_audit_markdown_claims(self):
        srv.set_sample("/bin/ls")
        srv.run_recon()
        rec = _first_evidence("file")
        text = "- 样本文件指纹已记录 [Evidence: %s] %s" % (rec["locator"], rec["symbol"])
        res = srv.audit_and_report(text, write_file=False)
        self.assertIn("[AUDIT_RESULT: PASS]", res)
        self.assertIn("样本文件指纹已记录", res)

    def test_08_negative_claim_warns_not_fails(self):
        srv.set_sample("/bin/ls")
        srv.run_recon()
        claims = json.dumps([{"id": "C1", "claim": "未找到反调试逻辑"}])
        res = srv.audit_and_report(claims, write_file=False)
        self.assertIn("[AUDIT_RESULT: PASS]", res)
        self.assertIn("AE-8", res)

    def test_09_cross_source_causal_warn(self):
        srv.set_sample("/bin/ls")
        srv.run_recon()
        evs = [r["id"] for r in srv._STATE["evidence"][:2]]
        claims = json.dumps([
            {"id": "C1", "claim": "因为 A 所以 B，导致后门被激活", "evidence": evs}
        ])
        res = srv.audit_and_report(claims, write_file=False)
        self.assertIn("AE-7", res)

    def test_11_no_sample_error(self):
        """没 set_sample 就调分析工具，必须明确报错而不是瞎猜"""
        srv._STATE["active_path"] = None
        res = srv.run_recon()
        self.assertIn("[ERROR]", res)
        self.assertIn("set_sample", res)

    def test_12_explicit_path_does_not_hijack(self):
        """显式传路径分析另一个文件，不能悄悄改掉已锁定的活跃样本"""
        srv.set_sample("/bin/ls")
        srv.run_recon("/bin/cat")
        self.assertEqual(srv._STATE["active_path"], "/bin/ls")

    def test_10_deep_dive_not_found(self):
        if not os.environ.get("RUN_GHIDRA"):
            self.skipTest("慢测试，设置 RUN_GHIDRA=1 才跑")
        srv.set_sample("/bin/ls")
        res = srv.deep_dive("this_symbol_should_not_exist_zzz")
        self.assertIn("未找到", res)
        self.assertIn("[Evidence:", res)


if __name__ == "__main__":
    print("=" * 60)
    print("Reverse-Toolkit v5.1 核心单元测试")
    print("=" * 60)
    unittest.main(verbosity=2)
