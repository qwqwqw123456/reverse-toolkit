#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reverse-Toolkit 核心单元测试
运行: python3 test_core.py
"""
import unittest
import sys
import os

# 把项目根目录加到 path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp_server import set_sample, get_context, get_overview, risk_check, _analysis_context


class TestReverseToolkitCore(unittest.TestCase):
    """核心功能测试"""

    def test_01_set_sample_valid(self):
        """测试正常设置样本"""
        res = set_sample("/bin/ls")
        self.assertIn("✅ 成功锁定目标样本", res)
        self.assertIsNotNone(_analysis_context["active_path"])
        self.assertEqual(_analysis_context["active_path"], "/bin/ls")

    def test_02_set_sample_invalid(self):
        """测试错误路径"""
        res = set_sample("/tmp/xxx_not_exist_99999")
        self.assertIn("[ERROR] 文件不存在", res)

    def test_03_get_context(self):
        """测试上下文查看"""
        set_sample("/bin/ls")
        res = get_context()
        self.assertIn("当前分析上下文", res)
        self.assertIn("/bin/ls", res)

    def test_04_resolve_path_auto(self):
        """测试不传路径时自动用活跃路径"""
        from mcp_server import _resolve_path
        set_sample("/bin/ls")
        path = _resolve_path()
        self.assertEqual(path, "/bin/ls")

    def test_05_resolve_path_explicit(self):
        """测试显式传路径时优先用显式路径"""
        from mcp_server import _resolve_path
        set_sample("/bin/ls")
        path = _resolve_path("/bin/cat")
        self.assertEqual(path, "/bin/cat")

    def test_06_get_overview_default_path(self):
        """测试不传参数时 get_overview 自动用活跃路径"""
        set_sample("/bin/ls")
        res = get_overview()
        self.assertIsInstance(res, str)
        self.assertNotIn("[ERROR] 文件不存在", res)
        self.assertIn("概览", res)

    def test_07_risk_check_default_path(self):
        """测试不传参数时 risk_check 自动用活跃路径"""
        set_sample("/bin/ls")
        res = risk_check()
        self.assertIsInstance(res, str)
        self.assertIn("风险评级", res)
        self.assertNotIn("[ERROR]", res)

    def test_08_no_sample_error(self):
        """测试没有 set_sample 时报错"""
        from mcp_server import _resolve_path
        # 先清空状态
        old_path = _analysis_context["active_path"]
        _analysis_context["active_path"] = None
        try:
            with self.assertRaises(ValueError):
                _resolve_path()
        finally:
            _analysis_context["active_path"] = old_path


if __name__ == '__main__':
    print("=" * 50)
    print("Reverse-Toolkit 核心单元测试")
    print("=" * 50)
    unittest.main(verbosity=2)
