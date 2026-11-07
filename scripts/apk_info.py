#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APK 结构解析：用 androguard 提取 manifest 关键信息（文本输出，供 apk_analyze.sh 汇总）"""
import sys
from loguru import logger
logger.remove()  # 关掉 androguard 的 DEBUG 日志噪音
from androguard.core.apk import APK

def main(path):
    apk = APK(path)
    out = []
    out.append("package=%s" % (apk.get_package() or "?"))
    out.append("versionName=%s" % (apk.get_androidversion_name() or "?"))
    out.append("versionCode=%s" % (apk.get_androidversion_code() or "?"))
    out.append("minSdk=%s" % (apk.get_min_sdk_version() or "?"))
    out.append("targetSdk=%s" % (apk.get_target_sdk_version() or "?"))
    out.append("mainActivity=%s" % (apk.get_main_activity() or "?"))
    out.append("")

    perms = apk.get_permissions()
    out.append("permissions(%d):" % len(perms))
    for p in perms:
        out.append("  " + p)

    acts = apk.get_activities()
    out.append("")
    out.append("activities(%d):" % len(acts))
    for a in acts:
        out.append("  " + a)

    svcs = apk.get_services()
    out.append("")
    out.append("services(%d):" % len(svcs))
    for s in svcs:
        out.append("  " + s)

    recv = apk.get_receivers()
    out.append("")
    out.append("receivers(%d):" % len(recv))
    for r in recv:
        out.append("  " + r)

    prov = apk.get_providers()
    out.append("")
    out.append("providers(%d):" % len(prov))
    for p in prov:
        out.append("  " + p)

    libs = apk.get_libraries()
    out.append("")
    out.append("nativeLibs(%d):" % len(libs))
    for l in libs:
        out.append("  " + l)

    sig = apk.get_signature()
    if sig:
        if isinstance(sig, bytes):
            sig = sig.decode("utf-8", errors="ignore")
        sig = sig[:40] + "..."
    out.append("")
    out.append("signature=%s" % (sig or "?"))

    # dex 文件列表
    out.append("")
    out.append("dexFiles:")
    for d in apk.get_files():
        if d.startswith("classes") and d.endswith(".dex"):
            out.append("  " + d)

    print("\n".join(clean_lines(out)))

def clean_lines(lines):
    """清洗输出：剔除非 ASCII 字节与控制字符，避免下游 grep 拒读"""
    import re
    cleaned = []
    for ln in lines:
        if isinstance(ln, bytes):
            ln = ln.decode("utf-8", errors="replace")
        cleaned.append(re.sub(r"[^\x20-\x7E]", "?", ln))
    return cleaned

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: apk_info.py <apk路径>")
        sys.exit(1)
    main(sys.argv[1])
