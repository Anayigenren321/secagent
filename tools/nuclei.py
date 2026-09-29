import subprocess
import os
import re
import time
import shutil
import tempfile
from tools.base import BaseTool


SCAN_MODES = {
    "fast": {
        "name": "⚡ 快速扫描",
        "timeout": 180,
        "args": ["-t", "http/misconfiguration/"],
        "desc": "配置检查（1-3分钟）",
    },
    "standard": {
        "name": "🔍 标准扫描",
        "timeout": 900,
        "args": [
            "-t", "http/misconfiguration/",
            "-t", "http/exposures/",
            "-t", "http/exposed-panels/",
            "-t", "http/default-logins/",
            "-t", "http/vulnerabilities/",
        ],
        "desc": "含常见漏洞（5-10分钟）",
    },
    "deep": {
        "name": "🎯 深度扫描",
        "timeout": 1800,
        "args": [
            "-t", "http/misconfiguration/",
            "-t", "http/exposures/",
            "-t", "http/exposed-panels/",
            "-t", "http/default-logins/",
            "-t", "http/vulnerabilities/",
            "-t", "http/cves/2024/",
        ],
        "desc": "全量扫描（10-30分钟）",
    },
}
class NucleiTool(BaseTool):
    name = "nuclei"
    description = "基于模板的漏洞扫描器，仿安恒明鉴分层扫描"

    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback

    def _report(self, message, percent=None):
        if self.progress_callback:
            self.progress_callback(message, percent)
        print(message)

    def _clear_cache(self):
        """清空 Nuclei 缓存，避免漏报"""
        cache_dirs = [
            os.path.expanduser("~/.cache/nuclei"),
            os.path.expanduser("~/.config/nuclei/cache"),
        ]
        for d in cache_dirs:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)
                print(f"[DEBUG] 已清空缓存: {d}")

    def run(self, target: str, mode: str = "fast", **kwargs) -> dict:
        if mode not in SCAN_MODES:
            mode = "fast"

        config = SCAN_MODES[mode]
        output_file = tempfile.mktemp(suffix=".txt")

        # ========== 关键：每次扫描前清空缓存 ==========
        self._clear_cache()

        cmd = [
            "nuclei",
            "-u", target,
            "-silent",
            "-o", output_file,
        ] + config["args"]

        self._report(f"[*] 扫描模式: {config['name']}", 10)
        self._report(f"[*] 目标: {target}", 20)
        print(f"[DEBUG] 命令: {' '.join(cmd)}")

        start_time = time.time()
        error_msg = None
        findings = []

        try:
            result = subprocess.run(
                cmd,
                timeout=config["timeout"],
                check=False,
                capture_output=True,
                text=True,
            )

            print(f"[DEBUG] stdout 长度: {len(result.stdout)}")
            print(f"[DEBUG] stderr 长度: {len(result.stderr)}")
            if result.stdout:
                print(f"[DEBUG] stdout 前500:\n{result.stdout[:500]}")
            if result.stderr:
                print(f"[DEBUG] stderr 前500:\n{result.stderr[:500]}")

            # 从文件读
            if os.path.exists(output_file):
                with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                print(f"[DEBUG] 文件大小: {len(content)}")

                pattern = re.compile(
                    r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)(.*)$"
                )

                for line in content.split("\n"):
                    line = line.strip()
                    if not line or not line.startswith("["):
                        continue
                    match = pattern.match(line)
                    if match:
                        template_id, protocol, severity, matched_at, extra = match.groups()
                        findings.append({
                            "template-id": template_id,
                            "protocol": protocol,
                            "severity": severity,
                            "matched-at": matched_at,
                            "extra": extra.strip(),
                        })

                os.remove(output_file)

        except subprocess.TimeoutExpired:
            error_msg = f"扫描超时（{config['timeout']}秒）"
            self._report(f"    [!] {error_msg}", 100)
        except FileNotFoundError:
            error_msg = "Nuclei 未安装"
            self._report(f"    [!] {error_msg}", 100)
        except Exception as e:
            error_msg = f"扫描异常: {e}"
            self._report(f"    [!] {error_msg}", 100)

        elapsed = time.time() - start_time
        self._report(f"[*] 耗时: {elapsed:.1f} 秒", 90)
        self._report(f"[+] 发现 {len(findings)} 个问题", 100)

        result = {
            "tool": "nuclei",
            "target": target,
            "mode": mode,
            "mode_name": config["name"],
            "total": len(findings),
            "findings": findings,
            "elapsed": round(elapsed, 1),
        }
        if error_msg:
            result["error"] = error_msg
        return result


if __name__ == "__main__":
    tool = NucleiTool()

    # 连续跑两次，验证缓存问题已解决
    print("=" * 60)
    print("第 1 次扫描")
    print("=" * 60)
    r1 = tool.run("http://192.168.12.128", mode="fast")
    print(f"结果: {r1['total']} 个漏洞\n")

    print("=" * 60)
    print("第 2 次扫描（应该也是 11 个）")
    print("=" * 60)
    r2 = tool.run("http://192.168.12.128", mode="fast")
    print(f"结果: {r2['total']} 个漏洞")
