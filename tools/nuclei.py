import subprocess
import os
import re
import time
import tempfile
from tools.base import BaseTool


SCAN_MODES = {
    "fast": {
        "name": "⚡ 快速扫描",
        "timeout": 120,
        "args": ["-t", "http/misconfiguration/"],
        "desc": "30-60秒",
    },
    "standard": {
        "name": "🔍 标准扫描",
        "timeout": 600,
        "args": ["-t", "http/misconfiguration/", "-t", "http/exposures/"],
        "desc": "3-5分钟",
    },
    "deep": {
        "name": "🎯 深度扫描",
        "timeout": 1800,
        "args": [],
        "desc": "30分钟",
    },
}


class NucleiTool(BaseTool):
    name = "nuclei"
    description = "基于模板的漏洞扫描器"

    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback

    def _report(self, message, percent=None):
        if self.progress_callback:
            self.progress_callback(message, percent)
        print(message)

    def run(self, target: str, mode: str = "fast", **kwargs) -> dict:
        if mode not in SCAN_MODES:
            mode = "fast"

        config = SCAN_MODES[mode]
        output_file = tempfile.mktemp(suffix=".txt")

        # 核心命令：最朴素版本
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
                if content:
                    print(f"[DEBUG] 文件前500:\n{content[:500]}")

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
        except Exception as e:
            error_msg = f"扫描异常: {e}"

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
    result = tool.run("http://192.168.12.128", mode="fast")
    print(f"\n{'=' * 60}")
    print(f"结果: {result['total']} 个漏洞，耗时 {result['elapsed']} 秒")
    print(f"{'=' * 60}")
    for f in result.get("findings", []):
        if isinstance(f, dict):
            print(f"[{f.get('severity', 'info').upper()}] {f.get('template-id')} - {f.get('matched-at')}")
