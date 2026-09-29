import json
from agent.llm import get_llm
from tools.nuclei import NucleiTool


class SecAgent:
    """SecAgent 核心：一个能思考、能扫描、能分析的 AI Agent"""

    def __init__(self):
        self.llm = get_llm()
        self.history = []
        self.tools = {
            "nuclei": NucleiTool(),
        }

    def think(self, prompt: str) -> str:
        """让 AI 思考并返回结果"""
        resp = self.llm.invoke(prompt)
        content = resp.content
        self.history.append({"prompt": prompt, "response": content})
        return content

    def scan(self, target: str) -> dict:
        """调用工具扫描目标"""
        print(f"[*] 正在调用 Nuclei 扫描 {target}...")
        result = self.tools["nuclei"].run(target)
        print(f"[+] 扫描完成，发现 {result.get('total', 0)} 个问题")
        return result

    def analyze_scan_result(self, scan_result: dict) -> str:
        """让 AI 分析扫描结果"""
        findings_text = self._format_findings(scan_result)

        prompt = f"""你是资深安全工程师。请分析以下 Nuclei 扫描结果：

目标: {scan_result.get('target')}
扫描发现: {scan_result.get('total', 0)} 个问题

{findings_text}

要求：
1. 总结整体安全状况（一句话）
2. 按风险等级排序漏洞（高危→低危）
3. 每个漏洞给出可执行的修复命令
4. 给出整体安全评分（0-100）
"""
        return self.think(prompt)

    def _format_findings(self, scan_result: dict) -> str:
        """把扫描结果格式化成可读文本"""
        findings = scan_result.get("findings", [])
        if not findings:
            return "本次扫描未发现明显漏洞。"

        lines = []
        for i, f in enumerate(findings, 1):
            info = f.get("info", {})
            lines.append(f"""
【漏洞 {i}】
- 模板ID: {f.get('template-id')}
- 名称: {info.get('name')}
- 风险等级: {info.get('severity')}
- 类型: {info.get('tags', [])}
- 目标: {f.get('matched-at')}
- 描述: {info.get('description', '无')}
""")
        return "\n".join(lines)


if __name__ == "__main__":
    # 测试
    agent = SecAgent()
    print("=" * 60)
    print("SecAgent 测试：真实扫描 + AI 分析")
    print("=" * 60)

    result = agent.scan("http://192.168.12.128")
    print("\n[*] 正在让 AI 分析...\n")
    report = agent.analyze_scan_result(result)
    print(report)
