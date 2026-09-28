from agent.llm import get_llm


class SecAgent:
    """SecAgent 核心：一个能思考、能分析的 AI Agent"""

    def __init__(self):
        self.llm = get_llm()
        self.history = []

    def think(self, prompt: str) -> str:
        """让 AI 思考并返回结果"""
        resp = self.llm.invoke(prompt)
        content = resp.content
        self.history.append({"prompt": prompt, "response": content})
        return content

    def analyze_scan_result(self, scan_result: str) -> str:
        """分析扫描结果"""
        prompt = f"""你是资深安全工程师。请分析以下扫描结果：

{scan_result}

要求：
1. 总结整体安全状况（一句话）
2. 按风险等级排序漏洞（高危→低危）
3. 每个漏洞给出可执行的修复命令
4. 给出整体安全评分（0-100）
"""
        return self.think(prompt)
