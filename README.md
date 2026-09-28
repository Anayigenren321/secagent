# 🛡️ SecAgent

AI 驱动的安全评估平台 —— 让安全评估更简单

## 功能特性

- 🤖 **AI 智能分析**：接入智谱 GLM-4-Flash，自动分析扫描结果
- 📊 **可视化界面**：Streamlit 数据看板
- 🔍 **漏洞管理**：按风险等级排序，给出修复建议
- 📥 **报告导出**：支持下载 Markdown 报告

## 快速开始

\`\`\`bash
git clone https://github.com/Anayigenren321/secagent.git
cd secagent
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "ZHIPU_API_KEY=你的Key" > .env
streamlit run app.py
\`\`\`

## 开发路线图

- [x] v0.1: AI 分析 + 可视化界面
- [ ] v0.2: 集成 Nuclei 扫描器
- [ ] v0.3: 集成 Nmap
- [ ] v0.4: 定时任务（7×24 扫描）
- [ ] v1.0: 完整的安全运营平台

## License

MIT
