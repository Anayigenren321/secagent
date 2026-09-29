import time
import streamlit as st
from agent.core import SecAgent
from tools.nuclei import NucleiTool
from reports.generator import ReportGenerator

# ========== 页面配置 ==========
st.set_page_config(
    page_title="SecAgent —— AI 安全评估平台",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ SecAgent")
st.caption("AI 驱动的安全评估平台 · 让安全评估更简单")

# ========== 侧边栏 ==========
with st.sidebar:
    st.header("📌 目标设置")
    target = st.text_input("目标地址", value="http://192.168.12.128")

    scan_mode = st.selectbox(
        "扫描模式",
        options=["fast", "standard", "deep"],
        format_func=lambda x: {
            "fast": "⚡ 快速扫描（1-3分钟）",
            "standard": "🔍 标准扫描（3-5分钟）",
            "deep": "🎯 深度扫描（10-20分钟）",
        }[x],
    )

    st.divider()
    if st.button("🚀 开始扫描", type="primary", use_container_width=True):
        # 重置状态
        st.session_state["scan_started"] = True
        st.session_state["target"] = target
        st.session_state["mode"] = scan_mode
        for key in ["scan_result", "ai_report", "report_paths"]:
            if key in st.session_state:
                del st.session_state[key]

    st.divider()
    st.header("⚙️ 关于")
    st.info("SecAgent v0.1\n\nAI 驱动的安全评估平台")

# ========== 主页面 ==========
if "scan_started" not in st.session_state:
    st.session_state["scan_started"] = False

if not st.session_state["scan_started"]:
    st.info("👈 在左侧输入目标地址，点击「开始扫描」")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("累计扫描", "0 次")
    with col2:
        st.metric("发现漏洞", "0 个")
    with col3:
        st.metric("安全评分", "—")
else:
    target = st.session_state["target"]
    mode = st.session_state["mode"]

    st.subheader(f"📡 目标: {target}")

    # ========== 扫描流程（只在第一次执行）==========
    if "scan_result" not in st.session_state:
        progress = st.progress(0, text="🔍 初始化...")

        # 1. Nuclei 扫描
        progress.progress(20, text=f"🔍 调用 Nuclei 扫描（{mode} 模式）...")
        tool = NucleiTool()
        scan_result = tool.run(target, mode=mode)

        # 2. AI 分析
        progress.progress(60, text="🤖 调用 AI 分析...")
        agent = SecAgent()
        ai_report = agent.analyze_scan_result(scan_result)

        # 3. 生成报告
        progress.progress(85, text="📝 生成报告...")
        gen = ReportGenerator(target, scan_result, ai_report)
        report_paths = {
            "markdown": gen.to_markdown(),
            "html": gen.to_html(),
            "word": None,
            "pdf": None,
        }
        try:
            report_paths["word"] = gen.to_word()
        except Exception as e:
            print(f"Word 生成失败: {e}")
        try:
            report_paths["pdf"] = gen.to_pdf()
        except Exception as e:
            print(f"PDF 生成失败: {e}")

        progress.progress(100, text="✅ 完成")
        time.sleep(0.3)
        progress.empty()

        # 缓存
        st.session_state["scan_result"] = scan_result
        st.session_state["ai_report"] = ai_report
        st.session_state["report_paths"] = report_paths

    # ========== 从缓存读取 ==========
    scan_result = st.session_state["scan_result"]
    ai_report = st.session_state["ai_report"]
    report_paths = st.session_state["report_paths"]

    findings = scan_result.get("findings", [])
    total = scan_result.get("total", 0)

    # ========== 安全概览 ==========
    st.divider()
    st.subheader("📊 安全概览")

    high = sum(1 for f in findings if f.get("severity") in ["high", "critical"])
    medium = sum(1 for f in findings if f.get("severity") == "medium")
    low = sum(1 for f in findings if f.get("severity") == "low")
    info = sum(1 for f in findings if f.get("severity") == "info")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("发现漏洞", total)
    with col2:
        st.metric("高危", high, delta_color="inverse")
    with col3:
        st.metric("中危", medium)
    with col4:
        st.metric("低危/信息", low + info)

    st.caption(
        f"扫描模式: {scan_result.get('mode_name', 'N/A')}  ·  "
        f"耗时: {scan_result.get('elapsed', 0)} 秒  ·  "
        f"扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )

    # ========== 漏洞列表 ==========
    if findings:
        st.divider()
        st.subheader("📋 漏洞详情")

        for i, f in enumerate(findings, 1):
            severity = f.get("severity", "info")
            emoji = {
                "critical": "🔴",
                "high": "🔴",
                "medium": "🟡",
                "low": "🟢",
            }.get(severity, "⚪")

            with st.expander(
                f"{emoji} {f.get('template-id')} ({severity})",
                expanded=(i == 1),
            ):
                st.markdown(f"""
                **模板ID**: `{f.get('template-id')}`  
                **风险等级**: {severity}  
                **目标**: `{f.get('matched-at')}`  
                **协议**: {f.get('protocol')}  
                """)
                if f.get("extra"):
                    st.caption(f"详情: {f.get('extra')}")
    else:
        st.success("✅ 本次扫描未发现明显漏洞")

    # ========== AI 分析报告 ==========
    st.divider()
    st.subheader("🤖 AI 分析报告")
    st.markdown(ai_report)

    # ========== 下载报告 ==========
    st.divider()
    st.subheader("📥 下载报告")

    safe_name = (
        target.replace("http://", "")
        .replace("https://", "")
        .replace("/", "_")
        .replace(":", "_")
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        try:
            with open(report_paths["markdown"], "rb") as f:
                md_data = f.read()
            st.download_button(
                "📄 Markdown",
                data=md_data,
                file_name=f"secagent_{safe_name}.md",
                mime="text/markdown",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"Markdown 下载失败: {e}")

    with col2:
        try:
            with open(report_paths["html"], "rb") as f:
                html_data = f.read()
            st.download_button(
                "🌐 HTML",
                data=html_data,
                file_name=f"secagent_{safe_name}.html",
                mime="text/html",
                use_container_width=True,
            )
        except Exception as e:
            st.error(f"HTML 下载失败: {e}")

    with col3:
        if report_paths.get("word"):
            try:
                with open(report_paths["word"], "rb") as f:
                    word_data = f.read()
                st.download_button(
                    "📝 Word",
                    data=word_data,
                    file_name=f"secagent_{safe_name}.docx",
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"Word 下载失败: {e}")
        else:
            st.button("📝 Word (生成失败)", disabled=True, use_container_width=True)

    with col4:
        if report_paths.get("pdf"):
            try:
                with open(report_paths["pdf"], "rb") as f:
                    pdf_data = f.read()
                st.download_button(
                    "📕 PDF",
                    data=pdf_data,
                    file_name=f"secagent_{safe_name}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"PDF 下载失败: {e}")
        else:
            st.button("📕 PDF (生成失败)", disabled=True, use_container_width=True)

    # ========== 重新扫描 ==========
    st.divider()
    if st.button("🔄 重新扫描", use_container_width=True):
        for key in ["scan_started", "scan_result", "ai_report", "report_paths"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()
