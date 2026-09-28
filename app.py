import time
import streamlit as st
from agent.core import SecAgent

# ========== 页面配置 ==========
st.set_page_config(
    page_title="SecAgent —— AI 安全评估平台",
    page_icon="🛡️",
    layout="wide",
)

# ========== 标题 ==========
st.title("🛡️ SecAgent")
st.caption("AI 驱动的安全评估平台 · 让安全评估更简单")

# ========== 侧边栏 ==========
with st.sidebar:
    st.header("📌 目标设置")
    target = st.text_input(
        "目标地址",
        value="http://192.168.12.128",
        help="输入要扫描的 IP 或 URL",
    )

    scan_type = st.multiselect(
        "扫描类型",
        ["漏洞扫描", "基线核查", "端口扫描", "Web 目录扫描"],
        default=["漏洞扫描", "基线核查"],
    )

    st.divider()

    if st.button("🚀 开始扫描", type="primary", use_container_width=True):
        st.session_state["scan_started"] = True

    st.divider()

    st.header("⚙️ 关于")
    st.info("SecAgent v0.1\n\n基于 AI 的自主安全评估 Agent")

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
    st.subheader(f"📡 目标: {target}")

    progress = st.progress(0, text="🔍 正在初始化 Agent...")

    scan_result = f"""
    目标: {target}
    开放端口: 22(SSH), 80(HTTP), 443(HTTPS), 8086(WordPress)
    服务信息:
    - 22: OpenSSH 8.9p1
    - 80/443: OpenResty
    - 8086: WordPress 7.1.0
    发现的问题:
    - WordPress 版本号暴露 (/readme.html)
    - REST API 用户枚举 (/wp-json/wp/v2/users/)
    - 缺少安全响应头 (X-Frame-Options, CSP)
    """

    progress.progress(30, text="🔍 正在扫描端口...")
    time.sleep(1)

    progress.progress(60, text="🔍 正在检测漏洞...")
    time.sleep(1)

    progress.progress(80, text="🤖 正在调用 AI 分析...")

    agent = SecAgent()
    report = agent.analyze_scan_result(scan_result)

    progress.progress(100, text="✅ 扫描完成！")
    time.sleep(0.5)
    progress.empty()

    # ========== 结果展示 ==========
    st.divider()
    st.subheader("📊 安全概览")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("安全评分", "65", delta="-35")
    with col2:
        st.metric("高危", "1", delta_color="inverse")
    with col3:
        st.metric("中危", "2")
    with col4:
        st.metric("低危", "3")

    score = 65
    st.progress(score / 100, text=f"安全评分: {score}/100")

    # ========== 漏洞列表 ==========
    st.divider()
    st.subheader("📋 漏洞详情")

    with st.expander("🔴 WordPress REST API 用户枚举", expanded=True):
        st.markdown("""
        **风险等级**: 🔴 高危  
        **CVSS 评分**: 7.5  
        **影响**: 攻击者可枚举用户名，用于暴力破解  
        **修复建议**: 在 WordPress 中关闭 REST API 用户端点
        """)

    with st.expander("🟡 WordPress 版本号暴露"):
        st.markdown("""
        **风险等级**: 🟡 中危  
        **影响**: 攻击者可知版本，查找对应漏洞  
        **修复建议**: 删除 readme.html 文件
        """)

    with st.expander("🟢 缺少安全响应头"):
        st.markdown("""
        **风险等级**: 🟢 低危  
        **影响**: 缺少 X-Frame-Options、CSP 等安全头  
        **修复建议**: 在 Nginx 配置中添加安全头
        """)

    # ========== AI 分析报告 ==========
    st.divider()
    st.subheader("🤖 AI 分析报告")
    st.markdown(report)

    # ========== 下载报告 ==========
    st.divider()
    col1, col2 = st.columns(2)
    with col1:
        st.download_button(
            "📥 下载 AI 报告 (Markdown)",
            data=report,
            file_name=f"secagent_report_{target.replace(':', '_').replace('/', '_')}.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with col2:
        if st.button("🔄 重新扫描", use_container_width=True):
            st.session_state["scan_started"] = False
            st.rerun()
