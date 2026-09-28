import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()


def get_llm():
    """获取 LLM 实例（智谱 GLM-4-Flash，免费）"""
    api_key = os.getenv("ZHIPU_API_KEY")
    if not api_key:
        raise ValueError("请在 .env 文件中配置 ZHIPU_API_KEY")

    return ChatOpenAI(
        api_key=api_key,
        base_url="https://open.bigmodel.cn/api/paas/v4/",
        model="glm-4-flash",
        temperature=0.3,
    )
