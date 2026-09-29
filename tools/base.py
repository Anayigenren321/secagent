from abc import ABC, abstractmethod


class BaseTool(ABC):
    """所有工具的基类"""
    name: str = "base"
    description: str = "基础工具"

    @abstractmethod
    def run(self, target: str, **kwargs) -> dict:
        """执行工具，返回结构化结果"""
        pass

    def to_schema(self) -> dict:
        """返回工具的描述，供 Agent 调用"""
        return {
            "name": self.name,
            "description": self.description,
        }
