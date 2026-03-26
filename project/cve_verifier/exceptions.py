"""
统一异常处理模块

定义贯穿整个验证系统的异常层级体系，
提供结构化的错误上下文信息（CVE ID、阶段名等）。
"""


class CVEVerifierError(Exception):
    """CVE 验证系统基础异常"""

    def __init__(self, message: str, cve_id: str = "", stage: str = "", **context):
        self.cve_id = cve_id
        self.stage = stage
        self.context = context
        parts = []
        if cve_id:
            parts.append(f"[{cve_id}]")
        if stage:
            parts.append(f"[{stage}]")
        parts.append(message)
        super().__init__(" ".join(parts))


class ParseError(CVEVerifierError):
    """输入解析错误（补丁文件、CVE 元数据等）"""

    def __init__(self, message: str, file_path: str = "", **kwargs):
        self.file_path = file_path
        super().__init__(message, stage="解析", file_path=file_path, **kwargs)


class RoutingError(CVEVerifierError):
    """智能分流决策错误"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, stage="分流", **kwargs)


class ReviewError(CVEVerifierError):
    """代码检视引擎错误"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, stage="检视", **kwargs)


class DynamicTestError(CVEVerifierError):
    """动态测试引擎错误"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, stage="动态测试", **kwargs)


class SandboxEnvironmentError(CVEVerifierError):
    """沙箱环境管理错误"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, stage="环境管理", **kwargs)


class ReportError(CVEVerifierError):
    """报告生成错误"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, stage="报告生成", **kwargs)


class LLMError(CVEVerifierError):
    """LLM 分析器错误"""

    def __init__(self, message: str, model: str = "", **kwargs):
        self.model = model
        super().__init__(message, stage="LLM分析", model=model, **kwargs)
