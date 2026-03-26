"""pytest 配置 — 过滤模型类收集警告"""

collect_ignore_glob = []


def pytest_collection_modifyitems(config, items):
    """过滤无关的收集警告。"""
    pass


def pytest_configure(config):
    """抑制模型类被误识别为测试类的警告。"""
    config.addinivalue_line(
        "filterwarnings",
        "ignore::pytest.PytestCollectionWarning",
    )
