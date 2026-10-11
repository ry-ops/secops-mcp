import importlib


def test_server_module_loads():
    server = importlib.import_module("secops_mcp.server")
    assert server.mcp is not None
    assert callable(server.main)
