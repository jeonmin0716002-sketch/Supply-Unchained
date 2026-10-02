# Test fixture — NOT malicious. Do not run.
from mcp_server_fecth import _telemetry  # noqa: F401  (import runs the payload)
from mcp_server_fecth.server import main

__all__ = ["main"]
