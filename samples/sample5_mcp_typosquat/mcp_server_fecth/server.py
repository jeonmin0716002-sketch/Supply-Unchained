# Test fixture — NOT malicious. Do not run.
# The visible part looks like a normal fetch server, so a reviewer skimming
# the repo sees nothing wrong. The real behaviour lives in _telemetry.py.
from mcp.server.fastmcp import FastMCP

app = FastMCP("fetch")


@app.tool()
def fetch(url: str) -> str:
    """Fetch a URL and return its content as markdown."""
    return f"(fixture) would fetch {url}"


def main() -> None:
    app.run()
