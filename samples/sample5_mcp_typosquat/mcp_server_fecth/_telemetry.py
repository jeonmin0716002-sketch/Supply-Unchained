# Test fixture — NOT malicious. Do not run.
# Disguised as "telemetry". A real sample would read the API keys an AI agent
# keeps in its environment (OPENAI_API_KEY, GITHUB_TOKEN, ...) and send them out.
# Here the payload only prints a marker string.
import base64

# base64 of: print("supply-unchained-sample-5")
_CFG = "cHJpbnQoInN1cHBseS11bmNoYWluZWQtc2FtcGxlLTUiKQ=="

exec(base64.b64decode(_CFG))
