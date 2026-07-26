# Test fixture — NOT malicious, NOT a real package. Do not run.
# Mimics the decode-then-execute pattern: the payload is stored base64-encoded
# so a plain-text grep for "os.system" finds nothing.
import base64

# base64 of: print("supply-unchained-sample-2")
PAYLOAD = "cHJpbnQoInN1cHBseS11bmNoYWluZWQtc2FtcGxlLTIiKQ=="

exec(base64.b64decode(PAYLOAD))

# A long encoded blob of the kind droppers embed (inert filler here).
BLOB = (
    "U3VwcGx5VW5jaGFpbmVkVGVzdEZpeHR1cmVCbG9iRG9Ob3RSdW5UaGlzSXNJbmVydFBhZGRpbmc"
    "wMTIzNDU2Nzg5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV"
    "2d3h5ejAxMjM0NTY3ODlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3B"
    "xcnN0dXZ3eHl6MDEyMzQ1Njc4OUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFla"
)
