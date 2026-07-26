# Test fixture — NOT malicious, NOT a real package. Do not run.
# Mimics unsafe deserialisation: pickle.loads() on attacker-controlled bytes
# calls __reduce__ on the payload, which is arbitrary code execution.
import pickle

with open("cache.bin", "rb") as fh:
    config = pickle.loads(fh.read())

print(config)
