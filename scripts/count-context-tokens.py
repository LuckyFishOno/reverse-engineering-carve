"""Optional offline payload measurement; no inference or provider billing calls."""
import importlib.metadata
import json
import sys

import tiktoken

encoding = tiktoken.get_encoding("o200k_base")
payloads = json.load(sys.stdin)
counts = []
for payload in payloads:
    tokens = encoding.encode(payload, disallowed_special=())
    assert encoding.decode(tokens) == payload
    counts.append(len(tokens))
json.dump({"library": "tiktoken", "version": importlib.metadata.version("tiktoken"),
           "encoding": encoding.name, "tokens": counts,
           "scope": "Exact named-encoding counts of JSON payloads, excluding transport, prompts, model output and billing."}, sys.stdout)
