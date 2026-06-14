import os
import re
import json
import requests

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
MODEL = "gemma3:27b"


def parse_json(text):
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            return json.loads(m.group(0))
    return None


def call_llm(prompt, temperature=0.1, num_ctx=None):
    options = {"temperature": temperature}
    if num_ctx:
        options["num_ctx"] = num_ctx

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": options
    }

    resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
    result = resp.json()
    text = result.get("response", "")
    return parse_json(text)
