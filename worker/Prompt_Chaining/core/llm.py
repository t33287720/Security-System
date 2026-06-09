import requests
import json
import re

OLLAMA_URL = "http://127.0.0.1:8083/api/generate"

def parse_json(text):
    try:
        return json.loads(text)
    except:
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            return json.loads(m.group(0))
    return None

def call_llm(prompt):
    payload = {
        "model": "gemma3:27b",
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    resp = requests.post(OLLAMA_URL, json=payload)
    result = resp.json()
    text = result.get("response", "")
    return parse_json(text)