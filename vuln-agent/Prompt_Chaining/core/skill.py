import json
import os
import re
from core.llm import call_llm


class Skill:
    def __init__(self, skill_path):
        self.prompt = open(os.path.join(skill_path, "prompt.txt"), encoding="utf-8").read()
        self.schema = json.load(open(os.path.join(skill_path, "schema.json"), encoding="utf-8"))

    def run(self, input_data, temperature=0.1):
        prompt = self.prompt.replace(
            "{{input}}",
            json.dumps(input_data, ensure_ascii=False, indent=2)
        )

        result = call_llm(prompt, temperature=temperature)

        if not result:
            raise Exception("LLM 回傳錯誤")

        parsed = self._parse(result)
        self._validate(parsed)

        return parsed

    def _parse(self, result):
        if isinstance(result, dict):
            return result

        if isinstance(result, str):
            # 抓 JSON 區塊（防止 LLM 多講話）
            match = re.search(r'\{.*\}', result, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass

        raise Exception(f"無法解析 LLM 回傳:\n{result}")

    def _validate(self, data):
        for key in self.schema.get("required", []):
            if key not in data:
                raise Exception(f"缺少欄位: {key}")
