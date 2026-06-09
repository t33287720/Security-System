from core.skill import Skill
print("[DEBUG] loading extract_behavior")
skill = Skill(__file__.replace("executor.py", ""))

def run(data):
    return skill.run(data)