from core.skill import Skill

skill = Skill(__file__.replace("executor.py", ""))

def run(data):
    return skill.run(data)