from core.skill import Skill

skill = Skill(__file__.replace("executor.py", ""))


def run(data):
    return skill.run(data, temperature=0.1, num_ctx=8192)
