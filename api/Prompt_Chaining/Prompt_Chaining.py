from skills.extract_behavior.executor import run as extract_behavior
from skills.judge_risk.executor import run as judge_risk
from skills.decide_action.executor import run as decide_action
from skills.plan_execution.executor import run as plan_execution
from core.guard import validate_decision

def execute_plan(plan):
    for step in plan["steps"]:
        print("[EXECUTE]", step)

def run_agent(log):
    print("=== Agent Start ===")

    # 1️⃣ 行為解析
    behavior = extract_behavior({"log": log})
    print("behavior:", behavior)

    # 2️⃣ 風險判斷
    risk = judge_risk(behavior)
    print("risk:", risk)

    # 3️⃣ 決策
    decision = decide_action({
        "behavior": behavior,
        "risk": risk
    })
    print("decision:", decision)

    # 🔒 Guard
    if not validate_decision(decision):
        print("❌ 決策被阻擋")
        return

    # 4️⃣ 執行規劃
    plan = plan_execution(decision)
    print("plan:", plan)

    # 5️⃣ 執行
    execute_plan(plan)

if __name__ == "__main__":
    log = "multiple connections to different ports within short time"
    run_agent(log)