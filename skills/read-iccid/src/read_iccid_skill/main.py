import sys
import json
from smartcard_skill_sdk import SkillContext, SessionStore, OutputCollector, ActionResult
from .skill import ReadIccidSkill


def main():
    skill = ReadIccidSkill()
    store = SessionStore("./.sessions")
    ctx = SkillContext(skill_id="read.iccid", sessions=store, output=OutputCollector())

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params", {})

        if method == "skill.init":
            result = skill.init(ctx, params.get("input", {}))
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
            print(json.dumps(response), flush=True)

        elif method == "skill.start":
            session_id = params["sessionId"]
            session = store.load(session_id)
            if not session:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": "SESSION_NOT_FOUND", "message": "会话不存在"}
                }
            else:
                result = skill.start(ctx, session)
                response = {"jsonrpc": "2.0", "id": request_id, "result": result.model_dump()}
            print(json.dumps(response), flush=True)

        elif method == "skill.handleActionResult":
            session_id = params["sessionId"]
            session = store.load(session_id)
            if not session:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": "SESSION_NOT_FOUND", "message": "会话不存在"}
                }
            else:
                action_result = ActionResult(**params["result"])
                result = skill.handle_action_result(ctx, action_result, session)
                response = {"jsonrpc": "2.0", "id": request_id, "result": result.model_dump()}
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
