import sys
import json
import os
import tempfile
from smartcard_skill_sdk import SkillContext, SessionStore, OutputCollector, ActionResult
from .skill import ReadIccidSkill


def main():
    # 使用临时目录存储会话
    session_dir = os.environ.get("SKILL_SESSION_DIR", tempfile.mkdtemp())
    
    skill = ReadIccidSkill()
    store = SessionStore(session_dir)
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
                store.save(session, "read.iccid")  # 保存状态
                response = {"jsonrpc": "2.0", "id": request_id, "result": result.model_dump(by_alias=True)}
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
                store.save(session, "read.iccid")  # 保存状态
                response = {"jsonrpc": "2.0", "id": request_id, "result": result.model_dump(by_alias=True)}
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
