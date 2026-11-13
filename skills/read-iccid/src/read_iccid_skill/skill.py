from smartcard_skill_sdk import SimpleApduSkill, SkillContext


class ReadIccidSkill(SimpleApduSkill):
    def build_apdu(self, ctx: SkillContext, params: dict) -> str:
        # SELECT MF (3F00)
        return "00A40000023F00"

    def parse_response(self, response: str, sw: str) -> dict:
        if sw != "9000":
            raise ValueError(f"APDU error: {sw}")
        # 简化示例：返回前 20 字符作为 ICCID
        return {"iccid": response[:20] if response else ""}

    def get_manifest(self) -> dict:
        return {
            "skillId": "read.iccid",
            "name": "读取 ICCID",
            "description": "读取 SIM 卡的 ICCID",
            "version": "1.0.0",
            "requiresReader": True,
            "supportsSession": True
        }
