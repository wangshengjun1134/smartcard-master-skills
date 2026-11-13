from smartcard_skill_sdk import SimpleApduSkill, SkillContext, SkillResult, ActionResult, Action, ActionType
from smartcard_skill_sdk.session_store import SkillSession
from enum import Enum


class ReadIccidState(str, Enum):
    """读取 ICCID 的状态机"""
    START = "START"
    WAIT_SELECT_MF = "WAIT_SELECT_MF"
    WAIT_SELECT_ICCID = "WAIT_SELECT_ICCID"
    WAIT_READ_BINARY = "WAIT_READ_BINARY"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class ReadIccidSkill(SimpleApduSkill):
    """
    读取 ICCID 的 Skill
    
    执行流程：
    1. SELECT MF (3F00) - 选择主文件
    2. SELECT EF_ICCID (2FE2) - 选择 ICCID 文件
    3. READ BINARY - 读取 10 字节 ICCID 内容
    4. 解析 BCD 编码的 ICCID
    """

    def get_manifest(self) -> dict:
        return {
            "skillId": "read.iccid",
            "name": "读取 ICCID",
            "description": "读取 SIM 卡的 ICCID（集成电路卡标识符）",
            "version": "1.0.0",
            "requiresReader": True,
            "supportsSession": True
        }

    def build_apdu(self, ctx: SkillContext, params: dict) -> str:
        """根据当前状态构建 APDU"""
        state = params.get("state", ReadIccidState.START)
        
        if state == ReadIccidState.START or state == ReadIccidState.WAIT_SELECT_MF:
            # SELECT MF: 00 A4 00 00 02 3F00
            return "00A40000023F00"
        elif state == ReadIccidState.WAIT_SELECT_ICCID:
            # SELECT EF_ICCID: 00 A4 00 00 02 2FE2
            return "00A40000022FE2"
        elif state == ReadIccidState.WAIT_READ_BINARY:
            # READ BINARY: 00 B0 00 00 0A (读取 10 字节)
            return "00B000000A"
        else:
            raise ValueError(f"未知状态: {state}")

    def parse_response(self, response: str, sw: str) -> dict:
        """解析响应（此方法在 SimpleApduSkill 基类中被调用，但我们需要多步处理）"""
        # 这个方法在简单场景下使用，但 ICCID 读取需要多步
        # 实际逻辑在 handle_action_result 中
        return {"raw": response, "sw": sw}

    def start(self, ctx: SkillContext, session: SkillSession) -> SkillResult:
        """开始执行，进入第一步：SELECT MF"""
        ctx.output.info("开始读取 ICCID")
        ctx.output.text("步骤 1/3: 选择主文件 (MF)")
        
        session.data["state"] = ReadIccidState.WAIT_SELECT_MF
        session.state = ReadIccidState.WAIT_SELECT_MF
        
        apdu = self.build_apdu(ctx, {"state": ReadIccidState.WAIT_SELECT_MF})
        action = Action(
            action_id="read.iccid.select-mf",
            type=ActionType.APDU,
            name="选择主文件",
            description="SELECT MF (3F00)",
            sensitive=False,
            payload={"apdu": apdu, "expectedStatus": ["9000"]}
        )
        return SkillResult.continue_with(session.session_id, action)

    def handle_action_result(
        self, ctx: SkillContext, result: ActionResult, session: SkillSession
    ) -> SkillResult:
        """处理 Action 结果，驱动状态机"""
        current_state = session.data.get("state", ReadIccidState.START)
        
        # 检查 APDU 执行状态
        if result.status.value != "OK":
            session.data["state"] = ReadIccidState.FAILED
            return SkillResult.failed(
                session.session_id,
                "APDU_ERROR",
                f"APDU 执行失败: {result.status}"
            )
        
        # 检查 SW (状态字)
        sw = result.data.get("sw", "")
        if sw != "9000":
            session.data["state"] = ReadIccidState.FAILED
            return SkillResult.failed(
                session.session_id,
                "APDU_STATUS_ERROR",
                f"卡片返回错误状态: {sw}"
            )
        
        # 状态机转换
        if current_state == ReadIccidState.WAIT_SELECT_MF:
            # MF 选择成功，进入下一步：选择 ICCID 文件
            ctx.output.text("步骤 2/3: 选择 ICCID 文件 (EF_ICCID)")
            session.data["state"] = ReadIccidState.WAIT_SELECT_ICCID
            session.state = ReadIccidState.WAIT_SELECT_ICCID
            
            apdu = self.build_apdu(ctx, {"state": ReadIccidState.WAIT_SELECT_ICCID})
            action = Action(
                action_id="read.iccid.select-iccid",
                type=ActionType.APDU,
                name="选择 ICCID 文件",
                description="SELECT EF_ICCID (2FE2)",
                sensitive=False,
                payload={"apdu": apdu, "expectedStatus": ["9000"]}
            )
            return SkillResult.continue_with(session.session_id, action)
        
        elif current_state == ReadIccidState.WAIT_SELECT_ICCID:
            # ICCID 文件选择成功，进入下一步：读取数据
            ctx.output.text("步骤 3/3: 读取 ICCID 数据")
            session.data["state"] = ReadIccidState.WAIT_READ_BINARY
            session.state = ReadIccidState.WAIT_READ_BINARY
            
            apdu = self.build_apdu(ctx, {"state": ReadIccidState.WAIT_READ_BINARY})
            action = Action(
                action_id="read.iccid.read-binary",
                type=ActionType.APDU,
                name="读取 ICCID 数据",
                description="READ BINARY (10 字节)",
                sensitive=False,
                payload={"apdu": apdu, "expectedStatus": ["9000"]}
            )
            return SkillResult.continue_with(session.session_id, action)
        
        elif current_state == ReadIccidState.WAIT_READ_BINARY:
            # 数据读取成功，解析 ICCID
            response = result.data.get("response", "")
            iccid = self._parse_iccid(response)
            
            ctx.output.info(f"ICCID 读取成功: {iccid}")
            
            session.data["state"] = ReadIccidState.SUCCESS
            session.data["iccid"] = iccid
            session.state = ReadIccidState.SUCCESS
            
            return SkillResult.success(session.session_id, {"iccid": iccid})
        
        # 未知状态
        return SkillResult.failed(
            session.session_id,
            "UNKNOWN_STATE",
            f"未知状态: {current_state}"
        )

    def _parse_iccid(self, hex_data: str) -> str:
        """
        解析 ICCID 的 BCD 编码
        
        ICCID 结构 (10 字节):
        - 字节 0-1: 89 (固定前缀，表示电信行业)
        - 字节 2-3: 国家代码 (如 86 = 中国)
        - 字节 4-5: 运营商代码
        - 字节 6-9: 个人化数据
        - 最后一个字节的高 4 位: 校验位 (Luhn 算法)
        
        BCD 编码规则:
        - 每个字节包含两个数字
        - 低 4 位在前，高 4 位在后
        - 例如: 0x89 -> "98" (低 4 位 9, 高 4 位 8)
        - F 表示填充位
        """
        if not hex_data or len(hex_data) < 20:
            return ""
        
        # 将 hex 字符串转换为字节列表
        bytes_data = bytes.fromhex(hex_data)
        
        # 解析 BCD 编码
        digits = []
        for byte in bytes_data:
            low = byte & 0x0F  # 低 4 位
            high = (byte >> 4) & 0x0F  # 高 4 位
            
            # 低 4 位在前
            if low <= 9:
                digits.append(str(low))
            elif low == 0x0F:
                break  # F 是填充位，结束
            
            # 高 4 位在后
            if high <= 9:
                digits.append(str(high))
            elif high == 0x0F:
                break  # F 是填充位，结束
        
        return "".join(digits)
