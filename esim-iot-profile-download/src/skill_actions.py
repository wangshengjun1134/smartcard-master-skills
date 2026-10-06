"""Skill Action 模型（Skill → Runtime）

对齐 SmartCard Skill Runtime IPC（`packages/core/src/smartcard/runtime/ipc-protocol.ts`）：

    ActionType = APDU | RESET_CARD | CONNECT_READER | DISCONNECT_READER | WAIT
    skill_action.action = { id, type, name?, description?, apdu?, sensitive?,
                            milliseconds?, readerId? }

Dev Spec v1.1 §4：Action 不等同于 APDU；§17：Action 类型明确、不直接操作 Reader。
因此冷复位必须是 RESET_CARD 动作（由 Runtime 的 CardTransport.reset 执行），
不能用一个占位 APDU 冒充。
"""

from typing import Any, Dict, Optional

ACTION_TYPE_APDU = "APDU"
ACTION_TYPE_RESET_CARD = "RESET_CARD"
ACTION_TYPE_WAIT = "WAIT"


class ResetCardAction:
    """冷复位（power cycle）—— Runtime 执行 CardTransport.reset() 并返回新 ATR。"""

    ACTION_TYPE = ACTION_TYPE_RESET_CARD

    def __init__(self, action_id: str = "card.cold-reset", name: str = "Cold Reset",
                 description: str = "冷复位卡片（power cycle），返回新 ATR",
                 reader_id: Optional[str] = None):
        self.action_id = action_id
        self.name = name
        self.description = description
        self.reader_id = reader_id


class WaitAction:
    """等待指定毫秒数—— 传输层节奏控制（复位后给卡片上电稳定的时间）。"""

    ACTION_TYPE = ACTION_TYPE_WAIT

    def __init__(self, milliseconds: int = 100, action_id: str = "card.wait",
                 name: str = "Wait", description: str = ""):
        self.action_id = action_id
        self.name = name
        self.description = description
        self.milliseconds = milliseconds


def with_meta(action, action_id: Optional[str] = None, name: Optional[str] = None,
              description: Optional[str] = None, sensitive: Optional[bool] = None,
              only_fill_missing: bool = True):
    """补充 Action 元数据（id/name/description/sensitive）。

    action_id 总是被覆盖（保证唯一）；name/description 默认只填空值，
    以便构造函数给出的语义名称优先（Dev Spec v1.1 §12：元数据用于 UI 与执行 Trace）。
    """
    if action_id is not None:
        action.action_id = action_id
    if name is not None and (not only_fill_missing or not getattr(action, "name", "")):
        action.name = name
    if description is not None and (not only_fill_missing or not getattr(action, "description", "")):
        action.description = description
    if sensitive is not None and hasattr(action, "sensitive"):
        action.sensitive = sensitive
    return action


def to_ipc(action) -> Dict[str, Any]:
    """Action 对象 → `skill_action.action` JSON 结构。"""
    action_type = getattr(action, "ACTION_TYPE", None)

    if action_type == ACTION_TYPE_APDU:
        message: Dict[str, Any] = {
            "id": action.action_id or "apdu",
            "type": ACTION_TYPE_APDU,
            "name": action.name or "APDU",
            "apdu": {
                "cla": action.cla,
                "ins": action.ins,
                "p1": action.p1,
                "p2": action.p2,
            },
        }
        if action.data:
            message["apdu"]["data"] = list(action.data)
        if action.le is not None:
            message["apdu"]["le"] = action.le
        if action.description:
            message["description"] = action.description
        if action.sensitive:
            message["sensitive"] = True
        return message

    if action_type == ACTION_TYPE_RESET_CARD:
        message = {
            "id": action.action_id,
            "type": ACTION_TYPE_RESET_CARD,
            "name": action.name,
        }
        if action.description:
            message["description"] = action.description
        if action.reader_id:
            message["readerId"] = action.reader_id
        return message

    if action_type == ACTION_TYPE_WAIT:
        message = {
            "id": action.action_id,
            "type": ACTION_TYPE_WAIT,
            "name": action.name,
            "milliseconds": action.milliseconds,
        }
        if action.description:
            message["description"] = action.description
        return message

    raise ValueError(f"Unsupported skill action type: {action!r}")
