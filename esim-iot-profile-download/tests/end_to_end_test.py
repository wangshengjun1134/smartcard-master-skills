#!/usr/bin/env python3
"""真卡连线端到端测试：复用 Skill 的执行器（同一份 IPC 循环逻辑）

本测试扮演 Runtime 的 ActionExecutor：执行器产出 Action（APDU / RESET_CARD / WAIT），
本测试用 pyscard 执行并把 `action_result` 回灌给执行器，因此可在真机上验证 Skill 的完整
流程与 IPC 语义（直接模式下载 + eIM 间接启用）。

用法:
    python3 end_to_end_test.py
    python3 end_to_end_test.py --reader "Reader Name"
    python3 end_to_end_test.py --input input-example-resources.json
"""

import argparse
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from card_reader import CardReader, CardError, bytes_to_hex
from main import ProfileDownloadExecutor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

DEFAULT_INPUT = os.path.join(os.path.dirname(__file__), 'input-example-resources.json')
DEFAULT_RESOURCES = os.path.join(os.path.dirname(__file__), '..', 'resources')


def cold_reset(card: CardReader):
    """冷复位（等价 Runtime 的 RESET_CARD 动作）"""
    from smartcard.CardConnection import CardConnection
    from smartcard.scard import SCARD_RESET_CARD
    card.connection.reconnect(CardConnection.T0_protocol, None, SCARD_RESET_CARD)
    return card.get_atr()


def run_action(card: CardReader, action) -> dict:
    """执行一条 Action，返回协议格式的 action_result（ipc-protocol.ts）"""
    action_type = getattr(action, 'ACTION_TYPE', None)

    if action_type == 'APDU':
        print(f"  TX: {action.to_hex()}")
        try:
            response, sw1, sw2 = card.transmit(
                action.cla, action.ins, action.p1, action.p2, action.data, action.le)
        except CardError as e:
            print(f"  RX: ERROR {e}")
            return {'success': False, 'error': str(e)}
        print(f"  RX: {bytes_to_hex(response)} SW={sw1:02X}{sw2:02X}")
        return {'success': True, 'response': {'sw': (sw1 << 8) | sw2, 'data': list(response)}}

    if action_type == 'RESET_CARD':
        try:
            atr = cold_reset(card)
        except Exception as e:                      # noqa: BLE001 - 卡片操作失败即回报 Runtime
            print(f"  [RESET_CARD] ERROR {e}")
            return {'success': False, 'error': str(e)}
        atr_hex = bytes_to_hex(atr) if atr else None
        print(f"  [RESET_CARD] ATR={atr_hex or 'N/A'}")
        return {'success': True, 'atr': atr_hex}

    if action_type == 'WAIT':
        print(f"  [WAIT] {action.milliseconds} ms")
        time.sleep(action.milliseconds / 1000.0)
        return {'success': True}

    return {'success': False, 'error': f'unsupported action type: {action_type}'}


def main() -> int:
    parser = argparse.ArgumentParser(description='eSIM IoT Profile Download - 真卡端到端测试')
    parser.add_argument('--reader', '-r', help='读卡器名称')
    parser.add_argument('--input', '-i', default=DEFAULT_INPUT, help='输入 JSON 文件')
    parser.add_argument('--mode', choices=['direct', 'indirect'], help='覆盖输入中的 mode')
    args = parser.parse_args()

    input_data = json.load(open(args.input, 'r'))
    input_data.setdefault('resources_dir', os.path.abspath(DEFAULT_RESOURCES))
    if args.mode:
        input_data['mode'] = args.mode

    print('=' * 60)
    print('eSIM IoT Profile Download - End-to-End Test（真卡）')
    print('=' * 60)
    print(f"Input: {args.input}")
    print(f"Mode: {input_data.get('mode')} ICCID: {input_data.get('iccid')}")

    pending_actions = []

    def on_output(level: str, message: str, data=None):
        print(f"[{level}] {message}")

    executor = ProfileDownloadExecutor(
        input_data,
        input_data['resources_dir'],
        execution_id='card-test',
        action_sink=lambda action: pending_actions.append(action),
        output_sink=on_output,
        finish_sink=lambda status, data=None, error=None: None,
    )

    with CardReader(args.reader) as card:
        atr = card.get_atr()
        print(f"Reader: {card.get_reader_name()}")
        print(f"ATR: {bytes_to_hex(atr) if atr else 'N/A'}")
        print()

        executor.start()

        action_index = 0
        while pending_actions and not executor.finished_status:
            action = pending_actions.pop(0)
            action_index += 1
            print(f"\n--- #{action_index} {getattr(action, 'action_id', '')} "
                  f"({getattr(action, 'ACTION_TYPE', '')}) ---")
            result = run_action(card, action)
            result.update({
                'type': 'action_result',
                'executionId': 'card-test',
                'actionId': getattr(action, 'action_id', ''),
                'actionType': getattr(action, 'ACTION_TYPE', ''),
            })
            executor.handle_action_result(result)

    print('\n' + '=' * 60)
    print(f"Status: {executor.finished_status}")
    if executor.finished_data:
        for key, value in executor.finished_data.items():
            print(f"  {key}: {value}")
    if executor.finished_error:
        print(f"  error: {executor.finished_error}")
    print('=' * 60)

    return 0 if executor.finished_status == 'SUCCESS' else 1


if __name__ == '__main__':
    sys.exit(main())
