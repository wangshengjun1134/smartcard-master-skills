#!/usr/bin/env python3
"""
eSIM IoT Profile Download Skill - 连卡测试脚本

用法:
    python3 test_card_connection.py --list-readers
    python3 test_card_connection.py --reader "Reader Name"
    python3 test_card_connection.py --apdu "00A40004023F0000"
    python3 test_card_connection.py --test-ic-sequence
    python3 test_card_connection.py --test-euicc-info
    python3 test_card_connection.py --interactive
"""

import argparse
import json
import sys
import os
import logging
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from card_reader import CardReader, CardError, bytes_to_hex, hex_to_bytes
from src.utils import sw_to_string, is_success, needs_fetch, has_more_data

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


def cmd_list_readers(args):
    readers = CardReader.list_readers()
    if not readers:
        print("No smart card readers found")
        return
    print(f"Found {len(readers)} reader(s):")
    for i, name in enumerate(readers):
        print(f"  [{i}] {name}")


def cmd_connect(args):
    try:
        reader_name = args.reader if args.reader else None
        with CardReader(reader_name) as card:
            atr = card.get_atr()
            print(f"Reader: {card.get_reader_name()}")
            print(f"ATR: {bytes_to_hex(atr) if atr else 'N/A'}")
            print(f"Connected: {card.is_connected()}")
    except CardError as e:
        logger.error(f"Card error: {e}")
        sys.exit(1)


def cmd_transmit_apdu(args):
    try:
        reader_name = args.reader if args.reader else None
        apdu_hex = args.apdu
        apdu_bytes = hex_to_bytes(apdu_hex)
        if len(apdu_bytes) < 4:
            logger.error("APDU must be at least 4 bytes")
            sys.exit(1)
        
        cla, ins, p1, p2 = apdu_bytes[0], apdu_bytes[1], apdu_bytes[2], apdu_bytes[3]
        data, le = None, None
        if len(apdu_bytes) > 4:
            lc = apdu_bytes[4]
            if lc > 0 and len(apdu_bytes) > 5:
                data = apdu_bytes[5:5+lc]
            if len(apdu_bytes) > 5 + lc:
                le = apdu_bytes[5 + lc]
        
        with CardReader(reader_name) as card:
            response, sw1, sw2 = card.transmit(cla, ins, p1, p2, data, le)
            print(f"TX: {apdu_hex.upper()}")
            print(f"RX: {bytes_to_hex(response)} SW={sw_to_string(sw1, sw2)}")
    except CardError as e:
        logger.error(f"Card error: {e}")
        sys.exit(1)


def cmd_test_ic_sequence(args):
    """严格按 Java 日志 000001.log 的 IC1/IC2 序列"""
    try:
        reader_name = args.reader if args.reader else None
        
        with CardReader(reader_name) as card:
            print(f"Reader: {card.get_reader_name()}")
            print(f"ATR: {bytes_to_hex(card.get_atr()) if card.get_atr() else 'N/A'}")
            print()
            
            # Step 1: SELECT MF
            # Java: 00A40004023F0000 -> 6226... SW=9000
            print("=== Step 1: SELECT MF ===")
            resp, sw1, sw2 = card.transmit(0x00, 0xA4, 0x00, 0x04, bytes([0x3F, 0x00]))
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: 00A40004023F0000")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            if sw.startswith("61"):
                resp, sw1, sw2 = card.transmit(0x00, 0xC0, 0x00, 0x00, le=sw2)
                sw = sw_to_string(sw1, sw2)
                print(f"  TX: 00C00000{sw2:02X}")
                print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            # Step 2: TERMINAL CAPABILITY
            # Java: 80AA000007A9058100830107 -> SW=9000
            print("\n=== Step 2: TERMINAL CAPABILITY ===")
            resp, sw1, sw2 = card.transmit(0x80, 0xAA, 0x00, 0x00, bytes([0xA9, 0x05, 0x81, 0x00, 0x83, 0x01, 0x07]))
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: 80AA000007A9058100830107")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            # Step 3: TERMINAL PROFILE
            # Java: 8010000020... -> 9110 -> FETCH -> 9000
            #       -> 8014... -> 910F -> FETCH -> 9000
            print("\n=== Step 3: TERMINAL PROFILE ===")
            tp = bytes([0xFF]*3 + [0x7F, 0x9D, 0x00, 0xDF, 0xBF, 0x00, 0x00, 0x1F, 0xE2, 0x00, 0x00, 0x00, 0xC7, 0xEB, 0x00, 0x00, 0x01, 0x68, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00])
            resp, sw1, sw2 = card.transmit(0x80, 0x10, 0x00, 0x00, tp)
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: 8010000020{tp.hex().upper()}")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            combined = bytearray()
            for _ in range(5):
                if not sw.startswith("91"):
                    break
                flen = int(sw[2:], 16)
                resp, sw1, sw2 = card.transmit(0x80, 0x12, 0x00, 0x00, le=flen)
                sw = sw_to_string(sw1, sw2)
                print(f"  TX: 80120000{flen:02X}")
                print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
                combined.extend(resp)
                if sw.startswith("91"):
                    es10 = bytes([0x81, 0x03, 0x01, 0x05, 0x00, 0x82, 0x02, 0x82, 0x81, 0x83, 0x01, 0x00])
                    resp, sw1, sw2 = card.transmit(0x80, 0x14, 0x00, 0x00, es10)
                    sw = sw_to_string(sw1, sw2)
                    print(f"  TX: 801400000C{es10.hex().upper()}")
                    print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
                    combined.extend(resp)
            
            # Step 4: STATUS
            # Java: 80F2000C -> SW=9000
            print("\n=== Step 4: STATUS ===")
            resp, sw1, sw2 = card.transmit(0x80, 0xF2, 0x00, 0x0C)
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: 80F2000C")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            # Step 5: MANAGE_CHANNEL_OPEN
            # Java: 0070000001 -> RESP: 01 SW=9000
            print("\n=== Step 5: MANAGE_CHANNEL_OPEN ===")
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: 0070000001")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            channel = resp[0] if resp and len(resp) > 0 else 1
            print(f"  -> Channel: {channel}")
            
            # Step 6: SELECT ISD-R
            # Java: 01A4040010A0000005591010FFFFFFFF8900000100 -> SW=9000
            # 但卡可能返回 61XX，需要 GET RESPONSE
            print(f"\n=== Step 6: SELECT ISD-R (ch=0x{channel:02X}) ===")
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            resp, sw1, sw2 = card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: {channel:02X}A4040010{isdr.hex().upper()}")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            # 处理 61XX (GET RESPONSE)
            if sw.startswith("61"):
                le = sw2
                resp, sw1, sw2 = card.transmit(channel, 0xC0, 0x00, 0x00, le=le)
                sw = sw_to_string(sw1, sw2)
                print(f"  TX: {channel:02X}C00000{le:02X} (GET RESPONSE)")
                print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            print("\n✓ IC1/IC2 completed")
    
    except CardError as e:
        logger.error(f"Card error: {e}")
        sys.exit(1)


def cmd_test_euicc_info(args):
    """测试 eUICC 信息读取 - 先执行 IC1/IC2 初始化"""
    try:
        reader_name = args.reader if args.reader else None
        
        with CardReader(reader_name) as card:
            print(f"Reader: {card.get_reader_name()}")
            print(f"ATR: {bytes_to_hex(card.get_atr()) if card.get_atr() else 'N/A'}")
            print()
            
            # IC1/IC2 初始化
            print("=== IC1/IC2 Initialization ===")
            
            # SELECT MF
            resp, sw1, sw2 = card.transmit(0x00, 0xA4, 0x00, 0x04, bytes([0x3F, 0x00]))
            sw = sw_to_string(sw1, sw2)
            print(f"  SELECT MF: SW={sw}")
            
            # TERMINAL CAPABILITY
            resp, sw1, sw2 = card.transmit(0x80, 0xAA, 0x00, 0x00, bytes([0xA9, 0x05, 0x81, 0x00, 0x83, 0x01, 0x07]))
            sw = sw_to_string(sw1, sw2)
            print(f"  TERMINAL CAPABILITY: SW={sw}")
            
            # TERMINAL PROFILE
            tp = bytes([0xFF]*3 + [0x7F, 0x9D, 0x00, 0xDF, 0xBF, 0x00, 0x00, 0x1F, 0xE2, 0x00, 0x00, 0x00, 0xC7, 0xEB, 0x00, 0x00, 0x01, 0x68, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00])
            resp, sw1, sw2 = card.transmit(0x80, 0x10, 0x00, 0x00, tp)
            sw = sw_to_string(sw1, sw2)
            print(f"  TERMINAL PROFILE: SW={sw}")
            
            # STATUS
            resp, sw1, sw2 = card.transmit(0x80, 0xF2, 0x00, 0x0C)
            sw = sw_to_string(sw1, sw2)
            print(f"  STATUS: SW={sw}")
            
            # MANAGE_CHANNEL_OPEN
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            sw = sw_to_string(sw1, sw2)
            channel = resp[0] if resp and len(resp) > 0 else 1
            print(f"  MANAGE_CHANNEL: SW={sw} Channel={channel}")
            
            # SELECT ISD-R
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            resp, sw1, sw2 = card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            sw = sw_to_string(sw1, sw2)
            print(f"  SELECT ISD-R: SW={sw}")
            
            print()
            
            # GetEuiccInfo1 (BF20)
            print("=== GetEuiccInfo1 (BF20) ===")
            resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x20, 0x00, 0x00]))
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: {(0x80|channel):02X}E2910003BF200000")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            # GetEuiccChallenge (BF2E)
            print("\n=== GetEuiccChallenge (BF2E) ===")
            resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x2E, 0x00, 0x00]))
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: {(0x80|channel):02X}E2910003BF2E0000")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            print("\n✓ eUICC info completed")
    
    except CardError as e:
        logger.error(f"Card error: {e}")
        sys.exit(1)


def cmd_interactive(args):
    try:
        reader_name = args.reader if args.reader else None
        
        with CardReader(reader_name) as card:
            print(f"Reader: {card.get_reader_name()}")
            print(f"ATR: {bytes_to_hex(card.get_atr()) if card.get_atr() else 'N/A'}")
            print()
            print("Interactive mode. Type 'quit' to exit.")
            print()
            
            while True:
                try:
                    apdu_input = input("APDU> ").strip()
                    if apdu_input.lower() in ('quit', 'exit', 'q'):
                        break
                    if not apdu_input:
                        continue
                    
                    apdu_bytes = hex_to_bytes(apdu_input)
                    if len(apdu_bytes) < 4:
                        print("Error: APDU must be at least 4 bytes")
                        continue
                    
                    cla, ins, p1, p2 = apdu_bytes[0], apdu_bytes[1], apdu_bytes[2], apdu_bytes[3]
                    data, le = None, None
                    if len(apdu_bytes) > 4:
                        lc = apdu_bytes[4]
                        if lc > 0 and len(apdu_bytes) > 5:
                            data = apdu_bytes[5:5+lc]
                        if len(apdu_bytes) > 5 + lc:
                            le = apdu_bytes[5 + lc]
                    
                    resp, sw1, sw2 = card.transmit(cla, ins, p1, p2, data, le)
                    print(f"  TX: {apdu_input.upper()}")
                    print(f"  RX: {bytes_to_hex(resp)} SW={sw_to_string(sw1, sw2)}")
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error: {e}")
            
            print("\nExiting")
    
    except CardError as e:
        logger.error(f"Card error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='eSIM IoT Profile Download - Card Test')
    parser.add_argument('--reader', '-r', help='Reader name')
    parser.add_argument('--channel', '-c', type=int, default=1, help='Logical channel')
    parser.add_argument('--debug', '-d', action='store_true', help='Debug mode')
    
    parser.add_argument('--list-readers', action='store_true')
    parser.add_argument('--connect', action='store_true')
    parser.add_argument('--apdu', type=str)
    parser.add_argument('--test-ic-sequence', action='store_true')
    parser.add_argument('--test-euicc-info', action='store_true')
    parser.add_argument('--interactive', action='store_true')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.list_readers: cmd_list_readers(args)
    elif args.connect: cmd_connect(args)
    elif args.apdu: cmd_transmit_apdu(args)
    elif args.test_ic_sequence: cmd_test_ic_sequence(args)
    elif args.test_euicc_info: cmd_test_euicc_info(args)
    elif args.interactive: cmd_interactive(args)
    else: parser.print_help()


if __name__ == '__main__':
    main()
