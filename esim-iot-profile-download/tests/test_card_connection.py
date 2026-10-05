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


def cmd_test_cleanup(args):
    """测试 Cleanup 流程 - 严格按 Java 日志执行序列"""
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
            
            # === Cleanup 流程 ===
            print("=== Cleanup 流程 ===")
            
            # Step 1: EuiccMemoryReset (BF34)
            # Java: 81E2910007BF3404820205E0 -> RESP: BF3403800101 SW=9000
            print("\n--- Step 1: EuiccMemoryReset (BF34) ---")
            bf34_data = bytes([0xBF, 0x34, 0x04, 0x82, 0x02, 0x05, 0xE0])
            resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bf34_data)
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: {(0x80|channel):02X}E2910007{bf34_data.hex().upper()}")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            # Step 2: ListNotification (BF28)
            # Java: 81E2910003BF280000 -> RESP: BF2802A000 SW=9000
            print("\n--- Step 2: ListNotification (BF28) ---")
            bf28_data = bytes([0xBF, 0x28, 0x00, 0x00])
            resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bf28_data)
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: {(0x80|channel):02X}E2910003{bf28_data.hex().upper()}")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            # Step 3: RemoveNotification (BF30) - 根据 ListNotification 响应动态生成
            # Java 日志中 ListNotification 返回 BF2802A000，没有 notification sequence，所以不需要 RemoveNotification
            # 但如果返回 A0 开头的 sequence，需要发送 BF30 命令
            print("\n--- Step 3: RemoveNotification (BF30) ---")
            if resp and len(resp) > 0:
                # 解析 ListNotification 响应，提取 notification sequences
                sequences = _extract_notification_sequences(resp)
                if sequences:
                    print(f"  Found {len(sequences)} notification(s)")
                    for seq in sequences:
                        bf30_data = bytes([0xBF, 0x30, 0x04, 0x80, 0x02]) + seq
                        resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bf30_data)
                        sw = sw_to_string(sw1, sw2)
                        print(f"  TX: {(0x80|channel):02X}E2910007{bf30_data.hex().upper()}")
                        print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
                else:
                    print("  No notifications to remove")
            else:
                print("  Empty response from ListNotification")
            
            print("\n✓ Cleanup completed")
    
    except CardError as e:
        logger.error(f"Card error: {e}")
        sys.exit(1)


def _extract_notification_sequences(response: bytes) -> list:
    """从 ListNotification 响应提取 notification sequences"""
    sequences = []
    if not response or len(response) < 2:
        return sequences
    
    # 简单解析：查找 A0 tag (notification list)
    # 完整实现应使用 pyasn1 解析 BER-TLV
    offset = 0
    while offset < len(response):
        tag = response[offset]
        offset += 1
        
        if tag == 0xA0:
            # 找到 notification list
            length = response[offset]
            offset += 1
            list_data = response[offset:offset + length]
            
            # 解析每个 notification
            list_offset = 0
            while list_offset < len(list_data):
                notif_tag = list_data[list_offset]
                list_offset += 1
                
                if notif_tag == 0xBF and list_offset < len(list_data) and list_data[list_offset] == 0x2F:
                    # 找到 BF2F (notification)
                    list_offset += 1
                    notif_length = list_data[list_offset]
                    list_offset += 1
                    notif_data = list_data[list_offset:list_offset + notif_length]
                    
                    # 提取 sequence (80 tag)
                    notif_offset = 0
                    while notif_offset < len(notif_data):
                        if notif_data[notif_offset] == 0x80 and notif_offset + 2 < len(notif_data):
                            seq_length = notif_data[notif_offset + 1]
                            if seq_length == 2:
                                sequences.append(notif_data[notif_offset + 2:notif_offset + 2 + seq_length])
                            notif_offset += 2 + seq_length
                        else:
                            notif_offset += 1
                    
                    list_offset += notif_length
                else:
                    list_offset += 1
            
            offset += length
        else:
            # 跳过未知 tag
            if offset < len(response):
                length = response[offset]
                offset += 1 + length
    
    return sequences


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


def cmd_test_profile_download(args):
    """测试完整 Profile 下载流程 (BF20 -> BF2E -> BF38 -> BF21 -> BF36)"""
    try:
        reader_name = args.reader if args.reader else None
        
        # 1. 初始化本地 SM-DP+
        print("=== 初始化本地 SM-DP+ ===")
        from src.smdp_plus import LocalSmdpPlus
        from src.profile_package_store import ProfilePackageStore, ProfilePackageTemplate
        from src.pki_manager import PkiIdentity, load_private_key_from_pem, load_certificate_from_der, load_certificate_from_pem
        from src.asn1_codec import encode_bf38_authenticate_server_request, encode_bf21_prepare_download_request, decode_bf2e_challenge
        from src.utils import bytes_to_hex, hex_to_bytes
        import os
        
        resources_dir = os.path.join(os.path.dirname(__file__), '..', 'resources')
        certs_dir = os.path.join(resources_dir, 'certs')
        profiles_dir = os.path.join(resources_dir, 'profiles')
        
        dp_auth_key = load_private_key_from_pem(open(os.path.join(certs_dir, 'SK_S_SM_DPauth_ECDSA_NIST.pem'), 'rb').read())
        dp_auth_cert = load_certificate_from_der(open(os.path.join(certs_dir, 'CERT_S_SM_DPauth_ECDSA_NIST.der'), 'rb').read())
        dp_pb_key = load_private_key_from_pem(open(os.path.join(certs_dir, 'SK_S_SM_DPpb_ECDSA_NIST.pem'), 'rb').read())
        dp_pb_cert = load_certificate_from_der(open(os.path.join(certs_dir, 'CERT_S_SM_DPpb_ECDSA_NIST.der'), 'rb').read())
        ci_cert = load_certificate_from_pem(open(os.path.join(certs_dir, 'CERT_CI_ECDSA_NIST.pem'), 'rb').read())
        
        upp_file = os.path.join(profiles_dir, 'PROFILE_OPERATIONAL1_8929901012345678905F.HEX')
        upp_payload = bytes.fromhex(open(upp_file, 'r').read().strip().replace(" ", "").replace("\n", ""))
        
        packages = ProfilePackageStore()
        packages.save(ProfilePackageTemplate(
            matching_id="04386-AGYFT-A74Y8-3F815",
            profile_id="A0000005591010FFFFFFFF8900001000",
            profile_name="IoT Profile",
            iccid="8929901012345678905",
            payload=upp_payload,
        ))
        
        smdp = LocalSmdpPlus(packages, PkiIdentity(dp_auth_key, [dp_auth_cert]), PkiIdentity(dp_pb_key, [dp_pb_cert]), ci_cert)
        print(f"  SM-DP+ initialized. Packages: {len(packages)}")
        
        with CardReader(reader_name) as card:
            print(f"\nReader: {card.get_reader_name()}")
            print(f"ATR: {bytes_to_hex(card.get_atr()) if card.get_atr() else 'N/A'}")
            print()
            
            # 2. IC1/IC2 初始化
            print("=== IC1/IC2 Initialization ===")
            card.transmit(0x00, 0xA4, 0x00, 0x04, bytes([0x3F, 0x00]))
            card.transmit(0x80, 0xAA, 0x00, 0x00, bytes([0xA9, 0x05, 0x81, 0x00, 0x83, 0x01, 0x07]))
            tp = bytes([0xFF]*3 + [0x7F, 0x9D, 0x00, 0xDF, 0xBF, 0x00, 0x00, 0x1F, 0xE2, 0x00, 0x00, 0x00, 0xC7, 0xEB, 0x00, 0x00, 0x01, 0x68, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00])
            card.transmit(0x80, 0x10, 0x00, 0x00, tp)
            card.transmit(0x80, 0xF2, 0x00, 0x0C)
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel = resp[0] if resp and len(resp) > 0 else 1
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            print(f"  Channel: {channel}")
            
            def store_data(data: bytes, desc: str):
                """发送 StoreData 命令 (ES10x)"""
                offset = 0
                block_num = 0
                while offset < len(data):
                    chunk = data[offset:offset + 255]
                    is_last = (offset + 255 >= len(data))
                    p1 = 0x91 if is_last else 0x11
                    print(f"  [{desc}] TX: {(0x80|channel):02X}E2{p1:02X}{block_num:02X}{len(chunk):02X}{bytes_to_hex(chunk)}")
                    resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, p1, block_num, chunk)
                    sw = sw_to_string(sw1, sw2)
                    print(f"  [{desc}] RX: {bytes_to_hex(resp)} SW={sw}")
                    if sw != "9000":
                        raise Exception(f"StoreData failed: {sw}")
                    offset += 255
                    block_num += 1
            
            # 3. GetEuiccInfo1 (BF20)
            print("\n=== GetEuiccInfo1 (BF20) ===")
            resp_bf20, _, _ = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x20, 0x00]))
            print(f"  RX: {bytes_to_hex(resp_bf20)}")
            
            # 4. GetEuiccChallenge (BF2E)
            print("\n=== GetEuiccChallenge (BF2E) ===")
            resp_bf2e, _, _ = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x2E, 0x00]))
            print(f"  RX: {bytes_to_hex(resp_bf2e)}")
            euicc_challenge = decode_bf2e_challenge(resp_bf2e)
            print(f"  Challenge: {bytes_to_hex(euicc_challenge)}")
            
            # 5. AuthenticateServer (BF38)
            print("\n=== AuthenticateServer (BF38) ===")
            auth_result = smdp.initiate_authentication(
                matching_id="04386-AGYFT-A74Y8-3F815",
                eid="89049032123451234512345678901235",
                euicc_challenge=euicc_challenge,
                euicc_info1=resp_bf20,
                smdp_address="testsmdpplus1.example.com",
            )
            bf38 = encode_bf38_authenticate_server_request(
                server_signed1=auth_result['server_signed1'],
                server_signature1=auth_result['server_signature1'],
                euicc_ci_pk_id=auth_result['euicc_ci_pk_id'],
                server_certificate=auth_result['server_certificate'],
                matching_id="04386-AGYFT-A74Y8-3F815",
                tac=b'\x00\x00\x00\x00',
            )
            store_data(bf38, "BF38")
            
            # 6. PrepareDownload (BF21)
            print("\n=== PrepareDownload (BF21) ===")
            auth_client_result = smdp.authenticate_client(
                transaction_id=auth_result['transaction_id'],
                authenticate_server_response=b'', # 简化处理
            )
            bf21 = encode_bf21_prepare_download_request(
                smdp_signed2=auth_client_result['smdp_signed2'],
                smdp_signature2=auth_client_result['smdp_signature2'],
                smdp_certificate=auth_client_result['smdp_certificate'],
            )
            print(f"  BF21 total length: {len(bf21)} bytes")
            print(f"  BF21 first 64 bytes: {bytes_to_hex(bf21[:64])}")
            
            # 捕获 BF21 响应（只在最后一个块之后返回）
            bf21_response = b''
            offset = 0
            while offset < len(bf21):
                chunk = bf21[offset:offset + 255]
                is_last = (offset + 255 >= len(bf21))
                p1 = 0x91 if is_last else 0x11
                resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, p1, offset // 255, chunk)
                sw = sw_to_string(sw1, sw2)
                print(f"  [BF21] TX: {(0x80|channel):02X}E2{p1:02X}{offset // 255:02X}{len(chunk):02X}...")
                print(f"  [BF21] RX: {bytes_to_hex(resp)} SW={sw}")
                if sw != "9000":
                    raise Exception(f"BF21 StoreData failed: {sw}")
                # 只在最后一个块之后保存响应
                if is_last and resp:
                    bf21_response = resp
                offset += 255
            
            print(f"  BF21 response length: {len(bf21_response)} bytes")
            print(f"  BF21 response: {bytes_to_hex(bf21_response)}")
            
            # 7. LoadProfilePackage (BF36)
            print("\n=== LoadProfilePackage (BF36) ===")
            bpp = smdp.get_bound_profile_package(
                transaction_id=auth_result['transaction_id'],
                prepare_download_response=bf21_response,
            )
            store_data(bpp, "BF36")
            
            print("\n✓ Profile Download flow completed")
    
    except CardError as e:
        logger.error(f"Card error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test error: {e}", exc_info=True)
        sys.exit(1)


def cmd_test_profile_download(args):
    """测试完整 Profile 下载流程 (BF20 -> BF2E -> BF38 -> BF21 -> BF36)"""
    try:
        reader_name = args.reader if args.reader else None
        
        # 1. 初始化本地 SM-DP+
        print("=== 初始化本地 SM-DP+ ===")
        from src.smdp_plus import LocalSmdpPlus
        from src.profile_package_store import ProfilePackageStore, ProfilePackageTemplate
        from src.pki_manager import PkiIdentity, load_private_key_from_pem, load_certificate_from_der, load_certificate_from_pem
        from src.asn1_codec import encode_bf38_authenticate_server_request, encode_bf21_prepare_download_request, decode_bf2e_challenge
        from src.utils import bytes_to_hex, hex_to_bytes
        import os
        
        resources_dir = os.path.join(os.path.dirname(__file__), '..', 'resources')
        certs_dir = os.path.join(resources_dir, 'certs')
        profiles_dir = os.path.join(resources_dir, 'profiles')
        
        dp_auth_key = load_private_key_from_pem(open(os.path.join(certs_dir, 'SK_S_SM_DPauth_ECDSA_NIST.pem'), 'rb').read())
        dp_auth_cert = load_certificate_from_der(open(os.path.join(certs_dir, 'CERT_S_SM_DPauth_ECDSA_NIST.der'), 'rb').read())
        dp_pb_key = load_private_key_from_pem(open(os.path.join(certs_dir, 'SK_S_SM_DPpb_ECDSA_NIST.pem'), 'rb').read())
        dp_pb_cert = load_certificate_from_der(open(os.path.join(certs_dir, 'CERT_S_SM_DPpb_ECDSA_NIST.der'), 'rb').read())
        ci_cert = load_certificate_from_pem(open(os.path.join(certs_dir, 'CERT_CI_ECDSA_NIST.pem'), 'rb').read())
        
        upp_file = os.path.join(profiles_dir, 'PROFILE_OPERATIONAL1_8929901012345678905F.HEX')
        upp_payload = bytes.fromhex(open(upp_file, 'r').read().strip().replace(" ", "").replace("\n", ""))
        
        packages = ProfilePackageStore()
        packages.save(ProfilePackageTemplate(
            matching_id="04386-AGYFT-A74Y8-3F815",
            profile_id="A0000005591010FFFFFFFF8900001000",
            profile_name="IoT Profile",
            iccid="8929901012345678905",
            payload=upp_payload,
        ))
        
        smdp = LocalSmdpPlus(packages, PkiIdentity(dp_auth_key, [dp_auth_cert]), PkiIdentity(dp_pb_key, [dp_pb_cert]), ci_cert)
        print(f"  SM-DP+ initialized. Packages: {len(packages)}")
        
        with CardReader(reader_name) as card:
            print(f"\nReader: {card.get_reader_name()}")
            print(f"ATR: {bytes_to_hex(card.get_atr()) if card.get_atr() else 'N/A'}")
            print()
            
            # 2. IC1/IC2 初始化
            print("=== IC1/IC2 Initialization ===")
            card.transmit(0x00, 0xA4, 0x00, 0x04, bytes([0x3F, 0x00]))
            card.transmit(0x80, 0xAA, 0x00, 0x00, bytes([0xA9, 0x05, 0x81, 0x00, 0x83, 0x01, 0x07]))
            tp = bytes([0xFF]*3 + [0x7F, 0x9D, 0x00, 0xDF, 0xBF, 0x00, 0x00, 0x1F, 0xE2, 0x00, 0x00, 0x00, 0xC7, 0xEB, 0x00, 0x00, 0x01, 0x68, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00])
            card.transmit(0x80, 0x10, 0x00, 0x00, tp)
            card.transmit(0x80, 0xF2, 0x00, 0x0C)
            # 打开第二个逻辑通道 (用于下载)
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel2 = resp[0] if resp and len(resp) > 0 else 2
            print(f"  MANAGE_CHANNEL (2nd): SW={sw_to_string(sw1, sw2)} Channel={channel2}")
            
            # 使用 channel2 进行下载操作
            channel = channel2
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            print(f"  SELECT ISD-R: Channel={channel}")
            channel = resp[0] if resp and len(resp) > 0 else 1
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel1 = resp[0] if resp and len(resp) > 0 else 1
            print(f"  MANAGE_CHANNEL (1st): SW={sw_to_string(sw1, sw2)} Channel={channel1}")
            
            # 打开第二个逻辑通道 (用于下载)
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel2 = resp[0] if resp and len(resp) > 0 else 2
            print(f"  MANAGE_CHANNEL (2nd): SW={sw_to_string(sw1, sw2)} Channel={channel2}")
            
            # 使用 channel2 进行下载操作
            channel = channel2
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            print(f"  SELECT ISD-R: Channel={channel}")
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel1 = resp[0] if resp and len(resp) > 0 else 1
            print(f"  MANAGE_CHANNEL (1st): SW={sw_to_string(sw1, sw2)} Channel={channel1}")
            
            # 打开第二个逻辑通道 (用于下载)
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel2 = resp[0] if resp and len(resp) > 0 else 2
            print(f"  MANAGE_CHANNEL (2nd): SW={sw_to_string(sw1, sw2)} Channel={channel2}")
            
            # 使用 channel2 进行下载操作
            channel = channel2
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            print(f"  SELECT ISD-R: Channel={channel}")
            card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel1 = resp[0] if resp and len(resp) > 0 else 1
            print(f"  MANAGE_CHANNEL (1st): SW={sw_to_string(sw1, sw2)} Channel={channel1}")
            
            # 打开第二个逻辑通道 (用于下载)
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel2 = resp[0] if resp and len(resp) > 0 else 2
            print(f"  MANAGE_CHANNEL (2nd): SW={sw_to_string(sw1, sw2)} Channel={channel2}")
            
            # 使用 channel2 进行下载操作
            channel = channel2
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            print(f"  SELECT ISD-R: Channel={channel}")
            print(f"  Channel: {channel}")
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel1 = resp[0] if resp and len(resp) > 0 else 1
            print(f"  MANAGE_CHANNEL (1st): SW={sw_to_string(sw1, sw2)} Channel={channel1}")
            
            # 打开第二个逻辑通道 (用于下载)
            resp, sw1, sw2 = card.transmit(0x00, 0x70, 0x00, 0x00, bytes([0x01]))
            channel2 = resp[0] if resp and len(resp) > 0 else 2
            print(f"  MANAGE_CHANNEL (2nd): SW={sw_to_string(sw1, sw2)} Channel={channel2}")
            
            # 使用 channel2 进行下载操作
            channel = channel2
            isdr = bytes([0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00])
            card.transmit(channel, 0xA4, 0x04, 0x00, isdr)
            print(f"  SELECT ISD-R: Channel={channel}")
            
            def store_data(data: bytes, desc: str):
                """发送 StoreData 命令 (ES10x)"""
                offset = 0
                block_num = 0
                while offset < len(data):
                    chunk = data[offset:offset + 255]
                    is_last = (offset + 255 >= len(data))
                    p1 = 0x91 if is_last else 0x11
                    print(f"  [{desc}] TX: {(0x80|channel):02X}E2{p1:02X}{block_num:02X}{len(chunk):02X}{bytes_to_hex(chunk)}")
                    resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, p1, block_num, chunk)
                    sw = sw_to_string(sw1, sw2)
                    print(f"  [{desc}] RX: {bytes_to_hex(resp)} SW={sw}")
                    if sw != "9000":
                        raise Exception(f"StoreData failed: {sw}")
                    offset += 255
                    block_num += 1
            
            # 3. GetEuiccInfo1 (BF20)
            print("\n=== GetEuiccInfo1 (BF20) ===")
            resp_bf20, _, _ = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x20, 0x00]))
            print(f"  RX: {bytes_to_hex(resp_bf20)}")
            
            # 4. GetEuiccChallenge (BF2E)
            print("\n=== GetEuiccChallenge (BF2E) ===")
            resp_bf2e, _, _ = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x2E, 0x00]))
            print(f"  RX: {bytes_to_hex(resp_bf2e)}")
            euicc_challenge = decode_bf2e_challenge(resp_bf2e)
            print(f"  Challenge: {bytes_to_hex(euicc_challenge)}")
            
            # 5. AuthenticateServer (BF38)
            print("\n=== AuthenticateServer (BF38) ===")
            auth_result = smdp.initiate_authentication(
                matching_id="04386-AGYFT-A74Y8-3F815",
                eid="89049032123451234512345678901235",
                euicc_challenge=euicc_challenge,
                euicc_info1=resp_bf20,
                smdp_address="testsmdpplus1.example.com",
            )
            bf38 = encode_bf38_authenticate_server_request(
                server_signed1=auth_result['server_signed1'],
                server_signature1=auth_result['server_signature1'],
                euicc_ci_pk_id=auth_result['euicc_ci_pk_id'],
                server_certificate=auth_result['server_certificate'],
                matching_id="04386-AGYFT-A74Y8-3F815",
                tac=b'\x00\x00\x00\x00',
            )
            store_data(bf38, "BF38")
            
            # 6. PrepareDownload (BF21)
            print("\n=== PrepareDownload (BF21) ===")
            auth_client_result = smdp.authenticate_client(
                transaction_id=auth_result['transaction_id'],
                authenticate_server_response=b'', # 简化处理
            )
            print(f"  smdp_signed2 length: {len(auth_client_result["smdp_signed2"])}")
            print(f"  smdp_signature2 length: {len(auth_client_result["smdp_signature2"])}")
            print(f"  smdp_certificate length: {len(auth_client_result["smdp_certificate"])}")
            bf21 = encode_bf21_prepare_download_request(
                smdp_signed2=auth_client_result['smdp_signed2'],
                smdp_signature2=auth_client_result['smdp_signature2'],
                smdp_certificate=auth_client_result['smdp_certificate'],
            )
            print(f"  BF21 total length: {len(bf21)} bytes")
            print(f"  BF21 first 64 bytes: {bytes_to_hex(bf21[:64])}")
            
            # 捕获 BF21 响应（只在最后一个块之后返回）
            bf21_response = b''
            offset = 0
            while offset < len(bf21):
                chunk = bf21[offset:offset + 255]
                is_last = (offset + 255 >= len(bf21))
                p1 = 0x91 if is_last else 0x11
                resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, p1, offset // 255, chunk)
                sw = sw_to_string(sw1, sw2)
                print(f"  [BF21] TX: {(0x80|channel):02X}E2{p1:02X}{offset // 255:02X}{len(chunk):02X}...")
                print(f"  [BF21] RX: {bytes_to_hex(resp)} SW={sw}")
                if sw != "9000":
                    raise Exception(f"BF21 StoreData failed: {sw}")
                # 只在最后一个块之后保存响应
                if is_last and resp:
                    bf21_response = resp
                offset += 255
            
            print(f"  BF21 response length: {len(bf21_response)} bytes")
            print(f"  BF21 response: {bytes_to_hex(bf21_response)}")
            
            # 7. LoadProfilePackage (BF36)
            print("\n=== LoadProfilePackage (BF36) ===")
            bpp = smdp.get_bound_profile_package(
                transaction_id=auth_result['transaction_id'],
                prepare_download_response=bf21_response,
            )
            store_data(bpp, "BF36")
            
            print("\n✓ Profile Download flow completed")
    
    except CardError as e:
        logger.error(f"Card error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test error: {e}", exc_info=True)
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
            resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x20, 0x00]))
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: {(0x80|channel):02X}E2910003BF2000")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            # GetEuiccChallenge (BF2E)
            print("\n=== GetEuiccChallenge (BF2E) ===")
            resp, sw1, sw2 = card.transmit(0x80 | channel, 0xE2, 0x91, 0x00, bytes([0xBF, 0x2E, 0x00]))
            sw = sw_to_string(sw1, sw2)
            print(f"  TX: {(0x80|channel):02X}E2910003BF2E00")
            print(f"  RX: {bytes_to_hex(resp)} SW={sw}")
            
            print("\n✓ eUICC info completed")
    
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
    parser.add_argument('--test-cleanup', action='store_true')
    parser.add_argument('--test-profile-download', action='store_true')
    parser.add_argument('--interactive', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.list_readers: cmd_list_readers(args)
    elif args.connect: cmd_connect(args)
    elif args.apdu: cmd_transmit_apdu(args)
    elif args.test_ic_sequence: cmd_test_ic_sequence(args)
    elif args.test_euicc_info: cmd_test_euicc_info(args)
    elif args.test_cleanup: cmd_test_cleanup(args)
    elif args.test_profile_download: cmd_test_profile_download(args)
    elif args.interactive: cmd_interactive(args)
    else: parser.print_help()


if __name__ == '__main__':
    main()
