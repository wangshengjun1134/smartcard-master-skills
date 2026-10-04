#!/usr/bin/env python3
"""
端到端 Profile 下载测试 - 连接读卡器 + 本地 SM-DP+

用法:
    python3 end_to_end_test.py
    python3 end_to_end_test.py --reader "Reader Name"
    python3 end_to_end_test.py --input input-example-resources.json
"""

import sys
import os
import json
import logging
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from card_reader import CardReader, CardError, bytes_to_hex
from src.apdu_builder import ApduCommand
from src.profile_download import ProfileDownloadFlow, ProfileDownloadError
from src.smdp_plus import LocalSmdpPlus
from src.pki_manager import PkiIdentity, load_private_key_from_pem, load_certificate_from_der, load_certificate_from_pem
from src.profile_package_store import ProfilePackageStore, ProfilePackageTemplate
from src.utils import sw_to_string, is_success, needs_fetch

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class CardBasedProfileDownload:
    """基于读卡器的 Profile 下载测试"""
    
    def __init__(self, input_data: dict, reader_name: Optional[str] = None):
        self.input = input_data
        self.reader_name = reader_name
        self.card: Optional[CardReader] = None
        self.flow: Optional[ProfileDownloadFlow] = None
        self.smdp_plus: Optional[LocalSmdpPlus] = None
    
    def setup(self):
        """初始化 SM-DP+ 和流程"""
        # 加载 PKI
        resources_dir = self.input.get('resources_dir')
        if not resources_dir:
            raise ProfileDownloadError("resources_dir is required")
        
        certs_dir = os.path.join(resources_dir, 'certs')
        profiles_dir = os.path.join(resources_dir, 'profiles')
        
        # 加载证书
        dp_auth_key = load_private_key_from_pem(
            open(os.path.join(certs_dir, 'SK_S_SM_DPauth_ECDSA_NIST.pem'), 'rb').read()
        )
        dp_auth_cert = load_certificate_from_der(
            open(os.path.join(certs_dir, 'CERT_S_SM_DPauth_ECDSA_NIST.der'), 'rb').read()
        )
        dp_pb_key = load_private_key_from_pem(
            open(os.path.join(certs_dir, 'SK_S_SM_DPpb_ECDSA_NIST.pem'), 'rb').read()
        )
        dp_pb_cert = load_certificate_from_der(
            open(os.path.join(certs_dir, 'CERT_S_SM_DPpb_ECDSA_NIST.der'), 'rb').read()
        )
        ci_cert = load_certificate_from_pem(
            open(os.path.join(certs_dir, 'CERT_CI_ECDSA_NIST.pem'), 'rb').read()
        )
        
        # 加载 Profile Payload
        import glob
        iccid = self.input['iccid']
        iccid_pattern = os.path.join(profiles_dir, f"*{iccid}*")
        iccid_files = glob.glob(iccid_pattern)
        
        if iccid_files:
            upp_file = iccid_files[0]
        else:
            default_hex = os.path.join(profiles_dir, "PROFILE_OPERATIONAL1.HEX")
            default_bin = os.path.join(profiles_dir, "PROFILE_OPERATIONAL1.bin")
            
            if os.path.exists(default_hex):
                upp_file = default_hex
            elif os.path.exists(default_bin):
                upp_file = default_bin
            else:
                logger.warning("No profile payload found, using empty payload")
                upp_file = None
        
        upp_payload = b''
        if upp_file:
            if upp_file.endswith('.HEX') or upp_file.endswith('.hex'):
                hex_content = open(upp_file, 'r').read().strip()
                upp_payload = bytes.fromhex(hex_content.replace(" ", "").replace("\n", ""))
            else:
                upp_payload = open(upp_file, 'rb').read()
            
            logger.info(f"Loaded profile payload: {len(upp_payload)} bytes from {os.path.basename(upp_file)}")
        
        # 初始化 Profile Package Store
        packages = ProfilePackageStore()
        template = ProfilePackageTemplate(
            matching_id=self.input['matching_id'],
            profile_id=self.input['profile_id'],
            profile_name=self.input.get('profile_name', 'IoT Profile'),
            iccid=iccid,
            service_provider_name=self.input.get('spn', ''),
            profile_class=self.input.get('profile_class', 2),
            payload=upp_payload,
        )
        packages.save(template)
        
        # 初始化 SM-DP+
        self.smdp_plus = LocalSmdpPlus(
            packages=packages,
            dp_auth_identity=PkiIdentity(dp_auth_key, [dp_auth_cert]),
            dp_profile_binding_identity=PkiIdentity(dp_pb_key, [dp_pb_cert]),
            trusted_root_certificate=ci_cert,
        )
        
        # 初始化流程
        self.flow = ProfileDownloadFlow(
            eid=self.input['eid'],
            smdp_address=self.input['smdp_address'],
            matching_id=self.input['matching_id'],
            iccid=iccid,
            profile_id=self.input['profile_id'],
            smdp_plus=self.smdp_plus,
            mode=self.input.get('mode', 'direct'),
            eim_id=self.input.get('eim_id'),
            tac=bytes.fromhex(self.input.get('tac', '00000000')),
            total_rounds=self.input.get('rounds', 1),
        )
        
        logger.info("SM-DP+ and ProfileDownloadFlow initialized")
    
    def send_apdu(self, cmd: ApduCommand) -> tuple:
        """发送 APDU 到读卡器"""
        if not self.card or not self.card.is_connected():
            raise CardError("Card not connected")
        
        return self.card.transmit(cmd.cla, cmd.ins, cmd.p1, cmd.p2, cmd.data, cmd.le)
    
    def run(self):
        """运行 Profile 下载流程"""
        print("=" * 60)
        print("eSIM IoT Profile Download - End-to-End Test")
        print("=" * 60)
        print(f"Reader: {self.reader_name or 'Auto-select'}")
        print(f"EID: {self.input.get('eid')}")
        print(f"ICCID: {self.input.get('iccid')}")
        print(f"Matching ID: {self.input.get('matching_id')}")
        print(f"Mode: {self.input.get('mode', 'direct')}")
        print()
        
        # 初始化
        self.setup()
        
        # 连接读卡器
        with CardReader(self.reader_name) as card:
            self.card = card
            
            atr = card.get_atr()
            print(f"✓ Connected to reader: {card.get_reader_name()}")
            print(f"  ATR: {bytes_to_hex(atr) if atr else 'N/A'}")
            print()
            
            # 执行流程
            current_step = 0
            step_count = 0
            max_steps = 200  # 防止无限循环
            
            apdu_response = None
            sw = None
            
            while current_step != -1 and step_count < max_steps:
                try:
                    # 执行步骤
                    apdus = self.flow.execute_step(current_step, apdu_response, sw)
                    
                    if not apdus:
                        # 没有 APDU，检查是否完成
                        next_step = self.flow.get_current_step()
                        if next_step == -1:
                            print(f"\n✓ Profile download completed successfully!")
                            print(f"  Rounds: {self.flow.current_round}/{self.flow.total_rounds}")
                            break
                        else:
                            current_step = next_step
                            continue
                    
                    # 发送 APDU
                    for apdu in apdus:
                        step_count += 1
                        print(f"Step {step_count}: [{self.flow.current_round}/{self.flow.total_rounds}] Sending APDU...")
                        print(f"  TX: {apdu.to_hex()}")
                        
                        # 发送 APDU
                        response, sw1, sw2 = self.send_apdu(apdu)
                        
                        sw_str = sw_to_string(sw1, sw2)
                        print(f"  RX: {bytes_to_hex(response)} SW={sw_str}")
                        
                        if is_success(sw1, sw2):
                            print(f"  ✓ SUCCESS")
                        elif needs_fetch(sw1, sw2):
                            print(f"  ⚠ NEED FETCH (len={sw2})")
                        else:
                            print(f"  ⚠ SW={sw_str}")
                        
                        # 更新状态
                        apdu_response = response
                        sw = sw_str
                        current_step = self.flow.get_current_step()
                        
                        # 短暂延迟
                        import time
                        time.sleep(0.1)
                
                except ProfileDownloadError as e:
                    print(f"\n❌ Profile download error: {e}")
                    break
                except CardError as e:
                    print(f"\n❌ Card error: {e}")
                    break
                except KeyboardInterrupt:
                    print(f"\n⚠ Test interrupted by user")
                    break
            
            if step_count >= max_steps:
                print(f"\n❌ Too many steps ({step_count}), aborting")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='End-to-End Profile Download Test')
    parser.add_argument('--reader', '-r', help='Reader name')
    parser.add_argument('--input', '-i', type=str, help='Input JSON file')
    parser.add_argument('--debug', '-d', action='store_true', help='Debug mode')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # 加载输入配置
    if args.input:
        with open(args.input, 'r') as f:
            input_data = json.load(f)
    else:
        # 使用默认配置
        input_data = {
            "operation": "install_and_enable",
            "mode": "direct",
            "eid": "89049032123451234512345678901235",
            "smdp_address": "testsmdpplus1.example.com",
            "matching_id": "04386-AGYFT-A74Y8-3F815",
            "iccid": "8929901012345678905",
            "profile_id": "A0000005591010FFFFFFFF8900001000",
            "resources_dir": os.path.join(os.path.dirname(__file__), '..', 'resources'),
            "profile_name": "IoT Profile",
            "spn": "Test SP",
            "profile_class": 2,
            "rounds": 1,
        }
    
    # 运行测试
    test = CardBasedProfileDownload(input_data, args.reader)
    test.run()


if __name__ == '__main__':
    main()
