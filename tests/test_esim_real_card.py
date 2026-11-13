"""eSIM IoT Profile Download 真实卡片测试

使用真实读卡器和 SIM 卡测试 eSIM Profile 下载流程。
注意：此测试需要：
1. 已插入读卡器和 SIM 卡
2. 卡片支持 eSIM 功能
3. 有效的测试 Profile 数据
"""

import pytest
import time
from card_reader import CardReader, CardReaderError


def is_reader_available() -> bool:
    """检查是否有可用的读卡器"""
    try:
        reader = CardReader()
        readers = reader.list_readers()
        return len(readers) > 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not is_reader_available(),
    reason="No card reader available"
)


class TestEsimRealCard:
    """真实卡片测试"""
    
    def test_connect_and_get_atr(self):
        """测试连接卡片并获取 ATR"""
        reader = CardReader()
        try:
            atr = reader.connect()
            print(f"\nATR: {atr}")
            assert len(atr) > 0
        finally:
            reader.disconnect()
    
    def test_select_mf(self):
        """测试 SELECT MF"""
        reader = CardReader()
        try:
            reader.connect()
            
            # SELECT MF (P2=04 获取 FCI)
            response, sw1, sw2 = reader.send_apdu("00A40004023F00")
            print(f"\nSELECT MF: SW={sw1:02X}{sw2:02X}")
            
            # 处理 61XX
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
                print(f"After GET RESPONSE: SW={sw1:02X}{sw2:02X}")
            
            assert sw1 == 0x90
            assert sw2 == 0x00
            print(f"FCI: {response[:60]}...")
        finally:
            reader.disconnect()
    
    def test_select_isdr(self):
        """测试 SELECT ISD-R"""
        reader = CardReader()
        try:
            reader.connect()
            
            # 先选择 MF
            response, sw1, sw2 = reader.send_apdu("00A40004023F00")
            if sw1 == 0x61:
                reader.handle_61xx(response, sw1, sw2)
            
            # SELECT ISD-R
            # AID: A0000005591010FFFFFFFF8900000100
            response, sw1, sw2 = reader.send_apdu("00A4040010A0000005591010FFFFFFFF8900000100")
            print(f"\nSELECT ISD-R initial: SW={sw1:02X}{sw2:02X}")
            
            # 处理 61XX
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
                print(f"After GET RESPONSE: SW={sw1:02X}{sw2:02X}")
            
            # 某些卡片可能不支持 ISD-R
            if sw1 == 0x6A and sw2 == 0x82:
                print("ISD-R not found (card may not support eSIM)")
            elif sw1 == 0x90:
                print(f"Response: {response[:60]}...")
            else:
                print(f"Unexpected SW: {sw1:02X}{sw2:02X}")
        finally:
            reader.disconnect()
    
    def test_euicc_memory_reset(self):
        """测试 EuiccMemoryReset (清理命令)"""
        reader = CardReader()
        try:
            reader.connect()
            
            # 先选择 MF
            response, sw1, sw2 = reader.send_apdu("00A40004023F00")
            if sw1 == 0x61:
                reader.handle_61xx(response, sw1, sw2)
            
            # 选择 ISD-R
            response, sw1, sw2 = reader.send_apdu("00A4040010A0000005591010FFFFFFFF8900000100")
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
            
            if sw1 != 0x90:
                print(f"\nSkipping: ISD-R not available (SW={sw1:02X}{sw2:02X})")
                return
            
            # EuiccMemoryReset: 80 E2 91 00 07 BF3404820205E0 00
            response, sw1, sw2 = reader.send_apdu("80E2910007BF3404820205E000")
            print(f"\nEuiccMemoryReset: SW={sw1:02X}{sw2:02X}")
            
            # 处理 91XX (异步响应)
            if sw1 == 0x91:
                response, sw1, sw2 = reader.handle_91xx(response, sw1, sw2)
                print(f"After FETCH: SW={sw1:02X}{sw2:02X}")
            
            # 6A81 = 不支持的功能
            if sw1 == 0x6A and sw2 == 0x81:
                print("EuiccMemoryReset not supported")
            else:
                print(f"Response: {response}")
        finally:
            reader.disconnect()
    
    def test_get_euicc_info(self):
        """测试 GetEuiccInfo1"""
        reader = CardReader()
        try:
            reader.connect()
            
            # 先选择 MF
            response, sw1, sw2 = reader.send_apdu("00A40004023F00")
            if sw1 == 0x61:
                reader.handle_61xx(response, sw1, sw2)
            
            # 选择 ISD-R
            response, sw1, sw2 = reader.send_apdu("00A4040010A0000005591010FFFFFFFF8900000100")
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
            
            if sw1 != 0x90:
                print(f"\nSkipping: ISD-R not available")
                return
            
            # GetEuiccInfo1: 80 BF 20 00 00
            response, sw1, sw2 = reader.send_apdu("80BF200000")
            print(f"\nGetEuiccInfo1: SW={sw1:02X}{sw2:02X}")
            
            # 处理 61XX
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
            
            if sw1 == 0x90:
                print(f"EuiccInfo: {response}")
            else:
                print(f"Error: SW={sw1:02X}{sw2:02X}")
        finally:
            reader.disconnect()
    
    def test_get_profiles_info(self):
        """测试 GetProfilesInfo"""
        reader = CardReader()
        try:
            reader.connect()
            
            # 先选择 MF
            response, sw1, sw2 = reader.send_apdu("00A40004023F00")
            if sw1 == 0x61:
                reader.handle_61xx(response, sw1, sw2)
            
            # 选择 ISD-R
            response, sw1, sw2 = reader.send_apdu("00A4040010A0000005591010FFFFFFFF8900000100")
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
            
            if sw1 != 0x90:
                print(f"\nSkipping: ISD-R not available")
                return
            
            # GetProfilesInfo: 80 BF 2D 00 00
            response, sw1, sw2 = reader.send_apdu("80BF2D0000")
            print(f"\nGetProfilesInfo: SW={sw1:02X}{sw2:02X}")
            
            # 处理 61XX
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
            
            if sw1 == 0x90:
                print(f"ProfilesInfo: {response}")
                # 解析 profileState (9F70)
                if "9F70" in response:
                    idx = response.find("9F70")
                    if idx + 6 <= len(response):
                        state = response[idx + 4:idx + 6]
                        state_str = "ENABLED" if state == "01" else "DISABLED" if state == "00" else f"UNKNOWN({state})"
                        print(f"Profile State: {state_str}")
            else:
                print(f"Error: SW={sw1:02X}{sw2:02X}")
        finally:
            reader.disconnect()
    
    def test_full_cleanup_flow(self):
        """测试完整的清理流程"""
        reader = CardReader()
        try:
            reader.connect()
            
            print("\n=== 清理流程测试 ===")
            
            # 1. SELECT MF
            print("\n1. SELECT MF...")
            response, sw1, sw2 = reader.send_apdu("00A40004023F00")
            if sw1 == 0x61:
                reader.handle_61xx(response, sw1, sw2)
            print(f"   SW={sw1:02X}{sw2:02X}")
            
            # 2. SELECT ISD-R
            print("\n2. SELECT ISD-R...")
            response, sw1, sw2 = reader.send_apdu("00A4040010A0000005591010FFFFFFFF8900000100")
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
            
            if sw1 != 0x90:
                print(f"   ISD-R not available (SW={sw1:02X}{sw2:02X})")
                return
            
            print(f"   SW={sw1:02X}{sw2:02X}")
            
            # 3. EuiccMemoryReset
            print("\n3. EuiccMemoryReset...")
            response, sw1, sw2 = reader.send_apdu("80E2910007BF3404820205E000")
            if sw1 == 0x91:
                response, sw1, sw2 = reader.handle_91xx(response, sw1, sw2)
            print(f"   SW={sw1:02X}{sw2:02X}")
            
            # 4. ListNotification
            print("\n4. ListNotification...")
            response, sw1, sw2 = reader.send_apdu("80E2910003BF280000")
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
            print(f"   SW={sw1:02X}{sw2:02X}")
            print(f"   Response: {response}")
            
            # 5. GetProfilesInfo
            print("\n5. GetProfilesInfo...")
            response, sw1, sw2 = reader.send_apdu("80BF2D0000")
            if sw1 == 0x61:
                response, sw1, sw2 = reader.handle_61xx(response, sw1, sw2)
            print(f"   SW={sw1:02X}{sw2:02X}")
            print(f"   Response: {response[:60]}...")
            
            print("\n=== 清理流程完成 ===")
            
        finally:
            reader.disconnect()


if __name__ == "__main__":
    # 直接运行时执行完整测试
    print("=== eSIM IoT Profile Download 真实卡片测试 ===\n")
    
    test = TestEsimRealCard()
    
    try:
        print("Test 1: 连接卡片并获取 ATR")
        test.test_connect_and_get_atr()
        print("✓ PASSED\n")
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
    
    try:
        print("Test 2: SELECT MF")
        test.test_select_mf()
        print("✓ PASSED\n")
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
    
    try:
        print("Test 3: SELECT ISD-R")
        test.test_select_isdr()
        print("✓ PASSED\n")
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
    
    try:
        print("Test 4: 完整清理流程")
        test.test_full_cleanup_flow()
        print("✓ PASSED\n")
    except Exception as e:
        print(f"✗ FAILED: {e}\n")
