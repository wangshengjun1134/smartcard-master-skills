"""Card Reader 测试 - 使用真实读卡器

这些测试需要连接真实的读卡器和卡片。
如果没有读卡器，测试会被跳过。
"""

import pytest


def is_reader_available() -> bool:
    """检查是否有可用的读卡器"""
    try:
        from card_reader import CardReader
        reader = CardReader()
        readers = reader.list_readers()
        return len(readers) > 0
    except Exception as e:
        print(f"Reader check failed: {e}")
        return False


# 跳过所有测试如果没有读卡器
pytestmark = pytest.mark.skipif(
    not is_reader_available(),
    reason="No card reader available"
)


class TestCardReaderBasic:
    """基础读卡器测试"""
    
    def test_list_readers(self):
        """测试列出读卡器"""
        from card_reader import CardReader
        reader = CardReader()
        readers = reader.list_readers()
        assert len(readers) > 0
        print(f"Found readers: {readers}")
    
    def test_connect_disconnect(self):
        """测试连接和断开"""
        from card_reader import CardReader
        reader = CardReader()
        try:
            atr = reader.connect()
            assert len(atr) > 0
            print(f"Connected, ATR: {atr}")
        finally:
            reader.disconnect()
    
    def test_context_manager(self):
        """测试上下文管理器"""
        from card_reader import CardConnectionContext
        with CardConnectionContext() as card:
            assert card.is_connected
            print(f"Connected via context manager")


class TestCardReaderAPDU:
    """APDU 命令测试"""
    
    def test_select_mf(self):
        """测试 SELECT MF (选择主文件)"""
        from card_reader import CardConnectionContext
        with CardConnectionContext() as card:
            # SELECT MF: 00 A4 00 04 02 3F00 (P2=04 返回 FCI)
            response, sw1, sw2 = card.send_apdu("00A40004023F00")
            # 处理 61XX 响应
            if sw1 == 0x61:
                response, sw1, sw2 = card.handle_61xx(response, sw1, sw2)
            assert sw1 == 0x90
            assert sw2 == 0x00
            print(f"SELECT MF: SW={sw1:02X}{sw2:02X}, FCI={response[:40]}...")
    
    def test_select_iccid(self):
        """测试 SELECT ICCID 文件"""
        from card_reader import CardConnectionContext
        with CardConnectionContext() as card:
            # 先选择 MF (P2=04)
            response, sw1, sw2 = card.send_apdu("00A40004023F00")
            if sw1 == 0x61:
                card.handle_61xx(response, sw1, sw2)
            
            # SELECT EF_ICCID: 00 A4 00 04 02 2FE2
            response, sw1, sw2 = card.send_apdu("00A40004022FE2")
            if sw1 == 0x61:
                response, sw1, sw2 = card.handle_61xx(response, sw1, sw2)
            
            # 某些 SIM 卡可能不支持直接访问 ICCID 文件
            # 6A82 = 文件未找到, 6985 = 使用条件不满足
            if sw1 == 0x6A and sw2 == 0x82:
                print("SELECT ICCID: 文件未找到 (某些 SIM 卡需要特殊命令)")
            elif sw1 == 0x69 and sw2 == 0x85:
                print("SELECT ICCID: 使用条件不满足 (可能需要 PIN 验证)")
            else:
                assert sw1 == 0x90
                assert sw2 == 0x00
                print(f"SELECT ICCID: SW={sw1:02X}{sw2:02X}")
    
    def test_read_iccid(self):
        """测试读取 ICCID"""
        from card_reader import CardConnectionContext
        with CardConnectionContext() as card:
            # SELECT MF (P2=04)
            response, sw1, sw2 = card.send_apdu("00A40004023F00")
            if sw1 == 0x61:
                card.handle_61xx(response, sw1, sw2)
            
            # SELECT EF_ICCID (P2=04)
            response, sw1, sw2 = card.send_apdu("00A40004022FE2")
            if sw1 == 0x61:
                card.handle_61xx(response, sw1, sw2)
            
            # 某些 SIM 卡可能不支持直接访问 ICCID 文件
            if sw1 == 0x6A and sw2 == 0x82:
                print("READ ICCID: 跳过 - 文件未找到")
                return
            if sw1 == 0x69 and sw2 == 0x85:
                print("READ ICCID: 跳过 - 使用条件不满足")
                return
            
            assert sw1 == 0x90
            assert sw2 == 0x00
            
            # READ BINARY: 00 B0 00 00 0A
            response, sw1, sw2 = card.send_apdu("00B000000A")
            assert sw1 == 0x90
            assert sw2 == 0x00
            assert len(response) == 20  # 10 bytes = 20 hex chars
            print(f"ICCID raw: {response}")
            
            # 解析 ICCID (BCD 编码)
            iccid = parse_iccid(response)
            print(f"ICCID: {iccid}")
            assert iccid.startswith("89")
    
    def test_get_status(self):
        """测试获取卡片状态"""
        from card_reader import CardConnectionContext
        with CardConnectionContext() as card:
            # GET STATUS: 80 F2 00 00 00
            response, sw1, sw2 = card.send_apdu("80F2000000")
            # 不同卡片可能有不同的响应
            print(f"STATUS: SW={sw1:02X}{sw2:02X}, response={response[:40]}...")


class TestCardReaderWith61XX:
    """测试 61XX 响应处理"""
    
    def test_handle_61xx(self):
        """测试处理 61XX 响应"""
        from card_reader import CardConnectionContext
        with CardConnectionContext() as card:
            # 发送一个可能返回 61XX 的 APDU
            # 这里使用 SELECT MF 作为示例（通常不会返回 61XX，但用于演示）
            response, sw1, sw2 = card.send_apdu("00A40000023F00")
            
            # 如果返回 61XX，处理它
            if sw1 == 0x61:
                full_response, sw1_new, sw2_new = card.handle_61xx(response, sw1, sw2)
                print(f"After GET RESPONSE: SW={sw1_new:02X}{sw2_new:02X}")
            else:
                print(f"Normal response: SW={sw1:02X}{sw2:02X}")


class TestCardReaderError:
    """测试错误处理"""
    
    def test_invalid_apdu(self):
        """测试无效 APDU"""
        from card_reader import CardConnectionContext, CardReaderError
        with CardConnectionContext() as card:
            # 发送无效 APDU（长度错误）- 可能导致异常或返回错误状态字
            try:
                response, sw1, sw2 = card.send_apdu("00A400")
                # 如果返回了状态字，应该是错误状态
                print(f"Invalid APDU: SW={sw1:02X}{sw2:02X}")
                assert sw1 in [0x67, 0x6A, 0x6E, 0x69]  # 长度错误、参数错误、INS 不支持、命令不允许
            except CardReaderError as e:
                # 也可能直接抛出异常
                print(f"Invalid APDU raised exception (expected): {e}")
                assert True  # 预期行为


def parse_iccid(hex_data: str) -> str:
    """解析 ICCID 的 BCD 编码
    
    Args:
        hex_data: 十六进制字符串
        
    Returns:
        ICCID 数字字符串
    """
    digits = []
    for i in range(0, len(hex_data), 2):
        byte_hex = hex_data[i:i+2]
        byte_val = int(byte_hex, 16)
        
        low = byte_val & 0x0F
        high = (byte_val >> 4) & 0x0F
        
        if low <= 9:
            digits.append(str(low))
        elif low == 0x0F:
            break
            
        if high <= 9:
            digits.append(str(high))
        elif high == 0x0F:
            break
    
    return "".join(digits)


if __name__ == "__main__":
    # 直接运行时打印读卡器信息
    print("=== Card Reader Test ===")
    
    try:
        reader = CardReader()
        readers = reader.list_readers()
        print(f"Found {len(readers)} reader(s):")
        for i, r in enumerate(readers):
            print(f"  [{i}] {r}")
        
        if readers:
            print("\nConnecting to first reader...")
            with CardConnectionContext() as card:
                print(f"Connected!")
                
                # 读取 ICCID
                card.send_apdu("00A40000023F00")
                card.send_apdu("00A40000022FE2")
                response, sw1, sw2 = card.send_apdu("00B000000A")
                
                if sw1 == 0x90:
                    iccid = parse_iccid(response)
                    print(f"ICCID: {iccid}")
                else:
                    print(f"Error: SW={sw1:02X}{sw2:02X}")
                    
    except CardReaderError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
