#!/usr/bin/env python3
"""
快速读卡器测试脚本

用法:
    python3 quick_test.py              # 列出读卡器并连接第一个
    python3 quick_test.py --reader "name"  # 连接指定读卡器
    python3 quick_test.py --apdu "00A40004023F0000"  # 发送 APDU
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

# 测试 pyscard 导入
try:
    from smartcard.System import readers
    print("✓ pyscard imported successfully")
    print(f"  readers() function: {readers}")
except Exception as e:
    print(f"❌ pyscard import failed: {type(e).__name__}: {e}")
    print()
    print("Troubleshooting:")
    print("  1. Check if pcscd is running: systemctl status pcscd")
    print("  2. Check if reader is connected: lsusb")
    print("  3. Reinstall pyscard: pip uninstall pyscard && pip install pyscard")
    sys.exit(1)

from card_reader import CardReader, CardError, bytes_to_hex


def main():
    print("=" * 50)
    print("Smart Card Reader Quick Test")
    print("=" * 50)
    print()
    
    # 列出所有读卡器
    readers = CardReader.list_readers()
    
    if not readers:
        print("❌ No smart card readers found")
        print()
        print("Troubleshooting:")
        print("  1. Check if pcscd is running: systemctl status pcscd")
        print("  2. Check if reader is connected: lsusb")
        print("  3. Install pyscard: pip install pyscard")
        return
    
    print(f"✓ Found {len(readers)} reader(s):")
    for i, name in enumerate(readers):
        print(f"  [{i}] {name}")
    print()
    
    # 连接第一个读卡器
    try:
        print(f"Connecting to: {readers[0]}")
        with CardReader(readers[0]) as card:
            atr = card.get_atr()
            
            print(f"✓ Connected!")
            print(f"  Reader: {card.get_reader_name()}")
            print(f"  ATR: {bytes_to_hex(atr) if atr else 'N/A'}")
            print()
            
            # 测试 SELECT MF
            print("Testing SELECT MF (00 A4 00 04 02 3F 00 00)...")
            response, sw1, sw2 = card.transmit(0x00, 0xA4, 0x00, 0x04, bytes([0x3F, 0x00]))
            
            sw = f"{sw1:02X}{sw2:02X}"
            print(f"  Response: {bytes_to_hex(response)} SW={sw}")
            
            if sw == "9000":
                print("  ✓ SELECT MF successful")
            elif sw == "6A86":
                print("  ⚠ SELECT MF returned 6A86, retrying...")
                response, sw1, sw2 = card.transmit(0x00, 0xA4, 0x00, 0x0C, bytes([0x3F, 0x00]))
                sw = f"{sw1:02X}{sw2:02X}"
                print(f"  Retry Response: {bytes_to_hex(response)} SW={sw}")
            else:
                print(f"  ⚠ SELECT MF returned unexpected SW: {sw}")
            
            print()
            print("✓ Quick test completed")
    
    except CardError as e:
        print(f"❌ Card error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠ Test interrupted")
        sys.exit(0)


if __name__ == '__main__':
    main()
