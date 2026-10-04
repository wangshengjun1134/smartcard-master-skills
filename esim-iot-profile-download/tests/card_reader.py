"""智能卡读卡器连接模块 - 基于 pyscard"""

from typing import Optional, List, Tuple
import logging

try:
    from smartcard.System import readers
    from smartcard.CardConnection import CardConnection
    # CardConnection3 在新版 pyscard 中可能不存在，使用 CardConnection 即可
    try:
        from smartcard.CardConnection import CardConnection3
    except ImportError:
        CardConnection3 = CardConnection  # 兼容旧代码
    HAS_PYSMARTCARD = True
except ImportError as e:
    HAS_PYSMARTCARD = False
    PYSMARTCARD_ERROR = str(e)
    logging.warning(f"pyscard import failed: {e}")
    logging.warning("Install with: pip install pyscard")
except Exception as e:
    HAS_PYSMARTCARD = False
    PYSMARTCARD_ERROR = str(e)
    logging.warning(f"pyscard initialization failed: {e}")

logger = logging.getLogger(__name__)


class CardError(Exception):
    """智能卡操作异常"""
    pass


class CardReader:
    """智能卡读卡器连接器"""
    
    def __init__(self, reader_name: Optional[str] = None):
        """
        初始化读卡器
        
        Args:
            reader_name: 读卡器名称（可选，默认选择第一个可用读卡器）
        """
        if not HAS_PYSMARTCARD:
            raise CardError("pyscard not installed. Install with: pip install pyscard")
        
        self.reader_name = reader_name
        self.connection: Optional[CardConnection] = None
        self._initialize_reader()
    
    def _initialize_reader(self):
        """初始化读卡器连接"""
        try:
            # 获取所有可用读卡器
            all_readers = readers()
            
            if not all_readers:
                raise CardError("No smart card readers found")
            
            logger.info(f"Found {len(all_readers)} reader(s):")
            for i, reader in enumerate(all_readers):
                logger.info(f"  [{i}] {reader.name}")
            
            # 选择读卡器
            if self.reader_name:
                # 按名称查找
                selected = None
                for reader in all_readers:
                    if self.reader_name.lower() in reader.name.lower():
                        selected = reader
                        break
                if not selected:
                    raise CardError(f"Reader not found: {self.reader_name}")
            else:
                # 使用第一个读卡器
                selected = all_readers[0]
            
            self.reader = selected
            logger.info(f"Selected reader: {self.reader.name}")
        
        except Exception as e:
            raise CardError(f"Failed to initialize reader: {e}")
    
    def connect(self, protocol: Optional[int] = None):
        """
        连接智能卡
        
        Args:
            protocol: 协议类型 (CardConnection.T0_protocol, CardConnection.T1_protocol, CardConnection.RAW_protocol)
        """
        try:
            if self.is_connected():
                logger.warning("Already connected to card")
                return
            
            self.connection = self.reader.createConnection()
            
            if protocol:
                self.connection.connect(protocol)
            else:
                # 使用 T0 协议（与 Java版本一致）
                from smartcard.CardConnection import CardConnection
                self.connection.connect(CardConnection.T0_protocol)
                logger.info("Connected using T0 protocol")
            
            logger.info(f"Connected to card: {self.connection.getATR()}")
        
        except Exception as e:
            raise CardError(f"Failed to connect to card: {e}")
    
    def disconnect(self):
        """断开智能卡连接"""
        try:
            if self.connection:
                self.connection.disconnect()
                logger.info("Disconnected from card")
        except Exception as e:
            logger.warning(f"Error disconnecting: {e}")
    
    def transmit(self, cla: int, ins: int, p1: int, p2: int, 
                 data: Optional[bytes] = None, le: Optional[int] = None) -> Tuple[bytes, int, int]:
        """
        发送 APDU 命令并接收响应
        
        Args:
            cla: CLA 字节
            ins: INS 字节
            p1: P1 字节
            p2: P2 字节
            data: 命令数据（可选）
            le: 期望响应长度（可选）
        
        Returns:
            (response_data, sw1, sw2) - 响应数据、SW1、SW2
        """
        if not self.is_connected():
            raise CardError("Not connected to card. Call connect() first.")
        
        try:
            # 构建 APDU
            # 对于 T0 协议，MANAGE_CHANNEL 需要特殊处理
            if cla == 0x00 and ins == 0x70:
                # MANAGE_CHANNEL: 00 70 P1 P2 [Lc] Data
                # T0 协议下，如果只有 1 字节数据，格式为: 00 70 P1 P2 01 Data
                if data and len(data) == 1 and le is None:
                    apdu = bytes([cla, ins, p1, p2, 0x01, data[0]])
                else:
                    apdu = bytes([cla, ins, p1, p2])
                    if data:
                        apdu += bytes([len(data)]) + data
                    if le is not None:
                        apdu += bytes([le])
            else:
                # 普通 APDU
                if data:
                    apdu = bytes([cla, ins, p1, p2, len(data)] + list(data))
                    if le is not None:
                        apdu += bytes([le])
                else:
                    apdu = bytes([cla, ins, p1, p2])
                    if le is not None:
                        apdu += bytes([le])
            
            logger.debug(f"TX: {apdu.hex().upper()}")
            
            # 发送 APDU
            response, sw1, sw2 = self.connection.transmit(list(apdu))
            
            response_bytes = bytes(response) if response else b''
            logger.debug(f"RX: {response_bytes.hex().upper()} SW={sw1:02X}{sw2:02X}")
            
            return response_bytes, sw1, sw2
        
        except Exception as e:
            raise CardError(f"APDU transmit failed: {e}")
    
    def get_atr(self) -> Optional[bytes]:
        """获取 ATR (Answer To Reset)"""
        if not self.is_connected():
            return None
        try:
            return self.connection.getATR()
        except Exception:
            return None
    
    def get_reader_name(self) -> str:
        """获取读卡器名称"""
        return self.reader.name if hasattr(self, 'reader') else "Unknown"
    
    def is_connected(self) -> bool:
        """检查是否已连接"""
        if self.connection is None:
            return False
        try:
            # pyscard 2.x 使用 getATR() 判断是否连接
            # 如果连接断开，getATR() 会抛出异常
            self.connection.getATR()
            return True
        except Exception:
            return False
    
    def __enter__(self):
        """上下文管理器入口"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.disconnect()
        return False
    
    @staticmethod
    def list_readers() -> List[str]:
        """列出所有可用读卡器"""
        if not HAS_PYSMARTCARD:
            return []
        try:
            return [reader.name for reader in readers()]
        except Exception:
            return []


def bytes_to_hex(data) -> str:
    """字节数组转十六进制字符串（兼容 list 和 bytes）"""
    if isinstance(data, list):
        data = bytes(data)
    return data.hex().upper()


def hex_to_bytes(hex_str: str) -> bytes:
    """十六进制字符串转字节数组"""
    cleaned = hex_str.replace(" ", "").replace("\n", "").replace("\r", "")
    return bytes.fromhex(cleaned)
