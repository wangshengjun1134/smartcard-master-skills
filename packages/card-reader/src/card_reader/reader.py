"""SmartCard Reader Connection and APDU Communication

This module provides a simple interface for connecting to smart card readers
and sending APDU commands.
"""

from typing import Optional, List, Tuple
from smartcard.System import readers
from smartcard.CardConnection import CardConnection
from smartcard.Exceptions import CardConnectionException, NoCardException
from smartcard.util import toBytes


class CardReaderError(Exception):
    """Card reader related exceptions"""
    pass


class CardReader:
    """Smart card reader interface
    
    Example:
        reader = CardReader()
        reader.connect()
        response, sw1, sw2 = reader.send_apdu("00A40000023F00")
        reader.disconnect()
    """
    
    def __init__(self, reader_index: int = 0):
        """Initialize card reader
        
        Args:
            reader_index: Index of the reader to use (default: 0)
        """
        self.reader_index = reader_index
        self.connection: Optional[CardConnection] = None
        self._reader_list: List = []
    
    def list_readers(self) -> List[str]:
        """List all available card readers
        
        Returns:
            List of reader names
        """
        try:
            self._reader_list = readers()
            return [str(r) for r in self._reader_list]
        except Exception as e:
            raise CardReaderError(f"Failed to list readers: {e}")
    
    def connect(self) -> str:
        """Connect to the card
        
        Returns:
            ATR (Answer To Reset) as hex string
            
        Raises:
            CardReaderError: If connection fails
        """
        try:
            self._reader_list = readers()
            if not self._reader_list:
                raise CardReaderError("No card readers found")
            
            if self.reader_index >= len(self._reader_list):
                raise CardReaderError(
                    f"Reader index {self.reader_index} out of range. "
                    f"Available readers: {len(self._reader_list)}"
                )
            
            reader = self._reader_list[self.reader_index]
            self.connection = reader.createConnection()
            # Try T=1 protocol first (more common for modern cards)
            try:
                self.connection.connect(CardConnection.T1_protocol)
            except CardConnectionException:
                # Fall back to T=0 protocol
                self.connection.connect(CardConnection.T0_protocol)
            
            # Get ATR
            atr = self.connection.getATR()
            return self._bytes_to_hex(atr)
            
        except CardConnectionException as e:
            raise CardReaderError(f"Card connection failed: {e}")
        except NoCardException:
            raise CardReaderError("No card present in reader")
        except Exception as e:
            raise CardReaderError(f"Connection failed: {e}")
    
    def disconnect(self) -> None:
        """Disconnect from the card"""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            finally:
                self.connection = None
    
    def send_apdu(self, apdu_hex: str) -> Tuple[str, int, int]:
        """Send APDU command to the card
        
        Args:
            apdu_hex: APDU command as hex string (e.g., "00A40000023F00")
            
        Returns:
            Tuple of (response_data, sw1, sw2)
            - response_data: Response data as hex string
            - sw1: Status word 1
            - sw2: Status word 2
            
        Raises:
            CardReaderError: If APDU transmission fails
        """
        if not self.connection:
            raise CardReaderError("Not connected to card")
        
        try:
            # Convert hex string to bytes
            apdu_bytes = self._hex_to_bytes(apdu_hex)
            
            # Send APDU
            response, sw1, sw2 = self.connection.transmit(apdu_bytes)
            
            # Convert response to hex string
            response_hex = self._bytes_to_hex(response) if response else ""
            
            return response_hex, sw1, sw2
            
        except CardConnectionException as e:
            raise CardReaderError(f"APDU transmission failed: {e}")
        except Exception as e:
            raise CardReaderError(f"APDU error: {e}")
    
    def send_apdu_with_retry(
        self,
        apdu_hex: str,
        expected_sw: Optional[List[int]] = None,
        max_retries: int = 3
    ) -> Tuple[str, int, int]:
        """Send APDU with retry on error
        
        Args:
            apdu_hex: APDU command as hex string
            expected_sw: List of expected SW1 values (e.g., [0x90, 0x61])
            max_retries: Maximum number of retries
            
        Returns:
            Tuple of (response_data, sw1, sw2)
        """
        last_error = None
        
        for attempt in range(max_retries):
            try:
                response, sw1, sw2 = self.send_apdu(apdu_hex)
                
                # Check if SW is expected
                if expected_sw is None or sw1 in expected_sw:
                    return response, sw1, sw2
                    
            except CardReaderError as e:
                last_error = e
                continue
        
        raise CardReaderError(
            f"APDU failed after {max_retries} retries: {last_error}"
        )
    
    def handle_61xx(self, response: str, sw1: int, sw2: int) -> Tuple[str, int, int]:
        """Handle 61XX response (more data available)
        
        Sends GET RESPONSE command to retrieve remaining data.
        
        Args:
            response: Initial response data
            sw1: Status word 1 (should be 0x61)
            sw2: Expected length of remaining data
            
        Returns:
            Tuple of (full_response, sw1, sw2)
        """
        if sw1 != 0x61:
            return response, sw1, sw2
        
        # GET RESPONSE: 00 C0 00 00 <Le>
        get_response_apdu = f"00C00000{sw2:02X}"
        additional_data, sw1_new, sw2_new = self.send_apdu(get_response_apdu)
        
        # Concatenate responses
        full_response = response + additional_data
        
        # Handle chained 61XX responses
        if sw1_new == 0x61:
            return self.handle_61xx(full_response, sw1_new, sw2_new)
        
        return full_response, sw1_new, sw2_new
    
    def handle_91xx(self, response: str, sw1: int, sw2: int) -> Tuple[str, int, int]:
        """Handle 91XX response (eUICC async response)
        
        Sends FETCH command to retrieve data.
        
        Args:
            response: Initial response data
            sw1: Status word 1 (should be 0x91)
            sw2: Expected length of data
            
        Returns:
            Tuple of (full_response, sw1, sw2)
        """
        if sw1 != 0x91:
            return response, sw1, sw2
        
        # FETCH: 80 C0 00 00 <Le>
        fetch_apdu = f"80C00000{sw2:02X}"
        additional_data, sw1_new, sw2_new = self.send_apdu(fetch_apdu)
        
        # Concatenate responses
        full_response = response + additional_data
        
        # Handle chained 91XX responses
        if sw1_new == 0x91:
            return self.handle_91xx(full_response, sw1_new, sw2_new)
        
        return full_response, sw1_new, sw2_new
    
    @property
    def is_connected(self) -> bool:
        """Check if connected to a card"""
        return self.connection is not None
    
    @staticmethod
    def _bytes_to_hex(data: bytes) -> str:
        """Convert bytes to hex string"""
        return "".join(f"{b:02X}" for b in data)
    
    @staticmethod
    def _hex_to_bytes(hex_str: str) -> List[int]:
        """Convert hex string to list of bytes"""
        hex_str = hex_str.replace(" ", "")
        return [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]


class CardConnectionContext:
    """Context manager for card connection
    
    Example:
        with CardConnectionContext() as card:
            response, sw1, sw2 = card.send_apdu("00A40000023F00")
    """
    
    def __init__(self, reader_index: int = 0):
        self.reader = CardReader(reader_index)
    
    def __enter__(self) -> CardReader:
        self.reader.connect()
        return self.reader
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.reader.disconnect()
