"""
F5OS Parser for the Network Configuration Parser.
"""

from pathlib import Path
from typing import Optional

from parsers.base_parser import BaseParser
from core.data_models import ParsedData, NetworkDevice, VendorInfo


class F5OSParser(BaseParser):
    """Parser for F5OS configurations."""
    
    def __init__(self):
        """Initialize the F5OS parser."""
        super().__init__()
        
        self.description = "F5OS configuration parser"
        self.supported_formats = ['conf', 'txt', 'cfg', 'json']
        self.vendor = "f5"
        self.os_family = "f5os"
    
    def parse_file(self, file_path: Path, vendor_info: VendorInfo) -> Optional[ParsedData]:
        """Parse an F5OS configuration file."""
        self.reset()
        
        content = self._read_file_content(file_path)
        if not content:
            return None
        
        device = self.extract_device_info(content)
        if device:
            device.source_file = str(file_path)
            self.current_source_file = str(file_path)
            self.current_device_id = device.device_id
            self.parsed_data.add_device(device)
        
        return self.parsed_data
    
    def extract_device_info(self, content: str) -> Optional[NetworkDevice]:
        """Extract device information from F5OS configuration."""
        device_id = self._generate_device_id("f5os_device", self.current_source_file)
        
        return NetworkDevice(
            device_id=device_id,
            hostname="f5os_device",
            vendor="f5",
            os_family="f5os",
            source_file=self.current_source_file
        ) 