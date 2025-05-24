"""
Juniper JunOS Parser for the Network Configuration Parser.
"""

from pathlib import Path
from typing import Optional

from parsers.base_parser import BaseParser
from core.data_models import ParsedData, NetworkDevice, VendorInfo


class JuniperJunOSParser(BaseParser):
    """Parser for Juniper JunOS configurations."""
    
    def __init__(self):
        """Initialize the Juniper JunOS parser."""
        super().__init__()
        
        self.description = "Juniper JunOS configuration parser"
        self.supported_formats = ['conf', 'txt', 'cfg']
        self.vendor = "juniper"
        self.os_family = "junos"
    
    def parse_file(self, file_path: Path, vendor_info: VendorInfo) -> Optional[ParsedData]:
        """Parse a Juniper JunOS configuration file."""
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
        """Extract device information from JunOS configuration."""
        device_id = self._generate_device_id("junos_device", self.current_source_file)
        
        return NetworkDevice(
            device_id=device_id,
            hostname="junos_device",
            vendor="juniper",
            os_family="junos",
            source_file=self.current_source_file
        ) 