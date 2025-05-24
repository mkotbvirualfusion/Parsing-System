"""
Fortinet FortiOS Parser for the Network Configuration Parser.
Handles Fortinet FortiGate configuration files.
"""

import re
from pathlib import Path
from typing import Optional

from parsers.base_parser import BaseParser
from core.data_models import (
    ParsedData, NetworkDevice, Interface, VendorInfo, 
    Zone, LoginBanner, LocalUser
)
from utils.helpers import extract_hostname, clean_string


class FortinetFortiOSParser(BaseParser):
    """Parser for Fortinet FortiOS configurations."""
    
    def __init__(self):
        """Initialize the Fortinet FortiOS parser."""
        super().__init__()
        
        self.description = "Fortinet FortiOS configuration parser"
        self.supported_formats = ['conf', 'cfg', 'txt']
        self.vendor = "fortinet"
        self.os_family = "fortios"
    
    def parse_file(self, file_path: Path, vendor_info: VendorInfo) -> Optional[ParsedData]:
        """
        Parse a Fortinet FortiOS configuration file.
        
        Args:
            file_path: Path to configuration file
            vendor_info: Detected vendor information
            
        Returns:
            ParsedData object if successful, None otherwise
        """
        try:
            self.reset()
            
            # Read file content
            content = self._read_file_content(file_path)
            if not content:
                return None
            
            self.logger.info(f"Parsing Fortinet FortiOS configuration: {file_path}")
            
            # Extract device information
            device = self.extract_device_info(content)
            if not device:
                self.logger.warning(f"Could not extract device info from {file_path}")
                return None
            
            # Set parsing context
            device.source_file = str(file_path)
            self.current_source_file = str(file_path)
            self.current_device_id = device.device_id
            
            # Add device to parsed data
            self.parsed_data.add_device(device)
            
            # Parse FortiOS specific configurations
            self._parse_fortios_interfaces(content)
            self._parse_fortios_zones(content)
            self._parse_fortios_users(content)
            self._parse_fortios_system_settings(content)
            
            self.logger.info(f"Successfully parsed {file_path}")
            return self.parsed_data
            
        except Exception as e:
            self.logger.error(f"Error parsing Fortinet FortiOS file {file_path}: {e}")
            return None
    
    def extract_device_info(self, content: str) -> Optional[NetworkDevice]:
        """Extract device information from FortiOS configuration."""
        try:
            # Extract hostname from system global config
            hostname = self._extract_fortios_hostname(content)
            
            # Extract version from config header
            version = self._extract_fortios_version(content)
            
            # Extract model/alias
            model = self._extract_fortios_model(content)
            
            device_id = self._generate_device_id(hostname or "fortigate", self.current_source_file)
            
            device = NetworkDevice(
                device_id=device_id,
                hostname=hostname or "",
                vendor="fortinet",
                model=model,
                os_family="fortios",
                os_version=version,
                source_file=self.current_source_file
            )
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error extracting FortiOS device info: {e}")
            return None
    
    def _extract_fortios_hostname(self, content: str) -> Optional[str]:
        """Extract hostname from FortiOS configuration."""
        # Look for hostname in system global config
        hostname_match = re.search(
            r'config system global\s+.*?set hostname "?([^"\n]+)"?',
            content, re.DOTALL | re.IGNORECASE
        )
        
        if hostname_match:
            return clean_string(hostname_match.group(1))
        
        # Fallback to alias
        alias_match = re.search(
            r'set alias "?([^"\n]+)"?',
            content, re.IGNORECASE
        )
        
        if alias_match:
            return clean_string(alias_match.group(1))
        
        return None
    
    def _extract_fortios_version(self, content: str) -> Optional[str]:
        """Extract FortiOS version from configuration."""
        # Look for version in config header comment
        version_patterns = [
            r'#config-version=.*?FG.*?-(\d+\.\d+\.\d+)',
            r'#buildno=(\d+)',
            r'FortiOS.*?v(\d+\.\d+\.\d+)'
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_fortios_model(self, content: str) -> Optional[str]:
        """Extract FortiGate model from configuration."""
        # Look for model in config header or alias
        model_patterns = [
            r'#config-version=.*?(FG\w+)',
            r'set alias "([^"]*FG\w+[^"]*)"'
        ]
        
        for pattern in model_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _parse_fortios_interfaces(self, content: str):
        """Parse FortiOS interface configurations."""
        try:
            # Find interface configurations
            interface_sections = re.finditer(
                r'config system interface\s+(.*?)(?=config|\Z)',
                content, re.DOTALL | re.IGNORECASE
            )
            
            for match in interface_sections:
                interface_config = match.group(1)
                
                # Parse individual interface blocks
                interface_blocks = re.finditer(
                    r'edit "([^"]+)"\s+(.*?)(?=edit|next|\Z)',
                    interface_config, re.DOTALL
                )
                
                for block in interface_blocks:
                    interface_name = block.group(1)
                    config_block = block.group(2)
                    
                    interface = self._parse_single_fortios_interface(interface_name, config_block)
                    if interface:
                        self.parsed_data.add_interface(interface)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.interfaces)} FortiOS interfaces")
            
        except Exception as e:
            self.logger.error(f"Error parsing FortiOS interfaces: {e}")
    
    def _parse_single_fortios_interface(self, name: str, config: str) -> Optional[Interface]:
        """Parse a single FortiOS interface configuration."""
        try:
            interface = Interface(
                device_id=self.current_device_id,
                interface_name=name,
                source_file=self.current_source_file
            )
            
            # Parse IP address
            ip_match = re.search(r'set ip (\S+) (\S+)', config, re.IGNORECASE)
            if ip_match:
                interface.ip_address = ip_match.group(1)
                interface.subnet_mask = ip_match.group(2)
            
            # Parse description/alias
            alias_match = re.search(r'set alias "([^"]+)"', config, re.IGNORECASE)
            if alias_match:
                interface.description = clean_string(alias_match.group(1))
            
            # Parse admin status
            if re.search(r'set status down', config, re.IGNORECASE):
                interface.admin_status = "down"
            else:
                interface.admin_status = "up"
            
            # Parse interface type
            if re.search(r'set type physical', config, re.IGNORECASE):
                interface.if_type = "physical"
            elif re.search(r'set type aggregate', config, re.IGNORECASE):
                interface.if_type = "aggregate"
            elif re.search(r'set type tunnel', config, re.IGNORECASE):
                interface.if_type = "tunnel"
            elif re.search(r'set type loopback', config, re.IGNORECASE):
                interface.if_type = "loopback"
            else:
                interface.if_type = "unknown"
            
            # Parse VLAN ID
            vlan_match = re.search(r'set vlanid (\d+)', config, re.IGNORECASE)
            if vlan_match:
                interface.vlan = vlan_match.group(1)
            
            # Parse MTU
            mtu_match = re.search(r'set mtu-override enable.*?set mtu (\d+)', config, re.IGNORECASE | re.DOTALL)
            if mtu_match:
                interface.mtu = mtu_match.group(1)
            
            return interface
            
        except Exception as e:
            self.logger.error(f"Error parsing FortiOS interface {name}: {e}")
            return None
    
    def _parse_fortios_zones(self, content: str):
        """Parse FortiOS security zone configurations."""
        try:
            # Find zone configurations
            zone_sections = re.finditer(
                r'config system zone\s+(.*?)(?=config|\Z)',
                content, re.DOTALL | re.IGNORECASE
            )
            
            for match in zone_sections:
                zone_config = match.group(1)
                
                # Parse individual zone blocks
                zone_blocks = re.finditer(
                    r'edit "([^"]+)"\s+(.*?)(?=edit|next|\Z)',
                    zone_config, re.DOTALL
                )
                
                for block in zone_blocks:
                    zone_name = block.group(1)
                    config_block = block.group(2)
                    
                    # Parse interfaces in zone
                    interface_matches = re.finditer(r'set interface "([^"]+)"', config_block)
                    interfaces_list = [match.group(1) for match in interface_matches]
                    
                    zone = Zone(
                        device_id=self.current_device_id,
                        zone_name=zone_name,
                        interfaces_list=", ".join(interfaces_list),
                        source_file=self.current_source_file
                    )
                    
                    self.parsed_data.add_zone(zone)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.zones)} FortiOS zones")
            
        except Exception as e:
            self.logger.error(f"Error parsing FortiOS zones: {e}")
    
    def _parse_fortios_users(self, content: str):
        """Parse FortiOS local user configurations."""
        try:
            # Find user configurations
            user_sections = re.finditer(
                r'config system admin\s+(.*?)(?=config|\Z)',
                content, re.DOTALL | re.IGNORECASE
            )
            
            for match in user_sections:
                user_config = match.group(1)
                
                # Parse individual user blocks
                user_blocks = re.finditer(
                    r'edit "([^"]+)"\s+(.*?)(?=edit|next|\Z)',
                    user_config, re.DOTALL
                )
                
                for block in user_blocks:
                    username = block.group(1)
                    config_block = block.group(2)
                    
                    user = LocalUser(
                        device_id=self.current_device_id,
                        username=username,
                        source_file=self.current_source_file
                    )
                    
                    # Parse privilege level
                    priv_match = re.search(r'set accprofile "([^"]+)"', config_block)
                    if priv_match:
                        user.privilege = priv_match.group(1)
                    
                    self.parsed_data.add_local_user(user)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.users_local)} FortiOS users")
            
        except Exception as e:
            self.logger.error(f"Error parsing FortiOS users: {e}")
    
    def _parse_fortios_system_settings(self, content: str):
        """Parse FortiOS system settings."""
        try:
            # Look for system global settings that might contain banners or other info
            global_match = re.search(
                r'config system global\s+(.*?)(?=config|\Z)',
                content, re.DOTALL | re.IGNORECASE
            )
            
            if global_match:
                global_config = global_match.group(1)
                
                # Parse admin server cert (could be used as banner info)
                cert_match = re.search(r'set admin-server-cert "([^"]+)"', global_config)
                if cert_match:
                    banner = LoginBanner(
                        device_id=self.current_device_id,
                        banner_type="admin_cert",
                        text=cert_match.group(1),
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_login_banner(banner)
            
        except Exception as e:
            self.logger.error(f"Error parsing FortiOS system settings: {e}") 