"""
Base Parser for the Network Configuration Parser.
Provides common functionality for all vendor-specific parsers.
"""

import logging
import re
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

from core.data_models import (
    ParsedData, NetworkDevice, Interface, VLAN, ACLEntry, StaticRoute,
    DynamicRouting, NTPServer, AAAServer, SNMPConfig, LocalUser, LogTarget,
    CryptoTLS, FeatureFlags, FirmwareInventory, HAStatus, NATRule,
    ServiceInventory, VPNTunnel, Zone, LoginBanner, VendorInfo
)
from utils.helpers import (
    extract_hostname, extract_version, extract_model, extract_serial_number,
    parse_ip_address, clean_string, parse_time_string
)


class BaseParser(ABC):
    """Base class for all configuration parsers."""
    
    def __init__(self):
        """Initialize the base parser."""
        self.logger = logging.getLogger(self.__class__.__module__ + '.' + self.__class__.__name__)
        self.parsed_data = ParsedData()
        self.current_device_id = ""
        self.current_source_file = ""
        
        # Parser capabilities
        self.description = "Base configuration parser"
        self.supported_formats = ['txt', 'conf', 'cfg']
        self.vendor = "generic"
        self.os_family = "unknown"
    
    @abstractmethod
    def parse_file(self, file_path: Path, vendor_info: VendorInfo) -> Optional[ParsedData]:
        """
        Parse a configuration file.
        
        Args:
            file_path: Path to configuration file
            vendor_info: Detected vendor information
            
        Returns:
            ParsedData object if successful, None otherwise
        """
        pass
    
    @abstractmethod
    def extract_device_info(self, content: str) -> Optional[NetworkDevice]:
        """
        Extract basic device information from configuration.
        
        Args:
            content: Configuration content
            
        Returns:
            NetworkDevice object if successful
        """
        pass
    
    def supports_file(self, file_path: Path) -> bool:
        """
        Check if parser supports the given file format.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            True if parser supports the file
        """
        file_ext = file_path.suffix.lower().lstrip('.')
        return file_ext in self.supported_formats
    
    def validate(self) -> bool:
        """
        Validate parser configuration and capabilities.
        
        Returns:
            True if parser is valid
        """
        required_methods = ['parse_file', 'extract_device_info']
        
        for method in required_methods:
            if not hasattr(self, method) or not callable(getattr(self, method)):
                self.logger.error(f"Parser missing required method: {method}")
                return False
        
        return True
    
    def _read_file_content(self, file_path: Path) -> Optional[str]:
        """
        Read and return file content.
        
        Args:
            file_path: Path to file
            
        Returns:
            File content as string
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            self.logger.debug(f"Read {len(content)} characters from {file_path}")
            return content
            
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    def _generate_device_id(self, hostname: str, source_file: str) -> str:
        """
        Generate a unique device ID.
        
        Args:
            hostname: Device hostname
            source_file: Source file path
            
        Returns:
            Unique device ID
        """
        if hostname:
            base_id = clean_string(hostname)
        else:
            # Use filename if no hostname
            base_id = Path(source_file).stem
        
        # Add hash of source file for uniqueness
        file_hash = hashlib.md5(source_file.encode()).hexdigest()[:8]
        return f"{base_id}_{file_hash}"
    
    def _extract_timestamp(self, content: str) -> Optional[str]:
        """
        Extract configuration timestamp from content.
        
        Args:
            content: Configuration content
            
        Returns:
            Timestamp string if found
        """
        # Common timestamp patterns
        timestamp_patterns = [
            r'!Time:\s*(.+)',
            r'!.*configuration.*:\s*(.+)',
            r'!.*last.*change.*:\s*(.+)',
            r'!.*generated.*:\s*(.+)',
            r'building.*configuration.*:\s*(.+)',
            r'current.*configuration.*:\s*(.+)',
        ]
        
        for pattern in timestamp_patterns:
            match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if match:
                timestamp_str = match.group(1).strip()
                return parse_time_string(timestamp_str)
        
        return None
    
    def _parse_interfaces_generic(self, content: str) -> List[Interface]:
        """
        Generic interface parsing - can be overridden by specific parsers.
        
        Args:
            content: Configuration content
            
        Returns:
            List of Interface objects
        """
        interfaces = []
        
        # Basic interface pattern matching
        interface_patterns = [
            r'interface\s+(\S+)',
            r'set\s+interfaces\s+(\S+)',
        ]
        
        for pattern in interface_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                interface_name = match.group(1)
                
                interface = Interface(
                    device_id=self.current_device_id,
                    interface_name=interface_name,
                    source_file=self.current_source_file
                )
                
                interfaces.append(interface)
        
        return interfaces
    
    def _parse_vlans_generic(self, content: str) -> List[VLAN]:
        """
        Generic VLAN parsing - can be overridden by specific parsers.
        
        Args:
            content: Configuration content
            
        Returns:
            List of VLAN objects
        """
        vlans = []
        
        # Basic VLAN pattern matching
        vlan_patterns = [
            r'vlan\s+(\d+)',
            r'set\s+vlans\s+(\S+)',
        ]
        
        for pattern in vlan_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                vlan_id = match.group(1)
                
                vlan = VLAN(
                    device_id=self.current_device_id,
                    vlan_id=vlan_id,
                    source_file=self.current_source_file
                )
                
                vlans.append(vlan)
        
        return vlans
    
    def _parse_static_routes_generic(self, content: str) -> List[StaticRoute]:
        """
        Generic static route parsing - can be overridden by specific parsers.
        
        Args:
            content: Configuration content
            
        Returns:
            List of StaticRoute objects
        """
        routes = []
        
        # Basic route pattern matching
        route_patterns = [
            r'ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)',
            r'route\s+(\S+)\s+(\S+)\s+(\S+)',
        ]
        
        for pattern in route_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                destination = match.group(1)
                mask = match.group(2)
                next_hop = match.group(3)
                
                route = StaticRoute(
                    device_id=self.current_device_id,
                    destination=destination,
                    prefix_length=mask,
                    next_hop=next_hop,
                    source_file=self.current_source_file
                )
                
                routes.append(route)
        
        return routes
    
    def _parse_ntp_servers_generic(self, content: str) -> List[NTPServer]:
        """
        Generic NTP server parsing - can be overridden by specific parsers.
        
        Args:
            content: Configuration content
            
        Returns:
            List of NTPServer objects
        """
        ntp_servers = []
        
        # Basic NTP pattern matching
        ntp_patterns = [
            r'ntp\s+server\s+(\S+)',
            r'set\s+system\s+ntp\s+server\s+(\S+)',
        ]
        
        for pattern in ntp_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                server_ip = match.group(1)
                
                ntp_server = NTPServer(
                    device_id=self.current_device_id,
                    ntp_server=server_ip,
                    source_file=self.current_source_file
                )
                
                ntp_servers.append(ntp_server)
        
        return ntp_servers
    
    def _parse_snmp_generic(self, content: str) -> List[SNMPConfig]:
        """
        Generic SNMP parsing - can be overridden by specific parsers.
        
        Args:
            content: Configuration content
            
        Returns:
            List of SNMPConfig objects
        """
        snmp_configs = []
        
        # Basic SNMP pattern matching
        snmp_patterns = [
            r'snmp-server\s+community\s+(\S+)',
            r'snmp\s+community\s+(\S+)',
        ]
        
        for pattern in snmp_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                community = match.group(1)
                
                snmp_config = SNMPConfig(
                    device_id=self.current_device_id,
                    version="v2c",
                    community_or_user=community,
                    source_file=self.current_source_file
                )
                
                snmp_configs.append(snmp_config)
        
        return snmp_configs
    
    def _parse_users_generic(self, content: str) -> List[LocalUser]:
        """
        Generic user parsing - can be overridden by specific parsers.
        
        Args:
            content: Configuration content
            
        Returns:
            List of LocalUser objects
        """
        users = []
        
        # Basic user pattern matching
        user_patterns = [
            r'username\s+(\S+)',
            r'user\s+(\S+)',
        ]
        
        for pattern in user_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                username = match.group(1)
                
                user = LocalUser(
                    device_id=self.current_device_id,
                    username=username,
                    source_file=self.current_source_file
                )
                
                users.append(user)
        
        return users
    
    def _parse_login_banner_generic(self, content: str) -> List[LoginBanner]:
        """
        Generic login banner parsing - can be overridden by specific parsers.
        
        Args:
            content: Configuration content
            
        Returns:
            List of LoginBanner objects
        """
        banners = []
        
        # Basic banner pattern matching
        banner_patterns = [
            (r'banner\s+motd\s+(.+?)(?=\n\w|\n!|\Z)', 'motd'),
            (r'banner\s+login\s+(.+?)(?=\n\w|\n!|\Z)', 'login'),
        ]
        
        for pattern, banner_type in banner_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            
            for match in matches:
                banner_text = match.group(1).strip()
                
                banner = LoginBanner(
                    device_id=self.current_device_id,
                    banner_type=banner_type,
                    text=banner_text,
                    source_file=self.current_source_file
                )
                
                banners.append(banner)
        
        return banners
    
    def _extract_section(self, content: str, start_pattern: str, 
                        end_pattern: Optional[str] = None) -> List[str]:
        """
        Extract configuration sections based on patterns.
        
        Args:
            content: Configuration content
            start_pattern: Pattern to match section start
            end_pattern: Pattern to match section end (optional)
            
        Returns:
            List of section strings
        """
        sections = []
        
        if end_pattern:
            # Extract sections with defined start and end
            pattern = f"{start_pattern}(.*?){end_pattern}"
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            
            for match in matches:
                sections.append(match.group(1).strip())
        else:
            # Extract individual lines matching the pattern
            matches = re.finditer(start_pattern, content, re.IGNORECASE | re.MULTILINE)
            
            for match in matches:
                sections.append(match.group(0))
        
        return sections
    
    def _clean_config_line(self, line: str) -> str:
        """
        Clean a configuration line by removing comments and extra whitespace.
        
        Args:
            line: Configuration line
            
        Returns:
            Cleaned line
        """
        # Remove inline comments (starting with ! or #)
        line = re.sub(r'[!#].*$', '', line)
        
        # Clean whitespace
        return line.strip()
    
    def _parse_key_value_pair(self, line: str, separator: str = None) -> Optional[tuple]:
        """
        Parse a key-value pair from a configuration line.
        
        Args:
            line: Configuration line
            separator: Key-value separator (auto-detect if None)
            
        Returns:
            Tuple of (key, value) if found
        """
        line = self._clean_config_line(line)
        
        if not line:
            return None
        
        # Auto-detect separator
        if separator is None:
            for sep in ['=', ':', ' ']:
                if sep in line:
                    separator = sep
                    break
            else:
                return None
        
        parts = line.split(separator, 1)
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip()
            return (key, value)
        
        return None
    
    def get_parser_info(self) -> Dict[str, Any]:
        """
        Get information about this parser.
        
        Returns:
            Parser information dictionary
        """
        return {
            'class_name': self.__class__.__name__,
            'description': self.description,
            'vendor': self.vendor,
            'os_family': self.os_family,
            'supported_formats': self.supported_formats,
            'module': self.__class__.__module__
        }
    
    def reset(self):
        """Reset parser state for processing a new file."""
        self.parsed_data = ParsedData()
        self.current_device_id = ""
        self.current_source_file = ""
    
    def set_current_context(self, device_id: str, source_file: str):
        """
        Set current parsing context.
        
        Args:
            device_id: Current device ID
            source_file: Current source file path
        """
        self.current_device_id = device_id
        self.current_source_file = source_file 