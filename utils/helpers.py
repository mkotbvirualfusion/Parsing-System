"""
Helper utilities for the Network Configuration Parser.
"""

import re
import ipaddress
from typing import Optional, Union, Dict, Any, List
from pathlib import Path
import hashlib


def safe_get(data: Dict[str, Any], key: str, default: Any = "") -> Any:
    """
    Safely get a value from a dictionary.
    
    Args:
        data: Dictionary to get value from
        key: Key to look for
        default: Default value if key not found
        
    Returns:
        Value if found, default otherwise
    """
    try:
        return data.get(key, default)
    except (AttributeError, TypeError):
        return default


def clean_string(text: str) -> str:
    """
    Clean and normalize a string.
    
    Args:
        text: String to clean
        
    Returns:
        Cleaned string
    """
    if not text or not isinstance(text, str):
        return ""
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text.strip())
    
    # Remove non-printable characters
    text = ''.join(char for char in text if char.isprintable())
    
    return text


def parse_ip_address(ip_str: str) -> Optional[str]:
    """
    Parse and validate an IP address string.
    
    Args:
        ip_str: IP address string
        
    Returns:
        Normalized IP address or None if invalid
    """
    if not ip_str or not isinstance(ip_str, str):
        return None
    
    # Remove common prefixes/suffixes
    ip_str = ip_str.strip()
    
    # Handle common formats
    ip_patterns = [
        r'(\d+\.\d+\.\d+\.\d+)',  # Basic IPv4
        r'(\d+\.\d+\.\d+\.\d+)/\d+',  # CIDR notation
        r'ip\s+(\d+\.\d+\.\d+\.\d+)',  # "ip x.x.x.x"
        r'address\s+(\d+\.\d+\.\d+\.\d+)',  # "address x.x.x.x"
    ]
    
    for pattern in ip_patterns:
        match = re.search(pattern, ip_str)
        if match:
            ip_str = match.group(1)
            break
    
    try:
        ip = ipaddress.ip_address(ip_str)
        return str(ip)
    except ValueError:
        return None


def extract_hostname(text: str) -> Optional[str]:
    """
    Extract hostname from configuration text.
    
    Args:
        text: Configuration text
        
    Returns:
        Hostname if found
    """
    if not text:
        return None
    
    # Common hostname patterns
    hostname_patterns = [
        r'hostname\s+([^\s\r\n]+)',
        r'set\s+system\s+host-name\s+([^\s\r\n]+)',
        r'set\s+hostname\s+"?([^"\s\r\n]+)"?',
        r'config\s+system\s+global.*?set\s+hostname\s+"?([^"\s\r\n]+)"?',
    ]
    
    for pattern in hostname_patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            hostname = match.group(1).strip('"\'')
            return clean_string(hostname)
    
    return None


def normalize_interface_name(interface: str) -> str:
    """
    Normalize interface name to standard format.
    
    Args:
        interface: Interface name
        
    Returns:
        Normalized interface name
    """
    if not interface:
        return ""
    
    interface = interface.strip()
    
    # Common interface name mappings
    interface_mappings = {
        'Gi': 'GigabitEthernet',
        'Fa': 'FastEthernet',
        'Eth': 'Ethernet', 
        'Te': 'TenGigabitEthernet',
        'Fo': 'FortyGigE',
        'Hu': 'HundredGigE',
        'Po': 'Port-channel',
        'Vl': 'Vlan',
        'Lo': 'Loopback',
        'Tu': 'Tunnel',
        'Se': 'Serial'
    }
    
    # Apply mappings
    for short, full in interface_mappings.items():
        if interface.startswith(short):
            interface = interface.replace(short, full, 1)
            break
    
    return interface


def parse_subnet_mask(mask_str: str) -> Optional[str]:
    """
    Parse subnet mask and convert to standard format.
    
    Args:
        mask_str: Subnet mask string (dotted decimal or CIDR)
        
    Returns:
        Normalized subnet mask
    """
    if not mask_str:
        return None
    
    mask_str = mask_str.strip()
    
    # Check if it's CIDR notation
    if mask_str.startswith('/'):
        try:
            prefix_len = int(mask_str[1:])
            if 0 <= prefix_len <= 32:
                return mask_str
        except ValueError:
            pass
    
    # Check if it's dotted decimal
    try:
        mask = ipaddress.IPv4Address(mask_str)
        # Convert to CIDR if it's a valid subnet mask
        network = ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False)
        return f"/{network.prefixlen}"
    except ValueError:
        pass
    
    return mask_str


def format_mac_address(mac_str: str) -> Optional[str]:
    """
    Format MAC address to standard format.
    
    Args:
        mac_str: MAC address string
        
    Returns:
        Formatted MAC address (XX:XX:XX:XX:XX:XX)
    """
    if not mac_str:
        return None
    
    # Remove common separators and spaces
    mac_clean = re.sub(r'[:\-\.\s]', '', mac_str.lower())
    
    # Check if it's valid length
    if len(mac_clean) != 12:
        return None
    
    # Check if all characters are hex
    if not all(c in '0123456789abcdef' for c in mac_clean):
        return None
    
    # Format as XX:XX:XX:XX:XX:XX
    return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2)).upper()


def extract_version(text: str, vendor: str = None) -> Optional[str]:
    """
    Extract version information from configuration text.
    
    Args:
        text: Configuration text
        vendor: Vendor name for specific patterns
        
    Returns:
        Version string if found
    """
    if not text:
        return None
    
    # Generic version patterns
    version_patterns = [
        r'version\s+(\d+\.\d+\S*)',
        r'software.*version\s+(\S+)',
        r'ios.*version\s+(\S+)',
        r'release\s+(\d+\.\d+\S*)',
        r'build\s+(\d+\.\d+\S*)'
    ]
    
    # Vendor-specific patterns
    if vendor == 'cisco':
        version_patterns.extend([
            r'cisco ios software.*version\s+(\S+)',
            r'cisco nexus operating system.*version\s+(\S+)',
            r'system:\s+version\s+(\S+)'
        ])
    elif vendor == 'fortinet':
        version_patterns.extend([
            r'#config-version=.*-(\d+\.\d+\S*)',
            r'fortios.*(\d+\.\d+\S*)'
        ])
    
    for pattern in version_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
    
    return None


def extract_model(text: str, vendor: str = None) -> Optional[str]:
    """
    Extract device model from configuration text.
    
    Args:
        text: Configuration text
        vendor: Vendor name for specific patterns
        
    Returns:
        Model string if found
    """
    if not text:
        return None
    
    # Generic model patterns
    model_patterns = [
        r'model\s+(\S+)',
        r'hardware\s+(\S+)',
        r'platform\s+(\S+)',
        r'chassis\s+(\S+)'
    ]
    
    # Vendor-specific patterns
    if vendor == 'cisco':
        model_patterns.extend([
            r'cisco\s+(\w+\d+\w*)',
            r'catalyst\s+(\d+\w*)',
            r'nexus\s+(\d+\w*)',
            r'asr\s+(\d+\w*)',
            r'isr\s+(\d+\w*)'
        ])
    elif vendor == 'fortinet':
        model_patterns.extend([
            r'fortigate[_\-]?(\d+\w*)',
            r'fg(\d+\w*)'
        ])
    
    for pattern in model_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).upper()
    
    return None


def extract_serial_number(text: str) -> Optional[str]:
    """
    Extract serial number from configuration text.
    
    Args:
        text: Configuration text
        
    Returns:
        Serial number if found
    """
    if not text:
        return None
    
    serial_patterns = [
        r'serial.*number[:\s]+(\S+)',
        r'chassis.*serial[:\s]+(\S+)',
        r'system.*serial[:\s]+(\S+)',
        r'processor.*id[:\s]+(\S+)',
        r'serial[:\s]+(\w{8,})'  # Generic serial pattern
    ]
    
    for pattern in serial_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            serial = match.group(1).strip()
            # Filter out common non-serial values
            if serial.lower() not in ['unknown', 'none', 'n/a', 'not', 'available']:
                return serial
    
    return None


def calculate_file_hash(file_path: Path, algorithm: str = 'md5') -> Optional[str]:
    """
    Calculate hash of a file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        Hex digest of file hash
    """
    try:
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    except Exception:
        return None


def parse_time_string(time_str: str) -> Optional[str]:
    """
    Parse and normalize time string from configuration.
    
    Args:
        time_str: Time string
        
    Returns:
        Normalized time string
    """
    if not time_str:
        return None
    
    # Common time patterns
    time_patterns = [
        r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2})',  # ISO format
        r'(\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})',  # Cisco format
        r'(\d{2}:\d{2}:\d{2}\s+\w{3}\s+\w{3}\s+\d{1,2}\s+\d{4})',  # Alternative
    ]
    
    for pattern in time_patterns:
        match = re.search(pattern, time_str)
        if match:
            return match.group(1)
    
    return time_str.strip()


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP address is private/internal.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if IP is private
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def expand_ip_range(ip_range: str) -> List[str]:
    """
    Expand IP range into list of individual IPs.
    
    Args:
        ip_range: IP range (CIDR or range format)
        
    Returns:
        List of IP addresses
    """
    try:
        if '/' in ip_range:
            # CIDR notation
            network = ipaddress.ip_network(ip_range, strict=False)
            return [str(ip) for ip in network.hosts()]
        elif '-' in ip_range:
            # Range format (x.x.x.x-y.y.y.y)
            start_ip, end_ip = ip_range.split('-')
            start = ipaddress.ip_address(start_ip.strip())
            end = ipaddress.ip_address(end_ip.strip())
            
            ips = []
            current = start
            while current <= end:
                ips.append(str(current))
                current += 1
            return ips
        else:
            # Single IP
            ip = ipaddress.ip_address(ip_range)
            return [str(ip)]
    
    except ValueError:
        return []


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    # Remove leading/trailing dots and spaces
    filename = filename.strip('. ')
    
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    
    return filename or 'unnamed'


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """
    Recursively merge two dictionaries.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result 