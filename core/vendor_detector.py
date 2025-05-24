"""
Vendor Detector for the Network Configuration Parser.
Identifies vendor and OS type from configuration files.
"""

import re
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import json

from .data_models import VendorInfo


class VendorDetector:
    """Detects network device vendor and OS from configuration files."""
    
    def __init__(self):
        """Initialize the vendor detector."""
        self.logger = logging.getLogger(__name__)
        
        # Vendor detection patterns
        self.detection_patterns = {
            'cisco': {
                'ios': [
                    r'(?i)cisco ios software',
                    r'(?i)building configuration',
                    r'(?i)current configuration.*bytes',
                    r'(?i)hostname\s+\S+',
                    r'(?i)interface (fast|gigabit|ten|forty|hundred)ethernet',
                    r'(?i)ip route\s+',
                    r'(?i)access-list\s+\d+',
                    r'(?i)router (ospf|eigrp|bgp)',
                    r'(?i)spanning-tree mode',
                    r'(?i)enable secret'
                ],
                'nxos': [
                    r'(?i)cisco nexus operating system',
                    r'(?i)nx-os',
                    r'(?i)version \d+\.\d+\(\d+\)',
                    r'(?i)feature\s+\w+',
                    r'(?i)vdc\s+\w+\s+id\s+\d+',
                    r'(?i)vpc\s+domain',
                    r'(?i)interface ethernet\d+/\d+',
                    r'(?i)switchport mode (access|trunk)',
                    r'(?i)ip prefix-list',
                    r'(?i)route-map\s+\w+'
                ],
                'aci': [
                    r'(?i)<topRoot.*?>',
                    r'(?i)<polUni.*?>',
                    r'(?i)<fvTenant.*?>',
                    r'(?i)<fvBD.*?>',
                    r'(?i)<fvAp.*?>',
                    r'(?i)<fvEpg.*?>',
                    r'(?i)<infraInfra.*?>',
                    r'(?i)<fabricInst.*?>',
                    r'(?i)dn="uni/',
                    r'(?i)apic'
                ],
                'iosxe': [
                    r'(?i)cisco ios-xe software',
                    r'(?i)ios-xe',
                    r'(?i)catalyst l3 switch software',
                    r'(?i)asr1000',
                    r'(?i)isr4000'
                ],
                'iosxr': [
                    r'(?i)cisco ios xr software',
                    r'(?i)ios-xr',
                    r'(?i)commit\s*$',
                    r'(?i)router static',
                    r'(?i)interface bundle-ether'
                ]
            },
            'palo_alto': {
                'panos': [
                    r'(?i)<config\s+version="10\.\d+\.\d+".*?>',
                    r'(?i)<config\s+version="\d+\.\d+\.\d+".*urldb="paloaltonetworks".*?>',
                    r'(?i)<mgt-config>',
                    r'(?i)<deviceconfig>',
                    r'(?i)<high-availability>',
                    r'(?i)<shared>.*<botnet>',
                    r'(?i)<devices>.*<entry name="localhost\.localdomain">',
                    r'(?i)<entry name="admin">.*<phash>',
                    r'(?i)<authentication-profile>TACACS</authentication-profile>',
                    r'(?i)<ike-crypto-profiles>',
                    r'(?i)<ipsec-crypto-profiles>',
                    r'(?i)<cluster-members>',
                    r'(?i)<ntp-servers>',
                    r'(?i)<hostname>NRR-DC-EW-FW-\d+</hostname>',
                    r'(?i)<update-server>updates\.paloaltonetworks\.com</update-server>'
                ]
            },
            'fortinet': {
                'fortios': [
                    r'(?i)#config-version=.*FG.*',
                    r'(?i)fortinet',
                    r'(?i)fortigate',
                    r'(?i)config system global',
                    r'(?i)config system interface',
                    r'(?i)config firewall address',
                    r'(?i)config firewall policy',
                    r'(?i)config router static',
                    r'(?i)config system admin',
                    r'(?i)set hostname'
                ]
            },
            'f5': {
                'tmos': [
                    r'(?i)f5 networks',
                    r'(?i)big-?ip',
                    r'(?i)tmsh',
                    r'(?i)ltm\s+(pool|virtual|node)',
                    r'(?i)net\s+(interface|vlan|route)',
                    r'(?i)sys\s+(global-settings|db)',
                    r'(?i)auth\s+user',
                    r'(?i)cm\s+device'
                ],
                'f5os': [
                    r'(?i)f5os',
                    r'(?i)config\s+system',
                    r'(?i)config\s+tenant',
                    r'(?i)velos',
                    r'(?i)rseries'
                ]
            },
            'juniper': {
                'junos': [
                    r'(?i)juniper networks',
                    r'(?i)junos',
                    r'(?i)set\s+system\s+host-name',
                    r'(?i)set\s+interfaces\s+\w+',
                    r'(?i)set\s+routing-options',
                    r'(?i)set\s+security\s+zones',
                    r'(?i)set\s+firewall\s+family',
                    r'(?i)set\s+protocols\s+bgp',
                    r'(?i)set\s+vlans\s+\w+',
                    r'(?i)commit'
                ]
            },
            'arista': {
                'eos': [
                    r'(?i)arista',
                    r'(?i)eos',
                    r'(?i)switchport trunk allowed vlan',
                    r'(?i)daemon terminattr',
                    r'(?i)spanning-tree mode mstp',
                    r'(?i)router bgp\s+\d+',
                    r'(?i)ip routing'
                ]
            },
            'brocade': {
                'nos': [
                    r'(?i)brocade',
                    r'(?i)network operating system',
                    r'(?i)nos',
                    r'(?i)switch-attributes',
                    r'(?i)rbridge-id'
                ]
            },
            'hp': {
                'comware': [
                    r'(?i)hp.*comware',
                    r'(?i)comware software',
                    r'(?i)display current-configuration',
                    r'(?i)interface gigabitethernet',
                    r'(?i)vlan\s+\d+'
                ],
                'procurve': [
                    r'(?i)hp.*procurve',
                    r'(?i)procurve',
                    r'(?i)show config',
                    r'(?i)hostname\s+".*?"'
                ]
            }
        }
        
        # File extension hints
        self.extension_hints = {
            '.xml': ['cisco_aci', 'palo_alto'],
            '.json': ['cisco_aci', 'palo_alto'],
            '.conf': ['fortinet', 'f5', 'cisco'],
            '.cfg': ['cisco', 'juniper'],
            '.log': ['cisco']
        }
        
        # Filename pattern hints
        self.filename_hints = [
            (r'(?i).*fortig.*', 'fortinet'),
            (r'(?i).*palo.*', 'palo_alto'),
            (r'(?i).*pa-.*', 'palo_alto'),
            (r'(?i).*big-?ip.*', 'f5'),
            (r'(?i).*f5.*', 'f5'),
            (r'(?i).*nexus.*', 'cisco'),
            (r'(?i).*aci.*', 'cisco'),
            (r'(?i).*juniper.*', 'juniper'),
            (r'(?i).*mx\d+.*', 'juniper'),
            (r'(?i).*ex\d+.*', 'juniper'),
            (r'(?i).*srx.*', 'juniper'),
            (r'(?i).*arista.*', 'arista'),
            (r'(?i).*eos.*', 'arista')
        ]
    
    def detect_vendor(self, file_path: Path) -> Optional[VendorInfo]:
        """
        Detect vendor and OS from configuration file.
        
        Args:
            file_path: Path to configuration file
            
        Returns:
            VendorInfo object if detected, None otherwise
        """
        try:
            self.logger.debug(f"Detecting vendor for: {file_path}")
            
            # Try different detection methods
            vendor_info = None
            
            # Method 1: Filename pattern hints
            vendor_info = self._detect_from_filename(file_path)
            if vendor_info and vendor_info.confidence > 0.7:
                return vendor_info
            
            # Method 2: File extension hints + content analysis
            content_vendor_info = self._detect_from_content(file_path)
            
            # Combine results
            if vendor_info and content_vendor_info:
                # Use content detection if more confident
                if content_vendor_info.confidence > vendor_info.confidence:
                    vendor_info = content_vendor_info
            elif content_vendor_info:
                vendor_info = content_vendor_info
            
            if vendor_info:
                self.logger.info(f"Detected vendor: {vendor_info.vendor}/{vendor_info.os_family} "
                               f"(confidence: {vendor_info.confidence:.2f}) for {file_path}")
            else:
                self.logger.warning(f"Could not detect vendor for: {file_path}")
            
            return vendor_info
            
        except Exception as e:
            self.logger.error(f"Error detecting vendor for {file_path}: {e}")
            return None
    
    def _detect_from_filename(self, file_path: Path) -> Optional[VendorInfo]:
        """Detect vendor from filename patterns."""
        filename = file_path.name
        
        for pattern, vendor in self.filename_hints:
            if re.search(pattern, filename):
                return VendorInfo(
                    vendor=vendor,
                    os_family='unknown',
                    confidence=0.6,
                    detection_method='filename'
                )
        
        return None
    
    def _detect_from_content(self, file_path: Path) -> Optional[VendorInfo]:
        """Detect vendor from file content."""
        try:
            # Check if it's XML first
            if file_path.suffix.lower() == '.xml':
                return self._detect_xml_vendor(file_path)
            
            # Check if it's JSON
            if file_path.suffix.lower() == '.json':
                return self._detect_json_vendor(file_path)
            
            # Read text content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Read first 50 lines or 10KB for analysis
                content_lines = []
                bytes_read = 0
                max_bytes = 10240
                
                for line in f:
                    content_lines.append(line)
                    bytes_read += len(line.encode('utf-8'))
                    
                    if len(content_lines) >= 50 or bytes_read >= max_bytes:
                        break
                
                content = '\n'.join(content_lines)
                
                return self._analyze_text_content(content, file_path)
                
        except Exception as e:
            self.logger.debug(f"Error reading content from {file_path}: {e}")
            return None
    
    def _detect_xml_vendor(self, file_path: Path) -> Optional[VendorInfo]:
        """Detect vendor from XML configuration files."""
        try:
            # Parse XML to check structure
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for Cisco ACI patterns
            if root.tag in ['topRoot', 'polUni'] or 'topRoot' in str(root):
                return VendorInfo(
                    vendor='cisco',
                    os_family='aci',
                    confidence=0.9,
                    detection_method='xml_structure'
                )
            
            # Check for Palo Alto patterns
            if root.tag == 'config' or 'deviceconfig' in str(root):
                # Read some content to confirm
                with open(file_path, 'r', encoding='utf-8') as f:
                    xml_content = f.read(5000)  # First 5KB
                    
                if any(pattern in xml_content.lower() for pattern in 
                       ['palo alto', 'pan-os', 'deviceconfig', 'vsys']):
                    return VendorInfo(
                        vendor='palo_alto',
                        os_family='panos',
                        confidence=0.9,
                        detection_method='xml_content'
                    )
            
        except ET.ParseError:
            # If XML parsing fails, try text analysis
            return self._detect_from_content(file_path)
        except Exception as e:
            self.logger.debug(f"Error parsing XML {file_path}: {e}")
            
        return None
    
    def _detect_json_vendor(self, file_path: Path) -> Optional[VendorInfo]:
        """Detect vendor from JSON configuration files."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Try to load as JSON
                data = json.load(f)
                
                # Convert to string for pattern matching
                json_str = json.dumps(data).lower()
                
                # Check for vendor-specific patterns
                if any(pattern in json_str for pattern in 
                       ['cisco', 'nexus', 'catalyst']):
                    return VendorInfo(
                        vendor='cisco',
                        os_family='unknown',
                        confidence=0.7,
                        detection_method='json_content'
                    )
                
                if any(pattern in json_str for pattern in 
                       ['palo alto', 'pan-os', 'firewall']):
                    return VendorInfo(
                        vendor='palo_alto',
                        os_family='panos',
                        confidence=0.7,
                        detection_method='json_content'
                    )
                
        except json.JSONDecodeError:
            # If JSON parsing fails, try text analysis
            return self._detect_from_content(file_path)
        except Exception as e:
            self.logger.debug(f"Error parsing JSON {file_path}: {e}")
            
        return None
    
    def _analyze_text_content(self, content: str, file_path: Path) -> Optional[VendorInfo]:
        """Analyze text content for vendor patterns."""
        content_lower = content.lower()
        
        vendor_scores = {}
        
        # Score each vendor based on pattern matches
        for vendor, os_patterns in self.detection_patterns.items():
            vendor_scores[vendor] = {}
            
            for os_family, patterns in os_patterns.items():
                score = 0
                matched_patterns = 0
                
                for pattern in patterns:
                    matches = len(re.findall(pattern, content, re.IGNORECASE))
                    if matches > 0:
                        matched_patterns += 1
                        score += matches
                
                # Calculate confidence based on pattern matches
                if matched_patterns > 0:
                    confidence = min(0.9, (matched_patterns / len(patterns)) * 0.7 + 
                                   min(score / 10, 0.2))
                    vendor_scores[vendor][os_family] = confidence
        
        # Find best match
        best_vendor = None
        best_os = None
        best_confidence = 0.0
        
        for vendor, os_scores in vendor_scores.items():
            for os_family, confidence in os_scores.items():
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_vendor = vendor
                    best_os = os_family
        
        if best_confidence > 0.3:  # Minimum confidence threshold
            # Try to extract version information
            version = self._extract_version(content, best_vendor, best_os)
            
            return VendorInfo(
                vendor=best_vendor,
                os_family=best_os,
                os_version=version,
                confidence=best_confidence,
                detection_method='content_analysis'
            )
        
        return None
    
    def _extract_version(self, content: str, vendor: str, os_family: str) -> Optional[str]:
        """Extract OS version from content."""
        version_patterns = {
            'cisco': {
                'ios': [
                    r'(?i)cisco ios software.*version (\S+)',
                    r'(?i)ios.*version (\d+\.\d+\S*)',
                    r'(?i)version (\d+\.\d+\S*)'
                ],
                'nxos': [
                    r'(?i)cisco nexus operating system.*software.*version (\S+)',
                    r'(?i)system version (\d+\.\d+\S*)',
                    r'(?i)version (\d+\.\d+\S*)'
                ],
                'aci': [
                    r'(?i)version="(\d+\.\d+\S*)"'
                ]
            },
            'palo_alto': {
                'panos': [
                    r'(?i)pan-os (\d+\.\d+\S*)',
                    r'(?i)version="(\d+\.\d+\S*)"'
                ]
            },
            'fortinet': {
                'fortios': [
                    r'(?i)#config-version=.*-(\d+\.\d+\S*)',
                    r'(?i)fortios.*version (\d+\.\d+\S*)'
                ]
            },
            'f5': {
                'tmos': [
                    r'(?i)big-ip.*(\d+\.\d+\S*)',
                    r'(?i)version (\d+\.\d+\S*)'
                ]
            },
            'juniper': {
                'junos': [
                    r'(?i)junos.*version (\d+\.\d+\S*)',
                    r'(?i)version (\d+\S*\.\d+\S*)'
                ]
            }
        }
        
        if vendor in version_patterns and os_family in version_patterns[vendor]:
            for pattern in version_patterns[vendor][os_family]:
                match = re.search(pattern, content)
                if match:
                    return match.group(1)
        
        return None
    
    def get_supported_vendors(self) -> List[str]:
        """Get list of supported vendors."""
        return list(self.detection_patterns.keys())
    
    def get_supported_os_families(self, vendor: str) -> List[str]:
        """Get list of supported OS families for a vendor."""
        if vendor in self.detection_patterns:
            return list(self.detection_patterns[vendor].keys())
        return [] 