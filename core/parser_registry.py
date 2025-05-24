"""
Parser Registry for the Network Configuration Parser.
Routes configuration files to appropriate vendor-specific parsers.
"""

import logging
from typing import Dict, Optional, Type, List, TYPE_CHECKING
from pathlib import Path

# Import BaseParser only for type checking to avoid circular imports
if TYPE_CHECKING:
    from parsers.base_parser import BaseParser

from .data_models import VendorInfo


class ParserRegistry:
    """Registry that manages and routes to vendor-specific parsers."""
    
    def __init__(self):
        """Initialize the parser registry."""
        self.logger = logging.getLogger(__name__)
        self._parsers: Dict[str, Dict[str, 'BaseParser']] = {}
        self._initialize_parsers()
    
    def _initialize_parsers(self):
        """Initialize all available parsers."""
        try:
            # Import parsers here to avoid circular imports
            from parsers.cisco.ios_parser import CiscoIOSParser
            from parsers.cisco.nxos_parser import CiscoNXOSParser
            from parsers.cisco.aci_parser import CiscoACIParser
            from parsers.palo_alto.panos_parser import PaloAltoPANOSParser
            from parsers.fortinet.fortios_parser import FortinetFortiOSParser
            from parsers.f5.tmos_parser import F5TMOSParser
            from parsers.f5.f5os_parser import F5OSParser
            from parsers.juniper.junos_parser import JuniperJunOSParser
            
            self.logger.info("Initializing parser registry")
            
            # Cisco parsers
            self._register_parser('cisco', 'ios', CiscoIOSParser())
            self._register_parser('cisco', 'nxos', CiscoNXOSParser())
            self._register_parser('cisco', 'aci', CiscoACIParser())
            self._register_parser('cisco', 'iosxe', CiscoIOSParser())  # Use IOS parser for IOS-XE
            self._register_parser('cisco', 'iosxr', CiscoIOSParser())  # Use IOS parser for IOS-XR
            
            # Palo Alto parsers
            self._register_parser('palo_alto', 'panos', PaloAltoPANOSParser())
            
            # Fortinet parsers
            self._register_parser('fortinet', 'fortios', FortinetFortiOSParser())
            
            # F5 parsers
            self._register_parser('f5', 'tmos', F5TMOSParser())
            self._register_parser('f5', 'f5os', F5OSParser())
            
            # Juniper parsers
            self._register_parser('juniper', 'junos', JuniperJunOSParser())
            
            # Additional vendor mappings
            self._register_parser('arista', 'eos', CiscoIOSParser())  # EOS is similar to IOS
            
            self.logger.info(f"Initialized {self._get_parser_count()} parsers")
            
        except Exception as e:
            self.logger.error(f"Error initializing parsers: {e}")
    
    def _register_parser(self, vendor: str, os_family: str, parser):
        """
        Register a parser for a specific vendor and OS family.
        
        Args:
            vendor: Vendor name
            os_family: OS family name
            parser: Parser instance
        """
        if vendor not in self._parsers:
            self._parsers[vendor] = {}
        
        self._parsers[vendor][os_family] = parser
        self.logger.debug(f"Registered parser: {vendor}/{os_family}")
    
    def get_parser(self, vendor: str, os_family: str) -> Optional['BaseParser']:
        """
        Get parser for specific vendor and OS family.
        
        Args:
            vendor: Vendor name
            os_family: OS family name
            
        Returns:
            Parser instance if available, None otherwise
        """
        try:
            if vendor in self._parsers and os_family in self._parsers[vendor]:
                parser = self._parsers[vendor][os_family]
                self.logger.debug(f"Found parser for {vendor}/{os_family}: {type(parser).__name__}")
                return parser
            
            # Try fallback options
            fallback_parser = self._get_fallback_parser(vendor, os_family)
            if fallback_parser:
                self.logger.info(f"Using fallback parser for {vendor}/{os_family}: {type(fallback_parser).__name__}")
                return fallback_parser
            
            self.logger.warning(f"No parser available for {vendor}/{os_family}")
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting parser for {vendor}/{os_family}: {e}")
            return None
    
    def _get_fallback_parser(self, vendor: str, os_family: str) -> Optional['BaseParser']:
        """
        Get fallback parser when exact match is not available.
        
        Args:
            vendor: Vendor name
            os_family: OS family name
            
        Returns:
            Fallback parser if available
        """
        # Fallback mappings
        fallback_mappings = {
            'cisco': {
                'unknown': 'ios',
                'catalyst': 'ios',
                'asa': 'ios'
            },
            'palo_alto': {
                'unknown': 'panos'
            },
            'fortinet': {
                'unknown': 'fortios',
                'fortiwifi': 'fortios'
            },
            'f5': {
                'unknown': 'tmos',
                'bigip': 'tmos'
            },
            'juniper': {
                'unknown': 'junos'
            }
        }
        
        # Check if vendor has fallback mapping
        if vendor in fallback_mappings and os_family in fallback_mappings[vendor]:
            fallback_os = fallback_mappings[vendor][os_family]
            if vendor in self._parsers and fallback_os in self._parsers[vendor]:
                return self._parsers[vendor][fallback_os]
        
        # Check if vendor has any parser available
        if vendor in self._parsers and self._parsers[vendor]:
            # Return first available parser for vendor
            first_os = list(self._parsers[vendor].keys())[0]
            return self._parsers[vendor][first_os]
        
        return None
    
    def get_available_vendors(self) -> List[str]:
        """Get list of vendors that have registered parsers."""
        return list(self._parsers.keys())
    
    def get_available_os_families(self, vendor: str) -> List[str]:
        """
        Get list of OS families for a vendor that have registered parsers.
        
        Args:
            vendor: Vendor name
            
        Returns:
            List of OS families
        """
        if vendor in self._parsers:
            return list(self._parsers[vendor].keys())
        return []
    
    def get_parser_info(self) -> Dict[str, Dict[str, str]]:
        """
        Get information about all registered parsers.
        
        Returns:
            Dictionary with parser information
        """
        parser_info = {}
        
        for vendor, os_parsers in self._parsers.items():
            parser_info[vendor] = {}
            for os_family, parser in os_parsers.items():
                parser_info[vendor][os_family] = {
                    'class_name': type(parser).__name__,
                    'description': getattr(parser, 'description', 'No description'),
                    'supported_formats': getattr(parser, 'supported_formats', [])
                }
        
        return parser_info
    
    def _get_parser_count(self) -> int:
        """Get total number of registered parsers."""
        count = 0
        for vendor_parsers in self._parsers.values():
            count += len(vendor_parsers)
        return count
    
    def validate_parsers(self) -> Dict[str, List[str]]:
        """
        Validate all registered parsers.
        
        Returns:
            Dictionary with validation results
        """
        results = {
            'valid': [],
            'invalid': [],
            'errors': []
        }
        
        for vendor, os_parsers in self._parsers.items():
            for os_family, parser in os_parsers.items():
                parser_name = f"{vendor}/{os_family}"
                
                try:
                    # Check if parser has required methods
                    required_methods = ['parse_file', 'extract_device_info']
                    
                    for method in required_methods:
                        if not hasattr(parser, method):
                            results['invalid'].append(parser_name)
                            results['errors'].append(f"{parser_name}: Missing method {method}")
                            break
                    else:
                        # Check if parser is properly initialized
                        if hasattr(parser, 'validate') and callable(parser.validate):
                            if parser.validate():
                                results['valid'].append(parser_name)
                            else:
                                results['invalid'].append(parser_name)
                                results['errors'].append(f"{parser_name}: Parser validation failed")
                        else:
                            results['valid'].append(parser_name)
                
                except Exception as e:
                    results['invalid'].append(parser_name)
                    results['errors'].append(f"{parser_name}: Validation error - {str(e)}")
        
        self.logger.info(f"Parser validation: {len(results['valid'])} valid, {len(results['invalid'])} invalid")
        
        return results
    
    def get_parser_for_file(self, file_path: Path, vendor_info: VendorInfo) -> Optional['BaseParser']:
        """
        Get appropriate parser for a specific file and vendor info.
        
        Args:
            file_path: Path to configuration file
            vendor_info: Detected vendor information
            
        Returns:
            Parser instance if available
        """
        try:
            # Get parser based on vendor info
            parser = self.get_parser(vendor_info.vendor, vendor_info.os_family)
            
            if parser:
                # Check if parser supports the file format
                if hasattr(parser, 'supports_file') and callable(parser.supports_file):
                    if not parser.supports_file(file_path):
                        self.logger.warning(f"Parser {type(parser).__name__} does not support file format: {file_path}")
                        return None
                
                return parser
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting parser for file {file_path}: {e}")
            return None
    
    def reload_parsers(self):
        """Reload all parsers - useful for development."""
        self.logger.info("Reloading parser registry")
        self._parsers.clear()
        self._initialize_parsers()
    
    def register_external_parser(self, vendor: str, os_family: str, 
                                parser_class: Type['BaseParser'], *args, **kwargs):
        """
        Register an external parser.
        
        Args:
            vendor: Vendor name
            os_family: OS family name
            parser_class: Parser class
            *args, **kwargs: Arguments for parser initialization
        """
        try:
            parser_instance = parser_class(*args, **kwargs)
            self._register_parser(vendor, os_family, parser_instance)
            self.logger.info(f"Registered external parser: {vendor}/{os_family}")
            
        except Exception as e:
            self.logger.error(f"Error registering external parser {vendor}/{os_family}: {e}")
    
    def get_stats(self) -> Dict[str, any]:
        """Get registry statistics."""
        return {
            'total_parsers': self._get_parser_count(),
            'vendors': len(self._parsers),
            'vendor_list': list(self._parsers.keys()),
            'parser_breakdown': {
                vendor: len(os_parsers) 
                for vendor, os_parsers in self._parsers.items()
            }
        } 