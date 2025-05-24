"""
Cisco ACI Parser for the Network Configuration Parser.
Handles Cisco ACI XML configuration files.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, List, Dict

from parsers.base_parser import BaseParser
from core.data_models import (
    ParsedData, NetworkDevice, VendorInfo, VLAN, Interface, Zone,
    ServiceInventory, FeatureFlags, FirmwareInventory
)
from utils.helpers import clean_string


class CiscoACIParser(BaseParser):
    """Parser for Cisco ACI configurations."""
    
    def __init__(self):
        """Initialize the Cisco ACI parser."""
        super().__init__()
        
        self.description = "Cisco ACI XML configuration parser"
        self.supported_formats = ['xml']
        self.vendor = "cisco"
        self.os_family = "aci"
    
    def parse_file(self, file_path: Path, vendor_info: VendorInfo) -> Optional[ParsedData]:
        """
        Parse a Cisco ACI XML configuration file.
        
        Args:
            file_path: Path to configuration file
            vendor_info: Detected vendor information
            
        Returns:
            ParsedData object if successful, None otherwise
        """
        try:
            self.reset()
            
            self.logger.info(f"Parsing Cisco ACI configuration: {file_path}")
            
            # Parse XML file
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Extract device information
            device = self.extract_device_info_from_xml(root)
            if not device:
                self.logger.warning(f"Could not extract device info from {file_path}")
                return None
            
            # Set parsing context
            device.source_file = str(file_path)
            self.current_source_file = str(file_path)
            self.current_device_id = device.device_id
            
            # Add device to parsed data
            self.parsed_data.add_device(device)
            
            # Parse ACI specific configurations
            self._parse_aci_vlans(root)
            self._parse_aci_interfaces(root)
            self._parse_aci_tenants(root)
            self._parse_aci_bridge_domains(root)
            self._parse_aci_epgs(root)
            self._parse_aci_zones(root)
            self._parse_aci_services(root)
            self._parse_aci_features(root)
            self._parse_aci_firmware(root)
            
            self.logger.info(f"Successfully parsed {file_path}")
            return self.parsed_data
            
        except Exception as e:
            self.logger.error(f"Error parsing Cisco ACI file {file_path}: {e}")
            return None
    
    def extract_device_info(self, content: str) -> Optional[NetworkDevice]:
        """Extract device information from text content."""
        # For ACI, we primarily work with XML, so this is a fallback
        device_id = self._generate_device_id("aci_device", self.current_source_file)
        
        device = NetworkDevice(
            device_id=device_id,
            hostname="aci_device",
            vendor="cisco",
            os_family="aci",
            source_file=self.current_source_file
        )
        
        return device
    
    def extract_device_info_from_xml(self, root: ET.Element) -> Optional[NetworkDevice]:
        """Extract device information from ACI XML."""
        try:
            # Extract information from XML structure
            device_id = self._generate_device_id("aci_apic", self.current_source_file)
            
            # Look for fabric instance or other identifying elements
            hostname = "aci_apic"
            fabric_inst = root.find(".//fabricInst")
            if fabric_inst is not None:
                hostname = fabric_inst.get('name', 'aci_apic')
            
            # Try to extract more device details
            model = "APIC"
            version = None
            
            # Look for version information in various places
            for elem in root.iter():
                if 'version' in elem.attrib:
                    version = elem.get('version')
                    break
            
            device = NetworkDevice(
                device_id=device_id,
                hostname=hostname,
                vendor="cisco",
                model=model,
                os_family="aci",
                os_version=version,
                source_file=self.current_source_file
            )
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error extracting ACI device info: {e}")
            return None
    
    def _parse_aci_vlans(self, root: ET.Element):
        """Parse ACI VLAN pool configurations."""
        try:
            # Parse VLAN encapsulation blocks
            vlan_blocks = root.findall(".//stpAllocEncapBlkDef")
            
            for block in vlan_blocks:
                from_vlan = block.get('from', '')
                to_vlan = block.get('to', '')
                
                # Extract VLAN IDs from format like "vlan-123"
                if from_vlan.startswith('vlan-'):
                    from_id = from_vlan.split('-')[1]
                    to_id = to_vlan.split('-')[1] if to_vlan.startswith('vlan-') else from_id
                    
                    # Create VLAN entries for the range
                    try:
                        start_vlan = int(from_id)
                        end_vlan = int(to_id)
                        
                        for vlan_id in range(start_vlan, min(end_vlan + 1, start_vlan + 10)):  # Limit to avoid too many entries
                            vlan = VLAN(
                                device_id=self.current_device_id,
                                vlan_id=str(vlan_id),
                                vlan_name=f"VLAN_{vlan_id}",
                                description=f"ACI VLAN from pool {from_vlan}-{to_vlan}",
                                state="active",
                                active="yes",
                                source_file=self.current_source_file
                            )
                            self.parsed_data.add_vlan(vlan)
                    except ValueError:
                        continue
            
            self.logger.debug(f"Parsed {len(self.parsed_data.vlans_vrfs)} ACI VLANs")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI VLANs: {e}")
    
    def _parse_aci_interfaces(self, root: ET.Element):
        """Parse ACI interface configurations."""
        try:
            # Parse fabric interfaces and ports
            interfaces = root.findall(".//fabricPort") + root.findall(".//fabricLink")
            
            for intf in interfaces:
                name = intf.get('name', '') or intf.get('dn', '').split('/')[-1]
                if name:
                    interface = Interface(
                        device_id=self.current_device_id,
                        interface_name=name,
                        description=f"ACI Fabric Interface",
                        if_type="fabric",
                        admin_status="up",
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_interface(interface)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.interfaces)} ACI interfaces")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI interfaces: {e}")
    
    def _parse_aci_tenants(self, root: ET.Element):
        """Parse ACI tenant configurations."""
        try:
            tenants = root.findall(".//fvTenant")
            tenant_count = 0
            
            for tenant in tenants:
                tenant_name = tenant.get('name', '')
                if tenant_name:
                    # Create a service entry for each tenant
                    service = ServiceInventory(
                        device_id=self.current_device_id,
                        service_name=f"Tenant-{tenant_name}",
                        state="enabled",
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_service_inventory(service)
                    tenant_count += 1
                    
            self.logger.debug(f"Found {tenant_count} ACI tenants")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI tenants: {e}")
    
    def _parse_aci_bridge_domains(self, root: ET.Element):
        """Parse ACI bridge domain configurations."""
        try:
            bridge_domains = root.findall(".//fvBD")
            bd_count = 0
            
            for bd in bridge_domains:
                bd_name = bd.get('name', '')
                if bd_name:
                    # Create VLAN entry for bridge domain
                    vlan = VLAN(
                        device_id=self.current_device_id,
                        vlan_id=str(hash(bd_name) % 4000),  # Generate pseudo VLAN ID
                        vlan_name=bd_name,
                        description=f"ACI Bridge Domain: {bd_name}",
                        state="active",
                        mode="bridge_domain",
                        active="yes",
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_vlan(vlan)
                    bd_count += 1
            
            self.logger.debug(f"Found {bd_count} ACI bridge domains")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI bridge domains: {e}")
    
    def _parse_aci_epgs(self, root: ET.Element):
        """Parse ACI EPG configurations."""
        try:
            epgs = root.findall(".//fvAEPg")
            epg_count = 0
            
            for epg in epgs:
                epg_name = epg.get('name', '')
                if epg_name:
                    # Create zone entry for EPG
                    zone = Zone(
                        device_id=self.current_device_id,
                        zone_name=epg_name,
                        interfaces_list="ACI EPG Interfaces",
                        inspection_profile="ACI Policy",
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_zone(zone)
                    epg_count += 1
            
            self.logger.debug(f"Found {epg_count} ACI EPGs")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI EPGs: {e}")
    
    def _parse_aci_zones(self, root: ET.Element):
        """Parse ACI security zone configurations."""
        try:
            # Parse fabric zones and domains
            fabric_zones = root.findall(".//fabricDomain") + root.findall(".//vmmDomP")
            
            for zone_elem in fabric_zones:
                zone_name = zone_elem.get('name', '') or zone_elem.get('dn', '').split('/')[-1]
                if zone_name:
                    zone = Zone(
                        device_id=self.current_device_id,
                        zone_name=zone_name,
                        interfaces_list="ACI Domain Interfaces",
                        inspection_profile="ACI Domain Policy",
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_zone(zone)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.zones)} ACI zones")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI zones: {e}")
    
    def _parse_aci_services(self, root: ET.Element):
        """Parse ACI service configurations."""
        try:
            # Parse various ACI services and policies
            services = []
            
            # Service graph templates
            svc_graphs = root.findall(".//vnsAbsGraph")
            for graph in svc_graphs:
                name = graph.get('name', '')
                if name:
                    services.append(f"ServiceGraph-{name}")
            
            # Load balancers
            lbs = root.findall(".//vnsAbsLDevInst")
            for lb in lbs:
                name = lb.get('name', '')
                if name:
                    services.append(f"LoadBalancer-{name}")
            
            # Create service inventory entries
            for service_name in services:
                service = ServiceInventory(
                    device_id=self.current_device_id,
                    service_name=service_name,
                    state="enabled",
                    source_file=self.current_source_file
                )
                self.parsed_data.add_service_inventory(service)
            
            self.logger.debug(f"Found {len(services)} ACI services")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI services: {e}")
    
    def _parse_aci_features(self, root: ET.Element):
        """Parse ACI feature flags and settings."""
        try:
            features = FeatureFlags(
                device_id=self.current_device_id,
                source_file=self.current_source_file
            )
            
            # Check for various ACI features
            if root.findall(".//fvTenant"):
                features.spanning_tree_bpduguard_default = "yes"  # ACI has built-in loop protection
            
            if root.findall(".//dhcpLbl") or root.findall(".//dhcpRsProv"):
                features.dhcp_snoop_enabled = "yes"
            
            if root.findall(".//arpInst"):
                features.arp_inspection_enabled = "yes"
            
            self.parsed_data.add_feature_flags(features)
            self.logger.debug("Parsed ACI feature flags")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI features: {e}")
    
    def _parse_aci_firmware(self, root: ET.Element):
        """Parse ACI firmware information."""
        try:
            # Look for firmware/version information
            firmware_elems = root.findall(".//firmwareRunning") + root.findall(".//maintMaintP")
            
            for fw in firmware_elems:
                version = fw.get('version', '') or fw.get('runningVer', '')
                if version:
                    firmware = FirmwareInventory(
                        device_id=self.current_device_id,
                        component="ACI System",
                        current_version=version,
                        running_image=f"ACI-{version}",
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_firmware_inventory(firmware)
                    break  # Only add one firmware entry
            
            self.logger.debug("Parsed ACI firmware information")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACI firmware: {e}") 