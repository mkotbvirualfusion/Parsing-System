"""
Cisco NX-OS Parser for the Network Configuration Parser.
Handles Cisco NX-OS configuration files with comprehensive data extraction.
"""

import re
from pathlib import Path
from typing import Optional, List

from parsers.base_parser import BaseParser
from core.data_models import (
    ParsedData, NetworkDevice, VendorInfo, Interface, VLAN, 
    StaticRoute, LocalUser, NTPServer, SNMPConfig, LogTarget, 
    ACLEntry, DynamicRouting, AAAServer, FeatureFlags,
    LoginBanner, ServiceInventory, HSRPVRRPGroup, DNSConfig
)
from utils.helpers import extract_hostname, extract_version, extract_model


class CiscoNXOSParser(BaseParser):
    """Enhanced parser for Cisco NX-OS configurations."""
    
    def __init__(self, filter_configured_only=False):
        """Initialize the Cisco NX-OS parser."""
        super().__init__()
        
        self.description = "Enhanced Cisco NX-OS configuration parser"
        self.supported_formats = ['txt', 'conf', 'cfg', 'log']
        self.vendor = "cisco"
        self.os_family = "nxos"
        self.filter_configured_only = filter_configured_only  # Filter to only configured interfaces
    
    def parse_file(self, file_path: Path, vendor_info: VendorInfo) -> Optional[ParsedData]:
        """
        Parse a Cisco NX-OS configuration file with comprehensive data extraction.
        
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
            
            self.logger.info(f"Parsing Cisco NX-OS configuration: {file_path}")
            
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
            
            # Parse all NX-OS configurations comprehensively
            self._parse_nxos_interfaces(content)
            self._parse_nxos_vlans(content)
            self._parse_nxos_static_routes(content)
            self._parse_nxos_acls(content)
            self._parse_nxos_users(content)
            self._parse_nxos_ntp(content)
            self._parse_nxos_snmp(content)
            self._parse_nxos_syslog(content)
            self._parse_nxos_ospf(content)
            self._parse_nxos_features(content)
            self._parse_nxos_aaa(content)
            self._parse_nxos_login_banner(content)
            
            # New enhanced parsers
            self._parse_nxos_hsrp_vrrp(content)
            self._parse_nxos_dns(content)
            
            self.logger.info(f"Successfully parsed {file_path}")
            return self.parsed_data
            
        except Exception as e:
            self.logger.error(f"Error parsing Cisco NX-OS file {file_path}: {e}")
            return None
    
    def extract_device_info(self, content: str) -> Optional[NetworkDevice]:
        """Extract comprehensive device information from NX-OS configuration."""
        try:
            # Extract hostname
            hostname_match = re.search(r'^hostname\s+(\S+)', content, re.MULTILINE)
            hostname = hostname_match.group(1) if hostname_match else ""
            
            # Extract OS version - Fixed for NX-OS proper version detection
            version_patterns = [
                r'version\s+([\d\.\(\)A-Za-z]+)(?:\s+Bios:|$)',  # Capture version before Bios or end of line
                r'Cisco\s+Nexus\s+Operating\s+System.*?Software.*?version\s+([^\s]+)',
                r'System\s+version:\s+([^\s]+)',
                r'NXOS:\s+version\s+([^\s]+)'
            ]
            
            os_version = ""
            for pattern in version_patterns:
                version_match = re.search(pattern, content, re.MULTILINE | re.DOTALL)
                if version_match:
                    os_version = version_match.group(1).strip()
                    break
            
            # Extract model - look for Nexus in various places
            model_patterns = [
                r'cisco\s+Nexus\s+(\S+)',
                r'Hardware\s+.*?cisco\s+(\S+)',
                r'Device:\s+(\S+)'
            ]
            
            model = "Nexus"  # Default for NX-OS
            for pattern in model_patterns:
                model_match = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
                if model_match:
                    model = f"Nexus {model_match.group(1)}"
                    break
            
            # Extract location from SNMP or other configs
            location_patterns = [
                r'snmp-server\s+location\s+(.+)',
                r'location\s+(.+)'
            ]
            location = ""
            for pattern in location_patterns:
                location_match = re.search(pattern, content, re.MULTILINE)
                if location_match:
                    location = location_match.group(1).strip()
                    break
            
            # Extract timestamp
            timestamp = self._extract_timestamp(content)
            
            device_id = hostname.lower().replace('-', '_') if hostname else "unknown"
            
            device = NetworkDevice(
                device_id=device_id,
                hostname=hostname,
                vendor="cisco",
                model=model,
                os_family="nx-os",
                os_version=os_version,
                location=location,
                config_timestamp=timestamp,
                source_file=self.current_source_file
            )
            
            return device
            
        except Exception as e:
            self.logger.error(f"Error extracting NX-OS device info: {e}")
            return None
    
    def _parse_nxos_interfaces(self, content: str):
        """Parse comprehensive NX-OS interface configurations with business context filtering."""
        # Find all interface sections
        interface_pattern = r'^interface\s+(\S+)(.*?)(?=^interface|\Z)'
        interface_matches = re.finditer(interface_pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in interface_matches:
            interface_name = match.group(1)
            interface_config = match.group(2)
            
            # Business context filtering - only include configured interfaces if filter is enabled
            if self.filter_configured_only:
                # Check if interface has meaningful configuration
                has_config = any([
                    'ip address' in interface_config,
                    'description' in interface_config,
                    'switchport' in interface_config,
                    'channel-group' in interface_config,
                    'vpc' in interface_config,
                    'hsrp' in interface_config,
                    'spanning-tree' in interface_config,
                    re.search(r'no shutdown', interface_config)
                ])
                
                # Skip unconfigured interfaces
                if not has_config and interface_name.startswith(('Ethernet', 'GigabitEthernet', 'TenGigE')):
                    continue
            
            # Extract interface details with enhanced context
            description = ""
            ip_address = ""
            subnet_mask = ""
            vlan = ""
            speed_mbps = ""
            mtu = "1500"  # Default
            admin_status = "up"  # Default
            if_type = self._determine_interface_type(interface_name)
            
            # Enhanced business context extraction
            business_priority = self._determine_interface_priority(interface_name, interface_config)
            
            # Parse description with business annotations
            desc_match = re.search(r'description\s+(.+)', interface_config)
            if desc_match:
                description = desc_match.group(1).strip()
            
            # Parse IP address
            ip_match = re.search(r'ip\s+address\s+(\S+)(?:\s+(\S+))?', interface_config)
            if ip_match:
                ip_address = ip_match.group(1)
                if '/' in ip_address:
                    # CIDR notation
                    ip_parts = ip_address.split('/')
                    ip_address = ip_parts[0]
                    prefix_len = int(ip_parts[1])
                    subnet_mask = self._cidr_to_netmask(prefix_len)
                elif ip_match.group(2):
                    subnet_mask = ip_match.group(2)
            
            # Parse VLAN for subinterfaces
            vlan_match = re.search(r'encapsulation\s+dot1q\s+(\d+)', interface_config)
            if vlan_match:
                vlan = vlan_match.group(1)
            elif 'Vlan' in interface_name:
                vlan_num = re.search(r'Vlan(\d+)', interface_name)
                if vlan_num:
                    vlan = vlan_num.group(1)
            
            # Parse speed
            speed_match = re.search(r'speed\s+(\d+)', interface_config)
            if speed_match:
                speed_mbps = speed_match.group(1)
            
            # Parse MTU
            mtu_match = re.search(r'mtu\s+(\d+)', interface_config)
            if mtu_match:
                mtu = mtu_match.group(1)
            
            # Check admin status
            if 'shutdown' in interface_config:
                admin_status = "down"
            
            # Extract additional business context
            port_security = "enabled" if 'switchport port-security' in interface_config else ""
            bpdu_guard = "enabled" if 'spanning-tree bpduguard enable' in interface_config else ""
            storm_control = "enabled" if 'storm-control' in interface_config else ""
            
            interface = Interface(
                device_id=self.current_device_id,
                interface_name=interface_name,
                description=description,
                ip_address=ip_address,
                subnet_mask=subnet_mask,
                vlan=vlan,
                speed_mbps=speed_mbps,
                admin_status=admin_status,
                operational_status=admin_status,  # Assume same as admin
                if_type=if_type,
                mtu=mtu,
                port_security=port_security,
                bpdu_guard=bpdu_guard,
                storm_control_pps=storm_control,
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_interface(interface)
    
    def _parse_nxos_vlans(self, content: str):
        """Parse NX-OS VLAN configurations."""
        # Parse VLAN definitions
        vlan_pattern = r'^vlan\s+(\d+)(.*?)(?=^vlan|\Z)'
        vlan_matches = re.finditer(vlan_pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in vlan_matches:
            vlan_id = match.group(1)
            vlan_config = match.group(2)
            
            # Parse VLAN name
            name_match = re.search(r'name\s+(.+)', vlan_config)
            vlan_name = name_match.group(1).strip() if name_match else ""
            
            vlan = VLAN(
                device_id=self.current_device_id,
                vlan_id=vlan_id,
                vlan_name=vlan_name,
                state="active",
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_vlan(vlan)
        
        # Also parse VLAN interface SVIs
        svi_pattern = r'^interface\s+Vlan(\d+)(.*?)(?=^interface|\Z)'
        svi_matches = re.finditer(svi_pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in svi_matches:
            vlan_id = match.group(1)
            svi_config = match.group(2)
            
            # Extract SVI IP
            svi_ip = ""
            ip_match = re.search(r'ip\s+address\s+(\S+)', svi_config)
            if ip_match:
                svi_ip = ip_match.group(1)
            
            # Create or update VLAN entry
            existing_vlan = None
            for vlan in self.parsed_data.vlans_vrfs:
                if vlan.vlan_id == vlan_id:
                    existing_vlan = vlan
                    break
            
            if existing_vlan:
                existing_vlan.svi_ip = svi_ip
                existing_vlan.mode = "routed" if svi_ip else "access"
            else:
                # Create new VLAN entry for SVI
                desc_match = re.search(r'description\s+(.+)', svi_config)
                description = desc_match.group(1).strip() if desc_match else ""
                
                vlan = VLAN(
                    device_id=self.current_device_id,
                    vlan_id=vlan_id,
                    description=description,
                    svi_ip=svi_ip,
                    mode="routed",
                    state="active",
                    active="true",
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_vlan(vlan)
    
    def _parse_nxos_static_routes(self, content: str):
        """Parse NX-OS static route configurations."""
        route_pattern = r'ip\s+route\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+name\s+(\S+))?(?:\s+tag\s+(\d+))?'
        route_matches = re.finditer(route_pattern, content, re.MULTILINE)
        
        for match in route_matches:
            destination = match.group(1)
            next_hop_or_mask = match.group(2)
            next_hop = match.group(3)
            description = match.group(4) if match.group(4) else ""
            tag = match.group(5) if match.group(5) else ""
            
            # Handle different route formats
            if next_hop_or_mask.count('.') == 3:  # It's a subnet mask
                subnet_mask = next_hop_or_mask
                # Convert subnet mask to prefix length
                prefix_length = self._netmask_to_cidr(subnet_mask)
            else:  # It's the next hop
                prefix_length = "32"  # Host route
                next_hop = next_hop_or_mask
            
            route = StaticRoute(
                device_id=self.current_device_id,
                destination=destination,
                prefix_length=str(prefix_length),
                next_hop=next_hop,
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_static_route(route)
    
    def _parse_nxos_acls(self, content: str):
        """Parse NX-OS ACL configurations with enhanced schema matching."""
        # Parse IP access lists
        acl_pattern = r'ip\s+access-list\s+(\S+)(.*?)(?=^ip\s+access-list|\Z)'
        acl_matches = re.finditer(acl_pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in acl_matches:
            acl_name = match.group(1)
            acl_config = match.group(2)
            
            # Determine ACL business context
            acl_description = self._determine_acl_business_context(acl_name)
            
            # Parse ACL entries
            entry_pattern = r'(\d+)\s+(permit|deny)\s+(.+)'
            entry_matches = re.finditer(entry_pattern, acl_config, re.MULTILINE)
            
            for entry_match in entry_matches:
                seq_number = entry_match.group(1)
                action = entry_match.group(2)
                entry_details = entry_match.group(3).strip()
                
                # Parse entry details with enhanced field mapping
                parts = entry_details.split()
                protocol = parts[0] if parts else ""
                
                # Initialize fields
                source_ip = ""
                source_mask = ""
                destination_ip = ""
                destination_mask = ""
                port = ""
                
                # Enhanced parsing for different ACL formats
                if protocol in ["tcp", "udp", "icmp"]:
                    # Extended ACL
                    acl_type = "extended"
                    
                    # Parse source
                    if len(parts) > 1:
                        source_ip = parts[1]
                        if source_ip == "any":
                            source_mask = "any"
                        elif "/" in source_ip:
                            # CIDR notation
                            ip_parts = source_ip.split('/')
                            source_ip = ip_parts[0]
                            prefix_len = int(ip_parts[1])
                            source_mask = self._cidr_to_netmask(prefix_len)
                        elif len(parts) > 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[2]):
                            # Wildcard mask format
                            source_mask = self._wildcard_to_netmask(parts[2])
                        else:
                            source_mask = "255.255.255.255"  # Host
                    
                    # Parse destination
                    dest_start_idx = 3 if source_mask != "any" and not "/" in parts[1] and len(parts) > 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[2]) else 2
                    if len(parts) > dest_start_idx:
                        destination_ip = parts[dest_start_idx]
                        if destination_ip == "any":
                            destination_mask = "any"
                        elif "/" in destination_ip:
                            # CIDR notation
                            ip_parts = destination_ip.split('/')
                            destination_ip = ip_parts[0]
                            prefix_len = int(ip_parts[1])
                            destination_mask = self._cidr_to_netmask(prefix_len)
                        elif len(parts) > dest_start_idx + 1 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[dest_start_idx + 1]):
                            # Wildcard mask format
                            destination_mask = self._wildcard_to_netmask(parts[dest_start_idx + 1])
                        else:
                            destination_mask = "255.255.255.255"  # Host
                    
                    # Extract port if present
                    if "eq" in entry_details:
                        eq_match = re.search(r'eq\s+(\S+)', entry_details)
                        if eq_match:
                            port = eq_match.group(1)
                
                elif protocol == "ip":
                    # Standard ACL format
                    acl_type = "standard"
                    
                    if len(parts) > 1:
                        source_ip = parts[1]
                        if source_ip == "any":
                            source_mask = "any"
                        elif "/" in source_ip:
                            # CIDR notation
                            ip_parts = source_ip.split('/')
                            source_ip = ip_parts[0]
                            prefix_len = int(ip_parts[1])
                            source_mask = self._cidr_to_netmask(prefix_len)
                        elif len(parts) > 2 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[2]):
                            # Wildcard mask format
                            source_mask = self._wildcard_to_netmask(parts[2])
                        else:
                            source_mask = "255.255.255.255"  # Host
                    
                    # For standard ACLs, destination is typically "any"
                    destination_ip = "any"
                    destination_mask = "any"
                
                else:
                    # Other protocols
                    acl_type = "extended"
                    if len(parts) > 1:
                        source_ip = parts[1]
                        source_mask = "255.255.255.255" if source_ip != "any" else "any"
                    if len(parts) > 2:
                        destination_ip = parts[2]
                        destination_mask = "255.255.255.255" if destination_ip != "any" else "any"
                
                # Create enhanced ACL entry
                acl_entry = ACLEntry(
                    device_id=self.current_device_id,
                    acl_name=acl_name,
                    acl_type=acl_type,
                    seq=seq_number,
                    action=action,
                    proto=protocol,
                    src=source_ip,
                    src_port="",  # Source port not commonly used in these ACLs
                    dst=destination_ip,
                    dst_port=port,
                    remarks=acl_description,
                    source_file=self.current_source_file,
                    
                    # Enhanced fields for standardized schema
                    seq_number=seq_number,
                    source_ip=source_ip,
                    source_mask=source_mask,
                    destination_ip=destination_ip,
                    destination_mask=destination_mask,
                    protocol=protocol,
                    port=port,
                    log="",  # Not commonly configured in these ACLs
                    description=acl_description,
                    direction=""  # Direction not specified in ACL definition
                )
                
                self.parsed_data.add_acl(acl_entry)
    
    def _determine_acl_business_context(self, acl_name: str) -> str:
        """Determine business context and description for ACL."""
        acl_contexts = {
            "25": "IP access list",
            "NEW_MGMT_ACL": "Management ACL for SSH",
            "MGMT": "Management access control",
            "SNMP": "SNMP community access control",
            "VTY": "Virtual terminal access control"
        }
        
        # Check for exact match first
        if acl_name in acl_contexts:
            return acl_contexts[acl_name]
        
        # Check for partial matches
        acl_name_upper = acl_name.upper()
        for key, description in acl_contexts.items():
            if key in acl_name_upper:
                return description
        
        # Default description
        return f"Access control list {acl_name}"
    
    def _wildcard_to_netmask(self, wildcard: str) -> str:
        """Convert wildcard mask to subnet mask."""
        try:
            octets = wildcard.split('.')
            netmask_octets = []
            for octet in octets:
                netmask_octets.append(str(255 - int(octet)))
            return '.'.join(netmask_octets)
        except:
            return "255.255.255.255"
    
    def _parse_nxos_users(self, content: str):
        """Parse NX-OS user configurations."""
        user_pattern = r'username\s+(\S+)\s+password\s+(\d+)\s+(\S+)\s+role\s+(\S+)'
        user_matches = re.finditer(user_pattern, content, re.MULTILINE)
        
        for match in user_matches:
            username = match.group(1)
            password_type = match.group(2)
            encrypted_password = match.group(3)
            role = match.group(4)
            
            # Map role to privilege level
            privilege_level = "15" if "admin" in role else "1"
            
            user = LocalUser(
                device_id=self.current_device_id,
                username=username,
                privilege=privilege_level,
                hash_type=password_type,
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_local_user(user)
    
    def _parse_nxos_ntp(self, content: str):
        """Parse NX-OS NTP configurations."""
        ntp_pattern = r'ntp\s+server\s+(\S+)(?:\s+(prefer))?(?:\s+use-vrf\s+(\S+))?(?:\s+key\s+(\d+))?'
        ntp_matches = re.finditer(ntp_pattern, content, re.MULTILINE)
        
        for match in ntp_matches:
            server_ip = match.group(1)
            prefer = "yes" if match.group(2) else "no"
            vrf = match.group(3) if match.group(3) else "default"
            key_id = match.group(4) if match.group(4) else ""
            
            # Check for authentication
            auth_enabled = "yes" if "ntp authenticate" in content else "no"
            
            ntp_server = NTPServer(
                device_id=self.current_device_id,
                ntp_server=server_ip,
                prefer_flag=prefer,
                key_id=key_id,
                auth_state=auth_enabled,
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_ntp(ntp_server)
    
    def _parse_nxos_snmp(self, content: str):
        """Parse NX-OS SNMP configurations."""
        # Parse SNMP communities
        community_pattern = r'snmp-server\s+community\s+(\S+)\s+group\s+(\S+)'
        community_matches = re.finditer(community_pattern, content, re.MULTILINE)
        
        for match in community_matches:
            community = match.group(1)
            group = match.group(2)
            access_mode = "ro" if "operator" in group else "rw"
            
            # Extract contact and location
            contact_match = re.search(r'snmp-server\s+contact\s+(.+)', content)
            location_match = re.search(r'snmp-server\s+location\s+(.+)', content)
            
            contact = contact_match.group(1).strip() if contact_match else ""
            location = location_match.group(1).strip() if location_match else ""
            
            snmp_config = SNMPConfig(
                device_id=self.current_device_id,
                version="v2c",
                community_or_user=community,
                auth_level=access_mode,
                trap_enable="yes",
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_snmp(snmp_config)
        
        # Parse SNMP v3 users
        user_pattern = r'snmp-server\s+user\s+(\S+)\s+(\S+)\s+auth\s+(\S+)'
        user_matches = re.finditer(user_pattern, content, re.MULTILINE)
        
        for match in user_matches:
            user = match.group(1)
            group = match.group(2)
            auth_protocol = match.group(3)
            
            # Extract host information
            host_pattern = rf'snmp-server\s+host\s+(\S+).*{user}'
            host_match = re.search(host_pattern, content)
            host = host_match.group(1) if host_match else ""
            
            access_mode = "ro" if "operator" in group else "rw"
            
            snmp_config = SNMPConfig(
                device_id=self.current_device_id,
                version="v3",
                community_or_user=user,
                auth_level=access_mode,
                target_host=host,
                trap_enable="yes",
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_snmp(snmp_config)
    
    def _parse_nxos_syslog(self, content: str):
        """Parse NX-OS syslog configurations."""
        syslog_pattern = r'logging\s+server\s+(\S+)(?:\s+(\d+))?(?:\s+port\s+(\d+))?(?:\s+use-vrf\s+(\S+))?'
        syslog_matches = re.finditer(syslog_pattern, content, re.MULTILINE)
        
        for match in syslog_matches:
            server = match.group(1)
            severity = match.group(2) if match.group(2) else "6"
            port = match.group(3) if match.group(3) else "514"
            vrf = match.group(4) if match.group(4) else "management"
            
            syslog_server = LogTarget(
                device_id=self.current_device_id,
                dest_ip=server,
                proto="udp",
                port=port,
                severity_mask=severity,
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_log_target(syslog_server)
    
    def _parse_nxos_ospf(self, content: str):
        """Parse enhanced NX-OS OSPF configurations with detailed parameters."""
        # Find OSPF router configurations
        ospf_pattern = r'router\s+ospf\s+(\S+)(.*?)(?=^router|\Z)'
        ospf_matches = re.finditer(ospf_pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in ospf_matches:
            process_id = match.group(1)
            ospf_config = match.group(2)
            
            # Parse router ID
            router_id_match = re.search(r'router-id\s+(\S+)', ospf_config)
            router_id = router_id_match.group(1) if router_id_match else ""
            
            # Parse area configurations
            area_pattern = r'area\s+(\S+)\s+(.*?)(?=area|\Z)'
            area_matches = re.finditer(area_pattern, ospf_config, re.MULTILINE | re.DOTALL)
            
            areas_info = []
            for area_match in area_matches:
                area_id = area_match.group(1)
                area_config = area_match.group(2)
                
                # Check for area authentication
                area_auth = ""
                if 'authentication message-digest' in area_config:
                    area_auth = "message-digest"
                elif 'authentication' in area_config:
                    area_auth = "simple"
                
                areas_info.append(f"{area_id}({area_auth})" if area_auth else area_id)
            
            # Parse redistributions
            redistribute_pattern = r'redistribute\s+(\S+)(?:\s+route-map\s+(\S+))?'
            redistribute_matches = re.finditer(redistribute_pattern, ospf_config, re.MULTILINE)
            redistributions = []
            for redist_match in redistribute_matches:
                protocol = redist_match.group(1)
                route_map = redist_match.group(2) if redist_match.group(2) else ""
                redistributions.append(f"{protocol}({route_map})" if route_map else protocol)
            
            # Find interfaces participating in this OSPF process
            interface_pattern = r'interface\s+(\S+)(.*?)(?=^interface|\Z)'
            interface_matches = re.finditer(interface_pattern, content, re.MULTILINE | re.DOTALL)
            
            for int_match in interface_matches:
                interface = int_match.group(1)
                int_config = int_match.group(2)
                
                # Check if this interface is in the current OSPF process
                ospf_proc_match = re.search(rf'ip\s+router\s+ospf\s+{process_id}\s+area\s+(\S+)', int_config)
                if ospf_proc_match:
                    area = ospf_proc_match.group(1)
                    
                    # Extract interface-specific OSPF parameters
                    hello_interval = ""
                    dead_interval = ""
                    priority = ""
                    cost = ""
                    network_type = ""
                    authentication = ""
                    passive_interface = "no"
                    
                    # Parse OSPF timers
                    hello_match = re.search(r'ip\s+ospf\s+hello-interval\s+(\d+)', int_config)
                    if hello_match:
                        hello_interval = hello_match.group(1)
                    
                    dead_match = re.search(r'ip\s+ospf\s+dead-interval\s+(\d+)', int_config)
                    if dead_match:
                        dead_interval = dead_match.group(1)
                    
                    # Parse OSPF priority
                    priority_match = re.search(r'ip\s+ospf\s+priority\s+(\d+)', int_config)
                    if priority_match:
                        priority = priority_match.group(1)
                    
                    # Parse OSPF cost
                    cost_match = re.search(r'ip\s+ospf\s+cost\s+(\d+)', int_config)
                    if cost_match:
                        cost = cost_match.group(1)
                    
                    # Parse network type
                    network_match = re.search(r'ip\s+ospf\s+network\s+(\S+)', int_config)
                    if network_match:
                        network_type = network_match.group(1)
                    
                    # Parse authentication
                    if 'ip ospf authentication key-chain' in int_config:
                        auth_match = re.search(r'ip\s+ospf\s+authentication\s+key-chain\s+(\S+)', int_config)
                        authentication = f"key-chain:{auth_match.group(1)}" if auth_match else "key-chain"
                    elif 'ip ospf authentication message-digest' in int_config:
                        authentication = "message-digest"
                    elif 'ip ospf authentication' in int_config:
                        authentication = "simple"
                    
                    # Check for passive interface
                    if f'passive-interface {interface}' in ospf_config:
                        passive_interface = "yes"
                    
                    # Determine area type
                    area_type = "normal"
                    for area_info in areas_info:
                        if area_info.startswith(area):
                            if 'stub' in ospf_config:
                                area_type = "stub"
                            elif 'nssa' in ospf_config:
                                area_type = "nssa"
                            break
                    
                    # Create enhanced dynamic routing entry for OSPF
                    ospf_entry = DynamicRouting(
                        device_id=self.current_device_id,
                        neighbor_ip=interface,  # Use interface as neighbor identifier for OSPF
                        protocol="ospf",
                        process_id=process_id,
                        router_id=router_id,
                        areas=f"{area}({area_type})",
                        redistributions=";".join(redistributions) if redistributions else "",
                        description=f"Interface:{interface}, Priority:{priority}, Auth:{authentication}, Passive:{passive_interface}",
                        source_file=self.current_source_file
                    )
                    
                    self.parsed_data.add_dynamic_routing(ospf_entry)
    
    def _parse_nxos_features(self, content: str):
        """Parse NX-OS enabled features."""
        feature_pattern = r'feature\s+(\S+)'
        feature_matches = re.finditer(feature_pattern, content, re.MULTILINE)
        
        features_found = []
        for match in feature_matches:
            feature_name = match.group(1)
            features_found.append(feature_name)
        
        if features_found:
            # Create a FeatureFlags entry with commonly parsed flags
            dhcp_snoop = "yes" if "dhcp" in " ".join(features_found) else ""
            arp_inspection = "yes" if "arp" in " ".join(features_found) else ""
            spanning_tree = "yes" if any("stp" in f or "spanning" in f for f in features_found) else ""
            
            feature_flags = FeatureFlags(
                device_id=self.current_device_id,
                dhcp_snoop_enabled=dhcp_snoop,
                arp_inspection_enabled=arp_inspection,
                spanning_tree_bpduguard_default=spanning_tree,
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_feature_flags(feature_flags)
    
    def _parse_nxos_aaa(self, content: str):
        """Parse NX-OS AAA/TACACS+ configurations."""
        # Parse TACACS servers
        tacacs_pattern = r'tacacs-server\s+host\s+(\S+)(?:\s+key\s+\d+\s+"([^"]+)")?'
        tacacs_matches = re.finditer(tacacs_pattern, content, re.MULTILINE)
        
        for match in tacacs_matches:
            server_ip = match.group(1)
            key = match.group(2) if match.group(2) else "encrypted"
            
            # Parse server groups
            group_pattern = rf'aaa\s+group\s+server\s+tacacs\+\s+(\S+).*?server\s+{server_ip}'
            group_match = re.search(group_pattern, content, re.DOTALL)
            server_group = group_match.group(1) if group_match else "default"
            
            aaa_server = AAAServer(
                device_id=self.current_device_id,
                server_type="tacacs+",
                server_group=server_group,
                server_ip=server_ip,
                key_hash=key,
                timeout_sec="5",  # Default
                vrf="default",
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_aaa_server(aaa_server)
    
    def _parse_nxos_login_banner(self, content: str):
        """Parse NX-OS login banner configurations."""
        # Parse banner motd
        banner_pattern = r'banner\s+motd\s+(.+?)(?=\n\w|\n!|\Z)'
        banner_match = re.search(banner_pattern, content, re.MULTILINE | re.DOTALL)
        
        if banner_match:
            banner_text = banner_match.group(1).strip()
            
            banner = LoginBanner(
                device_id=self.current_device_id,
                banner_type="motd",
                text=banner_text,
                source_file=self.current_source_file
            )
            
            self.parsed_data.add_login_banner(banner)
    
    def _determine_interface_type(self, interface_name: str) -> str:
        """Determine interface type from name."""
        if interface_name.startswith('mgmt'):
            return 'management'
        elif interface_name.startswith('loopback'):
            return 'loopback'
        elif interface_name.startswith('Vlan'):
            return 'vlan'
        elif interface_name.startswith('Ethernet'):
            return 'ethernet'
        elif interface_name.startswith('port-channel'):
            return 'port-channel'
        elif '.' in interface_name:
            return 'subinterface'
        else:
            return 'unknown'
    
    def _cidr_to_netmask(self, prefix_len: int) -> str:
        """Convert CIDR prefix length to subnet mask."""
        cidr_to_mask = {
            8: "255.0.0.0", 16: "255.255.0.0", 24: "255.255.255.0",
            25: "255.255.255.128", 26: "255.255.255.192", 27: "255.255.255.224",
            28: "255.255.255.240", 29: "255.255.255.248", 30: "255.255.255.252",
            31: "255.255.255.254", 32: "255.255.255.255"
        }
        return cidr_to_mask.get(prefix_len, "255.255.255.255")
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convert subnet mask to CIDR prefix length."""
        mask_to_cidr = {
            "255.0.0.0": 8, "255.255.0.0": 16, "255.255.255.0": 24,
            "255.255.255.128": 25, "255.255.255.192": 26, "255.255.255.224": 27,
            "255.255.255.240": 28, "255.255.255.248": 29, "255.255.255.252": 30,
            "255.255.255.254": 31, "255.255.255.255": 32
        }
        return mask_to_cidr.get(netmask, 32)
    
    def _determine_interface_priority(self, interface_name: str, interface_config: str) -> str:
        """Determine business priority of interface based on configuration."""
        if any(keyword in interface_config.lower() for keyword in ['core', 'uplink', 'trunk', 'server']):
            return "critical"
        elif any(keyword in interface_config.lower() for keyword in ['management', 'mgmt', 'admin']):
            return "management"
        elif 'hsrp' in interface_config.lower() or 'vpc' in interface_config.lower():
            return "high"
        elif 'ip address' in interface_config:
            return "medium"
        else:
            return "low"

    def _parse_nxos_hsrp_vrrp(self, content: str):
        """Parse NX-OS HSRP/VRRP configurations."""
        # Find all interface sections and look for HSRP configurations
        interface_pattern = r'^interface\s+(\S+)(.*?)(?=^interface|\Z)'
        interface_matches = re.finditer(interface_pattern, content, re.MULTILINE | re.DOTALL)
        
        for match in interface_matches:
            interface_name = match.group(1)
            interface_config = match.group(2)
            
            # Check for HSRP configurations in this interface
            if 'hsrp' in interface_config:
                # Parse HSRP version
                version_match = re.search(r'hsrp\s+version\s+(\d+)', interface_config)
                version = f"hsrp_v{version_match.group(1)}" if version_match else "hsrp_v1"
                
                # Find HSRP groups
                group_pattern = r'hsrp\s+(\d+)(.*?)(?=^hsrp|\Z)'
                group_matches = re.finditer(group_pattern, interface_config, re.MULTILINE | re.DOTALL)
                
                for group_match in group_matches:
                    group_id = group_match.group(1)
                    group_config = group_match.group(2)
                    
                    # Extract HSRP parameters
                    virtual_ip = ""
                    priority = ""
                    preempt = "no"
                    auth_type = ""
                    auth_key = ""
                    timers_hello = ""
                    timers_hold = ""
                    
                    # Parse virtual IP
                    vip_match = re.search(r'ip\s+(\d+\.\d+\.\d+\.\d+)', group_config)
                    if vip_match:
                        virtual_ip = vip_match.group(1)
                    
                    # Parse priority
                    priority_match = re.search(r'priority\s+(\d+)', group_config)
                    if priority_match:
                        priority = priority_match.group(1)
                    
                    # Check for preempt
                    if 'preempt' in group_config:
                        preempt = "yes"
                    
                    # Parse authentication
                    auth_match = re.search(r'authentication\s+(\w+)\s+key-string\s+(\S+)', group_config)
                    if auth_match:
                        auth_type = auth_match.group(1)
                        auth_key = auth_match.group(2)
                    
                    # Parse timers
                    timers_match = re.search(r'timers\s+(\d+)\s+(\d+)', group_config)
                    if timers_match:
                        timers_hello = timers_match.group(1)
                        timers_hold = timers_match.group(2)
                    
                    hsrp_group = HSRPVRRPGroup(
                        device_id=self.current_device_id,
                        interface=interface_name,
                        group_id=group_id,
                        protocol=version,
                        virtual_ip=virtual_ip,
                        priority=priority,
                        preempt=preempt,
                        authentication_type=auth_type,
                        authentication_key=auth_key,
                        timers_hello=timers_hello,
                        timers_hold=timers_hold,
                        status="active",  # Default status
                        source_file=self.current_source_file
                    )
                    
                    self.parsed_data.add_hsrp_vrrp_group(hsrp_group)
    
    def _parse_nxos_dns(self, content: str):
        """Parse NX-OS DNS configurations."""
        # Parse domain name
        domain_match = re.search(r'ip\s+domain-name\s+(\S+)', content)
        domain_name = domain_match.group(1) if domain_match else ""
        
        # Parse domain lookup setting
        lookup_enabled = "yes" if re.search(r'ip\s+domain-lookup', content) else "no"
        
        # Parse name servers
        nameserver_pattern = r'ip\s+name-server\s+([\d\.\s]+)'
        nameserver_matches = re.finditer(nameserver_pattern, content, re.MULTILINE)
        
        for match in nameserver_matches:
            servers = match.group(1).strip().split()
            for i, server_ip in enumerate(servers):
                if server_ip and re.match(r'\d+\.\d+\.\d+\.\d+', server_ip):
                    dns_type = "primary" if i == 0 else "secondary"
                    
                    dns_config = DNSConfig(
                        device_id=self.current_device_id,
                        dns_server=server_ip,
                        domain_name=domain_name,
                        dns_type=dns_type,
                        lookup_enabled=lookup_enabled,
                        source_file=self.current_source_file
                    )
                    
                    self.parsed_data.add_dns_config(dns_config) 