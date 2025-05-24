"""
Cisco IOS Parser for the Network Configuration Parser.
Handles Cisco IOS and IOS-XE configuration files.
"""

import re
from pathlib import Path
from typing import List, Optional, Dict, Any

from parsers.base_parser import BaseParser
from core.data_models import (
    ParsedData, NetworkDevice, Interface, VLAN, ACLEntry, StaticRoute,
    DynamicRouting, NTPServer, AAAServer, SNMPConfig, LocalUser, LogTarget,
    LoginBanner, VendorInfo, FeatureFlags, ServiceInventory, DNSConfig
)
from utils.helpers import (
    extract_hostname, extract_version, extract_model, extract_serial_number,
    parse_ip_address, clean_string, normalize_interface_name
)


class CiscoIOSParser(BaseParser):
    """Parser for Cisco IOS and IOS-XE configurations."""
    
    def __init__(self):
        """Initialize the Cisco IOS parser."""
        super().__init__()
        
        self.description = "Cisco IOS/IOS-XE configuration parser"
        self.supported_formats = ['txt', 'conf', 'cfg', 'log']
        self.vendor = "cisco"
        self.os_family = "ios"
    
    def parse_file(self, file_path: Path, vendor_info: VendorInfo) -> Optional[ParsedData]:
        """
        Parse a Cisco IOS configuration file.
        
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
            
            self.logger.info(f"Parsing Cisco IOS configuration: {file_path}")
            
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
            
            # Parse different configuration sections
            self._parse_interfaces(content)
            self._parse_vlans(content)
            self._parse_acls(content)
            self._parse_static_routes(content)
            self._parse_dynamic_routing(content)
            self._parse_ntp_servers(content)
            self._parse_aaa_servers(content)
            self._parse_snmp_config(content)
            self._parse_local_users(content)
            self._parse_logging_config(content)
            self._parse_login_banners(content)
            self._parse_feature_flags(content)
            self._parse_services(content)
            
            # Enhanced parsing methods for missing data
            self._parse_ospf_detailed(content)
            self._parse_bgp_detailed(content)
            self._parse_hsrp_vrrp(content)
            self._parse_spanning_tree(content)
            self._parse_qos_policies(content)
            self._parse_multicast(content)
            self._parse_lag_portchannels(content)
            self._parse_syslog_servers(content)
            self._parse_ha_status(content)
            self._parse_dns_servers(content)
            
            self.logger.info(f"Successfully parsed {file_path}")
            return self.parsed_data
            
        except Exception as e:
            self.logger.error(f"Error parsing Cisco IOS file {file_path}: {e}")
            return None
    
    def extract_device_info(self, content: str) -> Optional[NetworkDevice]:
        """
        Extract device information from Cisco IOS configuration.
        
        Args:
            content: Configuration content
            
        Returns:
            NetworkDevice object if successful
        """
        try:
            # Extract basic information
            hostname = extract_hostname(content)
            version = extract_version(content, 'cisco')
            model = extract_model(content, 'cisco')
            serial_number = extract_serial_number(content)
            timestamp = self._extract_timestamp(content)
            
            # Generate device ID
            device_id = self._generate_device_id(hostname or "unknown", self.current_source_file)
            
            # Extract location from SNMP location if available
            location = self._extract_snmp_location(content)
            
            device = NetworkDevice(
                device_id=device_id,
                hostname=hostname or "",
                vendor="cisco",
                model=model,
                os_family="ios",
                os_version=version,
                serial_number=serial_number,
                location=location,
                config_timestamp=timestamp,
                source_file=self.current_source_file
            )
            
            self.logger.debug(f"Extracted device info: {hostname} ({model})")
            return device
            
        except Exception as e:
            self.logger.error(f"Error extracting device info: {e}")
            return None
    
    def _extract_snmp_location(self, content: str) -> Optional[str]:
        """Extract SNMP location string."""
        match = re.search(r'snmp-server location (.+)', content, re.IGNORECASE)
        return match.group(1).strip() if match else None
    
    def _parse_interfaces(self, content: str):
        """Parse interface configurations."""
        try:
            # Find interface sections
            interface_sections = re.finditer(
                r'^interface\s+(\S+)\s*$\n((?:(?!\n\w).*\n?)*)',
                content, re.MULTILINE | re.IGNORECASE
            )
            
            for match in interface_sections:
                interface_name = match.group(1)
                interface_config = match.group(2)
                
                interface = self._parse_single_interface(interface_name, interface_config)
                if interface:
                    self.parsed_data.add_interface(interface)
                    
            self.logger.debug(f"Parsed {len(self.parsed_data.interfaces)} interfaces")
            
        except Exception as e:
            self.logger.error(f"Error parsing interfaces: {e}")
    
    def _parse_single_interface(self, name: str, config: str) -> Optional[Interface]:
        """Parse a single interface configuration."""
        try:
            interface = Interface(
                device_id=self.current_device_id,
                interface_name=normalize_interface_name(name),
                source_file=self.current_source_file
            )
            
            # Parse description
            desc_match = re.search(r'description (.+)', config, re.IGNORECASE)
            if desc_match:
                interface.description = clean_string(desc_match.group(1))
            
            # Parse IP address
            ip_match = re.search(r'ip address (\S+) (\S+)', config, re.IGNORECASE)
            if ip_match:
                interface.ip_address = ip_match.group(1)
                interface.subnet_mask = ip_match.group(2)
            
            # Parse VLAN (for access ports)
            vlan_match = re.search(r'switchport access vlan (\d+)', config, re.IGNORECASE)
            if vlan_match:
                interface.vlan = vlan_match.group(1)
            
            # Parse speed
            speed_match = re.search(r'speed (\d+)', config, re.IGNORECASE)
            if speed_match:
                interface.speed_mbps = speed_match.group(1)
            
            # Parse duplex
            duplex_match = re.search(r'duplex (\w+)', config, re.IGNORECASE)
            if duplex_match:
                interface.duplex = duplex_match.group(1)
            
            # Parse admin status
            if re.search(r'shutdown', config, re.IGNORECASE):
                interface.admin_status = "down"
            else:
                interface.admin_status = "up"
            
            # Parse switchport mode
            mode_match = re.search(r'switchport mode (\w+)', config, re.IGNORECASE)
            if mode_match:
                interface.mode = mode_match.group(1)
            
            # Parse MTU
            mtu_match = re.search(r'mtu (\d+)', config, re.IGNORECASE)
            if mtu_match:
                interface.mtu = mtu_match.group(1)
            
            # Determine interface type
            interface.if_type = self._determine_interface_type(name)
            
            return interface
            
        except Exception as e:
            self.logger.error(f"Error parsing interface {name}: {e}")
            return None
    
    def _determine_interface_type(self, name: str) -> str:
        """Determine interface type from name."""
        name_lower = name.lower()
        
        if name_lower.startswith(('gi', 'gigabit')):
            return "physical"
        elif name_lower.startswith(('fa', 'fast')):
            return "physical"
        elif name_lower.startswith(('te', 'ten')):
            return "physical"
        elif name_lower.startswith(('eth', 'ethernet')):
            return "physical"
        elif name_lower.startswith(('po', 'port-channel')):
            return "port-channel"
        elif name_lower.startswith(('vl', 'vlan')):
            return "svi"
        elif name_lower.startswith(('lo', 'loopback')):
            return "loopback"
        elif name_lower.startswith(('tu', 'tunnel')):
            return "tunnel"
        else:
            return "unknown"
    
    def _parse_vlans(self, content: str):
        """Parse VLAN configurations."""
        try:
            # Parse VLAN definitions
            vlan_matches = re.finditer(r'^vlan (\d+)\s*$\n((?:(?!\n\w).*\n?)*)', 
                                     content, re.MULTILINE | re.IGNORECASE)
            
            for match in vlan_matches:
                vlan_id = match.group(1)
                vlan_config = match.group(2)
                
                vlan = VLAN(
                    device_id=self.current_device_id,
                    vlan_id=vlan_id,
                    source_file=self.current_source_file
                )
                
                # Parse VLAN name
                name_match = re.search(r'name (.+)', vlan_config, re.IGNORECASE)
                if name_match:
                    vlan.vlan_name = clean_string(name_match.group(1))
                
                # Parse state
                if re.search(r'shutdown', vlan_config, re.IGNORECASE):
                    vlan.state = "inactive"
                else:
                    vlan.state = "active"
                
                vlan.active = "yes" if vlan.state == "active" else "no"
                
                self.parsed_data.add_vlan(vlan)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.vlans_vrfs)} VLANs")
            
        except Exception as e:
            self.logger.error(f"Error parsing VLANs: {e}")
    
    def _parse_acls(self, content: str):
        """Parse Access Control Lists with enhanced field extraction."""
        try:
            # Parse standard ACLs
            std_acl_matches = re.finditer(r'access-list (\d+) (\w+) (.+)', 
                                        content, re.IGNORECASE)
            
            for match in std_acl_matches:
                acl_name = match.group(1)
                action = match.group(2)
                rest = match.group(3)
                
                acl = ACLEntry(
                    device_id=self.current_device_id,
                    acl_name=acl_name,
                    acl_type="standard",
                    action=action.lower(),
                    src=rest.strip(),
                    source_file=self.current_source_file,
                    # Enhanced fields
                    source_ip=rest.strip(),
                    protocol="any",
                    direction="ingress",
                    description=f"Standard ACL {acl_name}"
                )
                
                self.parsed_data.add_acl(acl)
            
            # Parse named ACLs - Enhanced
            named_acl_sections = re.finditer(
                r'^ip access-list (\w+) (\S+)\s*$\n((?:(?!\n\w).*\n?)*)',
                content, re.MULTILINE | re.IGNORECASE
            )
            
            for match in named_acl_sections:
                acl_type = match.group(1)
                acl_name = match.group(2)
                acl_config = match.group(3)
                
                # Parse ACL entries with enhanced field extraction
                entry_matches = re.finditer(r'^\s*(?:(\d+)\s+)?(\w+)\s+(.+)$', 
                                          acl_config, re.MULTILINE)
                
                for entry_match in entry_matches:
                    seq = entry_match.group(1) or ""
                    action = entry_match.group(2)
                    rule = entry_match.group(3)
                    
                    acl = self._parse_acl_rule_enhanced(acl_name, acl_type, seq, action, rule)
                    if acl:
                        self.parsed_data.add_acl(acl)
            
            # Parse extended ACLs in different format
            extended_acl_matches = re.finditer(
                r'access-list (\d+) (\w+) (\w+) (\S+) (\S+)(?:\s+(\w+)\s+(\S+))?',
                content, re.IGNORECASE
            )
            
            for match in extended_acl_matches:
                acl_name = match.group(1)
                action = match.group(2)
                protocol = match.group(3)
                src_ip = match.group(4)
                dst_ip = match.group(5)
                proto_detail = match.group(6) or ""
                port = match.group(7) or ""
                
                acl = ACLEntry(
                    device_id=self.current_device_id,
                    acl_name=acl_name,
                    acl_type="extended",
                    action=action.lower(),
                    source_file=self.current_source_file,
                    # Enhanced fields
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=protocol,
                    port=port,
                    direction="ingress",
                    description=f"Extended ACL {acl_name}"
                )
                
                self.parsed_data.add_acl(acl)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.acls)} ACL entries")
            
        except Exception as e:
            self.logger.error(f"Error parsing ACLs: {e}")
    
    def _parse_acl_rule_enhanced(self, acl_name: str, acl_type: str, seq: str, 
                               action: str, rule: str) -> Optional[ACLEntry]:
        """Parse a single ACL rule with enhanced field extraction."""
        try:
            acl = ACLEntry(
                device_id=self.current_device_id,
                acl_name=acl_name,
                acl_type=acl_type,
                seq=seq,
                action=action.lower(),
                source_file=self.current_source_file,
                # Enhanced fields
                seq_number=seq,
                direction="ingress",
                description=f"{acl_type.title()} ACL"
            )
            
            # Parse protocol and addresses with enhanced logic
            parts = rule.split()
            if parts:
                # First part is usually protocol
                if parts[0] not in ['any', 'host']:
                    acl.protocol = parts[0]
                    acl.proto = parts[0]
                
                # Enhanced parsing for different ACL formats
                if 'host' in rule:
                    # Handle host entries
                    host_matches = re.findall(r'host\s+(\S+)', rule)
                    if host_matches:
                        acl.source_ip = host_matches[0]
                        acl.source_mask = "255.255.255.255"
                        if len(host_matches) > 1:
                            acl.destination_ip = host_matches[1]
                            acl.destination_mask = "255.255.255.255"
                
                # Handle network/mask pairs
                ip_mask_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)', rule)
                if ip_mask_matches:
                    if len(ip_mask_matches) >= 1:
                        acl.source_ip = ip_mask_matches[0][0]
                        acl.source_mask = ip_mask_matches[0][1]
                    if len(ip_mask_matches) >= 2:
                        acl.destination_ip = ip_mask_matches[1][0]
                        acl.destination_mask = ip_mask_matches[1][1]
                
                # Handle port information
                port_match = re.search(r'eq\s+(\w+|\d+)', rule)
                if port_match:
                    acl.port = port_match.group(1)
                
                # Handle port ranges
                port_range_match = re.search(r'range\s+(\w+|\d+)\s+(\w+|\d+)', rule)
                if port_range_match:
                    acl.port = f"{port_range_match.group(1)}-{port_range_match.group(2)}"
                
                # Check for logging
                if 'log' in rule.lower():
                    acl.log = "yes"
                
                # Handle 'any' entries
                if 'any' in parts:
                    if not acl.source_ip:
                        acl.source_ip = "any"
                    if not acl.destination_ip and parts.count('any') > 1:
                        acl.destination_ip = "any"
            
            return acl
            
        except Exception as e:
            self.logger.error(f"Error parsing ACL rule: {e}")
            return None
    
    def _parse_static_routes(self, content: str):
        """Parse static route configurations with enhanced field extraction."""
        try:
            # Enhanced route pattern to capture more fields
            route_matches = re.finditer(
                r'ip route (?:vrf\s+(\S+)\s+)?(\S+) (\S+) (\S+)(?:\s+(\d+))?(?:\s+name\s+(\S+))?(?:\s+tag\s+(\d+))?',
                content, re.IGNORECASE
            )
            
            for match in route_matches:
                vrf = match.group(1) or ""
                destination = match.group(2)
                mask = match.group(3)
                next_hop = match.group(4)
                admin_distance = match.group(5) or ""
                name = match.group(6) or ""
                tag = match.group(7) or ""
                
                # Convert mask to prefix length if needed
                prefix_length = self._mask_to_prefix_length(mask)
                
                # Determine if next_hop is an interface or IP
                interface = ""
                if not re.match(r'\d+\.\d+\.\d+\.\d+', next_hop):
                    interface = next_hop
                    next_hop = ""
                
                route = StaticRoute(
                    device_id=self.current_device_id,
                    destination=destination,
                    prefix_length=str(prefix_length) if prefix_length else "",
                    next_hop=next_hop,
                    interface=interface,
                    metric="",
                    route_type="static",
                    vrf=vrf,
                    distance=admin_distance,
                    source_file=self.current_source_file,
                    # Enhanced fields
                    admin_distance=admin_distance,
                    subnet_mask=mask,
                    tag=tag,
                    description=name if name else f"Static route to {destination}"
                )
                
                self.parsed_data.add_static_route(route)
            
            # Parse IPv6 static routes
            ipv6_route_matches = re.finditer(
                r'ipv6 route (?:vrf\s+(\S+)\s+)?(\S+/\d+) (\S+)(?:\s+(\d+))?(?:\s+name\s+(\S+))?',
                content, re.IGNORECASE
            )
            
            for match in ipv6_route_matches:
                vrf = match.group(1) or ""
                destination = match.group(2)
                next_hop = match.group(3)
                admin_distance = match.group(4) or ""
                name = match.group(5) or ""
                
                # Extract prefix length from destination
                prefix_length = ""
                if '/' in destination:
                    dest_parts = destination.split('/')
                    destination = dest_parts[0]
                    prefix_length = dest_parts[1]
                
                route = StaticRoute(
                    device_id=self.current_device_id,
                    destination=destination,
                    prefix_length=prefix_length,
                    next_hop=next_hop,
                    route_type="static_ipv6",
                    vrf=vrf,
                    distance=admin_distance,
                    source_file=self.current_source_file,
                    # Enhanced fields
                    admin_distance=admin_distance,
                    description=name if name else f"IPv6 static route to {destination}"
                )
                
                self.parsed_data.add_static_route(route)
                
            self.logger.debug(f"Parsed {len(self.parsed_data.routing_static)} static routes")
            
        except Exception as e:
            self.logger.error(f"Error parsing static routes: {e}")
    
    def _mask_to_prefix_length(self, mask: str) -> Optional[int]:
        """Convert subnet mask to prefix length."""
        try:
            # Handle CIDR notation
            if mask.startswith('/'):
                return int(mask[1:])
            
            # Handle dotted decimal masks
            if '.' in mask:
                import ipaddress
                return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
            
            return None
        except:
            return None
    
    def _parse_dynamic_routing(self, content: str):
        """Parse dynamic routing configurations."""
        try:
            # Parse BGP configuration
            bgp_match = re.search(r'router bgp (\d+)\s*$\n((?:(?!\n\w).*\n?)*)', 
                                content, re.MULTILINE | re.IGNORECASE)
            
            if bgp_match:
                as_number = bgp_match.group(1)
                bgp_config = bgp_match.group(2)
                
                # Parse BGP neighbors
                neighbor_matches = re.finditer(r'neighbor (\S+) remote-as (\d+)', 
                                             bgp_config, re.IGNORECASE)
                
                for neighbor_match in neighbor_matches:
                    neighbor_ip = neighbor_match.group(1)
                    remote_as = neighbor_match.group(2)
                    
                    routing = DynamicRouting(
                        device_id=self.current_device_id,
                        neighbor_ip=neighbor_ip,
                        remote_as=remote_as,
                        protocol="bgp",
                        process_id=as_number,
                        source_file=self.current_source_file
                    )
                    
                    self.parsed_data.add_dynamic_routing(routing)
            
            # Parse OSPF configuration
            ospf_match = re.search(r'router ospf (\d+)\s*$\n((?:(?!\n\w).*\n?)*)', 
                                 content, re.MULTILINE | re.IGNORECASE)
            
            if ospf_match:
                process_id = ospf_match.group(1)
                ospf_config = ospf_match.group(2)
                
                # Parse router ID
                router_id_match = re.search(r'router-id (\S+)', ospf_config, re.IGNORECASE)
                router_id = router_id_match.group(1) if router_id_match else ""
                
                routing = DynamicRouting(
                    device_id=self.current_device_id,
                    neighbor_ip="",
                    protocol="ospf",
                    process_id=process_id,
                    router_id=router_id,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_dynamic_routing(routing)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.routing_dynamic)} routing entries")
            
        except Exception as e:
            self.logger.error(f"Error parsing dynamic routing: {e}")
    
    def _parse_ntp_servers(self, content: str):
        """Parse NTP server configurations with enhanced field extraction."""
        try:
            # Enhanced NTP pattern to capture more fields
            ntp_matches = re.finditer(
                r'ntp server (?:vrf\s+(\S+)\s+)?(\S+)(?:\s+version\s+(\d+))?(?:\s+source\s+(\S+))?(?:\s+(prefer))?(?:\s+key\s+(\d+))?',
                content, re.IGNORECASE
            )
            
            for match in ntp_matches:
                vrf = match.group(1) or ""
                server_ip = match.group(2)
                version = match.group(3) or ""
                source_interface = match.group(4) or ""
                prefer = "yes" if match.group(5) else "no"
                key_id = match.group(6) or ""
                
                # Check for authentication
                auth_enabled = "yes" if key_id else "no"
                
                ntp_server = NTPServer(
                    device_id=self.current_device_id,
                    ntp_server=server_ip,
                    prefer_flag=prefer,
                    key_id=key_id,
                    source_file=self.current_source_file,
                    # Enhanced fields
                    version=version,
                    source_interface=source_interface,
                    prefer=prefer,
                    authentication_enabled=auth_enabled,
                    vrf=vrf,
                    description=f"NTP server {server_ip}"
                )
                
                self.parsed_data.add_ntp(ntp_server)
            
            # Parse NTP authentication keys
            ntp_key_matches = re.finditer(
                r'ntp authentication-key (\d+) md5 (\S+)',
                content, re.IGNORECASE
            )
            
            ntp_keys = {}
            for match in ntp_key_matches:
                key_id = match.group(1)
                key_value = match.group(2)
                ntp_keys[key_id] = key_value
            
            # Update NTP servers with key information
            for ntp_server in self.parsed_data.ntp:
                if ntp_server.key_id in ntp_keys:
                    ntp_server.authentication_enabled = "yes"
                    ntp_server.description += f" (Auth Key: {ntp_server.key_id})"
            
            # Parse NTP peer configurations
            ntp_peer_matches = re.finditer(
                r'ntp peer (?:vrf\s+(\S+)\s+)?(\S+)(?:\s+version\s+(\d+))?(?:\s+source\s+(\S+))?(?:\s+key\s+(\d+))?',
                content, re.IGNORECASE
            )
            
            for match in ntp_peer_matches:
                vrf = match.group(1) or ""
                server_ip = match.group(2)
                version = match.group(3) or ""
                source_interface = match.group(4) or ""
                key_id = match.group(5) or ""
                
                auth_enabled = "yes" if key_id else "no"
                
                ntp_server = NTPServer(
                    device_id=self.current_device_id,
                    ntp_server=server_ip,
                    key_id=key_id,
                    source_file=self.current_source_file,
                    # Enhanced fields
                    version=version,
                    source_interface=source_interface,
                    authentication_enabled=auth_enabled,
                    vrf=vrf,
                    description=f"NTP peer {server_ip}"
                )
                
                self.parsed_data.add_ntp(ntp_server)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.ntp)} NTP servers")
            
        except Exception as e:
            self.logger.error(f"Error parsing NTP servers: {e}")
    
    def _parse_aaa_servers(self, content: str):
        """Parse AAA server configurations."""
        try:
            # Parse TACACS servers
            tacacs_matches = re.finditer(
                r'tacacs-server host (\S+)(?:\s+key\s+\d*\s+"?([^"\n]+)"?)?',
                content, re.IGNORECASE
            )
            
            for match in tacacs_matches:
                server_ip = match.group(1)
                key = match.group(2) or ""
                
                aaa_server = AAAServer(
                    device_id=self.current_device_id,
                    server_type="tacacs+",
                    server_ip=server_ip,
                    key_hash=key,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_aaa_server(aaa_server)
            
            # Parse RADIUS servers
            radius_matches = re.finditer(
                r'radius-server host (\S+)(?:\s+key\s+\d*\s+"?([^"\n]+)"?)?',
                content, re.IGNORECASE
            )
            
            for match in radius_matches:
                server_ip = match.group(1)
                key = match.group(2) or ""
                
                aaa_server = AAAServer(
                    device_id=self.current_device_id,
                    server_type="radius",
                    server_ip=server_ip,
                    key_hash=key,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_aaa_server(aaa_server)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.aaa_servers)} AAA servers")
            
        except Exception as e:
            self.logger.error(f"Error parsing AAA servers: {e}")
    
    def _parse_snmp_config(self, content: str):
        """Parse SNMP configuration with enhanced field extraction."""
        try:
            # Parse SNMP communities with enhanced information
            community_matches = re.finditer(
                r'snmp-server community (\S+)(?:\s+(ro|rw))?(?:\s+(\d+))?(?:\s+access\s+(\S+))?',
                content, re.IGNORECASE
            )
            
            for match in community_matches:
                community = match.group(1)
                access_level = match.group(2) or "ro"
                acl = match.group(4) or ""
                
                snmp = SNMPConfig(
                    device_id=self.current_device_id,
                    version="v2c",
                    community_or_user=community,
                    auth_level=access_level,
                    acl_applied=acl,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_snmp(snmp)
            
            # Parse SNMP v3 users
            v3_user_matches = re.finditer(
                r'snmp-server user (\S+) (\S+)(?:\s+remote\s+(\S+))?(?:\s+v3\s+(\S+))?(?:\s+(\S+))?',
                content, re.IGNORECASE
            )
            
            for match in v3_user_matches:
                username = match.group(1)
                group = match.group(2)
                remote_host = match.group(3) or ""
                auth_level = match.group(4) or "noauth"
                
                snmp = SNMPConfig(
                    device_id=self.current_device_id,
                    version="v3",
                    community_or_user=username,
                    auth_level=auth_level,
                    target_host=remote_host,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_snmp(snmp)
            
            # Parse SNMP hosts (trap targets)
            host_matches = re.finditer(
                r'snmp-server host (\S+)(?:\s+(?:version\s+(\S+))?(?:\s+(\S+))?)?(?:\s+(.+))?',
                content, re.IGNORECASE
            )
            
            for match in host_matches:
                host_ip = match.group(1)
                version = match.group(2) or "2c"
                community = match.group(3) or ""
                traps = match.group(4) or ""
                
                snmp = SNMPConfig(
                    device_id=self.current_device_id,
                    version=version,
                    community_or_user=community,
                    target_host=host_ip,
                    trap_enable="yes",
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_snmp(snmp)
            
            # Parse SNMP location
            location_match = re.search(r'snmp-server location (.+)', content, re.IGNORECASE)
            location = location_match.group(1).strip() if location_match else ""
            
            # Parse SNMP contact
            contact_match = re.search(r'snmp-server contact (.+)', content, re.IGNORECASE)
            contact = contact_match.group(1).strip() if contact_match else ""
            
            # Parse SNMP source interface
            source_match = re.search(r'snmp-server source-interface\s+(?:traps\s+)?(\S+)', content, re.IGNORECASE)
            source_interface = source_match.group(1) if source_match else ""
            
            # Update all SNMP configs with global settings
            for snmp_config in self.parsed_data.snmp:
                if location and not snmp_config.location:
                    snmp_config.location = location
                if contact and not snmp_config.contact:
                    snmp_config.contact = contact
                if source_interface and not snmp_config.source_interface:
                    snmp_config.source_interface = source_interface
            
            # If we found global settings but no specific configs, create a general entry
            if (location or contact or source_interface) and not self.parsed_data.snmp:
                general_snmp = SNMPConfig(
                    device_id=self.current_device_id,
                    version="",
                    location=location,
                    contact=contact,
                    source_interface=source_interface,
                    source_file=self.current_source_file
                )
                self.parsed_data.add_snmp(general_snmp)
            
            # Parse SNMP enable traps
            trap_matches = re.finditer(
                r'snmp-server enable traps (.+)',
                content, re.IGNORECASE
            )
            
            trap_types = []
            for match in trap_matches:
                trap_types.append(match.group(1).strip())
            
            if trap_types:
                for snmp_config in self.parsed_data.snmp:
                    if not snmp_config.trap_enable:
                        snmp_config.trap_enable = "yes"
            
            self.logger.debug(f"Parsed {len(self.parsed_data.snmp)} SNMP configurations")
            
        except Exception as e:
            self.logger.error(f"Error parsing SNMP config: {e}")
    
    def _parse_local_users(self, content: str):
        """Parse local user configurations with enhanced field extraction."""
        try:
            # Enhanced user pattern to capture more fields
            user_matches = re.finditer(
                r'username\s+(\S+)(?:\s+(privilege\s+\d+|password\s+\d+\s+\S+|secret\s+\d+\s+\S+|role\s+\S+|view\s+\S+))*',
                content, re.IGNORECASE | re.MULTILINE
            )
            
            for match in user_matches:
                username = match.group(1)
                user_config = match.group(0)
                
                # Extract privilege level
                privilege_match = re.search(r'privilege\s+(\d+)', user_config, re.IGNORECASE)
                privilege = privilege_match.group(1) if privilege_match else ""
                
                # Extract password/secret hash
                password_match = re.search(r'(?:password|secret)\s+(\d+)\s+(\S+)', user_config, re.IGNORECASE)
                hash_type = ""
                password_hash = ""
                if password_match:
                    hash_type = password_match.group(1)
                    password_hash = password_match.group(2)
                
                # Extract role
                role_match = re.search(r'role\s+(\S+)', user_config, re.IGNORECASE)
                role = role_match.group(1) if role_match else ""
                
                # Extract view
                view_match = re.search(r'view\s+(\S+)', user_config, re.IGNORECASE)
                view = view_match.group(1) if view_match else ""
                
                # Determine status (assume active if configured)
                status = "active"
                
                user = LocalUser(
                    device_id=self.current_device_id,
                    username=username,
                    privilege=privilege,
                    hash_type=hash_type,
                    source_file=self.current_source_file,
                    # Enhanced fields
                    status=status,
                    hash=password_hash,
                    description=f"Local user {username}",
                    role=role if role else view
                )
                
                self.parsed_data.add_local_user(user)
            
            # Parse enable passwords/secrets
            enable_matches = re.finditer(
                r'enable\s+(?:password|secret)\s+(?:(\d+)\s+)?(\S+)',
                content, re.IGNORECASE
            )
            
            for match in enable_matches:
                hash_type = match.group(1) or "0"
                password_hash = match.group(2)
                
                enable_user = LocalUser(
                    device_id=self.current_device_id,
                    username="enable",
                    privilege="15",
                    hash_type=hash_type,
                    source_file=self.current_source_file,
                    # Enhanced fields
                    status="active",
                    hash=password_hash,
                    description="Enable password",
                    role="admin"
                )
                
                self.parsed_data.add_local_user(enable_user)
            
            # Parse console/vty password configurations
            console_matches = re.finditer(
                r'line (?:console|vty) \d+(?:\s+\d+)?\s*\n((?:(?!\nline|\n!).*\n?)*)',
                content, re.MULTILINE | re.IGNORECASE
            )
            
            for match in console_matches:
                line_config = match.group(1)
                
                # Extract login authentication method
                login_match = re.search(r'login(?:\s+(?:local|authentication\s+(\S+)))?', line_config, re.IGNORECASE)
                if login_match:
                    auth_method = login_match.group(1) if login_match.group(1) else "local"
                    
                    # Extract password if configured
                    password_match = re.search(r'password\s+(?:(\d+)\s+)?(\S+)', line_config, re.IGNORECASE)
                    if password_match:
                        hash_type = password_match.group(1) or "0"
                        password_hash = password_match.group(2)
                        
                        line_user = LocalUser(
                            device_id=self.current_device_id,
                            username=f"line_{auth_method}",
                            privilege="1",
                            hash_type=hash_type,
                            source_file=self.current_source_file,
                            # Enhanced fields
                            status="active",
                            hash=password_hash,
                            description=f"Line authentication ({auth_method})",
                            role="user"
                        )
                        
                        self.parsed_data.add_local_user(line_user)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.users_local)} local users")
            
        except Exception as e:
            self.logger.error(f"Error parsing local users: {e}")
    
    def _parse_logging_config(self, content: str):
        """Parse logging configurations."""
        try:
            logging_matches = re.finditer(
                r'logging (?:host\s+)?(\S+)(?:\s+(?:udp-port\s+)?(\d+))?',
                content, re.IGNORECASE
            )
            
            for match in logging_matches:
                dest_ip = match.group(1)
                port = match.group(2) or "514"
                
                # Skip local logging destinations
                if dest_ip.lower() in ['console', 'monitor', 'buffered']:
                    continue
                
                log_target = LogTarget(
                    device_id=self.current_device_id,
                    dest_ip=dest_ip,
                    proto="udp",
                    port=port,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_log_target(log_target)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.log_targets)} log targets")
            
        except Exception as e:
            self.logger.error(f"Error parsing logging config: {e}")
    
    def _parse_login_banners(self, content: str):
        """Parse login banner configurations."""
        try:
            # Parse MOTD banner
            motd_match = re.search(
                r'banner motd\s+(.)\s*(.*?)\s*\1',
                content, re.DOTALL | re.IGNORECASE
            )
            
            if motd_match:
                banner_text = motd_match.group(2).strip()
                
                banner = LoginBanner(
                    device_id=self.current_device_id,
                    banner_type="motd",
                    text=banner_text,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_login_banner(banner)
            
            # Parse login banner
            login_match = re.search(
                r'banner login\s+(.)\s*(.*?)\s*\1',
                content, re.DOTALL | re.IGNORECASE
            )
            
            if login_match:
                banner_text = login_match.group(2).strip()
                
                banner = LoginBanner(
                    device_id=self.current_device_id,
                    banner_type="login",
                    text=banner_text,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_login_banner(banner)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.login_banner)} login banners")
            
        except Exception as e:
            self.logger.error(f"Error parsing login banners: {e}")
    
    def _parse_feature_flags(self, content: str):
        """Parse feature flags and global settings."""
        try:
            features = FeatureFlags(
                device_id=self.current_device_id,
                source_file=self.current_source_file
            )
            
            # Check for spanning tree features
            if re.search(r'spanning-tree portfast default', content, re.IGNORECASE):
                features.portfast_default = "yes"
            
            if re.search(r'spanning-tree portfast bpduguard default', content, re.IGNORECASE):
                features.spanning_tree_bpduguard_default = "yes"
            
            # Check for DHCP snooping
            if re.search(r'ip dhcp snooping', content, re.IGNORECASE):
                features.dhcp_snoop_enabled = "yes"
            
            # Check for ARP inspection
            if re.search(r'ip arp inspection', content, re.IGNORECASE):
                features.arp_inspection_enabled = "yes"
            
            self.parsed_data.add_feature_flags(features)
            self.logger.debug("Parsed feature flags")
            
        except Exception as e:
            self.logger.error(f"Error parsing feature flags: {e}")
    
    def _parse_services(self, content: str):
        """Parse enabled services."""
        try:
            # Parse enabled services
            service_matches = re.finditer(r'^(?:no\s+)?service\s+(\S+)', content, re.MULTILINE | re.IGNORECASE)
            
            for match in service_matches:
                line = match.group(0)
                service_name = match.group(1)
                
                state = "disabled" if line.strip().startswith('no ') else "enabled"
                
                service = ServiceInventory(
                    device_id=self.current_device_id,
                    service_name=service_name,
                    state=state,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_service_inventory(service)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.service_inventory)} services")
            
        except Exception as e:
            self.logger.error(f"Error parsing services: {e}")

    def _parse_ospf_detailed(self, content: str):
        """Parse detailed OSPF configuration."""
        try:
            # Parse OSPF processes with detailed information
            ospf_matches = re.finditer(
                r'router ospf (\d+)(?:\s+vrf\s+(\S+))?\s*$\n((?:(?!\nrouter|\n!).*\n?)*)',
                content, re.MULTILINE | re.IGNORECASE
            )
            
            for match in ospf_matches:
                process_id = match.group(1)
                vrf = match.group(2) or ""
                ospf_config = match.group(3)
                
                # Parse router ID
                router_id_match = re.search(r'router-id (\S+)', ospf_config, re.IGNORECASE)
                router_id = router_id_match.group(1) if router_id_match else ""
                
                # Parse areas
                area_matches = re.finditer(r'area (\S+) (\S+)', ospf_config, re.IGNORECASE)
                areas = []
                for area_match in area_matches:
                    area_id = area_match.group(1)
                    area_type = area_match.group(2)
                    areas.append(f"{area_id}:{area_type}")
                
                # Parse network statements
                network_matches = re.finditer(r'network (\S+) (\S+) area (\S+)', ospf_config, re.IGNORECASE)
                networks = []
                for net_match in network_matches:
                    network = net_match.group(1)
                    wildcard = net_match.group(2)
                    area = net_match.group(3)
                    networks.append(f"{network}/{wildcard}@{area}")
                
                # Parse passive interfaces
                passive_matches = re.finditer(r'passive-interface (\S+)', ospf_config, re.IGNORECASE)
                passive_ints = [match.group(1) for match in passive_matches]
                
                # Parse redistributions
                redist_matches = re.finditer(r'redistribute (\S+)', ospf_config, re.IGNORECASE)
                redistributions = [match.group(1) for match in redist_matches]
                
                # Parse authentication
                auth_matches = re.finditer(r'area (\S+) authentication(?:\s+message-digest)?', ospf_config, re.IGNORECASE)
                auth_areas = []
                for auth_match in auth_matches:
                    area_id = auth_match.group(1)
                    auth_type = "md5" if "message-digest" in auth_match.group(0) else "plain"
                    auth_areas.append(f"{area_id}:{auth_type}")
                
                routing = DynamicRouting(
                    device_id=self.current_device_id,
                    protocol="ospf",
                    process_id=process_id,
                    router_id=router_id,
                    areas="; ".join(areas),
                    redistributions="; ".join(redistributions),
                    neighbor_ip="",  # OSPF neighbors are discovered dynamically
                    description=f"OSPF Process {process_id}" + (f" VRF {vrf}" if vrf else ""),
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_dynamic_routing(routing)
                
                # Create separate entries for each network
                for network in networks:
                    net_routing = DynamicRouting(
                        device_id=self.current_device_id,
                        protocol="ospf",
                        process_id=process_id,
                        router_id=router_id,
                        areas=network.split('@')[1],
                        description=f"OSPF Network {network.split('@')[0]}",
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_dynamic_routing(net_routing)
            
            self.logger.debug(f"Parsed detailed OSPF configurations")
            
        except Exception as e:
            self.logger.error(f"Error parsing detailed OSPF: {e}")

    def _parse_bgp_detailed(self, content: str):
        """Parse detailed BGP configuration."""
        try:
            # Parse BGP processes with detailed information
            bgp_matches = re.finditer(
                r'router bgp (\d+)\s*$\n((?:(?!\nrouter|\n!).*\n?)*)',
                content, re.MULTILINE | re.IGNORECASE
            )
            
            for match in bgp_matches:
                as_number = match.group(1)
                bgp_config = match.group(2)
                
                # Parse router ID
                router_id_match = re.search(r'bgp router-id (\S+)', bgp_config, re.IGNORECASE)
                router_id = router_id_match.group(1) if router_id_match else ""
                
                # Parse BGP neighbors with detailed information
                neighbor_matches = re.finditer(
                    r'neighbor (\S+) remote-as (\d+)', bgp_config, re.IGNORECASE
                )
                
                for neighbor_match in neighbor_matches:
                    neighbor_ip = neighbor_match.group(1)
                    remote_as = neighbor_match.group(2)
                    
                    # Extract neighbor-specific configuration
                    neighbor_config_pattern = f"neighbor {re.escape(neighbor_ip)} (.*?)(?=neighbor|$)"
                    neighbor_configs = re.findall(neighbor_config_pattern, bgp_config, re.IGNORECASE | re.DOTALL)
                    
                    description = ""
                    peer_group = ""
                    source_interface = ""
                    
                    for neighbor_config in neighbor_configs:
                        # Parse description
                        desc_match = re.search(r'description (.+)', neighbor_config, re.IGNORECASE)
                        if desc_match:
                            description = desc_match.group(1).strip()
                        
                        # Parse peer group
                        pg_match = re.search(r'peer-group (\S+)', neighbor_config, re.IGNORECASE)
                        if pg_match:
                            peer_group = pg_match.group(1)
                        
                        # Parse source interface
                        source_match = re.search(r'update-source (\S+)', neighbor_config, re.IGNORECASE)
                        if source_match:
                            source_interface = source_match.group(1)
                    
                    routing = DynamicRouting(
                        device_id=self.current_device_id,
                        neighbor_ip=neighbor_ip,
                        remote_as=remote_as,
                        protocol="bgp",
                        process_id=as_number,
                        router_id=router_id,
                        description=description or f"BGP Neighbor {neighbor_ip}",
                        peer_group=peer_group,
                        source_interface=source_interface,
                        source_file=self.current_source_file
                    )
                    
                    self.parsed_data.add_dynamic_routing(routing)
                
                # Parse redistributions
                redist_matches = re.finditer(r'redistribute (\S+)', bgp_config, re.IGNORECASE)
                redistributions = [match.group(1) for match in redist_matches]
                
                if redistributions:
                    redist_routing = DynamicRouting(
                        device_id=self.current_device_id,
                        protocol="bgp",
                        process_id=as_number,
                        router_id=router_id,
                        redistributions="; ".join(redistributions),
                        description=f"BGP AS {as_number} Redistributions",
                        source_file=self.current_source_file
                    )
                    self.parsed_data.add_dynamic_routing(redist_routing)
            
            self.logger.debug(f"Parsed detailed BGP configurations")
            
        except Exception as e:
            self.logger.error(f"Error parsing detailed BGP: {e}")

    def _parse_hsrp_vrrp(self, content: str):
        # Implementation of _parse_hsrp_vrrp method
        pass

    def _parse_spanning_tree(self, content: str):
        # Implementation of _parse_spanning_tree method
        pass

    def _parse_qos_policies(self, content: str):
        # Implementation of _parse_qos_policies method
        pass

    def _parse_multicast(self, content: str):
        # Implementation of _parse_multicast method
        pass

    def _parse_lag_portchannels(self, content: str):
        # Implementation of _parse_lag_portchannels method
        pass

    def _parse_syslog_servers(self, content: str):
        """Parse syslog server configurations."""
        try:
            # Parse syslog host configurations
            syslog_matches = re.finditer(
                r'logging host (\S+)(?:\s+transport\s+(\w+))?(?:\s+port\s+(\d+))?(?:\s+(?:facility\s+(\S+)|severity\s+(\S+)))?',
                content, re.IGNORECASE
            )
            
            for match in syslog_matches:
                dest_ip = match.group(1)
                proto = match.group(2) or "udp"
                port = match.group(3) or "514"
                facility = match.group(4) or ""
                severity = match.group(5) or ""
                
                log_target = LogTarget(
                    device_id=self.current_device_id,
                    dest_ip=dest_ip,
                    proto=proto,
                    port=port,
                    facility=facility,
                    severity_mask=severity,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_log_target(log_target)
            
            # Parse buffered logging settings
            buffer_matches = re.finditer(
                r'logging buffered (?:(\d+)\s+)?(\w+)?',
                content, re.IGNORECASE
            )
            
            for match in buffer_matches:
                buffer_size = match.group(1) or ""
                severity = match.group(2) or ""
                
                buffered_log = LogTarget(
                    device_id=self.current_device_id,
                    dest_ip="buffer",
                    buffered_size=buffer_size,
                    severity_mask=severity,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_log_target(buffered_log)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.log_targets)} syslog configurations")
            
        except Exception as e:
            self.logger.error(f"Error parsing syslog servers: {e}")

    def _parse_ha_status(self, content: str):
        # Implementation of _parse_ha_status method
        pass

    def _parse_dns_servers(self, content: str):
        """Parse DNS server configurations."""
        try:
            # Parse DNS servers (ip name-server)
            dns_matches = re.finditer(
                r'ip name-server (?:vrf\s+(\S+)\s+)?(\S+)',
                content, re.IGNORECASE
            )
            
            for match in dns_matches:
                vrf = match.group(1) or ""
                server_ip = match.group(2)
                
                dns_config = DNSConfig(
                    device_id=self.current_device_id,
                    dns_server=server_ip,
                    dns_type="primary",
                    vrf=vrf,
                    source_file=self.current_source_file
                )
                
                self.parsed_data.add_dns_config(dns_config)
            
            # Parse domain name
            domain_match = re.search(r'ip domain name (\S+)', content, re.IGNORECASE)
            domain_name = domain_match.group(1) if domain_match else ""
            
            # Parse domain lookup setting
            lookup_match = re.search(r'ip domain lookup', content, re.IGNORECASE)
            no_lookup_match = re.search(r'no ip domain lookup', content, re.IGNORECASE)
            
            lookup_enabled = "yes"
            if no_lookup_match:
                lookup_enabled = "no"
            elif not lookup_match:
                lookup_enabled = ""
            
            # Update DNS configs with domain information
            for dns_config in self.parsed_data.dns_configs:
                if domain_name and not dns_config.domain_name:
                    dns_config.domain_name = domain_name
                if lookup_enabled and not dns_config.lookup_enabled:
                    dns_config.lookup_enabled = lookup_enabled
            
            # If we have domain settings but no servers, create a general entry
            if (domain_name or lookup_enabled) and not self.parsed_data.dns_configs:
                general_dns = DNSConfig(
                    device_id=self.current_device_id,
                    dns_server="",
                    domain_name=domain_name,
                    lookup_enabled=lookup_enabled,
                    source_file=self.current_source_file
                )
                self.parsed_data.add_dns_config(general_dns)
            
            self.logger.debug(f"Parsed {len(self.parsed_data.dns_configs)} DNS configurations")
            
        except Exception as e:
            self.logger.error(f"Error parsing DNS servers: {e}") 