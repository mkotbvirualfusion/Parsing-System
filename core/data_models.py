"""
Data models and structures for the Network Configuration Parser.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import pandas as pd


@dataclass
class VendorInfo:
    """Information about detected vendor and OS."""
    vendor: str
    os_family: str
    os_version: Optional[str] = None
    model: Optional[str] = None
    confidence: float = 0.0
    detection_method: str = ""


@dataclass
class NetworkDevice:
    """Represents a network device with its configuration."""
    device_id: str
    hostname: str
    vendor: str
    model: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    serial_number: Optional[str] = None
    location: Optional[str] = None
    config_timestamp: Optional[str] = None
    source_file: str = ""


@dataclass
class Interface:
    """Represents a network interface."""
    device_id: str
    interface_name: str
    description: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    vlan: str = ""
    speed_mbps: str = ""
    duplex: str = ""
    admin_status: str = ""
    operational_status: str = ""
    mac_address: str = ""
    if_type: str = ""
    ip6_address: str = ""
    lldp_remote_sysname: str = ""
    port_security: str = ""
    bpdu_guard: str = ""
    root_guard: str = ""
    storm_control_pps: str = ""
    mtu: str = ""
    source_file: str = ""


@dataclass
class VLAN:
    """Represents a VLAN configuration."""
    device_id: str
    vlan_id: str
    vlan_name: str = ""
    description: str = ""
    state: str = ""
    mode: str = ""
    svi_ip: str = ""
    vrf_name: str = ""
    vrf_rd: str = ""
    active: str = ""
    source_file: str = ""


@dataclass
class ACLEntry:
    """Represents an ACL entry."""
    device_id: str
    acl_name: str
    acl_type: str = ""
    seq: str = ""
    action: str = ""
    proto: str = ""
    src: str = ""
    src_port: str = ""
    dst: str = ""
    dst_port: str = ""
    hitcnt: str = ""
    remarks: str = ""
    source_file: str = ""
    
    # Enhanced fields to match manual extraction schema
    seq_number: str = ""
    source_ip: str = ""
    source_mask: str = ""
    destination_ip: str = ""
    destination_mask: str = ""
    protocol: str = ""
    port: str = ""
    log: str = ""
    description: str = ""
    direction: str = ""


@dataclass
class StaticRoute:
    """Represents a static route."""
    device_id: str
    destination: str
    prefix_length: str = ""
    next_hop: str = ""
    interface: str = ""
    metric: str = ""
    route_type: str = ""
    vrf: str = ""
    distance: str = ""
    source_file: str = ""
    
    # Enhanced fields to match manual extraction schema
    admin_distance: str = ""
    subnet_mask: str = ""
    tag: str = ""
    description: str = ""


@dataclass
class DynamicRouting:
    """Represents dynamic routing information."""
    device_id: str
    neighbor_ip: str
    remote_as: str = ""
    description: str = ""
    peer_group: str = ""
    source_interface: str = ""
    protocol: str = ""
    process_id: str = ""
    router_id: str = ""
    areas: str = ""
    redistributions: str = ""
    source_file: str = ""


@dataclass
class NTPServer:
    """Represents NTP server configuration."""
    device_id: str
    ntp_server: str
    prefer_flag: str = ""
    key_id: str = ""
    auth_state: str = ""
    reachability: str = ""
    source_file: str = ""
    
    # Enhanced fields to match manual extraction schema
    version: str = ""
    source_interface: str = ""
    prefer: str = ""
    authentication_enabled: str = ""
    vrf: str = ""
    description: str = ""


@dataclass
class AAAServer:
    """Represents AAA server configuration."""
    device_id: str
    server_type: str
    server_ip: str
    vrf: str = ""
    key_hash: str = ""
    timeout_sec: str = ""
    server_group: str = ""
    accounting_enabled: str = ""
    source_file: str = ""
    
    # Enhanced fields to match manual extraction schema
    description: str = ""


@dataclass
class SNMPConfig:
    """Represents SNMP configuration."""
    device_id: str
    version: str
    community_or_user: str = ""
    auth_level: str = ""
    view: str = ""
    target_host: str = ""
    acl_applied: str = ""
    trap_enable: str = ""
    source_file: str = ""
    
    # Enhanced fields to match manual extraction schema
    location: str = ""
    source_interface: str = ""
    contact: str = ""


@dataclass
class LocalUser:
    """Represents local user configuration."""
    device_id: str
    username: str
    privilege: str = ""
    hash_type: str = ""
    last_pw_change: str = ""
    password_lifetime_days: str = ""
    source_file: str = ""
    
    # Enhanced fields to match manual extraction schema
    status: str = ""
    hash: str = ""
    description: str = ""
    role: str = ""


@dataclass
class LogTarget:
    """Represents logging target configuration."""
    device_id: str
    dest_ip: str
    proto: str = ""
    port: str = ""
    severity_mask: str = ""
    facility: str = ""
    buffered_size: str = ""
    source_file: str = ""


@dataclass
class CryptoTLS:
    """Represents crypto/TLS certificate configuration."""
    device_id: str
    cert_name: str
    usage: str = ""
    subject_cn: str = ""
    issuer_cn: str = ""
    expiry_date: str = ""
    key_bits: str = ""
    sha256_fingerprint: str = ""
    source_file: str = ""


@dataclass
class FeatureFlags:
    """Represents device feature flags."""
    device_id: str
    dhcp_snoop_enabled: str = ""
    arp_inspection_enabled: str = ""
    ipsg_enabled: str = ""
    portfast_default: str = ""
    spanning_tree_bpduguard_default: str = ""
    source_file: str = ""
    
    # Enhanced fields to match manual extraction schema
    description: str = ""
    status: str = ""
    feature_name: str = ""


@dataclass
class FirmwareInventory:
    """Represents firmware inventory information."""
    device_id: str
    boot_image: str = ""
    file_md5: str = ""
    release_date: str = ""
    secure_boot_enabled: str = ""
    image_signature_ok: str = ""
    component: str = ""
    current_version: str = ""
    backup_version: str = ""
    running_image: str = ""
    fallback_image: str = ""
    source_file: str = ""


@dataclass
class HAStatus:
    """Represents high availability status."""
    device_id: str
    ha_role: str = ""
    peer_id: str = ""
    sync_state: str = ""
    failover_timer: str = ""
    last_failover_ts: str = ""
    source_file: str = ""


@dataclass
class NATRule:
    """Represents NAT rule configuration."""
    device_id: str
    rule_id: str
    nat_type: str = ""
    orig_src: str = ""
    orig_dst: str = ""
    orig_svc: str = ""
    trans_src: str = ""
    trans_dst: str = ""
    trans_svc: str = ""
    zone_in: str = ""
    zone_out: str = ""
    action: str = ""
    hitcnt: str = ""
    source_file: str = ""


@dataclass
class ServiceInventory:
    """Represents network service inventory."""
    device_id: str
    service_name: str
    state: str = ""
    vrf: str = ""
    cipher_suite: str = ""
    tcp_keepalive: str = ""
    source_file: str = ""


@dataclass
class VPNTunnel:
    """Represents VPN tunnel configuration."""
    device_id: str
    tunnel_id: str
    peer_ip: str = ""
    mode: str = ""
    ike_policy: str = ""
    pfs_group: str = ""
    life_sec: str = ""
    state: str = ""
    bytes_in: str = ""
    bytes_out: str = ""
    source_file: str = ""


@dataclass
class Zone:
    """Represents security zone configuration."""
    device_id: str
    zone_name: str
    interfaces_list: str = ""
    inspection_profile: str = ""
    source_file: str = ""


@dataclass
class LoginBanner:
    """Represents login banner configuration."""
    device_id: str
    banner_type: str
    text: str = ""
    source_file: str = ""


@dataclass
class HSRPVRRPGroup:
    """Represents HSRP/VRRP group configuration."""
    device_id: str
    interface: str
    group_id: str
    protocol: str = ""  # hsrp_v1, hsrp_v2, vrrp
    virtual_ip: str = ""
    priority: str = ""
    preempt: str = ""
    track_interface: str = ""
    track_object: str = ""
    authentication_type: str = ""
    authentication_key: str = ""
    timers_hello: str = ""
    timers_hold: str = ""
    status: str = ""
    source_file: str = ""


@dataclass
class DNSConfig:
    """Represents DNS server configuration."""
    device_id: str
    dns_server: str
    domain_name: str = ""
    dns_type: str = ""  # primary, secondary, forwarder
    vrf: str = ""
    lookup_enabled: str = ""
    source_interface: str = ""
    source_file: str = ""


class ParsedData:
    """Container for all parsed configuration data."""
    
    def __init__(self):
        self.devices: List[NetworkDevice] = []
        self.interfaces: List[Interface] = []
        self.vlans_vrfs: List[VLAN] = []
        self.acls: List[ACLEntry] = []
        self.routing_static: List[StaticRoute] = []
        self.routing_dynamic: List[DynamicRouting] = []
        self.ntp: List[NTPServer] = []
        self.aaa_servers: List[AAAServer] = []
        self.snmp: List[SNMPConfig] = []
        self.users_local: List[LocalUser] = []
        self.log_targets: List[LogTarget] = []
        self.crypto_tls: List[CryptoTLS] = []
        self.feature_flags: List[FeatureFlags] = []
        self.firmware_inventory: List[FirmwareInventory] = []
        self.ha_status: List[HAStatus] = []
        self.nat_rules: List[NATRule] = []
        self.service_inventory: List[ServiceInventory] = []
        self.vpn_tunnels: List[VPNTunnel] = []
        self.zones: List[Zone] = []
        self.login_banner: List[LoginBanner] = []
        self.hsrp_vrrp_groups: List[HSRPVRRPGroup] = []
        self.dns_configs: List[DNSConfig] = []
    
    def add_device(self, device: NetworkDevice):
        """Add a device to the parsed data, avoiding duplicates."""
        # Check if device already exists based on device_id
        existing_device = None
        for existing in self.devices:
            if existing.device_id == device.device_id:
                existing_device = existing
                break
        
        if existing_device:
            # Update existing device with new information if more complete
            if device.hostname and not existing_device.hostname:
                existing_device.hostname = device.hostname
            if device.model and not existing_device.model:
                existing_device.model = device.model
            if device.os_version and not existing_device.os_version:
                existing_device.os_version = device.os_version
            if device.serial_number and not existing_device.serial_number:
                existing_device.serial_number = device.serial_number
            if device.location and not existing_device.location:
                existing_device.location = device.location
            if device.config_timestamp and not existing_device.config_timestamp:
                existing_device.config_timestamp = device.config_timestamp
            # Always append source file information
            if device.source_file not in existing_device.source_file:
                existing_device.source_file += f"; {device.source_file}"
        else:
            # Add new device
            self.devices.append(device)
    
    def add_interface(self, interface: Interface):
        """Add an interface to the parsed data."""
        self.interfaces.append(interface)
    
    def add_vlan(self, vlan: VLAN):
        """Add a VLAN to the parsed data."""
        self.vlans_vrfs.append(vlan)
    
    def add_acl(self, acl: ACLEntry):
        """Add an ACL entry to the parsed data."""
        self.acls.append(acl)
    
    def add_static_route(self, route: StaticRoute):
        """Add a static route to the parsed data."""
        self.routing_static.append(route)
    
    def add_dynamic_routing(self, routing: DynamicRouting):
        """Add dynamic routing info to the parsed data."""
        self.routing_dynamic.append(routing)
    
    def add_ntp(self, ntp: NTPServer):
        """Add NTP server to the parsed data."""
        self.ntp.append(ntp)
    
    def add_aaa_server(self, aaa: AAAServer):
        """Add AAA server to the parsed data."""
        self.aaa_servers.append(aaa)
    
    def add_snmp(self, snmp: SNMPConfig):
        """Add SNMP config to the parsed data."""
        self.snmp.append(snmp)
    
    def add_local_user(self, user: LocalUser):
        """Add local user to the parsed data."""
        self.users_local.append(user)
    
    def add_log_target(self, log_target: LogTarget):
        """Add log target to the parsed data."""
        self.log_targets.append(log_target)
    
    def add_crypto_tls(self, crypto: CryptoTLS):
        """Add crypto/TLS config to the parsed data."""
        self.crypto_tls.append(crypto)
    
    def add_feature_flags(self, features: FeatureFlags):
        """Add feature flags to the parsed data."""
        self.feature_flags.append(features)
    
    def add_firmware_inventory(self, firmware: FirmwareInventory):
        """Add firmware inventory to the parsed data."""
        self.firmware_inventory.append(firmware)
    
    def add_ha_status(self, ha: HAStatus):
        """Add HA status to the parsed data."""
        self.ha_status.append(ha)
    
    def add_nat_rule(self, nat: NATRule):
        """Add NAT rule to the parsed data."""
        self.nat_rules.append(nat)
    
    def add_service_inventory(self, service: ServiceInventory):
        """Add service inventory to the parsed data."""
        self.service_inventory.append(service)
    
    def add_vpn_tunnel(self, vpn: VPNTunnel):
        """Add VPN tunnel to the parsed data."""
        self.vpn_tunnels.append(vpn)
    
    def add_zone(self, zone: Zone):
        """Add security zone to the parsed data."""
        self.zones.append(zone)
    
    def add_login_banner(self, banner: LoginBanner):
        """Add login banner to the parsed data."""
        self.login_banner.append(banner)
    
    def add_hsrp_vrrp_group(self, group: HSRPVRRPGroup):
        """Add HSRP/VRRP group to the parsed data."""
        self.hsrp_vrrp_groups.append(group)
    
    def add_dns_config(self, config: DNSConfig):
        """Add DNS config to the parsed data."""
        self.dns_configs.append(config)
    
    def to_dataframes(self) -> Dict[str, pd.DataFrame]:
        """Convert all parsed data to pandas DataFrames."""
        dataframes = {}
        
        # Convert each data type to DataFrame
        if self.devices:
            dataframes['devices'] = pd.DataFrame([vars(d) for d in self.devices])
        
        if self.interfaces:
            dataframes['interfaces'] = pd.DataFrame([vars(i) for i in self.interfaces])
        
        if self.vlans_vrfs:
            dataframes['vlans_vrfs'] = pd.DataFrame([vars(v) for v in self.vlans_vrfs])
        
        if self.acls:
            dataframes['acls'] = pd.DataFrame([vars(a) for a in self.acls])
        
        if self.routing_static:
            dataframes['routing_static'] = pd.DataFrame([vars(r) for r in self.routing_static])
        
        if self.routing_dynamic:
            dataframes['routing_dynamic'] = pd.DataFrame([vars(r) for r in self.routing_dynamic])
        
        if self.ntp:
            dataframes['ntp'] = pd.DataFrame([vars(n) for n in self.ntp])
        
        if self.aaa_servers:
            dataframes['aaa_servers'] = pd.DataFrame([vars(a) for a in self.aaa_servers])
        
        if self.snmp:
            dataframes['snmp'] = pd.DataFrame([vars(s) for s in self.snmp])
        
        if self.users_local:
            dataframes['users_local'] = pd.DataFrame([vars(u) for u in self.users_local])
        
        if self.log_targets:
            dataframes['log_targets'] = pd.DataFrame([vars(l) for l in self.log_targets])
        
        if self.crypto_tls:
            dataframes['crypto_tls'] = pd.DataFrame([vars(c) for c in self.crypto_tls])
        
        if self.feature_flags:
            dataframes['feature_flags'] = pd.DataFrame([vars(f) for f in self.feature_flags])
        
        if self.firmware_inventory:
            dataframes['firmware_inventory'] = pd.DataFrame([vars(f) for f in self.firmware_inventory])
        
        if self.ha_status:
            dataframes['ha_status'] = pd.DataFrame([vars(h) for h in self.ha_status])
        
        if self.nat_rules:
            dataframes['nat_rules'] = pd.DataFrame([vars(n) for n in self.nat_rules])
        
        if self.service_inventory:
            dataframes['service_inventory'] = pd.DataFrame([vars(s) for s in self.service_inventory])
        
        if self.vpn_tunnels:
            dataframes['vpn_tunnels'] = pd.DataFrame([vars(v) for v in self.vpn_tunnels])
        
        if self.zones:
            dataframes['zones'] = pd.DataFrame([vars(z) for z in self.zones])
        
        if self.login_banner:
            dataframes['login_banner'] = pd.DataFrame([vars(b) for b in self.login_banner])
        
        if self.hsrp_vrrp_groups:
            dataframes['hsrp_vrrp_groups'] = pd.DataFrame([vars(g) for g in self.hsrp_vrrp_groups])
        
        if self.dns_configs:
            dataframes['dns_configs'] = pd.DataFrame([vars(c) for c in self.dns_configs])
        
        return dataframes
    
    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about parsed data."""
        return {
            'devices': len(self.devices),
            'interfaces': len(self.interfaces),
            'vlans_vrfs': len(self.vlans_vrfs),
            'acls': len(self.acls),
            'routing_static': len(self.routing_static),
            'routing_dynamic': len(self.routing_dynamic),
            'ntp': len(self.ntp),
            'aaa_servers': len(self.aaa_servers),
            'snmp': len(self.snmp),
            'users_local': len(self.users_local),
            'log_targets': len(self.log_targets),
            'crypto_tls': len(self.crypto_tls),
            'feature_flags': len(self.feature_flags),
            'firmware_inventory': len(self.firmware_inventory),
            'ha_status': len(self.ha_status),
            'nat_rules': len(self.nat_rules),
            'service_inventory': len(self.service_inventory),
            'vpn_tunnels': len(self.vpn_tunnels),
            'zones': len(self.zones),
            'login_banner': len(self.login_banner),
            'hsrp_vrrp_groups': len(self.hsrp_vrrp_groups),
            'dns_configs': len(self.dns_configs)
        } 