"""
Data Normalizer for the Network Configuration Parser.
Handles data cleaning, normalization, and standardization.
"""

import re
import logging
from typing import Dict, List, Any, Optional, Union
import pandas as pd
from utils.helpers import (
    clean_string, parse_ip_address, format_mac_address, 
    normalize_interface_name, parse_subnet_mask
)


class DataNormalizer:
    """Normalizes and cleans parsed configuration data."""
    
    def __init__(self):
        """Initialize the data normalizer."""
        self.logger = logging.getLogger(__name__)
        
        # Normalization rules for different data types
        self.normalization_rules = {
            'ip_address': self._normalize_ip_address,
            'mac_address': self._normalize_mac_address,
            'interface_name': self._normalize_interface_name,
            'subnet_mask': self._normalize_subnet_mask,
            'boolean': self._normalize_boolean,
            'numeric': self._normalize_numeric,
            'text': self._normalize_text,
            'port': self._normalize_port,
            'protocol': self._normalize_protocol,
            'action': self._normalize_action,
            'state': self._normalize_state
        }
        
        # Field type mappings for each CSV schema
        self.field_types = {
            'devices': {
                'device_id': 'text',
                'hostname': 'text',
                'vendor': 'text',
                'model': 'text',
                'os_family': 'text',
                'os_version': 'text',
                'serial_number': 'text',
                'location': 'text',
                'config_timestamp': 'text',
                'source_file': 'text'
            },
            'interfaces': {
                'device_id': 'text',
                'interface_name': 'interface_name',
                'description': 'text',
                'ip_address': 'ip_address',
                'subnet_mask': 'subnet_mask',
                'vlan': 'numeric',
                'speed_mbps': 'numeric',
                'duplex': 'text',
                'admin_status': 'state',
                'operational_status': 'state',
                'mac_address': 'mac_address',
                'if_type': 'text',
                'ip6_address': 'ip_address',
                'lldp_remote_sysname': 'text',
                'port_security': 'boolean',
                'bpdu_guard': 'boolean',
                'root_guard': 'boolean',
                'storm_control_pps': 'numeric',
                'mtu': 'numeric',
                'source_file': 'text'
            },
            'vlans_vrfs': {
                'device_id': 'text',
                'vlan_id': 'numeric',
                'vlan_name': 'text',
                'description': 'text',
                'state': 'state',
                'mode': 'text',
                'svi_ip': 'ip_address',
                'vrf_name': 'text',
                'vrf_rd': 'text',
                'active': 'boolean',
                'source_file': 'text'
            },
            'acls': {
                'device_id': 'text',
                'acl_name': 'text',
                'acl_type': 'text',
                'seq': 'numeric',
                'action': 'action',
                'proto': 'protocol',
                'src': 'text',
                'src_port': 'port',
                'dst': 'text',
                'dst_port': 'port',
                'hitcnt': 'numeric',
                'remarks': 'text',
                'source_file': 'text'
            },
            'routing_static': {
                'device_id': 'text',
                'destination': 'ip_address',
                'prefix_length': 'numeric',
                'next_hop': 'ip_address',
                'interface': 'interface_name',
                'metric': 'numeric',
                'route_type': 'text',
                'vrf': 'text',
                'distance': 'numeric',
                'source_file': 'text'
            },
            'routing_dynamic': {
                'device_id': 'text',
                'neighbor_ip': 'ip_address',
                'remote_as': 'numeric',
                'description': 'text',
                'peer_group': 'text',
                'source_interface': 'interface_name',
                'protocol': 'protocol',
                'process_id': 'numeric',
                'router_id': 'ip_address',
                'areas': 'text',
                'redistributions': 'text',
                'source_file': 'text'
            },
            'ntp': {
                'device_id': 'text',
                'ntp_server': 'ip_address',
                'prefer_flag': 'boolean',
                'key_id': 'numeric',
                'auth_state': 'state',
                'reachability': 'state',
                'source_file': 'text'
            },
            'aaa_servers': {
                'device_id': 'text',
                'server_type': 'text',
                'server_ip': 'ip_address',
                'vrf': 'text',
                'key_hash': 'text',
                'timeout_sec': 'numeric',
                'server_group': 'text',
                'accounting_enabled': 'boolean',
                'source_file': 'text'
            },
            'snmp': {
                'device_id': 'text',
                'version': 'text',
                'community_or_user': 'text',
                'auth_level': 'text',
                'view': 'text',
                'target_host': 'ip_address',
                'acl_applied': 'text',
                'trap_enable': 'boolean',
                'source_file': 'text'
            },
            'users_local': {
                'device_id': 'text',
                'username': 'text',
                'privilege': 'numeric',
                'hash_type': 'text',
                'last_pw_change': 'text',
                'password_lifetime_days': 'numeric',
                'source_file': 'text'
            },
            'log_targets': {
                'device_id': 'text',
                'dest_ip': 'ip_address',
                'proto': 'protocol',
                'port': 'port',
                'severity_mask': 'text',
                'facility': 'text',
                'buffered_size': 'numeric',
                'source_file': 'text'
            },
            'crypto_tls': {
                'device_id': 'text',
                'cert_name': 'text',
                'usage': 'text',
                'subject_cn': 'text',
                'issuer_cn': 'text',
                'expiry_date': 'text',
                'key_bits': 'numeric',
                'sha256_fingerprint': 'text',
                'source_file': 'text'
            },
            'feature_flags': {
                'device_id': 'text',
                'dhcp_snoop_enabled': 'boolean',
                'arp_inspection_enabled': 'boolean',
                'ipsg_enabled': 'boolean',
                'portfast_default': 'boolean',
                'spanning_tree_bpduguard_default': 'boolean',
                'source_file': 'text'
            },
            'firmware_inventory': {
                'device_id': 'text',
                'boot_image': 'text',
                'file_md5': 'text',
                'release_date': 'text',
                'secure_boot_enabled': 'boolean',
                'image_signature_ok': 'boolean',
                'component': 'text',
                'current_version': 'text',
                'backup_version': 'text',
                'running_image': 'text',
                'fallback_image': 'text',
                'source_file': 'text'
            },
            'ha_status': {
                'device_id': 'text',
                'ha_role': 'text',
                'peer_id': 'text',
                'sync_state': 'state',
                'failover_timer': 'numeric',
                'last_failover_ts': 'text',
                'source_file': 'text'
            },
            'nat_rules': {
                'device_id': 'text',
                'rule_id': 'text',
                'nat_type': 'text',
                'orig_src': 'text',
                'orig_dst': 'text',
                'orig_svc': 'text',
                'trans_src': 'text',
                'trans_dst': 'text',
                'trans_svc': 'text',
                'zone_in': 'text',
                'zone_out': 'text',
                'action': 'action',
                'hitcnt': 'numeric',
                'source_file': 'text'
            },
            'service_inventory': {
                'device_id': 'text',
                'service_name': 'text',
                'state': 'state',
                'vrf': 'text',
                'cipher_suite': 'text',
                'tcp_keepalive': 'boolean',
                'source_file': 'text'
            },
            'vpn_tunnels': {
                'device_id': 'text',
                'tunnel_id': 'text',
                'peer_ip': 'ip_address',
                'mode': 'text',
                'ike_policy': 'text',
                'pfs_group': 'text',
                'life_sec': 'numeric',
                'state': 'state',
                'bytes_in': 'numeric',
                'bytes_out': 'numeric',
                'source_file': 'text'
            },
            'zones': {
                'device_id': 'text',
                'zone_name': 'text',
                'interfaces_list': 'text',
                'inspection_profile': 'text',
                'source_file': 'text'
            },
            'login_banner': {
                'device_id': 'text',
                'banner_type': 'text',
                'text': 'text',
                'source_file': 'text'
            }
        }
    
    def normalize_dataframe(self, df: pd.DataFrame, schema_name: str) -> pd.DataFrame:
        """
        Normalize an entire DataFrame according to its schema.
        
        Args:
            df: DataFrame to normalize
            schema_name: Name of the schema (CSV type)
            
        Returns:
            Normalized DataFrame
        """
        if df.empty:
            return df
        
        self.logger.debug(f"Normalizing {len(df)} rows for schema: {schema_name}")
        
        # Get field types for this schema
        field_types = self.field_types.get(schema_name, {})
        
        # Apply normalization to each column
        normalized_df = df.copy()
        
        for column in df.columns:
            if column in field_types:
                field_type = field_types[column]
                try:
                    normalized_df[column] = df[column].apply(
                        lambda x: self._normalize_field(x, field_type)
                    )
                except Exception as e:
                    self.logger.warning(f"Error normalizing column {column}: {e}")
                    continue
        
        # Remove duplicate rows
        initial_count = len(normalized_df)
        normalized_df = normalized_df.drop_duplicates()
        final_count = len(normalized_df)
        
        if initial_count != final_count:
            self.logger.info(f"Removed {initial_count - final_count} duplicate rows from {schema_name}")
        
        return normalized_df
    
    def _normalize_field(self, value: Any, field_type: str) -> str:
        """
        Normalize a single field value.
        
        Args:
            value: Value to normalize
            field_type: Type of field
            
        Returns:
            Normalized value as string
        """
        if pd.isna(value) or value is None:
            return ""
        
        # Convert to string first
        str_value = str(value).strip()
        
        if not str_value:
            return ""
        
        # Apply appropriate normalization function
        if field_type in self.normalization_rules:
            try:
                normalized = self.normalization_rules[field_type](str_value)
                return normalized if normalized is not None else ""
            except Exception as e:
                self.logger.debug(f"Error normalizing value '{str_value}' as {field_type}: {e}")
                return str_value
        
        return str_value
    
    def _normalize_ip_address(self, value: str) -> str:
        """Normalize IP address."""
        normalized = parse_ip_address(value)
        return normalized if normalized else value
    
    def _normalize_mac_address(self, value: str) -> str:
        """Normalize MAC address."""
        normalized = format_mac_address(value)
        return normalized if normalized else value
    
    def _normalize_interface_name(self, value: str) -> str:
        """Normalize interface name."""
        return normalize_interface_name(value)
    
    def _normalize_subnet_mask(self, value: str) -> str:
        """Normalize subnet mask."""
        normalized = parse_subnet_mask(value)
        return normalized if normalized else value
    
    def _normalize_boolean(self, value: str) -> str:
        """Normalize boolean values."""
        value_lower = value.lower().strip()
        
        # Map various boolean representations
        true_values = {'true', 'yes', 'on', 'enabled', 'enable', '1', 'active', 'up'}
        false_values = {'false', 'no', 'off', 'disabled', 'disable', '0', 'inactive', 'down'}
        
        if value_lower in true_values:
            return "yes"
        elif value_lower in false_values:
            return "no"
        else:
            return value
    
    def _normalize_numeric(self, value: str) -> str:
        """Normalize numeric values."""
        # Remove non-numeric characters except decimal point
        numeric_value = re.sub(r'[^\d.]', '', value)
        
        if not numeric_value:
            return ""
        
        try:
            # Try to convert to number and back to remove leading zeros
            if '.' in numeric_value:
                return str(float(numeric_value))
            else:
                return str(int(numeric_value))
        except ValueError:
            return value
    
    def _normalize_text(self, value: str) -> str:
        """Normalize text values."""
        return clean_string(value)
    
    def _normalize_port(self, value: str) -> str:
        """Normalize port values."""
        # Handle port ranges and common port names
        value = value.strip()
        
        # Port name mappings
        port_mappings = {
            'ssh': '22',
            'telnet': '23',
            'smtp': '25',
            'dns': '53',
            'http': '80',
            'pop3': '110',
            'ntp': '123',
            'snmp': '161',
            'https': '443',
            'smtps': '465',
            'syslog': '514'
        }
        
        value_lower = value.lower()
        if value_lower in port_mappings:
            return port_mappings[value_lower]
        
        # Extract numeric port
        port_match = re.search(r'\d+', value)
        if port_match:
            port_num = int(port_match.group())
            if 1 <= port_num <= 65535:
                return str(port_num)
        
        return value
    
    def _normalize_protocol(self, value: str) -> str:
        """Normalize protocol values."""
        value = value.strip().lower()
        
        # Protocol mappings
        protocol_mappings = {
            'tcp': 'tcp',
            'udp': 'udp',
            'icmp': 'icmp',
            'esp': 'esp',
            'ah': 'ah',
            'gre': 'gre',
            'ospf': 'ospf',
            'eigrp': 'eigrp',
            'bgp': 'bgp',
            'rip': 'rip',
            'http': 'tcp',
            'https': 'tcp',
            'ssh': 'tcp',
            'telnet': 'tcp',
            'ftp': 'tcp',
            'snmp': 'udp',
            'dns': 'udp',
            'dhcp': 'udp',
            'ntp': 'udp'
        }
        
        return protocol_mappings.get(value, value)
    
    def _normalize_action(self, value: str) -> str:
        """Normalize action values."""
        value = value.strip().lower()
        
        # Action mappings
        action_mappings = {
            'permit': 'permit',
            'allow': 'permit',
            'accept': 'permit',
            'deny': 'deny',
            'drop': 'deny',
            'reject': 'deny',
            'block': 'deny'
        }
        
        return action_mappings.get(value, value)
    
    def _normalize_state(self, value: str) -> str:
        """Normalize state values."""
        value = value.strip().lower()
        
        # State mappings
        state_mappings = {
            'up': 'up',
            'active': 'up',
            'enabled': 'up',
            'online': 'up',
            'running': 'up',
            'down': 'down',
            'inactive': 'down',
            'disabled': 'down',
            'offline': 'down',
            'stopped': 'down',
            'admin-down': 'admin-down',
            'administratively down': 'admin-down'
        }
        
        return state_mappings.get(value, value)
    
    def validate_data(self, df: pd.DataFrame, schema_name: str) -> Dict[str, Any]:
        """
        Validate normalized data against schema requirements.
        
        Args:
            df: DataFrame to validate
            schema_name: Schema name
            
        Returns:
            Validation results
        """
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'record_count': len(df),
            'field_validation': {}
        }
        
        if df.empty:
            return validation_results
        
        field_types = self.field_types.get(schema_name, {})
        
        for column in df.columns:
            if column in field_types:
                field_result = self._validate_field(df[column], field_types[column])
                validation_results['field_validation'][column] = field_result
                
                if field_result['errors']:
                    validation_results['valid'] = False
                    validation_results['errors'].extend(field_result['errors'])
                
                if field_result['warnings']:
                    validation_results['warnings'].extend(field_result['warnings'])
        
        return validation_results
    
    def _validate_field(self, series: pd.Series, field_type: str) -> Dict[str, Any]:
        """
        Validate a field series against its type.
        
        Args:
            series: Pandas series to validate
            field_type: Expected field type
            
        Returns:
            Validation results for the field
        """
        result = {
            'errors': [],
            'warnings': [],
            'empty_count': series.isna().sum() + (series == "").sum(),
            'total_count': len(series)
        }
        
        # Type-specific validations
        if field_type == 'ip_address':
            invalid_ips = []
            for idx, value in series.items():
                if value and value != "" and not self._is_valid_ip(value):
                    invalid_ips.append(f"Row {idx}: '{value}'")
            
            if invalid_ips:
                result['warnings'].extend([f"Invalid IP addresses: {ip}" for ip in invalid_ips[:5]])
        
        elif field_type == 'mac_address':
            invalid_macs = []
            for idx, value in series.items():
                if value and value != "" and not self._is_valid_mac(value):
                    invalid_macs.append(f"Row {idx}: '{value}'")
            
            if invalid_macs:
                result['warnings'].extend([f"Invalid MAC addresses: {mac}" for mac in invalid_macs[:5]])
        
        elif field_type == 'numeric':
            non_numeric = []
            for idx, value in series.items():
                if value and value != "" and not self._is_numeric(value):
                    non_numeric.append(f"Row {idx}: '{value}'")
            
            if non_numeric:
                result['warnings'].extend([f"Non-numeric values: {val}" for val in non_numeric[:5]])
        
        return result
    
    def _is_valid_ip(self, value: str) -> bool:
        """Check if value is a valid IP address."""
        try:
            import ipaddress
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    
    def _is_valid_mac(self, value: str) -> bool:
        """Check if value is a valid MAC address."""
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(mac_pattern, value))
    
    def _is_numeric(self, value: str) -> bool:
        """Check if value is numeric."""
        try:
            float(value)
            return True
        except ValueError:
            return False
    
    def get_normalization_stats(self, original_df: pd.DataFrame, 
                               normalized_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Get statistics about the normalization process.
        
        Args:
            original_df: Original DataFrame
            normalized_df: Normalized DataFrame
            
        Returns:
            Statistics dictionary
        """
        return {
            'original_rows': len(original_df),
            'normalized_rows': len(normalized_df),
            'rows_removed': len(original_df) - len(normalized_df),
            'columns': len(normalized_df.columns) if not normalized_df.empty else 0,
            'empty_fields_before': original_df.isna().sum().sum() if not original_df.empty else 0,
            'empty_fields_after': normalized_df.isna().sum().sum() if not normalized_df.empty else 0
        } 