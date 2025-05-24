"""
CSV Writer for the Network Configuration Parser.
Handles writing parsed data to standardized CSV files.
"""

import csv
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import pandas as pd
from datetime import datetime

from core.data_models import ParsedData
from .data_normalizer import DataNormalizer


class CSVWriter:
    """Writes parsed configuration data to CSV files."""
    
    # CSV field definitions for each output file
    CSV_SCHEMAS = {
        'devices': [
            'device_id', 'hostname', 'vendor', 'model', 'os_family', 'os_version',
            'serial_number', 'location', 'config_timestamp', 'source_file'
        ],
        'interfaces': [
            'device_id', 'interface_name', 'description', 'ip_address', 'subnet_mask',
            'vlan', 'speed_mbps', 'duplex', 'admin_status', 'operational_status',
            'mac_address', 'if_type', 'ip6_address', 'lldp_remote_sysname',
            'port_security', 'bpdu_guard', 'root_guard', 'storm_control_pps',
            'mtu', 'source_file'
        ],
        'vlans_vrfs': [
            'device_id', 'vlan_id', 'vlan_name', 'description', 'state', 'mode',
            'svi_ip', 'vrf_name', 'vrf_rd', 'active', 'source_file'
        ],
        'acls': [
            'device_id', 'acl_name', 'acl_type', 'seq', 'action', 'proto', 'src',
            'src_port', 'dst', 'dst_port', 'hitcnt', 'remarks', 'source_file'
        ],
        'routing_static': [
            'device_id', 'destination', 'prefix_length', 'next_hop', 'interface',
            'metric', 'route_type', 'vrf', 'distance', 'source_file'
        ],
        'routing_dynamic': [
            'device_id', 'neighbor_ip', 'remote_as', 'description', 'peer_group',
            'source_interface', 'protocol', 'process_id', 'router_id', 'areas',
            'redistributions', 'source_file'
        ],
        'ntp': [
            'device_id', 'ntp_server', 'prefer_flag', 'key_id', 'auth_state',
            'reachability', 'source_file'
        ],
        'aaa_servers': [
            'device_id', 'server_type', 'server_ip', 'vrf', 'key_hash',
            'timeout_sec', 'server_group', 'accounting_enabled', 'source_file'
        ],
        'snmp': [
            'device_id', 'version', 'community_or_user', 'auth_level', 'view',
            'target_host', 'acl_applied', 'trap_enable', 'source_file'
        ],
        'users_local': [
            'device_id', 'username', 'privilege', 'hash_type', 'last_pw_change',
            'password_lifetime_days', 'source_file'
        ],
        'log_targets': [
            'device_id', 'dest_ip', 'proto', 'port', 'severity_mask', 'facility',
            'buffered_size', 'source_file'
        ],
        'crypto_tls': [
            'device_id', 'cert_name', 'usage', 'subject_cn', 'issuer_cn',
            'expiry_date', 'key_bits', 'sha256_fingerprint', 'source_file'
        ],
        'feature_flags': [
            'device_id', 'dhcp_snoop_enabled', 'arp_inspection_enabled',
            'ipsg_enabled', 'portfast_default', 'spanning_tree_bpduguard_default',
            'source_file'
        ],
        'firmware_inventory': [
            'device_id', 'boot_image', 'file_md5', 'release_date',
            'secure_boot_enabled', 'image_signature_ok', 'component',
            'current_version', 'backup_version', 'running_image',
            'fallback_image', 'source_file'
        ],
        'ha_status': [
            'device_id', 'ha_role', 'peer_id', 'sync_state', 'failover_timer',
            'last_failover_ts', 'source_file'
        ],
        'nat_rules': [
            'device_id', 'rule_id', 'nat_type', 'orig_src', 'orig_dst',
            'orig_svc', 'trans_src', 'trans_dst', 'trans_svc', 'zone_in',
            'zone_out', 'action', 'hitcnt', 'source_file'
        ],
        'service_inventory': [
            'device_id', 'service_name', 'state', 'vrf', 'cipher_suite',
            'tcp_keepalive', 'source_file'
        ],
        'vpn_tunnels': [
            'device_id', 'tunnel_id', 'peer_ip', 'mode', 'ike_policy',
            'pfs_group', 'life_sec', 'state', 'bytes_in', 'bytes_out',
            'source_file'
        ],
        'zones': [
            'device_id', 'zone_name', 'interfaces_list', 'inspection_profile',
            'source_file'
        ],
        'login_banner': [
            'device_id', 'banner_type', 'text', 'source_file'
        ],
        'hsrp_vrrp_groups': [
            'device_id', 'interface', 'group_id', 'protocol', 'virtual_ip',
            'priority', 'preempt', 'track_interface', 'track_object',
            'authentication_type', 'authentication_key', 'timers_hello',
            'timers_hold', 'status', 'source_file'
        ],
        'dns_configs': [
            'device_id', 'dns_server', 'domain_name', 'dns_type', 'vrf',
            'lookup_enabled', 'source_interface', 'source_file'
        ]
    }
    
    def __init__(self, output_dir: Path):
        """
        Initialize the CSV writer.
        
        Args:
            output_dir: Directory for CSV output files
        """
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger(__name__)
        self.normalizer = DataNormalizer()
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Track written files
        self.written_files = set()
        
        # CSV write options
        self.csv_options = {
            'quoting': csv.QUOTE_MINIMAL,
            'lineterminator': '\n',
            'encoding': 'utf-8'
        }
    
    def write_data(self, parsed_data: ParsedData) -> Dict[str, str]:
        """
        Write all parsed data to CSV files.
        
        Args:
            parsed_data: ParsedData object containing all parsed information
            
        Returns:
            Dictionary mapping CSV file names to their paths
        """
        self.logger.info("Writing parsed data to CSV files")
        
        # Convert parsed data to DataFrames
        dataframes = parsed_data.to_dataframes()
        
        written_files = {}
        
        # Ensure all 20 CSV schemas are created, even if empty
        for csv_name in self.CSV_SCHEMAS.keys():
            try:
                # Get DataFrame if it exists, otherwise create empty one
                if csv_name in dataframes and not dataframes[csv_name].empty:
                    df = dataframes[csv_name]
                else:
                    # Create empty DataFrame with correct schema
                    df = pd.DataFrame(columns=self.CSV_SCHEMAS[csv_name])
                
                # Normalize data
                df = self.normalizer.normalize_dataframe(df, csv_name)
                
                # Write to CSV
                csv_path = self._write_csv(csv_name, df)
                written_files[csv_name] = str(csv_path)
                
                if not df.empty:
                    self.logger.info(f"Written {len(df)} rows to {csv_path}")
                else:
                    self.logger.info(f"Created empty CSV file: {csv_path}")
                    
            except Exception as e:
                self.logger.error(f"Error writing {csv_name}.csv: {e}")
                continue
        
        # Generate metadata file
        self._write_metadata(written_files, parsed_data)
        
        self.logger.info(f"CSV generation completed. {len(written_files)} files written.")
        return written_files
    
    def _write_csv(self, csv_name: str, df: pd.DataFrame) -> Path:
        """
        Write a DataFrame to a CSV file.
        
        Args:
            csv_name: Name of the CSV file (without extension)
            df: DataFrame to write
            
        Returns:
            Path to the written CSV file
        """
        csv_path = self.output_dir / f"{csv_name}.csv"
        
        # Ensure DataFrame has the correct columns
        schema = self.CSV_SCHEMAS.get(csv_name, list(df.columns))
        
        # Add missing columns with empty values
        for col in schema:
            if col not in df.columns:
                df[col] = ""
        
        # Reorder columns to match schema
        df = df.reindex(columns=schema, fill_value="")
        
        # Write CSV file
        mode = 'a' if csv_path.exists() and csv_name in self.written_files else 'w'
        header = mode == 'w'  # Write header only for new files
        
        df.to_csv(
            csv_path,
            mode=mode,
            header=header,
            index=False,
            **self.csv_options
        )
        
        self.written_files.add(csv_name)
        return csv_path
    
    def _write_metadata(self, written_files: Dict[str, str], parsed_data: ParsedData):
        """
        Write metadata about the CSV generation process.
        
        Args:
            written_files: Dictionary of written CSV files
            parsed_data: Original parsed data
        """
        metadata_path = self.output_dir / "metadata.json"
        
        stats = parsed_data.get_statistics()
        
        metadata = {
            'generation_time': datetime.now().isoformat(),
            'csv_files_generated': len(written_files),
            'files': written_files,
            'record_counts': stats,
            'total_records': sum(stats.values()),
            'schemas': self.CSV_SCHEMAS
        }
        
        import json
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        self.logger.info(f"Metadata written to {metadata_path}")
    
    def append_data(self, csv_name: str, data: List[Dict[str, Any]]) -> bool:
        """
        Append data to an existing CSV file.
        
        Args:
            csv_name: Name of the CSV file
            data: List of dictionaries to append
            
        Returns:
            True if successful
        """
        try:
            if not data:
                return True
            
            df = pd.DataFrame(data)
            df = self.normalizer.normalize_dataframe(df, csv_name)
            
            csv_path = self._write_csv(csv_name, df)
            
            self.logger.debug(f"Appended {len(data)} rows to {csv_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error appending to {csv_name}.csv: {e}")
            return False
    
    def create_empty_csvs(self) -> Dict[str, str]:
        """
        Create empty CSV files with headers for all schemas.
        
        Returns:
            Dictionary mapping CSV names to file paths
        """
        created_files = {}
        
        for csv_name, schema in self.CSV_SCHEMAS.items():
            csv_path = self.output_dir / f"{csv_name}.csv"
            
            try:
                # Create empty DataFrame with schema columns
                df = pd.DataFrame(columns=schema)
                
                # Write header only
                df.to_csv(csv_path, index=False, **self.csv_options)
                
                created_files[csv_name] = str(csv_path)
                self.logger.debug(f"Created empty CSV: {csv_path}")
                
            except Exception as e:
                self.logger.error(f"Error creating empty CSV {csv_name}: {e}")
        
        self.logger.info(f"Created {len(created_files)} empty CSV files")
        return created_files
    
    def validate_csv_files(self) -> Dict[str, Dict[str, Any]]:
        """
        Validate existing CSV files against schemas.
        
        Returns:
            Dictionary with validation results for each file
        """
        validation_results = {}
        
        for csv_name, expected_schema in self.CSV_SCHEMAS.items():
            csv_path = self.output_dir / f"{csv_name}.csv"
            
            result = {
                'exists': csv_path.exists(),
                'valid': False,
                'errors': [],
                'row_count': 0,
                'missing_columns': [],
                'extra_columns': []
            }
            
            if csv_path.exists():
                try:
                    # Read CSV and check schema
                    df = pd.read_csv(csv_path, nrows=1)  # Read just header
                    actual_columns = list(df.columns)
                    
                    result['row_count'] = len(pd.read_csv(csv_path))
                    result['missing_columns'] = [col for col in expected_schema if col not in actual_columns]
                    result['extra_columns'] = [col for col in actual_columns if col not in expected_schema]
                    
                    if not result['missing_columns'] and not result['extra_columns']:
                        result['valid'] = True
                    else:
                        if result['missing_columns']:
                            result['errors'].append(f"Missing columns: {result['missing_columns']}")
                        if result['extra_columns']:
                            result['errors'].append(f"Extra columns: {result['extra_columns']}")
                
                except Exception as e:
                    result['errors'].append(f"Read error: {str(e)}")
            
            validation_results[csv_name] = result
        
        return validation_results
    
    def get_csv_summary(self) -> Dict[str, Any]:
        """
        Get summary information about generated CSV files.
        
        Returns:
            Summary dictionary
        """
        summary = {
            'output_directory': str(self.output_dir),
            'csv_files': {},
            'total_files': 0,
            'total_size_bytes': 0,
            'last_modified': None
        }
        
        for csv_name in self.CSV_SCHEMAS.keys():
            csv_path = self.output_dir / f"{csv_name}.csv"
            
            if csv_path.exists():
                try:
                    stat = csv_path.stat()
                    row_count = len(pd.read_csv(csv_path)) if stat.st_size > 0 else 0
                    
                    summary['csv_files'][csv_name] = {
                        'path': str(csv_path),
                        'size_bytes': stat.st_size,
                        'row_count': row_count,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    }
                    
                    summary['total_files'] += 1
                    summary['total_size_bytes'] += stat.st_size
                    
                    if not summary['last_modified'] or stat.st_mtime > summary['last_modified']:
                        summary['last_modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
                
                except Exception as e:
                    self.logger.error(f"Error getting info for {csv_path}: {e}")
        
        return summary
    
    def clean_output_directory(self) -> bool:
        """
        Clean the output directory by removing all CSV files.
        
        Returns:
            True if successful
        """
        try:
            removed_count = 0
            
            for csv_file in self.output_dir.glob("*.csv"):
                csv_file.unlink()
                removed_count += 1
            
            # Also remove metadata file
            metadata_file = self.output_dir / "metadata.json"
            if metadata_file.exists():
                metadata_file.unlink()
                removed_count += 1
            
            self.written_files.clear()
            
            self.logger.info(f"Cleaned output directory: removed {removed_count} files")
            return True
            
        except Exception as e:
            self.logger.error(f"Error cleaning output directory: {e}")
            return False
    
    def merge_csv_files(self, source_dir: Path) -> Dict[str, int]:
        """
        Merge CSV files from another directory into this output directory.
        
        Args:
            source_dir: Directory containing CSV files to merge
            
        Returns:
            Dictionary with merge statistics
        """
        merge_stats = {}
        
        for csv_name in self.CSV_SCHEMAS.keys():
            source_csv = source_dir / f"{csv_name}.csv"
            target_csv = self.output_dir / f"{csv_name}.csv"
            
            if source_csv.exists():
                try:
                    # Read source data
                    source_df = pd.read_csv(source_csv)
                    
                    if not source_df.empty:
                        # Normalize data
                        source_df = self.normalizer.normalize_dataframe(source_df, csv_name)
                        
                        # Append to target
                        if target_csv.exists():
                            target_df = pd.read_csv(target_csv)
                            combined_df = pd.concat([target_df, source_df], ignore_index=True)
                        else:
                            combined_df = source_df
                        
                        # Remove duplicates based on all columns
                        initial_count = len(combined_df)
                        combined_df = combined_df.drop_duplicates()
                        final_count = len(combined_df)
                        
                        # Write merged data
                        self._write_csv(csv_name, combined_df)
                        
                        merge_stats[csv_name] = {
                            'added_rows': len(source_df),
                            'total_rows': final_count,
                            'duplicates_removed': initial_count - final_count
                        }
                        
                        self.logger.info(f"Merged {csv_name}: added {len(source_df)} rows")
                
                except Exception as e:
                    self.logger.error(f"Error merging {csv_name}: {e}")
                    merge_stats[csv_name] = {'error': str(e)}
        
        return merge_stats 