"""
File Scanner for the Network Configuration Parser.
Discovers and filters configuration files from input directories.
"""

import os
import logging
from pathlib import Path
from typing import List, Set, Optional
import re


class FileScanner:
    """Scans directories for network configuration files."""
    
    # Supported file extensions for configuration files
    CONFIG_EXTENSIONS = {
        '.txt', '.conf', '.cfg', '.config', '.xml', '.json', 
        '.log', '.bak', '.backup', '.running', '.startup'
    }
    
    # File patterns that likely contain configuration data
    CONFIG_PATTERNS = [
        r'.*running.*config.*',
        r'.*startup.*config.*', 
        r'.*\.conf$',
        r'.*\.cfg$',
        r'.*config.*\.txt$',
        r'.*backup.*',
        r'.*\.log$',
        r'.*\.xml$',
        r'.*\.json$'
    ]
    
    # Patterns to exclude (logs, temporary files, etc.)
    EXCLUDE_PATTERNS = [
        r'.*\.tmp$',
        r'.*\.temp$',
        r'.*\.swp$',
        r'.*\.bak\d+$',
        r'.*~$',
        r'.*\.pyc$',
        r'.*\.pyo$',
        r'.*__pycache__.*',
        r'.*\.git.*',
        r'.*\.svn.*'
    ]
    
    # Minimum file size (bytes) to consider
    MIN_FILE_SIZE = 50
    
    # Maximum file size (bytes) to consider (500MB)
    MAX_FILE_SIZE = 500 * 1024 * 1024
    
    def __init__(self):
        """Initialize the file scanner."""
        self.logger = logging.getLogger(__name__)
        
    def scan_directory(self, directory: Path, recursive: bool = True) -> List[Path]:
        """
        Scan directory for configuration files.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories
            
        Returns:
            List of configuration file paths
        """
        config_files = []
        
        if not directory.exists():
            self.logger.error(f"Directory does not exist: {directory}")
            return config_files
            
        if not directory.is_dir():
            self.logger.error(f"Path is not a directory: {directory}")
            return config_files
        
        self.logger.info(f"Scanning directory: {directory}")
        
        try:
            if recursive:
                # Recursively walk through directory
                for root, dirs, files in os.walk(directory):
                    # Filter out hidden directories
                    dirs[:] = [d for d in dirs if not d.startswith('.')]
                    
                    for file in files:
                        file_path = Path(root) / file
                        if self._is_config_file(file_path):
                            config_files.append(file_path)
                            self.logger.debug(f"Found config file: {file_path}")
            else:
                # Only scan immediate directory
                for item in directory.iterdir():
                    if item.is_file() and self._is_config_file(item):
                        config_files.append(item)
                        self.logger.debug(f"Found config file: {item}")
                        
        except PermissionError as e:
            self.logger.error(f"Permission denied accessing directory: {directory} - {e}")
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {e}")
        
        self.logger.info(f"Found {len(config_files)} configuration files")
        return sorted(config_files)
    
    def _is_config_file(self, file_path: Path) -> bool:
        """
        Determine if a file is likely a configuration file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file appears to be a configuration file
        """
        # Check if file exists and is readable
        if not file_path.exists() or not file_path.is_file():
            return False
        
        # Check file size constraints
        try:
            file_size = file_path.stat().st_size
            if file_size < self.MIN_FILE_SIZE or file_size > self.MAX_FILE_SIZE:
                self.logger.debug(f"File size out of range: {file_path} ({file_size} bytes)")
                return False
        except OSError:
            return False
        
        filename = file_path.name.lower()
        
        # Check exclude patterns first
        for pattern in self.EXCLUDE_PATTERNS:
            if re.match(pattern, filename):
                self.logger.debug(f"File excluded by pattern: {file_path}")
                return False
        
        # Check file extension
        if file_path.suffix.lower() in self.CONFIG_EXTENSIONS:
            return True
        
        # Check filename patterns
        for pattern in self.CONFIG_PATTERNS:
            if re.match(pattern, filename, re.IGNORECASE):
                return True
        
        # Check if file contains configuration-like content
        if self._has_config_content(file_path):
            return True
        
        return False
    
    def _has_config_content(self, file_path: Path) -> bool:
        """
        Check if file contains configuration-like content by sampling.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if content appears to be configuration data
        """
        try:
            # Read first few lines to check content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Read first 10 lines or 2KB, whichever is smaller
                content_lines = []
                bytes_read = 0
                max_bytes = 2048
                
                for line in f:
                    content_lines.append(line.strip())
                    bytes_read += len(line.encode('utf-8'))
                    
                    if len(content_lines) >= 10 or bytes_read >= max_bytes:
                        break
                
                content = '\n'.join(content_lines).lower()
                
                # Look for configuration keywords
                config_keywords = [
                    'hostname', 'interface', 'vlan', 'router', 'switch',
                    'ip address', 'subnet', 'gateway', 'route', 'acl',
                    'access-list', 'snmp', 'ntp', 'aaa', 'username',
                    'enable', 'configure', 'config', 'version',
                    'service', 'line vty', 'line console', 'crypto',
                    'certificate', 'trustpoint', 'policy-map',
                    'class-map', 'spanning-tree', 'port-channel',
                    'management', 'logging', 'archive', 'feature',
                    'firewall', 'security', 'zone', 'nat', 'vpn'
                ]
                
                # Check XML/JSON indicators
                xml_indicators = ['<config', '<?xml', '<topology', '<device']
                json_indicators = ['{', '"config":', '"device":', '"interface":']
                
                keyword_count = 0
                for keyword in config_keywords:
                    if keyword in content:
                        keyword_count += 1
                
                # Check for XML content
                for indicator in xml_indicators:
                    if indicator in content:
                        return True
                
                # Check for JSON content
                for indicator in json_indicators:
                    if indicator in content:
                        return True
                
                # If we found multiple configuration keywords, likely a config file
                if keyword_count >= 2:
                    return True
                
                # Check for command-line interface patterns
                cli_patterns = [
                    r'#.*show.*',
                    r'.*#.*config.*',
                    r'.*\(config\)#.*',
                    r'.*>.*',
                    r'.*%.*',
                    r'building configuration',
                    r'current configuration',
                    r'running configuration'
                ]
                
                for pattern in cli_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
                
        except (UnicodeDecodeError, IOError, OSError):
            # If we can't read as text, might be binary - skip
            return False
        
        return False
    
    def get_file_info(self, file_path: Path) -> dict:
        """
        Get detailed information about a configuration file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with file information
        """
        try:
            stat = file_path.stat()
            return {
                'path': str(file_path),
                'name': file_path.name,
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'extension': file_path.suffix.lower(),
                'is_readable': os.access(file_path, os.R_OK)
            }
        except OSError as e:
            self.logger.error(f"Error getting file info for {file_path}: {e}")
            return {
                'path': str(file_path),
                'name': file_path.name,
                'size': 0,
                'modified': 0,
                'extension': '',
                'is_readable': False,
                'error': str(e)
            }
    
    def filter_by_size(self, files: List[Path], min_size: int = None, 
                      max_size: int = None) -> List[Path]:
        """
        Filter files by size constraints.
        
        Args:
            files: List of file paths
            min_size: Minimum file size in bytes
            max_size: Maximum file size in bytes
            
        Returns:
            Filtered list of file paths
        """
        if min_size is None:
            min_size = self.MIN_FILE_SIZE
        if max_size is None:
            max_size = self.MAX_FILE_SIZE
        
        filtered_files = []
        
        for file_path in files:
            try:
                file_size = file_path.stat().st_size
                if min_size <= file_size <= max_size:
                    filtered_files.append(file_path)
                else:
                    self.logger.debug(f"File filtered by size: {file_path} ({file_size} bytes)")
            except OSError:
                continue
        
        return filtered_files
    
    def filter_by_extension(self, files: List[Path], 
                           extensions: Set[str]) -> List[Path]:
        """
        Filter files by extension.
        
        Args:
            files: List of file paths
            extensions: Set of allowed extensions (with dots)
            
        Returns:
            Filtered list of file paths
        """
        return [f for f in files if f.suffix.lower() in extensions] 