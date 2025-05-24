#!/usr/bin/env python3
"""
Network Configuration Parser
Main entry point for the network configuration parsing system.
"""

import argparse
import sys
import os
import logging
from pathlib import Path
from typing import List, Optional

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.file_scanner import FileScanner
from core.vendor_detector import VendorDetector
from core.parser_registry import ParserRegistry
from output.csv_writer import CSVWriter
from utils.logging_config import setup_logging


class NetworkConfigParser:
    """Main parser orchestrator."""
    
    def __init__(self, input_dir: str, output_dir: str = "output_csv", 
                 config_file: Optional[str] = None):
        """
        Initialize the parser.
        
        Args:
            input_dir: Directory containing configuration files
            output_dir: Directory for CSV output files
            config_file: Optional configuration file path
        """
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.config_file = config_file
        
        # Initialize components
        self.file_scanner = FileScanner()
        self.vendor_detector = VendorDetector()
        self.parser_registry = ParserRegistry()
        self.csv_writer = CSVWriter(self.output_dir)
        
        # Setup logging
        setup_logging()
        self.logger = logging.getLogger(__name__)
        
    def parse_configurations(self) -> bool:
        """
        Main parsing pipeline.
        
        Returns:
            bool: True if parsing completed successfully
        """
        try:
            self.logger.info("Starting network configuration parsing")
            self.logger.info(f"Input directory: {self.input_dir}")
            self.logger.info(f"Output directory: {self.output_dir}")
            
            # Step 1: Scan for configuration files
            self.logger.info("Scanning for configuration files...")
            config_files = self.file_scanner.scan_directory(self.input_dir)
            self.logger.info(f"Found {len(config_files)} configuration files")
            
            if not config_files:
                self.logger.warning("No configuration files found")
                return False
            
            # Step 2: Process each file
            processed_count = 0
            failed_count = 0
            
            for file_path in config_files:
                try:
                    self.logger.info(f"Processing: {file_path}")
                    
                    # Detect vendor and OS
                    vendor_info = self.vendor_detector.detect_vendor(file_path)
                    if not vendor_info:
                        self.logger.warning(f"Could not detect vendor for: {file_path}")
                        failed_count += 1
                        continue
                    
                    self.logger.debug(f"Detected: {vendor_info}")
                    
                    # Get appropriate parser
                    parser = self.parser_registry.get_parser(
                        vendor_info.vendor,
                        vendor_info.os_family
                    )
                    
                    if not parser:
                        self.logger.warning(f"No parser available for {vendor_info}")
                        failed_count += 1
                        continue
                    
                    # Parse configuration
                    parsed_data = parser.parse_file(file_path, vendor_info)
                    
                    if parsed_data:
                        # Write to CSV files
                        self.csv_writer.write_data(parsed_data)
                        processed_count += 1
                        self.logger.info(f"Successfully processed: {file_path}")
                    else:
                        self.logger.error(f"Failed to parse: {file_path}")
                        failed_count += 1
                        
                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {str(e)}")
                    failed_count += 1
                    continue
            
            # Final summary
            self.logger.info(f"Parsing completed. Processed: {processed_count}, Failed: {failed_count}")
            
            # Generate summary report
            self._generate_summary_report(processed_count, failed_count, len(config_files))
            
            return processed_count > 0
            
        except Exception as e:
            self.logger.error(f"Critical error in parsing pipeline: {str(e)}")
            return False
    
    def _generate_summary_report(self, processed: int, failed: int, total: int):
        """Generate a summary report of the parsing results."""
        summary_file = self.output_dir / "parsing_summary.txt"
        
        with open(summary_file, 'w') as f:
            f.write("Network Configuration Parser - Summary Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Total files found: {total}\n")
            f.write(f"Successfully processed: {processed}\n")
            f.write(f"Failed to process: {failed}\n")
            f.write(f"Success rate: {(processed/total)*100:.1f}%\n\n")
            
            # List CSV files generated
            csv_files = list(self.output_dir.glob("*.csv"))
            f.write(f"Generated CSV files ({len(csv_files)}):\n")
            for csv_file in sorted(csv_files):
                f.write(f"  - {csv_file.name}\n")
        
        self.logger.info(f"Summary report saved to: {summary_file}")


def main():
    """Main function with CLI interface."""
    parser = argparse.ArgumentParser(
        description="Network Configuration Parser - Transform network configs to structured CSV data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py /path/to/configs
  python main.py /path/to/configs -o /path/to/output
  python main.py /path/to/configs --verbose
  python main.py /path/to/configs --config custom_config.yaml
        """
    )
    
    parser.add_argument('input_dir', 
                       help='Directory containing network configuration files')
    parser.add_argument('-o', '--output', 
                       default='output_csv',
                       help='Output directory for CSV files (default: output_csv)')
    parser.add_argument('-c', '--config', 
                       help='Configuration file path')
    parser.add_argument('-v', '--verbose', 
                       action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--version', 
                       action='version', 
                       version='Network Configuration Parser 1.0.0')
    
    args = parser.parse_args()
    
    # Validate input directory
    if not os.path.exists(args.input_dir):
        print(f"Error: Input directory '{args.input_dir}' does not exist")
        sys.exit(1)
    
    if not os.path.isdir(args.input_dir):
        print(f"Error: '{args.input_dir}' is not a directory")
        sys.exit(1)
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create parser instance and run
    try:
        config_parser = NetworkConfigParser(
            input_dir=args.input_dir,
            output_dir=args.output,
            config_file=args.config
        )
        
        success = config_parser.parse_configurations()
        
        if success:
            print(f"\n✅ Parsing completed successfully!")
            print(f"📁 CSV files saved to: {args.output}")
            sys.exit(0)
        else:
            print(f"\n❌ Parsing failed or no files processed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n⚠️  Parsing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Critical error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 