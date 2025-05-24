#!/usr/bin/env python3
"""
Enhanced Network Configuration Parser
Focused on capturing missing data identified in comparison analysis.
"""

import sys
import logging
from pathlib import Path
from typing import Dict, List

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from main import NetworkConfigParser
from core.data_models import ParsedData
from utils.logging_config import setup_logging


class EnhancedNetworkParser(NetworkConfigParser):
    """Enhanced parser with focus on data completeness."""
    
    def __init__(self, input_dir: str, output_dir: str = "output_csv"):
        super().__init__(input_dir, output_dir)
        self.setup_enhanced_logging()
        
    def setup_enhanced_logging(self):
        """Setup enhanced logging for detailed analysis."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('enhanced_parsing.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def parse_configurations_enhanced(self) -> bool:
        """Enhanced parsing pipeline with focus on missing data."""
        try:
            self.logger.info("Starting ENHANCED network configuration parsing")
            self.logger.info("Focus: Capturing missing data from comparison analysis")
            self.logger.info(f"Input directory: {self.input_dir}")
            self.logger.info(f"Output directory: {self.output_dir}")
            
            # Step 1: Scan for configuration files
            self.logger.info("Scanning for configuration files...")
            config_files = self.file_scanner.scan_directory(self.input_dir)
            self.logger.info(f"Found {len(config_files)} configuration files")
            
            if not config_files:
                self.logger.warning("No configuration files found")
                return False
            
            # Step 2: Process each file with enhanced extraction
            processed_count = 0
            failed_count = 0
            total_extracted_items = 0
            
            for file_path in config_files:
                try:
                    self.logger.info(f"Processing: {file_path}")
                    
                    # Detect vendor and OS
                    vendor_info = self.vendor_detector.detect_vendor(file_path)
                    if not vendor_info:
                        self.logger.warning(f"Could not detect vendor for: {file_path}")
                        failed_count += 1
                        continue
                    
                    self.logger.info(f"Detected: {vendor_info.vendor} {vendor_info.os_family}")
                    
                    # Get appropriate parser
                    parser = self.parser_registry.get_parser(
                        vendor_info.vendor,
                        vendor_info.os_family
                    )
                    
                    if not parser:
                        self.logger.warning(f"No parser available for {vendor_info}")
                        failed_count += 1
                        continue
                    
                    # Parse configuration with enhanced logging
                    parsed_data = parser.parse_file(file_path, vendor_info)
                    
                    if parsed_data:
                        # Log detailed extraction statistics
                        stats = parsed_data.get_statistics()
                        self.logger.info(f"Extraction statistics for {file_path}:")
                        for data_type, count in stats.items():
                            if count > 0:
                                self.logger.info(f"  - {data_type}: {count} items")
                                total_extracted_items += count
                        
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
            
            # Enhanced summary report
            self.logger.info("=" * 60)
            self.logger.info("ENHANCED PARSING COMPLETED")
            self.logger.info("=" * 60)
            self.logger.info(f"Processed: {processed_count}/{len(config_files)} files")
            self.logger.info(f"Failed: {failed_count} files")
            self.logger.info(f"Total extracted items: {total_extracted_items}")
            self.logger.info(f"Success rate: {(processed_count/len(config_files))*100:.1f}%")
            
            # Generate enhanced summary report
            self._generate_enhanced_summary_report(
                processed_count, failed_count, len(config_files), total_extracted_items
            )
            
            return processed_count > 0
            
        except Exception as e:
            self.logger.error(f"Critical error in enhanced parsing pipeline: {str(e)}")
            return False
    
    def _generate_enhanced_summary_report(self, processed: int, failed: int, 
                                        total: int, total_items: int):
        """Generate enhanced summary report with detailed statistics."""
        summary_file = self.output_dir / "enhanced_parsing_summary.txt"
        
        with open(summary_file, 'w') as f:
            f.write("Enhanced Network Configuration Parser - Summary Report\n")
            f.write("=" * 60 + "\n\n")
            f.write("PROCESSING SUMMARY:\n")
            f.write(f"Total files found: {total}\n")
            f.write(f"Successfully processed: {processed}\n")
            f.write(f"Failed to process: {failed}\n")
            f.write(f"Success rate: {(processed/total)*100:.1f}%\n")
            f.write(f"Total configuration items extracted: {total_items}\n\n")
            
            # List CSV files generated with sizes
            csv_files = list(self.output_dir.glob("*.csv"))
            f.write(f"GENERATED CSV FILES ({len(csv_files)}):\n")
            for csv_file in sorted(csv_files):
                size_kb = csv_file.stat().st_size / 1024
                f.write(f"  - {csv_file.name} ({size_kb:.1f} KB)\n")
            
            f.write("\nENHANCEMENTS APPLIED:\n")
            f.write("• Enhanced ACL parsing with detailed field extraction\n")
            f.write("• Improved static route parsing with admin distance and tags\n")
            f.write("• Enhanced NTP server parsing with authentication and VRF\n")
            f.write("• Detailed user parsing with roles and status\n")
            f.write("• Comprehensive SNMP parsing with location and contact\n")
            f.write("• Added detailed OSPF and BGP parsing\n")
            f.write("• Enhanced DNS server configuration extraction\n")
            
        self.logger.info(f"Enhanced summary report saved to: {summary_file}")


def main():
    """Main function for enhanced parsing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced Network Configuration Parser - Focused on Data Completeness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This enhanced parser addresses missing data identified in comparison analysis:
• Captures detailed ACL configurations with all fields
• Extracts comprehensive routing information
• Parses user configurations with roles and status
• Includes SNMP location and contact information
• Provides detailed OSPF and BGP parsing
• Enhanced NTP server configurations

Examples:
  python enhanced_parser_system.py /path/to/configs
  python enhanced_parser_system.py /path/to/configs -o /path/to/output
        """
    )
    
    parser.add_argument('input_dir', 
                       help='Directory containing network configuration files')
    parser.add_argument('-o', '--output', 
                       default='output_csv',
                       help='Output directory for CSV files (default: output_csv)')
    parser.add_argument('-v', '--verbose', 
                       action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Validate input directory
    if not Path(args.input_dir).exists():
        print(f"Error: Input directory '{args.input_dir}' does not exist")
        sys.exit(1)
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create enhanced parser instance and run
    try:
        enhanced_parser = EnhancedNetworkParser(
            input_dir=args.input_dir,
            output_dir=args.output
        )
        
        success = enhanced_parser.parse_configurations_enhanced()
        
        if success:
            print(f"\n✅ Enhanced parsing completed successfully!")
            print(f"📁 CSV files saved to: {args.output}")
            print(f"📊 Check enhanced_parsing_summary.txt for detailed statistics")
            sys.exit(0)
        else:
            print(f"\n❌ Enhanced parsing failed or no files processed")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f"\n⚠️  Enhanced parsing interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Critical error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 