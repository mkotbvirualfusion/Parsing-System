#!/usr/bin/env python3
"""
Test Script for Enhanced Network Configuration Parser
Runs enhanced parsing and compares results with manual extraction.
"""

import subprocess
import sys
from pathlib import Path
import shutil


def run_enhanced_parser(input_dir: str, output_dir: str = "output_csv_enhanced"):
    """Run the enhanced parser system."""
    print("🚀 Running Enhanced Network Configuration Parser...")
    print(f"📁 Input directory: {input_dir}")
    print(f"📁 Output directory: {output_dir}")
    
    try:
        # Clean output directory if it exists
        if Path(output_dir).exists():
            shutil.rmtree(output_dir)
            
        # Run enhanced parser
        cmd = [sys.executable, "enhanced_parser_system.py", input_dir, "-o", output_dir, "-v"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Enhanced parsing completed successfully!")
            print(result.stdout)
            return True
        else:
            print("❌ Enhanced parsing failed!")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"💥 Error running enhanced parser: {e}")
        return False


def run_comparison_analysis(manual_dir: str = "ALL_DEVICES_MANUAL_EXTRACTION", 
                          enhanced_dir: str = "output_csv_enhanced"):
    """Run comparison between manual extraction and enhanced parser output."""
    print("\n🔍 Running Comparison Analysis...")
    print(f"📊 Comparing: {manual_dir} vs {enhanced_dir}")
    
    try:
        # Create a temporary comparison script
        comparison_code = f'''
import sys
import pandas as pd
import json
from pathlib import Path
from typing import Dict, List, Tuple, Set
import numpy as np

class CSVComparator:
    def __init__(self, manual_dir: str, output_dir: str):
        self.manual_dir = Path(manual_dir)
        self.output_dir = Path(output_dir)
        
    def get_csv_files(self, directory: Path) -> Set[str]:
        return {{f.name for f in directory.glob("*.csv")}}
    
    def read_csv_safe(self, file_path: Path) -> Tuple[pd.DataFrame, str]:
        try:
            for encoding in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']:
                try:
                    df = pd.read_csv(file_path, encoding=encoding, low_memory=False)
                    return df, "success"
                except UnicodeDecodeError:
                    continue
            return pd.DataFrame(), "encoding_error"
        except Exception as e:
            return pd.DataFrame(), f"error: {{str(e)}}"
    
    def analyze_file_presence(self) -> Dict:
        manual_files = self.get_csv_files(self.manual_dir)
        output_files = self.get_csv_files(self.output_dir)
        
        return {{
            "manual_only": manual_files - output_files,
            "output_only": output_files - manual_files,
            "common_files": manual_files & output_files,
            "manual_total": len(manual_files),
            "output_total": len(output_files)
        }}
    
    def compare_csv_structure(self, file1: Path, file2: Path) -> Dict:
        df1, status1 = self.read_csv_safe(file1)
        df2, status2 = self.read_csv_safe(file2)
        
        if status1 != "success" or status2 != "success":
            return {{
                "status": "read_error",
                "manual_status": status1,
                "output_status": status2
            }}
        
        return {{
            "status": "success",
            "manual_rows": len(df1),
            "output_rows": len(df2),
            "manual_columns": len(df1.columns),
            "output_columns": len(df2.columns),
            "row_difference": len(df1) - len(df2),
            "column_difference": len(df1.columns) - len(df2.columns),
            "improvement_pct": ((len(df2) - len(df1)) / len(df1) * 100) if len(df1) > 0 else 0
        }}
    
    def run_quick_comparison(self) -> Dict:
        file_presence = self.analyze_file_presence()
        detailed_comparisons = {{}}
        
        for filename in sorted(file_presence["common_files"]):
            manual_file = self.manual_dir / filename
            output_file = self.output_dir / filename
            
            structure_comp = self.compare_csv_structure(manual_file, output_file)
            detailed_comparisons[filename] = structure_comp
        
        return {{
            "file_presence": file_presence,
            "detailed_comparisons": detailed_comparisons
        }}

# Run comparison
comparator = CSVComparator("{manual_dir}", "{enhanced_dir}")
results = comparator.run_quick_comparison()

# Generate quick report
print("\\n" + "="*60)
print("ENHANCED PARSER COMPARISON RESULTS")
print("="*60)

summary = results["file_presence"]
print(f"📁 Manual extraction files: {{summary['manual_total']}}")
print(f"📁 Enhanced parser files: {{summary['output_total']}}")
print(f"📁 Common files: {{len(summary['common_files'])}}")

print("\\n📊 RECORD COUNT IMPROVEMENTS:")
total_manual_records = 0
total_enhanced_records = 0
improvements = []

for filename, data in results["detailed_comparisons"].items():
    if data["status"] == "success":
        manual_rows = data["manual_rows"]
        enhanced_rows = data["output_rows"]
        improvement = data["improvement_pct"]
        
        total_manual_records += manual_rows
        total_enhanced_records += enhanced_rows
        
        if manual_rows > 0:
            improvements.append(improvement)
            status = "✅" if improvement >= -10 else "⚠️" if improvement >= -50 else "❌"
            print(f"{{status}} {{filename}}: {{manual_rows}} → {{enhanced_rows}} ({{improvement:+.1f}}%)")

print(f"\\n🎯 OVERALL STATISTICS:")
print(f"Total records - Manual: {{total_manual_records:,}}")
print(f"Total records - Enhanced: {{total_enhanced_records:,}}")
if total_manual_records > 0:
    overall_improvement = ((total_enhanced_records - total_manual_records) / total_manual_records) * 100
    print(f"Overall improvement: {{overall_improvement:+.1f}}%")

if improvements:
    avg_improvement = sum(improvements) / len(improvements)
    print(f"Average file improvement: {{avg_improvement:+.1f}}%")
    
    good_files = len([i for i in improvements if i >= -10])
    print(f"Files with <10% loss: {{good_files}}/{{len(improvements)}} ({{(good_files/len(improvements))*100:.1f}}%)")

print("\\n" + "="*60)
        '''
        
        with open("temp_comparison.py", "w") as f:
            f.write(comparison_code)
        
        # Run comparison
        result = subprocess.run([sys.executable, "temp_comparison.py"], 
                              capture_output=True, text=True)
        
        print(result.stdout)
        if result.stderr:
            print(f"⚠️ Comparison warnings: {result.stderr}")
        
        # Clean up
        Path("temp_comparison.py").unlink()
        
        return True
        
    except Exception as e:
        print(f"💥 Error running comparison: {e}")
        return False


def main():
    """Main test function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Test Enhanced Network Configuration Parser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script runs the enhanced parser and compares results with manual extraction.

Examples:
  python test_enhanced_parser.py /path/to/configs
  python test_enhanced_parser.py configs --output enhanced_output
        """
    )
    
    parser.add_argument('input_dir', 
                       help='Directory containing network configuration files')
    parser.add_argument('--output', 
                       default='output_csv_enhanced',
                       help='Output directory for enhanced CSV files')
    parser.add_argument('--manual-dir',
                       default='ALL_DEVICES_MANUAL_EXTRACTION',
                       help='Directory containing manual extraction CSV files')
    parser.add_argument('--skip-parse',
                       action='store_true',
                       help='Skip parsing, only run comparison')
    
    args = parser.parse_args()
    
    # Validate input directory
    if not Path(args.input_dir).exists() and not args.skip_parse:
        print(f"❌ Error: Input directory '{args.input_dir}' does not exist")
        sys.exit(1)
    
    if not Path(args.manual_dir).exists():
        print(f"❌ Error: Manual extraction directory '{args.manual_dir}' does not exist")
        sys.exit(1)
    
    print("🧪 Enhanced Network Configuration Parser - Test Suite")
    print("=" * 60)
    
    # Step 1: Run enhanced parser (unless skipped)
    if not args.skip_parse:
        success = run_enhanced_parser(args.input_dir, args.output)
        if not success:
            print("❌ Enhanced parsing failed. Exiting.")
            sys.exit(1)
    else:
        print("⏭️ Skipping parsing step...")
    
    # Step 2: Run comparison analysis
    if not Path(args.output).exists():
        print(f"❌ Error: Enhanced output directory '{args.output}' does not exist")
        sys.exit(1)
    
    success = run_comparison_analysis(args.manual_dir, args.output)
    if success:
        print("\\n🎉 Test completed successfully!")
        print(f"📁 Enhanced results saved to: {args.output}")
    else:
        print("\\n❌ Test failed during comparison!")
        sys.exit(1)


if __name__ == "__main__":
    main() 